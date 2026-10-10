// Package gh implements source.Source on top of go-github.
package gh

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/go-github/v92/github"
	"github.com/runsweep/runsweep/internal/source"
)

const (
	maxRetries  = 5
	maxParallel = 10
	maxWait     = time.Hour // longest single wait for a rate limit reset or Retry-After
	runsCap     = 1000      // GitHub returns at most 1000 runs for a `created` filter
)

var maxLogBytes int64 = 64 << 20 // a var so tests can shrink it

// backoff between retries of transient failures (network errors, HTTP 5xx).
var backoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// Client is a GitHub REST API client implementing source.Source.
type Client struct {
	gh    *github.Client
	http  *http.Client
	sem   chan struct{}
	cache sync.Map // "tree:repo@sha" -> treeVal; blobs are not cached, callers cache what they parse
	fl    flight   // one in-flight request per tree, blob or file

	Logf  func(format string, args ...any)
	Sleep func(ctx context.Context, d time.Duration) error
}

// flight shares the result of a call among concurrent callers of the same key; nothing is kept
// afterwards, so errors are not cached.
type flight struct {
	mu sync.Mutex
	m  map[string]*flightCall
}

type flightCall struct {
	done chan struct{}
	val  any
	err  error
}

// shared runs f unless a call for key is in flight, in which case it waits for that one. A waiter
// whose own context is alive retries when the call it waited for died of its caller's context.
func shared[T any](ctx context.Context, g *flight, key string, f func() (T, error)) (T, error) {
	for {
		g.mu.Lock()
		if call, ok := g.m[key]; ok {
			g.mu.Unlock()
			select {
			case <-call.done:
			case <-ctx.Done():
				var zero T
				return zero, ctx.Err()
			}
			if call.err != nil && ctx.Err() == nil && (errors.Is(call.err, context.Canceled) || errors.Is(call.err, context.DeadlineExceeded)) {
				continue
			}
			v, _ := call.val.(T)
			return v, call.err
		}
		call := &flightCall{done: make(chan struct{})}
		if g.m == nil {
			g.m = map[string]*flightCall{}
		}
		g.m[key] = call
		g.mu.Unlock()
		return run(g, key, call, f)
	}
}

// errPanic is what waiters see when the call they wait for panicked.
var errPanic = errors.New("shared request panicked")

// run executes f and always releases the waiters, also when f panics (the panic goes on).
func run[T any](g *flight, key string, call *flightCall, f func() (T, error)) (T, error) {
	call.err = errPanic
	defer func() {
		g.mu.Lock()
		delete(g.m, key)
		g.mu.Unlock()
		close(call.done)
	}()
	v, err := f()
	call.val, call.err = v, err
	return v, err
}

type treeVal struct {
	entries   []source.TreeEntry
	truncated bool
}

// New returns a Client for baseURL authenticated with token.
func New(httpClient *http.Client, token, baseURL string) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	apiHTTP := *httpClient // the auth transport re-adds the token on every hop: keep redirects on the host
	apiHTTP.CheckRedirect = sameHost
	opts := []github.ClientOptionsFunc{github.WithHTTPClient(&apiHTTP), github.WithRateLimitRedirectionalEndpoints()}
	if token != "" {
		opts = append(opts, github.WithAuthToken(token))
	}
	if baseURL != "" {
		opts = append(opts, github.WithURLs(&baseURL, nil))
	}
	g, err := github.NewClient(opts...)
	if err != nil {
		return nil, err
	}
	logHTTP := *httpClient // go-github copied it: this one carries no token
	logHTTP.CheckRedirect = httpsOnly
	return &Client{gh: g, http: &logHTTP, sem: make(chan struct{}, maxParallel),
		Logf: func(string, ...any) {}, Sleep: sleepCtx}, nil
}

// errNotHTTPS refuses a job log URL or redirect hop that is not https.
var errNotHTTPS = fmt.Errorf("%w: job log URL is not https", source.ErrNoAccess)

// httpsOnly is the log client's redirect policy: https on every hop, at most 10 hops.
func httpsOnly(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" {
		return errNotHTTPS
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

// errCrossHost refuses an API redirect that leaves the host or the https scheme.
var errCrossHost = fmt.Errorf("%w: API redirected to another host or to http", source.ErrNoAccess)

// sameHost is the API client's redirect policy: https, the host of the first request, at most 10 hops.
func sameHost(req *http.Request, via []*http.Request) error {
	if req.URL.Scheme != "https" || req.URL.Host != via[0].URL.Host {
		return errCrossHost
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func split(repo string) (string, string) {
	o, r, _ := strings.Cut(repo, "/")
	return o, r
}

// transient reports a failure worth retrying: no HTTP response (network error) or HTTP 5xx.
func transient(ctx context.Context, status int, err error) bool {
	return ctx.Err() == nil && (status == 0 && err != nil || status >= 500)
}

// do runs f with the concurrency limit, retrying on rate limits and transient errors and mapping errors.
func (c *Client) do(ctx context.Context, f func() (*github.Response, error)) error {
	tries := 0
	for attempt := 0; ; attempt++ {
		select {
		case c.sem <- struct{}{}:
		case <-ctx.Done():
			return ctx.Err()
		}
		resp, err := f()
		<-c.sem
		if err == nil {
			return nil
		}
		var rl *github.RateLimitError
		var ab *github.AbuseRateLimitError
		var wait time.Duration
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		if transient(ctx, status, err) {
			if tries == len(backoff) {
				return mapErr(resp, err)
			}
			c.Logf("transient error, retrying in %s: %v", backoff[tries], err)
			if err := c.Sleep(ctx, backoff[tries]); err != nil {
				return err
			}
			tries++
			continue
		}
		switch {
		case errors.As(err, &rl):
			wait = time.Until(rl.Rate.Reset.Time) + time.Second
		case errors.As(err, &ab):
			wait = ab.GetRetryAfter()
			if wait == 0 {
				wait = time.Minute
			}
		default:
			secs, perr := 0, errors.New("no retry-after")
			if resp != nil && (resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests) {
				secs, perr = strconv.Atoi(resp.Header.Get("Retry-After"))
			}
			if perr != nil || secs < 0 {
				return mapErr(resp, err)
			}
			wait = time.Duration(secs) * time.Second
		}
		if attempt >= maxRetries {
			return err
		}
		wait = min(max(wait, time.Second), maxWait)
		c.Logf("rate limited, waiting %s (until %s)", wait.Round(time.Second), time.Now().Add(wait).UTC().Format("15:04:05 UTC"))
		if err := c.Sleep(ctx, wait); err != nil {
			return err
		}
	}
}

// mapErr makes a 4xx soft (the repo or run becomes UNCHECKED), except 401 and 429, which are
// fatal; rate limits that carry a reset time never get here.
func mapErr(resp *github.Response, err error) error {
	if resp != nil {
		msg := err.Error()
		if er := (*github.ErrorResponse)(nil); errors.As(err, &er) {
			msg = er.Message // not the request URL
		}
		switch code := resp.StatusCode; {
		case code == http.StatusGone:
			return source.ErrGone
		case code == http.StatusUnauthorized:
			return fmt.Errorf("%w: the token was rejected (expired, revoked or mistyped): %s", source.ErrAuth, msg)
		case code == http.StatusNotFound:
			return fmt.Errorf("%w: HTTP 404, not found or the token cannot see it (check its repository access and SSO authorization): %s", source.ErrNoAccess, msg)
		case code == http.StatusForbidden:
			return fmt.Errorf("%w: HTTP 403, the token lacks read access to Actions, Contents or Metadata, or SSO is not authorized: %s", source.ErrNoAccess, msg)
		case code >= 400 && code < 500 && code != http.StatusTooManyRequests:
			return fmt.Errorf("%w: HTTP %d: %s", source.ErrNoAccess, code, msg)
		}
	}
	return err
}

// ListRepos lists the repositories of an organisation.
func (c *Client) ListRepos(ctx context.Context, org string) ([]string, error) {
	opt := &github.RepositoryListByOrgOptions{Type: "all", ListOptions: github.ListOptions{PerPage: 100}}
	var out []string
	for {
		var repos []*github.Repository
		var resp *github.Response
		err := c.do(ctx, func() (*github.Response, error) {
			var err error
			repos, resp, err = c.gh.Repositories.ListByOrg(ctx, org, opt)
			return resp, err
		})
		if err != nil {
			return nil, err
		}
		for _, r := range repos {
			out = append(out, r.GetFullName())
		}
		if resp.NextPage == 0 {
			return out, nil
		}
		opt.Page = resp.NextPage
	}
}

// ListRuns lists workflow runs created within the given window. When GitHub caps a window it
// will not split further, it returns the runs it got with source.ErrRunsCapped.
func (c *Client) ListRuns(ctx context.Context, repo string, start, end time.Time) ([]source.Run, error) {
	owner, name := split(repo)
	opt := &github.ListWorkflowRunsOptions{
		Created:     start.UTC().Format(time.RFC3339) + ".." + end.UTC().Format(time.RFC3339),
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var out []source.Run
	var capped error
	for {
		var page *github.WorkflowRuns
		var resp *github.Response
		err := c.do(ctx, func() (*github.Response, error) {
			var err error
			page, resp, err = c.gh.Actions.ListRepositoryWorkflowRuns(ctx, owner, name, opt)
			return resp, err
		})
		if err != nil {
			return nil, err
		}
		if opt.Page == 0 && page.GetTotalCount() >= runsCap && end.Sub(start) <= time.Minute {
			c.Logf("%s: %d runs between %s and %s; GitHub returns at most %d — some runs not scanned",
				repo, page.GetTotalCount(), start.UTC().Format(time.RFC3339), end.UTC().Format(time.RFC3339), runsCap)
			capped = source.ErrRunsCapped
		}
		if opt.Page == 0 && page.GetTotalCount() >= runsCap && end.Sub(start) > time.Minute {
			mid := start.Add(end.Sub(start) / 2)
			c.Logf("%s: %d runs in window, splitting", repo, page.GetTotalCount())
			a, errA := c.ListRuns(ctx, repo, start, mid)
			if errA != nil && !errors.Is(errA, source.ErrRunsCapped) {
				return nil, errA
			}
			b, errB := c.ListRuns(ctx, repo, mid.Add(time.Second), end)
			if errB != nil && !errors.Is(errB, source.ErrRunsCapped) {
				return nil, errB
			}
			return append(a, b...), cmp.Or(errA, errB)
		}
		for _, r := range page.WorkflowRuns {
			out = append(out, source.Run{ID: r.GetID(), Name: r.GetName(), Path: r.GetPath(), HeadSHA: r.GetHeadSHA(), Event: r.GetEvent(),
				URL: r.GetHTMLURL(), CreatedAt: r.GetCreatedAt().Time, StartedAt: r.GetRunStartedAt().Time,
				UpdatedAt: r.GetUpdatedAt().Time, Attempt: r.GetRunAttempt(), Status: r.GetStatus()})
		}
		if resp.NextPage == 0 {
			return out, capped
		}
		opt.Page = resp.NextPage
	}
}

// ListJobs lists the jobs of a workflow run.
func (c *Client) ListJobs(ctx context.Context, repo string, runID int64) ([]source.Job, error) {
	owner, name := split(repo)
	opt := &github.ListWorkflowJobsOptions{Filter: "all", ListOptions: github.ListOptions{PerPage: 100}}
	var out []source.Job
	for {
		var jobs *github.Jobs
		var resp *github.Response
		err := c.do(ctx, func() (*github.Response, error) {
			var err error
			jobs, resp, err = c.gh.Actions.ListWorkflowJobs(ctx, owner, name, runID, opt)
			return resp, err
		})
		if err != nil {
			return nil, err
		}
		for _, j := range jobs.Jobs {
			out = append(out, source.Job{ID: j.GetID(), Name: j.GetName(), URL: j.GetHTMLURL(), Conclusion: j.GetConclusion(),
				StartedAt: j.GetStartedAt().Time, CompletedAt: j.GetCompletedAt().Time, Attempt: int(j.GetRunAttempt())})
		}
		if resp.NextPage == 0 {
			return out, nil
		}
		opt.Page = resp.NextPage
	}
}

// JobLog follows the short-lived (1 minute) redirect immediately.
func (c *Client) JobLog(ctx context.Context, repo string, jobID int64) (string, error) {
	owner, name := split(repo)
	var u *url.URL
	err := c.do(ctx, func() (*github.Response, error) {
		var resp *github.Response
		var err error
		u, resp, err = c.gh.Actions.GetWorkflowJobLogs(ctx, owner, name, jobID, 3)
		return resp, err
	})
	if err != nil {
		return "", err
	}
	for try := 0; ; try++ {
		log, status, err := c.downloadLog(ctx, u.String())
		if !transient(ctx, status, err) && status != http.StatusTooManyRequests {
			return log, err
		}
		if try == len(backoff) {
			return "", fmt.Errorf("%w: %w", source.ErrIncomplete, err)
		}
		c.Logf("job log download failed, retrying in %s: %v", backoff[try], err)
		if err := c.Sleep(ctx, backoff[try]); err != nil {
			return "", err
		}
	}
}

// downloadLog fetches the signed log URL; status is 0 when no HTTP response was received.
func (c *Client) downloadLog(ctx context.Context, u string) (string, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", -1, err // not retryable
	}
	if req.URL.Scheme != "https" {
		return "", -1, errNotHTTPS
	}
	resp, err := c.http.Do(req)
	if errors.Is(err, errNotHTTPS) {
		return "", -1, errNotHTTPS
	}
	if err != nil {
		return "", 0, fmt.Errorf("download job log: %w", errors.Unwrap(err)) // drop the signed URL from *url.Error
	}
	defer func() { _ = resp.Body.Close() }()
	switch code := resp.StatusCode; {
	case code == http.StatusOK:
	case code == http.StatusGone || code == http.StatusNotFound:
		return "", code, source.ErrGone
	case code >= 400 && code < 500 && code != http.StatusTooManyRequests: // signed URL refused: the job is UNCHECKED
		return "", code, fmt.Errorf("%w: download job log: HTTP %d", source.ErrNoAccess, code)
	default: // 429 and 5xx are retried by JobLog
		return "", code, fmt.Errorf("download job log: HTTP %d", code)
	}
	var b strings.Builder // String() does not copy; sized from Content-Length so it never regrows
	if resp.ContentLength > 0 {
		b.Grow(int(min(resp.ContentLength, maxLogBytes+1)))
	}
	if _, err := io.Copy(&b, io.LimitReader(resp.Body, maxLogBytes+1)); err != nil {
		return "", 0, err // body cut mid-transfer: retry
	}
	if int64(b.Len()) > maxLogBytes {
		return "", resp.StatusCode, fmt.Errorf("%w: job log exceeds %d MB", source.ErrIncomplete, maxLogBytes>>20)
	}
	return b.String(), resp.StatusCode, nil
}

// Tree returns the git tree of a commit.
func (c *Client) Tree(ctx context.Context, repo, sha string) ([]source.TreeEntry, bool, error) {
	key := "tree:" + repo + "@" + sha
	if v, ok := c.cache.Load(key); ok {
		t := v.(treeVal)
		return t.entries, t.truncated, nil
	}
	t, err := shared(ctx, &c.fl, key, func() (treeVal, error) {
		if v, ok := c.cache.Load(key); ok { // filled while this call was starting
			return v.(treeVal), nil
		}
		owner, name := split(repo)
		var tree *github.Tree
		err := c.do(ctx, func() (*github.Response, error) {
			var resp *github.Response
			var err error
			tree, resp, err = c.gh.Git.GetTree(ctx, owner, name, sha, true)
			return resp, err
		})
		if err != nil {
			return treeVal{}, err
		}
		var t treeVal
		for _, e := range tree.Entries {
			if e.GetType() == "blob" {
				t.entries = append(t.entries, source.TreeEntry{Path: e.GetPath(), SHA: e.GetSHA()})
			}
		}
		t.truncated = tree.GetTruncated()
		c.cache.Store(key, t)
		return t, nil
	})
	return t.entries, t.truncated, err
}

// Blob returns the content of a git blob, or source.ErrIncomplete if it exceeds limit bytes.
func (c *Client) Blob(ctx context.Context, repo, blobSHA string, limit int) ([]byte, error) {
	owner, name := split(repo)
	return c.raw(ctx, fmt.Sprintf("repos/%v/%v/git/blobs/%v", owner, name, blobSHA), limit)
}

// File returns the content of path at ref through the contents API, or source.ErrIncomplete if
// it exceeds limit bytes. One file, instead of the commit's whole tree.
func (c *Client) File(ctx context.Context, repo, ref, path string, limit int) ([]byte, error) {
	owner, name := split(repo)
	return c.raw(ctx, fmt.Sprintf("repos/%v/%v/contents/%v?ref=%v", owner, name, (&url.URL{Path: path}).EscapedPath(), url.QueryEscape(ref)), limit)
}

// RepoPublic reports whether repo is public: visibility "public", or private explicitly false.
func (c *Client) RepoPublic(ctx context.Context, repo string) (bool, error) {
	owner, name := split(repo)
	var r *github.Repository
	err := c.do(ctx, func() (*github.Response, error) {
		var resp *github.Response
		var err error
		r, resp, err = c.gh.Repositories.Get(ctx, owner, name)
		return resp, err
	})
	if err != nil {
		return false, err
	}
	return r.GetVisibility() == "public" || r.Visibility == nil && r.Private != nil && !*r.Private, nil
}

// raw GETs an API URL with the raw media type, streaming the body into a buffer capped at limit
// bytes instead of reading it whole.
func (c *Client) raw(ctx context.Context, u string, limit int) ([]byte, error) {
	// the bytes are shared by concurrent callers: they only read them
	return shared(ctx, &c.fl, fmt.Sprintf("raw:%d:%s", limit, u), func() ([]byte, error) { return c.fetchRaw(ctx, u, limit) })
}

func (c *Client) fetchRaw(ctx context.Context, u string, limit int) ([]byte, error) {
	buf := capBuf{max: limit}
	bodyErr := false // the last attempt got a 200 whose body stalled or broke
	err := c.do(ctx, func() (*github.Response, error) {
		req, err := c.gh.NewRequest(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github.v3.raw")
		buf.b.Reset()
		resp, err := c.gh.Do(req, &buf)
		bodyErr = err != nil && resp != nil && resp.StatusCode == http.StatusOK && !errors.Is(err, source.ErrIncomplete)
		if bodyErr {
			return nil, err // no response: retried like a network error
		}
		return resp, err
	})
	if err != nil && bodyErr && ctx.Err() == nil {
		return nil, fmt.Errorf("%w: %w", source.ErrIncomplete, err)
	}
	if err != nil {
		return nil, err
	}
	return buf.b.Bytes(), nil
}

// capBuf fails writes past max bytes. Not an embedded bytes.Buffer: io.Copy would use its ReadFrom.
type capBuf struct {
	b   bytes.Buffer
	max int
}

func (c *capBuf) Write(p []byte) (int, error) {
	if c.b.Len()+len(p) > c.max {
		return 0, fmt.Errorf("%w: file exceeds %d bytes", source.ErrIncomplete, c.max)
	}
	return c.b.Write(p)
}
