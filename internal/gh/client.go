// Package gh implements source.Source on top of go-github.
package gh

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dmitriy86it/runsweep/internal/source"
	"github.com/google/go-github/v92/github"
)

const (
	maxRetries  = 5
	maxParallel = 10
	maxLogBytes = 64 << 20
	runsCap     = 1000 // GitHub returns at most 1000 runs for a `created` filter
)

type Client struct {
	gh    *github.Client
	http  *http.Client
	sem   chan struct{}
	cache sync.Map // "tree:repo@sha" / "blob:repo@sha" -> value

	Logf  func(format string, args ...any)
	Sleep func(time.Duration)
}

type treeVal struct {
	entries   []source.TreeEntry
	truncated bool
}

func New(httpClient *http.Client, token, baseURL string) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	opts := []github.ClientOptionsFunc{github.WithHTTPClient(httpClient)}
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
	return &Client{gh: g, http: httpClient, sem: make(chan struct{}, maxParallel),
		Logf: func(string, ...any) {}, Sleep: time.Sleep}, nil
}

func split(repo string) (string, string) {
	o, r, _ := strings.Cut(repo, "/")
	return o, r
}

// do runs f with the concurrency limit, retrying on rate limits and mapping errors.
func (c *Client) do(ctx context.Context, f func() (*github.Response, error)) error {
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
		switch {
		case errors.As(err, &rl):
			wait = time.Until(rl.Rate.Reset.Time) + time.Second
		case errors.As(err, &ab):
			wait = ab.GetRetryAfter()
			if wait == 0 {
				wait = time.Minute
			}
		default:
			return mapErr(resp, err)
		}
		if attempt >= maxRetries {
			return err
		}
		c.Logf("rate limited, waiting %s", wait.Round(time.Second))
		c.Sleep(max(wait, time.Second))
	}
}

func mapErr(resp *github.Response, err error) error {
	if resp != nil {
		switch resp.StatusCode {
		case http.StatusGone:
			return source.ErrGone
		case http.StatusForbidden, http.StatusNotFound:
			return fmt.Errorf("%w: %v", source.ErrNoAccess, err)
		}
	}
	return err
}

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

func (c *Client) ListRuns(ctx context.Context, repo string, start, end time.Time) ([]source.Run, error) {
	owner, name := split(repo)
	opt := &github.ListWorkflowRunsOptions{
		Created:     start.UTC().Format(time.RFC3339) + ".." + end.UTC().Format(time.RFC3339),
		ListOptions: github.ListOptions{PerPage: 100},
	}
	var out []source.Run
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
		if opt.Page == 0 && page.GetTotalCount() >= runsCap && end.Sub(start) > time.Minute {
			mid := start.Add(end.Sub(start) / 2)
			c.Logf("%s: %d runs in window, splitting", repo, page.GetTotalCount())
			a, err := c.ListRuns(ctx, repo, start, mid)
			if err != nil {
				return nil, err
			}
			b, err := c.ListRuns(ctx, repo, mid.Add(time.Second), end)
			if err != nil {
				return nil, err
			}
			return append(a, b...), nil
		}
		for _, r := range page.WorkflowRuns {
			out = append(out, source.Run{ID: r.GetID(), Name: r.GetName(), Path: r.GetPath(), HeadSHA: r.GetHeadSHA(),
				URL: r.GetHTMLURL(), CreatedAt: r.GetCreatedAt().Time})
		}
		if resp.NextPage == 0 {
			return out, nil
		}
		opt.Page = resp.NextPage
	}
}

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
			out = append(out, source.Job{ID: j.GetID(), Name: j.GetName(), URL: j.GetHTMLURL()})
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
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusGone, http.StatusNotFound:
		return "", source.ErrGone
	default:
		return "", fmt.Errorf("download job log: HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxLogBytes))
	return string(b), err
}

func (c *Client) Tree(ctx context.Context, repo, sha string) ([]source.TreeEntry, bool, error) {
	key := "tree:" + repo + "@" + sha
	if v, ok := c.cache.Load(key); ok {
		t := v.(treeVal)
		return t.entries, t.truncated, nil
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
		return nil, false, err
	}
	var t treeVal
	for _, e := range tree.Entries {
		if e.GetType() == "blob" {
			t.entries = append(t.entries, source.TreeEntry{Path: e.GetPath(), SHA: e.GetSHA()})
		}
	}
	t.truncated = tree.GetTruncated()
	c.cache.Store(key, t)
	return t.entries, t.truncated, nil
}

func (c *Client) Blob(ctx context.Context, repo, blobSHA string) ([]byte, error) {
	key := "blob:" + repo + "@" + blobSHA
	if v, ok := c.cache.Load(key); ok {
		return v.([]byte), nil
	}
	owner, name := split(repo)
	var b []byte
	err := c.do(ctx, func() (*github.Response, error) {
		var resp *github.Response
		var err error
		b, resp, err = c.gh.Git.GetBlobRaw(ctx, owner, name, blobSHA)
		return resp, err
	})
	if err != nil {
		return nil, err
	}
	c.cache.Store(key, b)
	return b, nil
}
