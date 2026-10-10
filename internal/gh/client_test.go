package gh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/runsweep/runsweep/internal/source"
)

func newTest(t *testing.T, h http.Handler) *Client {
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	c, err := New(srv.Client(), "tok", srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	c.Sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestListRunsSplitsWindow(t *testing.T) {
	var calls atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		created := r.URL.Query().Get("created")
		start, end, _ := strings.Cut(created, "..")
		s, _ := time.Parse(time.RFC3339, start)
		e, _ := time.Parse(time.RFC3339, end)
		if e.Sub(s) <= 12*time.Hour { // small window: return real runs
			_, _ = fmt.Fprintf(w, `{"total_count":2,"workflow_runs":[{"id":%d,"head_sha":"a","path":".github/workflows/ci.yml","created_at":"%s"},{"id":%d,"head_sha":"b","path":".github/workflows/ci.yml","created_at":"%s"}]}`, //nolint:gosec // G705: test server, values are numeric/time-formatted
				s.Unix(), s.Format(time.RFC3339), s.Unix()+1, s.Format(time.RFC3339))
			return
		}
		_, _ = fmt.Fprint(w, `{"total_count":1500,"workflow_runs":[]}`)
	}))
	start := time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)
	runs, err := c.ListRuns(context.Background(), "o/r", start, start.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 4 {
		t.Fatalf("want runs from both halves, got %d (%d calls)", len(runs), calls.Load())
	}
}

func TestJobLogGone(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusGone)
		_, _ = fmt.Fprint(w, `{"message":"gone"}`)
	}))
	_, err := c.JobLog(context.Background(), "o/r", 7)
	if !errors.Is(err, source.ErrGone) {
		t.Fatalf("want ErrGone, got %v", err)
	}
}

func TestNoAccess(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"message":"Not Found"}`)
	}))
	_, err := c.ListJobs(context.Background(), "o/r", 1)
	if !errors.Is(err, source.ErrNoAccess) {
		t.Fatalf("want ErrNoAccess, got %v", err)
	}
}

// Any 4xx other than 401 and rate limits is soft (the repo or run is UNCHECKED); 401 stays fatal.
func TestClientErrorsAreSoftExceptAuth(t *testing.T) {
	for _, code := range []int{http.StatusBadRequest, http.StatusUnprocessableEntity, http.StatusConflict} {
		c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(code)
			_, _ = fmt.Fprint(w, `{"message":"nope"}`)
		}))
		_, err := c.ListJobs(context.Background(), "o/r", 1)
		if !errors.Is(err, source.ErrNoAccess) || !strings.Contains(err.Error(), strconv.Itoa(code)) {
			t.Errorf("%d: %v", code, err)
		}
	}
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"message":"Bad credentials"}`)
	}))
	_, err := c.ListJobs(context.Background(), "o/r", 1)
	if !errors.Is(err, source.ErrAuth) || errors.Is(err, source.ErrNoAccess) {
		t.Fatalf("401: %v", err)
	}
}

func TestRetriesOnRateLimit(t *testing.T) {
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("X-RateLimit-Limit", "5000")
			w.Header().Set("X-RateLimit-Remaining", "0")
			// reset already passed: go-github would otherwise refuse the retry client-side until reset
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10))
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"total_count":1,"jobs":[{"id":5,"name":"build","html_url":"u"}]}`)
	}))
	var slept bool
	c.Sleep = func(context.Context, time.Duration) error { slept = true; return nil }
	jobs, err := c.ListJobs(context.Background(), "o/r", 1)
	if err != nil || len(jobs) != 1 || !slept {
		t.Fatalf("%v %v slept=%v", jobs, err, slept)
	}
}

// Trees are cached; blobs are not (callers cache what they parse from them).
func TestTreeCached(t *testing.T) {
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		switch {
		case strings.Contains(r.URL.Path, "/git/trees/"):
			_, _ = fmt.Fprint(w, `{"sha":"s","truncated":false,"tree":[{"path":"package-lock.json","type":"blob","sha":"b1"},{"path":"src","type":"tree","sha":"t1"}]}`)
		case strings.Contains(r.URL.Path, "/git/blobs/"):
			_, _ = fmt.Fprint(w, `{"lockfileVersion":3}`)
		}
	}))
	ctx := context.Background()
	for range 2 {
		es, tr, err := c.Tree(ctx, "o/r", "s")
		if err != nil || tr || len(es) != 1 || es[0].SHA != "b1" {
			t.Fatalf("%v %v %v", es, tr, err)
		}
		if b, err := c.Blob(ctx, "o/r", "b1", 100); err != nil || string(b) != `{"lockfileVersion":3}` {
			t.Fatalf("%s %v", b, err)
		}
	}
	if n.Load() != 3 {
		t.Fatalf("want 3 HTTP calls (tree cached), got %d", n.Load())
	}
}

// logTarget serves the signed-URL redirect target and records the Authorization header it sees.
func logTarget(t *testing.T, body string, authSeen *atomic.Value) string {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authSeen.Store(r.Header.Get("Authorization"))
		_, _ = fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/signed"
}

func TestJobLogRetriesRateLimitAndNoAuthOnRedirect(t *testing.T) {
	var auth atomic.Value
	target := logTarget(t, "log body", &auth)
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("X-RateLimit-Limit", "5000")
			w.Header().Set("X-RateLimit-Remaining", "0")
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10))
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
			return
		}
		http.Redirect(w, r, target, http.StatusFound)
	}))
	var slept bool
	c.Sleep = func(context.Context, time.Duration) error { slept = true; return nil }
	log, err := c.JobLog(context.Background(), "o/r", 7)
	if err != nil || log != "log body" || !slept {
		t.Fatalf("%q %v slept=%v", log, err, slept)
	}
	if a := auth.Load(); a != "" {
		t.Fatalf("Authorization leaked to redirect host: %q", a)
	}
}

func TestJobLogTruncated(t *testing.T) {
	old := maxLogBytes
	maxLogBytes = 10
	t.Cleanup(func() { maxLogBytes = old })
	var auth atomic.Value
	target := logTarget(t, strings.Repeat("x", 11), &auth)
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target, http.StatusFound)
	}))
	if _, err := c.JobLog(context.Background(), "o/r", 7); !errors.Is(err, source.ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
}

func TestJobLogSignedURLRefusedIsSoft(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	t.Cleanup(srv.Close)
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/signed", http.StatusFound)
	}))
	if _, err := c.JobLog(context.Background(), "o/r", 7); !errors.Is(err, source.ErrNoAccess) || !strings.Contains(err.Error(), "403") {
		t.Fatalf("want ErrNoAccess, got %v", err)
	}
}

func TestRunsCapInUnsplittableWindow(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"total_count":1500,"workflow_runs":[]}`)
	}))
	var logged bool
	c.Logf = func(f string, a ...any) {
		if strings.Contains(fmt.Sprintf(f, a...), "some runs not scanned") {
			logged = true
		}
	}
	start := time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)
	if _, err := c.ListRuns(context.Background(), "o/r", start, start.Add(30*time.Second)); !errors.Is(err, source.ErrRunsCapped) {
		t.Fatalf("want ErrRunsCapped, got %v", err)
	}
	if !logged {
		t.Fatal("want cap warning")
	}
}

func TestRunsCapAfterSplitKeepsRuns(t *testing.T) {
	var id atomic.Int64
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"total_count":1500,"workflow_runs":[{"id":%d}]}`, id.Add(1))
	}))
	start := time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)
	runs, err := c.ListRuns(context.Background(), "o/r", start, start.Add(2*time.Minute))
	if !errors.Is(err, source.ErrRunsCapped) || len(runs) != 2 {
		t.Fatalf("want both capped halves' runs and ErrRunsCapped, got %d runs, %v", len(runs), err)
	}
}

func TestRetryAfterSecondaryLimit(t *testing.T) {
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"message":"slow down"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"total_count":1,"jobs":[{"id":5}]}`)
	}))
	var slept time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = d; return nil }
	jobs, err := c.ListJobs(context.Background(), "o/r", 1)
	if err != nil || len(jobs) != 1 || slept != time.Second {
		t.Fatalf("%v %v slept=%v", jobs, err, slept)
	}
}

// A primary reset or a Retry-After far away is waited for at most an hour at a time.
func TestRateLimitWaitCapped(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(http.Header)
	}{
		{"primary", func(h http.Header) {
			h.Set("X-RateLimit-Limit", "5000")
			h.Set("X-RateLimit-Remaining", "0")
			h.Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(3*time.Hour).Unix(), 10))
		}},
		{"secondary", func(h http.Header) { h.Set("Retry-After", "10800") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				tc.set(w.Header())
				w.WriteHeader(http.StatusForbidden)
				_, _ = fmt.Fprint(w, `{"message":"API rate limit exceeded","documentation_url":"https://docs.github.com/rest/overview/rate-limits-for-the-rest-api#about-secondary-rate-limits"}`)
			}))
			sleeps := recordSleeps(c)
			if _, err := c.ListJobs(context.Background(), "o/r", 1); err == nil {
				t.Fatal("want an error after the retries")
			}
			if len(*sleeps) != maxRetries {
				t.Fatalf("want %d waits, got %v", maxRetries, *sleeps)
			}
			for _, d := range *sleeps {
				if d > time.Hour {
					t.Fatalf("wait %s exceeds 1h", d)
				}
			}
		})
	}
}

func TestSleepCancelled(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = fmt.Fprint(w, `{"message":"slow"}`)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	c.Sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	if _, err := c.ListJobs(ctx, "o/r", 1); !errors.Is(err, context.Canceled) {
		t.Fatalf("want Canceled, got %v", err)
	}
}

func TestSplitRangesContiguous(t *testing.T) {
	var mu sync.Mutex
	var ranges [][2]time.Time
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, e, _ := strings.Cut(r.URL.Query().Get("created"), "..")
		st, _ := time.Parse(time.RFC3339, s)
		en, _ := time.Parse(time.RFC3339, e)
		if en.Sub(st) <= 12*time.Hour {
			mu.Lock()
			ranges = append(ranges, [2]time.Time{st, en})
			mu.Unlock()
			_, _ = fmt.Fprint(w, `{"total_count":0,"workflow_runs":[]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"total_count":1500,"workflow_runs":[]}`)
	}))
	start := time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	if _, err := c.ListRuns(context.Background(), "o/r", start, end); err != nil {
		t.Fatal(err)
	}
	if len(ranges) != 2 || !ranges[0][0].Equal(start) || !ranges[1][0].Equal(ranges[0][1].Add(time.Second)) || !ranges[1][1].Equal(end) {
		t.Fatalf("ranges not contiguous/non-overlapping: %v", ranges)
	}
}

func TestPagination(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, _ = fmt.Fprint(w, `{"total_count":2,"jobs":[{"id":2}]}`)
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?page=2>; rel="next"`, r.Host, r.URL.Path))
		_, _ = fmt.Fprint(w, `{"total_count":2,"jobs":[{"id":1}]}`)
	}))
	jobs, err := c.ListJobs(context.Background(), "o/r", 1)
	if err != nil || len(jobs) != 2 || jobs[0].ID != 1 || jobs[1].ID != 2 {
		t.Fatalf("%v %v", jobs, err)
	}
}

func recordSleeps(c *Client) *[]time.Duration {
	var mu sync.Mutex
	var d []time.Duration
	c.Sleep = func(_ context.Context, x time.Duration) error { mu.Lock(); d = append(d, x); mu.Unlock(); return nil }
	return &d
}

func TestRetriesTransientErrors(t *testing.T) {
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch n.Add(1) {
		case 1:
			w.Header().Set("Connection", "close") // next request on a fresh connection, which the transport never retries
			w.WriteHeader(http.StatusBadGateway)
		case 2: // network error: drop the connection
			conn, _, _ := w.(http.Hijacker).Hijack()
			_ = conn.Close()
		default:
			_, _ = fmt.Fprint(w, `{"total_count":1,"jobs":[{"id":5,"name":"build","conclusion":"skipped"}]}`)
		}
	}))
	sleeps := recordSleeps(c)
	jobs, err := c.ListJobs(context.Background(), "o/r", 1)
	if err != nil || len(jobs) != 1 || jobs[0].Conclusion != "skipped" {
		t.Fatalf("%v %v", jobs, err)
	}
	if fmt.Sprint(*sleeps) != "[1s 2s]" {
		t.Fatalf("backoff %v", *sleeps)
	}
}

func TestPersistent5xxGivesUp(t *testing.T) {
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	sleeps := recordSleeps(c)
	if _, err := c.ListJobs(context.Background(), "o/r", 1); err == nil {
		t.Fatal("want error")
	}
	if n.Load() != 4 || fmt.Sprint(*sleeps) != "[1s 2s 4s]" {
		t.Fatalf("calls %d backoff %v", n.Load(), *sleeps)
	}
}

func TestJobLogDownloadRetries(t *testing.T) {
	var hits atomic.Int32
	var status atomic.Int32 // status served after the first 503
	status.Store(http.StatusOK)
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if hits.Add(1) == 1 || status.Load() != http.StatusOK {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = fmt.Fprint(w, "log body")
	}))
	t.Cleanup(target.Close)
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/signed", http.StatusFound)
	}))
	sleeps := recordSleeps(c)
	if log, err := c.JobLog(context.Background(), "o/r", 7); err != nil || log != "log body" {
		t.Fatalf("%q %v", log, err)
	}
	hits.Store(0)
	status.Store(http.StatusServiceUnavailable)
	*sleeps = nil
	if _, err := c.JobLog(context.Background(), "o/r", 7); !errors.Is(err, source.ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	if hits.Load() != 4 || fmt.Sprint(*sleeps) != "[1s 2s 4s]" {
		t.Fatalf("hits %d backoff %v", hits.Load(), *sleeps)
	}
}

func TestBlobTooBig(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := "0123456789"
		if strings.HasSuffix(r.URL.Path, "/big") {
			body += "a"
		}
		_, _ = fmt.Fprint(w, body)
	}))
	if b, err := c.Blob(context.Background(), "o/r", "small", 10); err != nil || string(b) != "0123456789" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := c.Blob(context.Background(), "o/r", "big", 10); !errors.Is(err, source.ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
}

func TestRunAndJobAttempts(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/jobs") {
			_, _ = fmt.Fprint(w, `{"total_count":2,"jobs":[`+
				`{"id":1,"run_attempt":1,"started_at":"2026-03-20T10:00:00Z"},`+
				`{"id":2,"run_attempt":2,"started_at":"2026-03-31T01:00:00Z","completed_at":"2026-03-31T01:02:00Z"}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"total_count":1,"workflow_runs":[{"id":5,"status":"completed","run_attempt":2,`+
			`"created_at":"2026-03-20T10:00:00Z","run_started_at":"2026-03-31T01:00:00Z","updated_at":"2026-03-31T01:05:00Z"}]}`)
	}))
	start := time.Date(2026, 3, 24, 0, 0, 0, 0, time.UTC)
	runs, err := c.ListRuns(context.Background(), "o/r", start, start.Add(8*24*time.Hour))
	if err != nil || len(runs) != 1 {
		t.Fatalf("%v %v", runs, err)
	}
	r := runs[0]
	if r.Status != "completed" || r.Attempt != 2 || !r.StartedAt.Equal(time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)) ||
		!r.UpdatedAt.Equal(time.Date(2026, 3, 31, 1, 5, 0, 0, time.UTC)) {
		t.Fatalf("%+v", r)
	}
	jobs, err := c.ListJobs(context.Background(), "o/r", 5)
	if err != nil || len(jobs) != 2 || jobs[0].Attempt != 1 || jobs[1].Attempt != 2 ||
		!jobs[1].CompletedAt.Equal(time.Date(2026, 3, 31, 1, 2, 0, 0, time.UTC)) || !jobs[0].CompletedAt.IsZero() ||
		!jobs[1].StartedAt.Equal(time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("%+v %v", jobs, err)
	}
}

func TestRunAndJobMissingTimesAndAttempt(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/jobs") {
			_, _ = fmt.Fprint(w, `{"total_count":1,"jobs":[{"id":1}]}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"total_count":1,"workflow_runs":[{"id":5,"created_at":"2026-03-25T10:00:00Z"}]}`)
	}))
	start := time.Date(2026, 3, 24, 0, 0, 0, 0, time.UTC)
	runs, err := c.ListRuns(context.Background(), "o/r", start, start.Add(8*24*time.Hour))
	if err != nil || len(runs) != 1 || runs[0].Attempt != 0 || !runs[0].StartedAt.IsZero() || !runs[0].UpdatedAt.IsZero() {
		t.Fatalf("%+v %v", runs, err)
	}
	jobs, err := c.ListJobs(context.Background(), "o/r", 5)
	if err != nil || len(jobs) != 1 || jobs[0].Attempt != 0 || !jobs[0].StartedAt.IsZero() || !jobs[0].CompletedAt.IsZero() {
		t.Fatalf("%+v %v", jobs, err)
	}
}

// A job log is fetched only over https, on every redirect hop; a refusal is not retried.
func TestJobLogRequiresHTTPS(t *testing.T) {
	var hits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = fmt.Fprint(w, "log body")
	}))
	t.Cleanup(plain.Close)
	hop := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/signed", http.StatusFound)
	}))
	t.Cleanup(hop.Close)
	for _, target := range []string{plain.URL + "/signed", hop.URL + "/hop"} {
		c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target, http.StatusFound)
		}))
		sleeps := recordSleeps(c)
		if _, err := c.JobLog(context.Background(), "o/r", 7); !errors.Is(err, source.ErrNoAccess) || !strings.Contains(err.Error(), "https") {
			t.Fatalf("%s: want ErrNoAccess (not https), got %v", target, err)
		}
		if hits.Load() != 0 || len(*sleeps) != 0 {
			t.Fatalf("%s: plain-http log fetched %d times, retries %v", target, hits.Load(), *sleeps)
		}
	}
}

// File reads one file at a ref through the contents API, with the raw media type and a size cap.
func TestFile(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/repos/o/r/contents/.github/workflows/a%20b.yml" || r.URL.Query().Get("ref") != "abc" ||
			!strings.Contains(r.Header.Get("Accept"), "raw") {
			http.Error(w, r.URL.String(), http.StatusNotFound)
			return
		}
		_, _ = fmt.Fprint(w, "on: push")
	}))
	if b, err := c.File(context.Background(), "o/r", "abc", ".github/workflows/a b.yml", 100); err != nil || string(b) != "on: push" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := c.File(context.Background(), "o/r", "abc", ".github/workflows/a b.yml", 3); !errors.Is(err, source.ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
}

// A 200 whose body stalls past the client timeout (or breaks) is retried like a network error,
// then is soft (ErrIncomplete), never an error that aborts the scan.
func TestRawBodyStallRetriedThenIncomplete(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Length", "100")
		_, _ = fmt.Fprint(w, "on: ")
		w.(http.Flusher).Flush()
		<-r.Context().Done() // stall until the client gives up
	}))
	t.Cleanup(srv.Close)
	hc := srv.Client()
	hc.Timeout = 100 * time.Millisecond
	c, err := New(hc, "tok", srv.URL+"/")
	if err != nil {
		t.Fatal(err)
	}
	sleeps := recordSleeps(c)
	if _, err := c.File(context.Background(), "o/r", "abc", ".github/workflows/a.yml", 1000); !errors.Is(err, source.ErrIncomplete) {
		t.Fatalf("want ErrIncomplete, got %v", err)
	}
	if hits.Load() != 4 || fmt.Sprint(*sleeps) != "[1s 2s 4s]" {
		t.Fatalf("hits %d backoff %v", hits.Load(), *sleeps)
	}
}

func TestRepoPublic(t *testing.T) {
	for body, want := range map[string]bool{
		`{"visibility":"public","private":false}`: true,
		`{"private":false}`:                       true,
		`{"visibility":"private","private":true}`: false,
		`{"visibility":"internal"}`:               false,
		`{}`:                                      false,
	} {
		c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/repos/o/r" {
				http.NotFound(w, r)
				return
			}
			_, _ = fmt.Fprint(w, body)
		}))
		if got, err := c.RepoPublic(context.Background(), "o/r"); err != nil || got != want {
			t.Errorf("%s: got %v %v, want %v", body, got, err, want)
		}
	}
}

func TestListRunsMapsEvent(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, `{"total_count":1,"workflow_runs":[{"id":1,"event":"pull_request_target","head_sha":"a"}]}`)
	}))
	start := time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)
	runs, err := c.ListRuns(context.Background(), "o/r", start, start.Add(time.Hour))
	if err != nil || len(runs) != 1 || runs[0].Event != "pull_request_target" {
		t.Fatalf("%+v %v", runs, err)
	}
}

// An API redirect to another host or to http never carries the token.
func TestAPIRedirectStaysOnHost(t *testing.T) {
	var seen atomic.Value
	seen.Store("")
	evil := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("on: push\n"))
	}))
	defer evil.Close()
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			_, _ = w.Write([]byte("ok"))
			return
		}
		if strings.Contains(r.URL.Path, "/blobs/same") {
			http.Redirect(w, r, "/same", http.StatusFound)
			return
		}
		http.Redirect(w, r, evil.URL+"/steal", http.StatusFound)
	}))
	_, err := c.Blob(context.Background(), "o/r", "abc", 1<<20)
	if !errors.Is(err, source.ErrNoAccess) || seen.Load() != "" {
		t.Fatalf("err=%v auth at the other host=%q", err, seen.Load())
	}
	if b, err := c.Blob(context.Background(), "o/r", "same", 1<<20); err != nil || string(b) != "ok" {
		t.Fatalf("same-host redirect: %q %v", b, err)
	}
}

// A job log is read once into a buffer sized from Content-Length and returned without a copy.
func TestJobLogMemory(t *testing.T) {
	body := []byte(strings.Repeat("0123456789abcdef\n", 1<<20)) // 17 MB
	logSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		_, _ = w.Write(body)
	}))
	defer logSrv.Close()
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, logSrv.URL+"/log", http.StatusFound)
	}))
	c.http.Transport = logSrv.Client().Transport
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	log, err := c.JobLog(context.Background(), "o/r", 1)
	runtime.ReadMemStats(&after)
	if err != nil || len(log) != len(body) {
		t.Fatalf("%d %v", len(log), err)
	}
	if got := after.TotalAlloc - before.TotalAlloc; got > uint64(len(body))*3/2 {
		t.Errorf("allocated %d MB for a %d MB log", got>>20, len(body)>>20)
	}
}

// Concurrent requests for the same tree, blob or file share one API call; a failure is not remembered.
func TestConcurrentFetchesShareOneCall(t *testing.T) {
	var calls, fails atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond) // long enough for all callers to be waiting
		if strings.Contains(r.URL.Path, "/missing") {
			fails.Add(1)
			http.NotFound(w, r)
			return
		}
		calls.Add(1)
		if strings.Contains(r.URL.Path, "/git/trees/") {
			_, _ = w.Write([]byte(`{"sha":"s","tree":[{"path":"a","type":"blob","sha":"b"}]}`))
			return
		}
		_, _ = w.Write([]byte("body"))
	}))
	ctx := context.Background()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			if e, _, err := c.Tree(ctx, "o/r", "sha"); err != nil || len(e) != 1 {
				t.Errorf("tree: %v %v", e, err)
			}
			if b, err := c.Blob(ctx, "o/r", "blob", 1<<20); err != nil || string(b) != "body" {
				t.Errorf("blob: %q %v", b, err)
			}
			if b, err := c.File(ctx, "o/r", "ref", "p.yml", 1<<20); err != nil || string(b) != "body" {
				t.Errorf("file: %q %v", b, err)
			}
		})
	}
	wg.Wait()
	if n := calls.Load(); n != 3 {
		t.Errorf("%d API calls for 8 x (tree, blob, file), want 3", n)
	}
	for range 2 {
		if _, err := c.Blob(ctx, "o/r", "missing", 1<<20); !errors.Is(err, source.ErrNoAccess) {
			t.Fatal(err)
		}
	}
	if fails.Load() != 2 {
		t.Errorf("an error was cached: %d calls for 2 sequential requests", fails.Load())
	}
}

// 401 and 404 say what is likely wrong and carry no request URL.
func TestErrorTextsExplainTheCause(t *testing.T) {
	for _, tc := range []struct {
		code int
		want string
	}{
		{http.StatusUnauthorized, "token was rejected"},
		{http.StatusNotFound, "token cannot see it"},
		{http.StatusForbidden, "SSO"},
	} {
		c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.code)
			_, _ = fmt.Fprint(w, `{"message":"Server said so"}`)
		}))
		_, err := c.ListJobs(context.Background(), "o/r", 1)
		if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), fmt.Sprintf("HTTP %d", tc.code)) ||
			!strings.Contains(err.Error(), "Server said so") || strings.Contains(err.Error(), "https://") {
			t.Errorf("%d: %v", tc.code, err)
		}
	}
}

func TestRateLimitWaitShowsResetTime(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "5000")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(90*time.Second).Unix(), 10))
		w.WriteHeader(http.StatusForbidden)
		_, _ = fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
	}))
	var logs []string
	c.Logf = func(f string, a ...any) { logs = append(logs, fmt.Sprintf(f, a...)) }
	_, _ = c.ListJobs(context.Background(), "o/r", 1)
	if len(logs) == 0 || !regexp.MustCompile(`^rate limited, waiting 1m\d\ds \(until \d\d:\d\d:\d\d UTC\)$`).MatchString(logs[0]) {
		t.Fatalf("%q", logs)
	}
}
