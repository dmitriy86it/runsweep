package gh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dmitriy86it/runsweep/internal/source"
)

func newTest(t *testing.T, h http.Handler) *Client {
	srv := httptest.NewServer(h)
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
			fmt.Fprintf(w, `{"total_count":2,"workflow_runs":[{"id":%d,"head_sha":"a","path":".github/workflows/ci.yml","created_at":"%s"},{"id":%d,"head_sha":"b","path":".github/workflows/ci.yml","created_at":"%s"}]}`,
				s.Unix(), s.Format(time.RFC3339), s.Unix()+1, s.Format(time.RFC3339))
			return
		}
		fmt.Fprint(w, `{"total_count":1500,"workflow_runs":[]}`)
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
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
		fmt.Fprint(w, `{"message":"gone"}`)
	}))
	_, err := c.JobLog(context.Background(), "o/r", 7)
	if !errors.Is(err, source.ErrGone) {
		t.Fatalf("want ErrGone, got %v", err)
	}
}

func TestNoAccess(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	}))
	_, err := c.ListJobs(context.Background(), "o/r", 1)
	if !errors.Is(err, source.ErrNoAccess) {
		t.Fatalf("want ErrNoAccess, got %v", err)
	}
}

func TestRetriesOnRateLimit(t *testing.T) {
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("X-RateLimit-Limit", "5000")
			w.Header().Set("X-RateLimit-Remaining", "0")
			// reset already passed: go-github would otherwise refuse the retry client-side until reset
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10))
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
			return
		}
		fmt.Fprint(w, `{"total_count":1,"jobs":[{"id":5,"name":"build","html_url":"u"}]}`)
	}))
	var slept bool
	c.Sleep = func(context.Context, time.Duration) error { slept = true; return nil }
	jobs, err := c.ListJobs(context.Background(), "o/r", 1)
	if err != nil || len(jobs) != 1 || !slept {
		t.Fatalf("%v %v slept=%v", jobs, err, slept)
	}
}

func TestTreeAndBlobCached(t *testing.T) {
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		switch {
		case strings.Contains(r.URL.Path, "/git/trees/"):
			fmt.Fprint(w, `{"sha":"s","truncated":false,"tree":[{"path":"package-lock.json","type":"blob","sha":"b1"},{"path":"src","type":"tree","sha":"t1"}]}`)
		case strings.Contains(r.URL.Path, "/git/blobs/"):
			fmt.Fprint(w, `{"lockfileVersion":3}`)
		}
	}))
	ctx := context.Background()
	for range 2 {
		es, tr, err := c.Tree(ctx, "o/r", "s")
		if err != nil || tr || len(es) != 1 || es[0].SHA != "b1" {
			t.Fatalf("%v %v %v", es, tr, err)
		}
		if b, err := c.Blob(ctx, "o/r", "b1"); err != nil || string(b) != `{"lockfileVersion":3}` {
			t.Fatalf("%s %v", b, err)
		}
	}
	if n.Load() != 2 {
		t.Fatalf("want 2 HTTP calls (cached), got %d", n.Load())
	}
}

// logTarget serves the signed-URL redirect target and records the Authorization header it sees.
func logTarget(t *testing.T, body string, authSeen *atomic.Value) string {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authSeen.Store(r.Header.Get("Authorization"))
		fmt.Fprint(w, body)
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
			fmt.Fprint(w, `{"message":"API rate limit exceeded"}`)
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

func TestRunsCapInUnsplittableWindow(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"total_count":1500,"workflow_runs":[]}`)
	}))
	var logged bool
	c.Logf = func(f string, a ...any) {
		if strings.Contains(fmt.Sprintf(f, a...), "some runs not scanned") {
			logged = true
		}
	}
	start := time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC)
	if _, err := c.ListRuns(context.Background(), "o/r", start, start.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if !logged {
		t.Fatal("want cap warning")
	}
}

func TestRetryAfterSecondaryLimit(t *testing.T) {
	var n atomic.Int32
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"message":"slow down"}`)
			return
		}
		fmt.Fprint(w, `{"total_count":1,"jobs":[{"id":5}]}`)
	}))
	var slept time.Duration
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = d; return nil }
	jobs, err := c.ListJobs(context.Background(), "o/r", 1)
	if err != nil || len(jobs) != 1 || slept != time.Second {
		t.Fatalf("%v %v slept=%v", jobs, err, slept)
	}
}

func TestSleepCancelled(t *testing.T) {
	c := newTest(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"message":"slow"}`)
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
			fmt.Fprint(w, `{"total_count":0,"workflow_runs":[]}`)
			return
		}
		fmt.Fprint(w, `{"total_count":1500,"workflow_runs":[]}`)
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
			fmt.Fprint(w, `{"total_count":2,"jobs":[{"id":2}]}`)
			return
		}
		w.Header().Set("Link", fmt.Sprintf(`<http://%s%s?page=2>; rel="next"`, r.Host, r.URL.Path))
		fmt.Fprint(w, `{"total_count":2,"jobs":[{"id":1}]}`)
	}))
	jobs, err := c.ListJobs(context.Background(), "o/r", 1)
	if err != nil || len(jobs) != 2 || jobs[0].ID != 1 || jobs[1].ID != 2 {
		t.Fatalf("%v %v", jobs, err)
	}
}
