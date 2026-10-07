package gh

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
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
	c.Sleep = func(time.Duration) {}
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
	c.Sleep = func(time.Duration) { slept = true }
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
