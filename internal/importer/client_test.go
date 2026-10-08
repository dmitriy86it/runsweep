package importer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testClient points both bases at one test server and records sleeps instead of sleeping.
func testClient(t *testing.T, h http.Handler) (*Client, *[]time.Duration) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	var slept []time.Duration
	c := New()
	c.HTTP = srv.Client()
	c.OSVBase, c.NPMBase = srv.URL+"/osv", srv.URL+"/npm"
	c.Sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }
	return c, &slept
}

func TestFetchRetries429And5xxThenSucceeds(t *testing.T) {
	var n atomic.Int32
	c, slept := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		switch n.Add(1) {
		case 1:
			w.Header().Set("Retry-After", "3")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(http.StatusBadGateway)
		default:
			_, _ = fmt.Fprint(w, `{}`)
		}
	}))
	b, err := c.fetch(context.Background(), c.OSVBase+"/x", nil)
	if err != nil || string(b) != "{}" {
		t.Fatalf("%q %v", b, err)
	}
	if fmt.Sprint(*slept) != "[3s 2s]" { // Retry-After wins over the 1s backoff; then backoff[1]
		t.Fatalf("sleeps %v", *slept)
	}
}

func TestFetchGivesUpAfterBackoff(t *testing.T) {
	var n atomic.Int32
	c, slept := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	if _, err := c.fetch(context.Background(), c.OSVBase+"/x", nil); err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("want HTTP 503 error, got %v", err)
	}
	if n.Load() != 4 || fmt.Sprint(*slept) != "[1s 2s 4s]" {
		t.Fatalf("calls %d sleeps %v", n.Load(), *slept)
	}
}

func TestFetchNoRetryOn4xx(t *testing.T) {
	var n atomic.Int32
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		if r.URL.Path == "/osv/missing" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	if _, err := c.fetch(context.Background(), c.OSVBase+"/missing", nil); !errors.Is(err, errNotFound) {
		t.Fatalf("want errNotFound, got %v", err)
	}
	if _, err := c.fetch(context.Background(), c.OSVBase+"/bad", []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "POST") {
		t.Fatalf("want POST error, got %v", err)
	}
	if n.Load() != 2 {
		t.Fatalf("4xx must not be retried, calls %d", n.Load())
	}
}

func TestFetchSizeCap(t *testing.T) {
	old := maxBody
	maxBody = 10
	t.Cleanup(func() { maxBody = old })
	c, slept := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprint(w, strings.Repeat("x", 11))
	}))
	if _, err := c.fetch(context.Background(), c.NPMBase+"/big", nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("want size error, got %v", err)
	}
	if len(*slept) != 0 {
		t.Fatal("an oversized body must not be retried")
	}
}

func TestFetchPostsJSON(t *testing.T) {
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprint(w, `{"ok":true}`)
	}))
	if b, err := c.fetch(context.Background(), c.OSVBase+"/v1/query", []byte(`{}`)); err != nil || string(b) != `{"ok":true}` {
		t.Fatalf("%q %v", b, err)
	}
}

func TestFetchCancelledDuringSleep(t *testing.T) {
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	ctx, cancel := context.WithCancel(context.Background())
	c.Sleep = func(ctx context.Context, _ time.Duration) error { cancel(); return ctx.Err() }
	if _, err := c.fetch(ctx, c.OSVBase+"/x", nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("want context.Canceled, got %v", err)
	}
}

func TestFetchRetryAfterCapped(t *testing.T) {
	var n atomic.Int32
	c, slept := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = fmt.Fprint(w, `{}`)
	}))
	if _, err := c.fetch(context.Background(), c.OSVBase+"/x", nil); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(*slept) != "[1m0s]" {
		t.Fatalf("sleeps %v", *slept)
	}
}

func TestFetchRefusesCrossHostRedirect(t *testing.T) {
	var hit atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit.Add(1)
		_, _ = fmt.Fprint(w, `{}`)
	}))
	t.Cleanup(other.Close)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		if r.URL.Path == "/ok" {
			_, _ = fmt.Fprint(w, `{}`)
			return
		}
		http.Redirect(w, r, other.URL+"/x", http.StatusFound)
	}))
	t.Cleanup(srv.Close)
	c := New()
	var slept int
	c.Sleep = func(context.Context, time.Duration) error { slept++; return nil }
	if b, err := c.fetch(context.Background(), srv.URL+"/same", nil); err != nil || string(b) != "{}" {
		t.Fatalf("same-host redirect: %q %v", b, err)
	}
	if _, err := c.fetch(context.Background(), srv.URL+"/cross", nil); err == nil || !strings.Contains(err.Error(), "redirect") {
		t.Fatalf("want redirect error, got %v", err)
	}
	if hit.Load() != 0 || slept != 0 {
		t.Fatalf("other host hit %d times, %d retries", hit.Load(), slept)
	}
}
