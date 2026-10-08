// Package importer builds incident definitions from OSV advisories and npm registry metadata.
package importer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// maxBody caps every response body; a var so tests can shrink it.
var maxBody int64 = 32 << 20

// backoff between retries of network errors, HTTP 429 and HTTP 5xx.
var backoff = []time.Duration{time.Second, 2 * time.Second, 4 * time.Second}

// maxRetryAfter caps a server-requested wait.
const maxRetryAfter = time.Minute

// errNotFound is returned for HTTP 404.
var errNotFound = errors.New("not found (HTTP 404)")

// Client talks to the OSV API and the npm registry.
type Client struct {
	HTTP    *http.Client
	OSVBase string // https://api.osv.dev
	NPMBase string // https://registry.npmjs.org
	Logf    func(format string, args ...any)
	Sleep   func(ctx context.Context, d time.Duration) error
}

// New returns a Client for the public OSV API and npm registry.
func New() *Client {
	return &Client{
		HTTP:    &http.Client{Timeout: 2 * time.Minute},
		OSVBase: "https://api.osv.dev",
		NPMBase: "https://registry.npmjs.org",
		Logf:    func(string, ...any) {},
		Sleep:   sleepCtx,
	}
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fetch sends the request (POST when body != nil), retrying network errors, 429 and 5xx.
func (c *Client) fetch(ctx context.Context, url string, body []byte) ([]byte, error) {
	for try := 0; ; try++ {
		b, status, wait, err := c.once(ctx, url, body)
		retry := ctx.Err() == nil && (status == 0 && err != nil || status == http.StatusTooManyRequests || status >= 500)
		if !retry {
			return b, err
		}
		if try == len(backoff) {
			return nil, err
		}
		wait = max(wait, backoff[try])
		c.Logf("%v; retrying in %s", err, wait)
		if err := c.Sleep(ctx, wait); err != nil {
			return nil, err
		}
	}
}

// once does one request. status is 0 when no complete response was received;
// wait is the server's Retry-After (0 if absent).
func (c *Client) once(ctx context.Context, url string, body []byte) ([]byte, int, time.Duration, error) {
	method, rd := http.MethodGet, io.Reader(nil)
	if body != nil {
		method, rd = http.MethodPost, bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rd)
	if err != nil {
		return nil, -1, 0, err // not retryable
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	var wait time.Duration
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
		wait = min(time.Duration(s)*time.Second, maxRetryAfter)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, resp.StatusCode, 0, fmt.Errorf("%s %s: %w", method, url, errNotFound)
	case resp.StatusCode != http.StatusOK:
		return nil, resp.StatusCode, wait, fmt.Errorf("%s %s: HTTP %d", method, url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("%s %s: %w", method, url, err) // cut mid-transfer: retry
	}
	if int64(len(b)) > maxBody {
		return nil, resp.StatusCode, 0, fmt.Errorf("%s %s: response exceeds %d MB", method, url, maxBody>>20)
	}
	return b, resp.StatusCode, 0, nil
}
