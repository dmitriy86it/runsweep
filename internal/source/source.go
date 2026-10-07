// Package source abstracts the GitHub data runsweep reads.
package source

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrGone: GitHub deleted the object (retention, HTTP 410).
	ErrGone = errors.New("deleted by GitHub retention (HTTP 410)")
	// ErrNoAccess: 403/404 — missing permission or not found.
	ErrNoAccess = errors.New("no access (HTTP 403/404)")
)

type Run struct {
	ID        int64
	Name      string // workflow name
	Path      string // e.g. .github/workflows/ci.yml
	HeadSHA   string
	URL       string
	CreatedAt time.Time
}

type Job struct {
	ID   int64
	Name string // display name from the API
	URL  string
}

type TreeEntry struct {
	Path string
	SHA  string // blob SHA
}

type Source interface {
	ListRepos(ctx context.Context, org string) ([]string, error) // "owner/name"
	ListRuns(ctx context.Context, repo string, start, end time.Time) ([]Run, error)
	ListJobs(ctx context.Context, repo string, runID int64) ([]Job, error)
	JobLog(ctx context.Context, repo string, jobID int64) (string, error)
	Tree(ctx context.Context, repo, sha string) (entries []TreeEntry, truncated bool, err error)
	Blob(ctx context.Context, repo, blobSHA string) ([]byte, error)
}
