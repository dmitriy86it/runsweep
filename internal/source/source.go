// Package source abstracts the GitHub data runsweep reads.
package source

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrGone means GitHub deleted the object (retention, HTTP 410).
	ErrGone = errors.New("deleted by GitHub retention (HTTP 410)")
	// ErrIncomplete means data truncated by a size limit or an API cap.
	ErrIncomplete = errors.New("data incomplete (size or API cap)")
	// ErrNoAccess means a 4xx other than 401 and rate limits — missing permission, not found or
	// a rejected request.
	ErrNoAccess = errors.New("no access (HTTP 4xx)")
	// ErrAuth means the token was rejected (HTTP 401): fatal, nothing more can be read.
	ErrAuth = errors.New("authentication failed (HTTP 401)")
)

// Run is a workflow run.
type Run struct {
	ID        int64
	Name      string // workflow name
	Path      string // e.g. .github/workflows/ci.yml
	HeadSHA   string
	URL       string
	CreatedAt time.Time
	StartedAt time.Time // start of the latest attempt (run_started_at); zero if unknown
	UpdatedAt time.Time
	Attempt   int    // latest attempt (run_attempt); 0 means the API omitted it
	Status    string // "completed" once finished; empty if the API omitted it
}

// Job is a job of a workflow run.
type Job struct {
	ID   int64
	Name string // display name from the API
	URL  string
	// Conclusion from the API ("success", "skipped", ...); empty while running.
	Conclusion  string
	StartedAt   time.Time // zero if the job never started
	CompletedAt time.Time // zero while running or if unknown
	Attempt     int       // run attempt this job belongs to
}

// TreeEntry is one entry of a git tree.
type TreeEntry struct {
	Path string
	SHA  string // blob SHA
}

// Source abstracts the GitHub data the scanner needs.
type Source interface {
	ListRepos(ctx context.Context, org string) ([]string, error) // "owner/name"
	ListRuns(ctx context.Context, repo string, start, end time.Time) ([]Run, error)
	ListJobs(ctx context.Context, repo string, runID int64) ([]Job, error)
	JobLog(ctx context.Context, repo string, jobID int64) (string, error)
	Tree(ctx context.Context, repo, sha string) (entries []TreeEntry, truncated bool, err error)
	Blob(ctx context.Context, repo, blobSHA string) ([]byte, error)
}
