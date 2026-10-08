// Package sourcetest provides an in-memory source.Source for tests.
package sourcetest

import (
	"context"
	"time"

	"github.com/dmitriy86it/runsweep/internal/source"
)

// Fake is an in-memory source.Source for tests.
type Fake struct {
	Orgs      map[string][]string           // org -> repos
	Runs      map[string][]source.Run       // repo -> runs
	Jobs      map[int64][]source.Job        // run ID -> jobs
	Logs      map[int64]string              // job ID -> log
	GoneLogs  map[int64]bool                // job ID -> 410
	Trees     map[string][]source.TreeEntry // repo@sha -> entries
	Truncated map[string]bool               // repo@sha
	Blobs     map[string][]byte             // blob SHA -> content
	NoAccess  map[string]bool               // repo -> 403
	Public    map[string]bool               // repo -> public
}

// New returns an empty Fake.
func New() *Fake {
	return &Fake{Orgs: map[string][]string{}, Runs: map[string][]source.Run{}, Jobs: map[int64][]source.Job{},
		Logs: map[int64]string{}, GoneLogs: map[int64]bool{}, Trees: map[string][]source.TreeEntry{},
		Truncated: map[string]bool{}, Blobs: map[string][]byte{}, NoAccess: map[string]bool{},
		Public: map[string]bool{}}
}

// AddFile puts a file into the tree of repo@sha.
func (f *Fake) AddFile(repo, sha, path string, content []byte) {
	blob := repo + "@" + sha + ":" + path
	f.Trees[repo+"@"+sha] = append(f.Trees[repo+"@"+sha], source.TreeEntry{Path: path, SHA: blob})
	f.Blobs[blob] = content
}

// ListRepos implements source.Source.
func (f *Fake) ListRepos(_ context.Context, org string) ([]string, error) { return f.Orgs[org], nil }

// ListRuns implements source.Source.
func (f *Fake) ListRuns(_ context.Context, repo string, start, end time.Time) ([]source.Run, error) {
	if f.NoAccess[repo] {
		return nil, source.ErrNoAccess
	}
	var out []source.Run
	for _, r := range f.Runs[repo] {
		if !r.CreatedAt.Before(start) && !r.CreatedAt.After(end) {
			out = append(out, r)
		}
	}
	return out, nil
}

// ListJobs implements source.Source.
func (f *Fake) ListJobs(_ context.Context, _ string, runID int64) ([]source.Job, error) {
	return f.Jobs[runID], nil
}

// JobLog implements source.Source.
func (f *Fake) JobLog(_ context.Context, _ string, jobID int64) (string, error) {
	if f.GoneLogs[jobID] {
		return "", source.ErrGone
	}
	return f.Logs[jobID], nil
}

// Tree implements source.Source.
func (f *Fake) Tree(_ context.Context, repo, sha string) ([]source.TreeEntry, bool, error) {
	return f.Trees[repo+"@"+sha], f.Truncated[repo+"@"+sha], nil
}

// Blob implements source.Source.
func (f *Fake) Blob(_ context.Context, _ string, blobSHA string, limit int) ([]byte, error) {
	b, ok := f.Blobs[blobSHA]
	if !ok {
		return nil, source.ErrNoAccess
	}
	if len(b) > limit {
		return nil, source.ErrIncomplete
	}
	return b, nil
}

// File implements source.Source: the file added with AddFile to repo@ref; ErrNoAccess (HTTP 404) if absent.
func (f *Fake) File(ctx context.Context, repo, ref, path string, limit int) ([]byte, error) {
	for _, e := range f.Trees[repo+"@"+ref] {
		if e.Path == path {
			return f.Blob(ctx, repo, e.SHA, limit)
		}
	}
	return nil, source.ErrNoAccess
}

// RepoPublic implements source.Source.
func (f *Fake) RepoPublic(_ context.Context, repo string) (bool, error) {
	if f.NoAccess[repo] {
		return false, source.ErrNoAccess
	}
	return f.Public[repo], nil
}
