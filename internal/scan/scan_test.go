package scan

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
	"github.com/runsweep/runsweep/internal/source"
	"github.com/runsweep/runsweep/internal/source/sourcetest"
)

const actionSHA = "0e58ed8671d6b60d0890c21b07f8835ace038e67"

var t0 = time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)

var inc = &incident.Incident{ID: "t", Window: incident.Window{Start: t0.Add(-time.Hour), End: t0.Add(time.Hour)},
	NPM:     []incident.NPMPackage{{Name: "axios", Versions: []string{"1.14.1"}}},
	Actions: []incident.Action{{Uses: "tj-actions/changed-files", SHAs: []string{actionSHA}}}}

const ciYAML = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: tj-actions/changed-files@v45
      - run: npm ci
        env: {NPM_TOKEN: "${{ secrets.NPM_TOKEN }}"}
  lint:
    runs-on: ubuntu-latest
    steps: [{run: echo lint}]
`

func fixture() *sourcetest.Fake {
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
	f.Jobs[1] = []source.Job{{ID: 10, Name: "build"}, {ID: 11, Name: "lint"}}
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(ciYAML))
	f.AddFile("o/a", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	f.Logs[10] = "2026-03-31T01:00:00Z Download action repository 'tj-actions/changed-files@v45' (SHA:1111111111111111111111111111111111111111)\n" +
		"2026-03-31T01:00:00Z ##[group]GITHUB_TOKEN Permissions\n2026-03-31T01:00:00Z Contents: write\n2026-03-31T01:00:00Z ##[endgroup]\n"
	f.Logs[11] = ""
	return f
}

func TestScanAffected(t *testing.T) {
	res, err := Run(context.Background(), fixture(), inc, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.RunsScanned != 1 || res.JobsScanned != 2 || len(res.Findings) != 1 {
		t.Fatalf("%+v", res)
	}
	f := res.Findings[0]
	if f.Status != model.Affected || f.Run.Job != "build" || f.Exposure == nil ||
		f.Exposure.Secrets[0] != "NPM_TOKEN" || f.Exposure.TokenPerms["contents"] != "write" {
		t.Fatalf("%+v %+v", f, f.Exposure)
	}
	if len(res.Rotation) == 0 || res.Rotation[0].Name != "NPM_TOKEN" {
		t.Fatalf("%+v", res.Rotation)
	}
}

func TestScanLogGoneFallsBackToWorkflow(t *testing.T) {
	f := fixture()
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // keep only the workflow file: no npm hit
	f.GoneLogs[10], f.GoneLogs[11] = true, true
	res, err := Run(context.Background(), f, inc, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 || res.Findings[0].Status != model.Possible || res.Findings[0].Run.Job != "build" ||
		res.Findings[1].Status != model.Unchecked || res.Findings[1].Run.Job != "lint" || !hasNote(res.Findings[1], "job log unavailable (deleted by GitHub retention (HTTP 410)); composite actions not checked") {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestScanSkipsNoAccessRepo(t *testing.T) {
	f := fixture()
	f.Orgs["o"] = []string{"o/secret", "o/a"}
	f.NoAccess["o/secret"] = true
	res, err := Run(context.Background(), f, inc, Options{Org: "o"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Skipped) != 1 || res.Skipped[0].Repo != "o/secret" || res.Count(model.Affected) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestScanWorkflowMissingUsesAllJobs(t *testing.T) {
	f := fixture()
	f.Runs["o/a"][0].Path = "dynamic/dependabot"
	f.Logs[10] += "2026-03-31T01:00:00Z added 12 packages in 1s\n"
	f.Logs[11] = f.Logs[10]
	res, err := Run(context.Background(), f, inc, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, fd := range res.Findings {
		if fd.Status == model.Affected && fd.Exposure != nil && fd.Exposure.JobMatched {
			t.Fatalf("without a workflow file the job cannot be matched: %+v", fd)
		}
	}
	if res.Count(model.Affected) != 2 {
		t.Fatalf("without a workflow every installing job of an npm-affected run is AFFECTED: %+v", res.Findings)
	}
}

// errSrc injects errors the Fake cannot produce.
type errSrc struct {
	*sourcetest.Fake
	logErr  map[int64]error
	treeErr error
	blobErr map[string]error // blob SHA -> error
}

func (s errSrc) Blob(ctx context.Context, repo, sha string, limit int) ([]byte, error) {
	if err := s.blobErr[sha]; err != nil {
		return nil, err
	}
	return s.Fake.Blob(ctx, repo, sha, limit)
}

func (s errSrc) File(ctx context.Context, repo, ref, path string, limit int) ([]byte, error) {
	if err := s.blobErr[repo+"@"+ref+":"+path]; err != nil {
		return nil, err
	}
	return s.Fake.File(ctx, repo, ref, path, limit)
}

func (s errSrc) JobLog(ctx context.Context, repo string, id int64) (string, error) {
	if err := s.logErr[id]; err != nil {
		return "", err
	}
	return s.Fake.JobLog(ctx, repo, id)
}

func (s errSrc) Tree(ctx context.Context, repo, sha string) ([]source.TreeEntry, bool, error) {
	if s.treeErr != nil {
		return nil, false, s.treeErr
	}
	return s.Fake.Tree(ctx, repo, sha)
}

func hasNote(f model.Finding, sub string) bool {
	for _, e := range f.Evidence {
		if e.Kind == "note" && strings.Contains(e.Detail, sub) {
			return true
		}
	}
	return false
}

func TestScanIncompleteLogIsUnchecked(t *testing.T) {
	f := fixture()
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // no npm hit
	src := errSrc{Fake: f, logErr: map[int64]error{11: source.ErrIncomplete}}
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	res, err := Run(context.Background(), src, actOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Run.Job != "lint" || res.Findings[0].Status != model.Unchecked ||
		!hasNote(res.Findings[0], source.ErrIncomplete.Error()) {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestScanTreeNoAccessIsUnchecked(t *testing.T) {
	src := errSrc{Fake: fixture(), treeErr: source.ErrNoAccess}
	npmOnly := &incident.Incident{ID: "t", Window: inc.Window, NPM: inc.NPM}
	res, err := Run(context.Background(), src, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	// Workflow file unavailable too, so npm "unchecked" applies to every job.
	if len(res.Findings) != 2 || res.Count(model.Unchecked) != 2 || !hasNote(res.Findings[0], "no access") {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestScanBadWorkflowAppliesNPMToAllJobs(t *testing.T) {
	f := fixture()
	f.Trees["o/a@s1"] = nil
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("jobs: [unclosed"))
	f.AddFile("o/a", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	f.Logs[10], f.Logs[11] = "2026-03-31T01:00:00Z added 12 packages in 1s\n", "2026-03-31T01:00:00Z added 12 packages in 1s\n"
	npmOnly := &incident.Incident{ID: "t", Window: inc.Window, NPM: inc.NPM}
	res, err := Run(context.Background(), f, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count(model.Affected) != 2 {
		t.Fatalf("%+v", res.Findings)
	}
	for _, fd := range res.Findings {
		if fd.Exposure == nil || fd.Exposure.JobMatched || !hasNote(fd, "secrets unknown") {
			t.Fatalf("%+v", fd)
		}
	}
}

func TestScanUnknownJobLogGoneUsesAllJobs(t *testing.T) {
	f := fixture()
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // no npm hit
	f.Jobs[1] = []source.Job{{ID: 12, Name: "deploy"}}
	f.GoneLogs[12] = true
	res, err := Run(context.Background(), f, inc, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Status != model.Possible ||
		res.Findings[0].Exposure == nil || res.Findings[0].Exposure.JobMatched {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestScanDedupesRepos(t *testing.T) {
	f := fixture()
	f.Orgs["o"] = []string{"o/a"}
	res, err := Run(context.Background(), f, inc, Options{Repos: []string{"o/a", "o/a"}, Org: "o"})
	if err != nil {
		t.Fatal(err)
	}
	if res.RunsScanned != 1 || res.JobsScanned != 2 || len(res.Findings) != 1 || res.Count(model.Affected) != 1 {
		t.Fatalf("%+v", res)
	}
}

func TestScanNPMKeepsEvidenceBeforeSoftError(t *testing.T) {
	f := fixture()
	f.AddFile("o/a", "s1", "web/package-lock.json", []byte(`{"lockfileVersion":3,"packages":{}}`))
	src := errSrc{Fake: f, blobErr: map[string]error{"o/a@s1:web/package-lock.json": source.ErrNoAccess}}
	npmOnly := &incident.Incident{ID: "t", Window: inc.Window, NPM: inc.NPM}
	res, err := Run(context.Background(), src, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Status != model.Affected || !hasNote(res.Findings[0], "no access") {
		t.Fatalf("%+v", res.Findings)
	}
	var npmEv bool
	for _, e := range res.Findings[0].Evidence {
		npmEv = npmEv || e.Kind == "npm"
	}
	if !npmEv {
		t.Fatalf("AFFECTED evidence lost: %+v", res.Findings[0].Evidence)
	}
}

func TestScanHardTreeErrorPropagates(t *testing.T) {
	src := errSrc{Fake: fixture(), treeErr: errors.New("boom")}
	res, err := Run(context.Background(), src, inc, Options{Repos: []string{"o/a"}})
	if err == nil {
		t.Fatal("want error")
	}
	// the partial result keeps the run, UNCHECKED with the error, never dropped
	if res == nil || len(res.Findings) != 1 || res.Findings[0].Status != model.Unchecked || !hasNote(res.Findings[0], "boom") {
		t.Fatalf("%+v", res)
	}
}

type runsErrSrc struct {
	*sourcetest.Fake
	err map[string]error // repo -> ListRuns error
}

func (s runsErrSrc) ListRuns(ctx context.Context, repo string, start, end time.Time) ([]source.Run, error) {
	if err := s.err[repo]; err != nil {
		return nil, err
	}
	return s.Fake.ListRuns(ctx, repo, start, end)
}

func TestScanHardErrorKeepsPartialResult(t *testing.T) {
	for _, tc := range []struct {
		err      error
		failNote string
	}{{errors.New("boom"), "boom"}, {context.Canceled, "interrupted: not scanned"}} {
		src := runsErrSrc{fixture(), map[string]error{"o/b": tc.err}}
		res, err := Run(context.Background(), src, inc, Options{Repos: []string{"o/c", "o/b", "o/a"}})
		if !errors.Is(err, tc.err) || res == nil {
			t.Fatalf("%v %+v", err, res)
		}
		want := []model.Skip{{Repo: "o/b", Reason: tc.failNote}, {Repo: "o/c", Reason: "interrupted: not scanned"}}
		if res.Count(model.Affected) != 1 || res.ReposTargeted != 3 || !reflect.DeepEqual(res.Skipped, want) {
			t.Fatalf("%+v", res)
		}
	}
}

// A hard error mid-run keeps the jobs already judged and adds a run-level UNCHECKED.
func TestScanHardErrorKeepsRunFindings(t *testing.T) {
	src := errSrc{Fake: fixture(), logErr: map[int64]error{11: errors.New("boom")}}
	res, err := Run(context.Background(), src, inc, Options{Repos: []string{"o/a"}})
	if err == nil || res.Count(model.Affected) != 1 || res.Count(model.Unchecked) != 1 || res.JobsScanned != 2 {
		t.Fatalf("%v %+v", err, res)
	}
	for _, f := range res.Findings {
		if f.Status == model.Unchecked && (f.Run.JobID != 0 || !hasNote(f, "boom")) {
			t.Fatalf("%+v", f)
		}
	}
}

type panicSrc struct{ *sourcetest.Fake }

func (panicSrc) ListJobs(context.Context, string, int64) ([]source.Job, error) {
	panic("kaboom\x1b[2J")
}

func TestScanPanicIsUnchecked(t *testing.T) {
	res, err := Run(context.Background(), panicSrc{fixture()}, inc, Options{Repos: []string{"o/a"}})
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Status != model.Unchecked ||
		!hasNote(res.Findings[0], "internal error: kaboom[2J") {
		t.Fatalf("%v %+v", err, res)
	}
}

func TestScanReposTargetedDeduped(t *testing.T) {
	f := sourcetest.New()
	f.Orgs["o"] = []string{"o/a", "o/b"}
	res, err := Run(context.Background(), f, inc, Options{Repos: []string{"o/a"}, Org: "o"})
	if err != nil {
		t.Fatal(err)
	}
	if res.ReposTargeted != 2 {
		t.Fatalf("ReposTargeted = %d, want 2", res.ReposTargeted)
	}
}

func TestScanNPMHiddenInstallIsAffected(t *testing.T) {
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
	f.Jobs[1] = []source.Job{{ID: 10, Name: "build"}, {ID: 11, Name: "reuse / test"}, {ID: 12, Name: "plain"}, {ID: 13, Name: "logged"}}
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(`on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/setup
      - run: make test
  reuse:
    uses: ./.github/workflows/build.yml
    secrets: inherit
  plain:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
  logged:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: echo hi
`))
	f.AddFile("o/a", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	f.Logs[10] = "2026-03-31T01:00:00Z added 312 packages in 4s\n"
	f.Logs[11], f.Logs[12] = f.Logs[10], ""
	f.Logs[13] = f.Logs[10]
	npmOnly := &incident.Incident{ID: "t", Window: inc.Window, NPM: inc.NPM}
	res, err := Run(context.Background(), f, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]model.Status{}
	for _, fd := range res.Findings {
		got[fd.Run.Job] = fd.Status
	}
	want := map[string]model.Status{"build": model.Affected, "reuse / test": model.Affected, "logged": model.Affected}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s: %v (all: %v)", k, got[k], got)
		}
	}
}

func TestScanLogWithoutDownloadsFallsBackToUses(t *testing.T) {
	f := fixture()
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // no npm hit
	f.Logs[10] = "2026-03-31T01:00:00Z log without download records\n"
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	res, err := Run(context.Background(), f, actOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	// build's log has no download records but the job uses tj-actions/changed-files@v45 (mutable ref);
	// lint has no remote uses and stays clean.
	if len(res.Findings) != 1 || res.Findings[0].Run.Job != "build" || res.Findings[0].Status != model.Possible ||
		!hasNote(res.Findings[0], "job log has no action download records") {
		t.Fatalf("%+v", res.Findings)
	}
}

func TestScanSkippedJobNeverRan(t *testing.T) {
	f := fixture()
	f.Jobs[1] = append(f.Jobs[1], source.Job{ID: 12, Name: "lint", Conclusion: "skipped"})
	f.Jobs[1][0].Conclusion = "skipped"         // build: would be AFFECTED by npm if it had run
	f.GoneLogs[10], f.GoneLogs[12] = true, true // GitHub has no log for skipped jobs
	res, err := Run(context.Background(), f, inc, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 0 || res.JobsScanned != 3 {
		t.Fatalf("%+v", res)
	}
}

func TestScanNoWorkflowNoDownloadsIsUnchecked(t *testing.T) {
	f := fixture()
	f.Runs["o/a"][0].Path = ".github/workflows/missing.yml"
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // no npm hit
	f.Logs[10] = "2026-03-31T01:00:00Z log without download records\n"
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	res, err := Run(context.Background(), f, actOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 2 {
		t.Fatalf("%+v", res.Findings)
	}
	for _, fd := range res.Findings {
		if fd.Status != model.Unchecked || !hasNote(fd, "job log has no action download records and the workflow file is unavailable") {
			t.Fatalf("%+v", fd)
		}
	}
}

// rerun: run 1 was created two days before the window; attempt 1 ran then, attempt 2 inside it.
func rerun() *sourcetest.Fake {
	f := fixture()
	r := &f.Runs["o/a"][0]
	r.CreatedAt, r.StartedAt, r.UpdatedAt, r.Attempt = t0.Add(-48*time.Hour), t0, t0.Add(10*time.Minute), 2
	f.Jobs[1] = []source.Job{
		{ID: 20, Name: "build", Attempt: 1, StartedAt: t0.Add(-48 * time.Hour), CompletedAt: t0.Add(-47 * time.Hour)},
		{ID: 10, Name: "build", Attempt: 2, StartedAt: t0},
		{ID: 11, Name: "lint", Attempt: 2, StartedAt: t0},
	}
	f.Logs[20] = f.Logs[10]
	return f
}

func TestScanReRunInWindow(t *testing.T) {
	res, err := Run(context.Background(), rerun(), inc, Options{Repos: []string{"o/a"}, Lookback: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.RunsScanned != 1 || res.JobsScanned != 2 || len(res.Findings) != 1 {
		t.Fatalf("%+v", res)
	}
	if f := res.Findings[0]; f.Status != model.Affected || f.Run.JobID != 10 || f.Run.Attempt != 2 {
		t.Fatalf("attempt 1 started before the window must not be reported: %+v", f)
	}
	if res.Lookback != 7*24*time.Hour {
		t.Fatalf("lookback %v", res.Lookback)
	}
	res, err = Run(context.Background(), rerun(), inc, Options{Repos: []string{"o/a"}})
	if err != nil || res.RunsScanned != 0 || len(res.Findings) != 0 {
		t.Fatalf("no lookback: the run is created before the window and not listed: %+v %v", res, err)
	}
}

type noJobs struct {
	*sourcetest.Fake
	t *testing.T
}

func (s noJobs) ListJobs(_ context.Context, _ string, id int64) ([]source.Job, error) {
	s.t.Errorf("ListJobs(%d) called for a run that ended before the window", id)
	return nil, nil
}

func TestScanRunBeforeWindowSkipsJobs(t *testing.T) {
	f := fixture()
	r := &f.Runs["o/a"][0]
	r.CreatedAt, r.StartedAt, r.UpdatedAt, r.Attempt, r.Status = t0.Add(-72*time.Hour), t0.Add(-72*time.Hour), t0.Add(-71*time.Hour), 1, "completed"
	res, err := Run(context.Background(), noJobs{f, t}, inc, Options{Repos: []string{"o/a"}, Lookback: 7 * 24 * time.Hour})
	if err != nil || res.RunsScanned != 0 || res.JobsScanned != 0 || len(res.Findings) != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestScanZeroStartTimesAreChecked(t *testing.T) {
	f := fixture()
	r := &f.Runs["o/a"][0]
	// created in the lookback; start times unknown, updated before the window: still checked
	r.CreatedAt, r.UpdatedAt = t0.Add(-72*time.Hour), t0.Add(-71*time.Hour)
	res, err := Run(context.Background(), f, inc, Options{Repos: []string{"o/a"}, Lookback: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if res.RunsScanned != 1 || res.JobsScanned != 2 || res.Count(model.Affected) != 1 {
		t.Fatalf("unknown start time must be checked, never dropped: %+v", res)
	}
}

func TestScanJobRunningIntoWindowIsChecked(t *testing.T) {
	f := fixture()
	f.Jobs[1] = []source.Job{
		{ID: 10, Name: "build", StartedAt: inc.Window.Start.Add(-5 * time.Minute), CompletedAt: inc.Window.Start.Add(5 * time.Minute)},
		{ID: 11, Name: "lint", StartedAt: inc.Window.Start.Add(-5 * time.Minute)}, // still running: no completion time
		{ID: 12, Name: "lint", StartedAt: inc.Window.Start.Add(-5 * time.Minute), CompletedAt: inc.Window.Start.Add(-time.Minute)},
		{ID: 13, Name: "lint", StartedAt: inc.Window.Start}, // boundary: kept
	}
	res, err := Run(context.Background(), f, inc, Options{Repos: []string{"o/a"}})
	if err != nil || res.JobsScanned != 3 {
		t.Fatalf("jobs 10, 11 and 13 must be checked, 12 ended before the window: %+v %v", res, err)
	}
}

type listedJobs struct {
	*sourcetest.Fake
	calls *int
}

func (s listedJobs) ListJobs(ctx context.Context, repo string, id int64) ([]source.Job, error) {
	*s.calls++
	return s.Fake.ListJobs(ctx, repo, id)
}

func TestScanInProgressRunBeforeWindowStillListsJobs(t *testing.T) {
	f := fixture()
	r := &f.Runs["o/a"][0]
	r.CreatedAt, r.StartedAt, r.UpdatedAt, r.Status = t0.Add(-72*time.Hour), t0.Add(-72*time.Hour), t0.Add(-71*time.Hour), "in_progress"
	calls := 0
	_, err := Run(context.Background(), listedJobs{f, &calls}, inc, Options{Repos: []string{"o/a"}, Lookback: 7 * 24 * time.Hour})
	if err != nil || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

type goneJobs struct{ *sourcetest.Fake }

func (goneJobs) ListJobs(context.Context, string, int64) ([]source.Job, error) {
	return nil, source.ErrGone
}

func TestScanRunLevelFindingKeepsRunAttempt(t *testing.T) {
	f := fixture()
	f.Runs["o/a"][0].Attempt = 2
	res, err := Run(context.Background(), goneJobs{f}, inc, Options{Repos: []string{"o/a"}})
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Run.Attempt != 2 {
		t.Fatalf("%+v %v", res, err)
	}
}

func TestScanFullyFilteredRunNotCounted(t *testing.T) {
	f := fixture()
	f.Jobs[1] = []source.Job{{ID: 10, Name: "build", StartedAt: t0.Add(-48 * time.Hour), CompletedAt: t0.Add(-47 * time.Hour)}}
	res, err := Run(context.Background(), f, inc, Options{Repos: []string{"o/a"}})
	if err != nil || res.RunsScanned != 0 || res.JobsScanned != 0 {
		t.Fatalf("%+v %v", res, err)
	}
}

const pinned = "0123456789abcdef0123456789abcdef01234567"

const deployYAML = `on: workflow_call
jobs:
  release:
    runs-on: ubuntu-latest
    permissions: {id-token: write}
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with: {role-to-assume: "arn:aws:iam::1:role/deploy"}
      - run: npm ci
        env: {T: "${{ secrets.NPM_TOKEN }}"}
`

// callFixture: run 1 has one job, API name apiName, of a ci.yml that calls `uses` with `secrets: inherit`.
func callFixture(uses, apiName string) *sourcetest.Fake {
	f := fixture()
	f.Trees["o/a@s1"] = nil
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  deploy:\n    uses: "+uses+"\n    secrets: inherit\n"))
	f.AddFile("o/a", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	f.Jobs[1] = []source.Job{{ID: 10, Name: apiName}}
	f.Logs[10] += "2026-03-31T01:00:00Z added 12 packages in 1s\n"
	return f
}

var npmOnly = &incident.Incident{ID: "t", Window: inc.Window, NPM: inc.NPM}

func scanOne(t *testing.T, f *sourcetest.Fake, i *incident.Incident) model.Finding {
	t.Helper()
	res, err := Run(context.Background(), f, i, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("%+v", res.Findings)
	}
	return res.Findings[0]
}

func hasRole(f model.Finding) bool {
	return f.Exposure != nil && len(f.Exposure.CloudRoles) == 1 && f.Exposure.CloudRoles[0].Role == "arn:aws:iam::1:role/deploy"
}

func TestScanLocalReusableWorkflow(t *testing.T) {
	f := callFixture("./.github/workflows/deploy.yml", "deploy / release")
	f.AddFile("o/a", "s1", ".github/workflows/deploy.yml", []byte(deployYAML))
	fd := scanOne(t, f, npmOnly)
	if fd.Status != model.Affected || !hasRole(fd) || !fd.Exposure.JobMatched || !fd.Exposure.IDTokenWrite ||
		!fd.Exposure.InheritAll || !slices.Contains(fd.Exposure.Secrets, "NPM_TOKEN") {
		t.Fatalf("%+v %+v", fd, fd.Exposure)
	}
}

func TestScanRemoteReusableWorkflowAtSHA(t *testing.T) {
	f := callFixture("o/shared/.github/workflows/deploy.yml@"+pinned, "deploy / release")
	f.AddFile("o/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
	if fd := scanOne(t, f, npmOnly); !hasRole(fd) {
		t.Fatalf("callee must be read from o/shared@%s: %+v", pinned, fd.Exposure)
	}
}

func TestScanReusableWorkflowByTagNotRead(t *testing.T) {
	f := callFixture("o/shared/.github/workflows/deploy.yml@v1", "deploy / release")
	f.AddFile("o/shared", "v1", ".github/workflows/deploy.yml", []byte(deployYAML)) // must not be read
	fd := scanOne(t, f, npmOnly)
	if fd.Status != model.Affected || hasRole(fd) || !fd.Exposure.InheritAll ||
		!hasNote(fd, "called workflow o/shared/.github/workflows/deploy.yml@v1 is not pinned to a SHA — not read") {
		t.Fatalf("%+v %+v", fd, fd.Exposure)
	}
}

func TestScanNestedReusableWorkflows(t *testing.T) {
	f := callFixture("./.github/workflows/mid.yml", "deploy / inner / release")
	f.AddFile("o/a", "s1", ".github/workflows/mid.yml", []byte("on: workflow_call\njobs:\n  inner:\n    uses: o/shared/.github/workflows/deploy.yml@"+pinned+"\n    secrets: inherit\n"))
	f.AddFile("o/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
	if fd := scanOne(t, f, npmOnly); !hasRole(fd) || !fd.Exposure.JobMatched {
		t.Fatalf("%+v", fd.Exposure)
	}
}

func TestScanCalledWorkflowUnavailableStaysSoft(t *testing.T) {
	f := callFixture("./.github/workflows/gone.yml", "deploy / release")
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // workflow only: no npm hit
	f.Logs[10] = "2026-03-31T01:00:00Z Download action repository 'actions/checkout@v4' (SHA:1111111111111111111111111111111111111111)\n"
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	fd := scanOne(t, f, actOnly)
	if fd.Status != model.Unchecked || !hasNote(fd, "called workflow ./.github/workflows/gone.yml unavailable") {
		t.Fatalf("an unreadable called workflow must be UNCHECKED, never CLEAN or an error: %+v", fd)
	}
}

func TestScanCalledJobAmbiguous(t *testing.T) {
	f := callFixture("./.github/workflows/deploy.yml", "deploy / Release")
	f.AddFile("o/a", "s1", ".github/workflows/deploy.yml", []byte(deployYAML+
		"  release-eu:\n    name: Release\n    runs-on: x\n    steps: [{run: echo}]\n"+
		"  release-us:\n    name: Release\n    runs-on: x\n    steps: [{run: echo}]\n"))
	fd := scanOne(t, f, npmOnly)
	if fd.Exposure.JobMatched || !hasRole(fd) || !hasNote(fd, `job "Release" not identified in called workflow`) {
		t.Fatalf("ambiguous callee job: union of the called workflow, not matched: %+v %+v", fd, fd.Exposure)
	}
}

func TestScanSelfCallingWorkflowStops(t *testing.T) {
	f := callFixture("./.github/workflows/ci.yml", "deploy / deploy / deploy / deploy / deploy / deploy")
	if fd := scanOne(t, f, npmOnly); !hasNote(fd, "nested more than 10 levels deep") {
		t.Fatalf("%+v", fd)
	}
}

func TestScanUnidentifiedCalledJobKeepsEnvironmentSecrets(t *testing.T) {
	f := fixture()
	f.Trees["o/a@s1"] = nil
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  deploy:\n    uses: ./.github/workflows/deploy.yml\n"))
	f.AddFile("o/a", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	f.Jobs[1] = []source.Job{{ID: 10, Name: "deploy / nope"}}
	f.AddFile("o/a", "s1", ".github/workflows/deploy.yml", []byte("on: workflow_call\njobs:\n  a:\n    environment: prod\n    runs-on: x\n    steps: [{run: npm ci, env: {T: \"${{ secrets.PROD_TOKEN }}\"}}]\n"))
	if fd := scanOne(t, f, npmOnly); fd.Exposure.JobMatched || !slices.Contains(fd.Exposure.Secrets, "PROD_TOKEN") {
		t.Fatalf("%+v", fd.Exposure)
	}
}

const sharedCall = "o/shared/.github/workflows/deploy.yml@" + pinned

// A called workflow is never listed in the runner log's download records: the call ref itself must be matched.
func TestScanCalledWorkflowRefMatchesIncident(t *testing.T) {
	for _, tc := range []struct {
		name string
		gone bool
	}{{"log without downloads", false}, {"log gone", true}} {
		t.Run(tc.name, func(t *testing.T) {
			f := callFixture(sharedCall, "deploy / release")
			f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1]
			f.AddFile("o/shared", pinned, ".github/workflows/deploy.yml", []byte("on: workflow_call\njobs:\n  release:\n    runs-on: x\n    steps: [{run: make release}]\n"))
			f.Logs[10] = "2026-03-31T01:00:00Z hello\n"
			f.GoneLogs[10] = tc.gone
			i := &incident.Incident{ID: "t", Window: inc.Window, Actions: []incident.Action{{Uses: "o/shared", SHAs: []string{pinned}}}}
			fd := scanOne(t, f, i)
			if fd.Status != model.Affected || !slices.ContainsFunc(fd.Evidence, func(e model.Evidence) bool {
				return e.Detail == "reusable workflow "+sharedCall+" at compromised SHA"
			}) {
				t.Fatalf("%+v", fd)
			}
			if !tc.gone && slices.ContainsFunc(fd.Evidence, func(e model.Evidence) bool { return strings.Contains(e.Detail, "log unavailable") }) {
				t.Fatalf("the log is present: %+v", fd.Evidence)
			}
		})
	}
}

func TestScanUnidentifiedCalledJobResolvesNestedCalls(t *testing.T) {
	f := callFixture("./.github/workflows/mid.yml", "deploy / Inner")
	f.AddFile("o/a", "s1", ".github/workflows/mid.yml", []byte("on: workflow_call\njobs:\n"+
		"  a:\n    name: Inner\n    uses: ./.github/workflows/deploy.yml\n    secrets: inherit\n"+
		"  b:\n    name: Inner\n    uses: ./.github/workflows/deploy.yml\n    secrets: inherit\n"))
	f.AddFile("o/a", "s1", ".github/workflows/deploy.yml", []byte(deployYAML))
	fd := scanOne(t, f, npmOnly)
	if fd.Exposure.JobMatched || !hasRole(fd) || !fd.Exposure.IDTokenWrite {
		t.Fatalf("%+v %+v", fd, fd.Exposure)
	}
}

func TestScanLocalCallInRemoteWorkflowStaysInRemoteRepo(t *testing.T) {
	f := callFixture(sharedCall, "deploy / mid / release")
	f.AddFile("o/shared", pinned, ".github/workflows/deploy.yml", []byte("on: workflow_call\njobs:\n  mid:\n    uses: ./.github/workflows/x.yml\n    secrets: inherit\n"))
	f.AddFile("o/shared", pinned, ".github/workflows/x.yml", []byte(deployYAML))
	f.AddFile("o/a", "s1", ".github/workflows/x.yml", []byte(strings.ReplaceAll(deployYAML, "role/deploy", "role/WRONG")))
	if fd := scanOne(t, f, npmOnly); !hasRole(fd) {
		t.Fatalf("%+v", fd.Exposure)
	}
}

func TestScanRemoteCalleeErrorIsSoft(t *testing.T) {
	f := callFixture(sharedCall, "deploy / release")
	f.AddFile("o/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
	src := errSrc{Fake: f, blobErr: map[string]error{"o/shared@" + pinned + ":.github/workflows/deploy.yml": errors.New("boom")}}
	res, err := Run(context.Background(), src, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatalf("a remote callee must not abort the scan: %v", err)
	}
	if fd := res.Findings[0]; fd.Status != model.Affected || !hasNote(fd, "unavailable (boom)") {
		t.Fatalf("%+v", fd)
	}
}

func TestScanCalledWorkflowUnavailableReason(t *testing.T) {
	blob := "o/shared@" + pinned + ":.github/workflows/deploy.yml"
	for _, tc := range []struct {
		name, want string
		setup      func(*sourcetest.Fake) source.Source
	}{
		{"missing", "unavailable (no access", func(f *sourcetest.Fake) source.Source { return f }},
		{"403", "no access", func(f *sourcetest.Fake) source.Source {
			f.AddFile("o/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
			return errSrc{Fake: f, blobErr: map[string]error{blob: source.ErrNoAccess}}
		}},
		{"too large", "too large", func(f *sourcetest.Fake) source.Source {
			f.AddFile("o/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
			return errSrc{Fake: f, blobErr: map[string]error{blob: source.ErrIncomplete}}
		}},
		{"parse", "parse error", func(f *sourcetest.Fake) source.Source {
			f.AddFile("o/shared", pinned, ".github/workflows/deploy.yml", []byte("jobs: [unclosed"))
			return f
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := callFixture(sharedCall, "deploy / release")
			res, err := Run(context.Background(), tc.setup(f), npmOnly, Options{Repos: []string{"o/a"}})
			if err != nil || len(res.Findings) != 1 || !hasNote(res.Findings[0], tc.want) {
				t.Fatalf("%v %+v", err, res.Findings)
			}
		})
	}
}

func TestScanUnidentifiedCallerJobWithCallsIsUnchecked(t *testing.T) {
	f := callFixture("./.github/workflows/deploy.yml", "no such job")
	f.AddFile("o/a", "s1", ".github/workflows/deploy.yml", []byte(deployYAML))
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1]
	f.Logs[10] = "2026-03-31T01:00:00Z hi\n"
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	fd := scanOne(t, f, actOnly)
	if fd.Status != model.Unchecked || !hasNote(fd, "called workflows were not read") {
		t.Fatalf("%+v", fd)
	}
}

// Two local workflows whose 20 jobs each call the other: the read budget ends the walk, once.
func TestScanMutuallyRecursiveUnionStopsAtBudget(t *testing.T) {
	f := callFixture("./.github/workflows/a.yml", "deploy / nope")
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // workflow only: no npm hit
	f.Logs[10] = "2026-03-31T01:00:00Z Download action repository 'actions/checkout@v4' (SHA:1111111111111111111111111111111111111111)\n"
	for _, p := range [][2]string{{"a", "b"}, {"b", "a"}} {
		var b strings.Builder
		b.WriteString("on: workflow_call\njobs:\n")
		for i := range 20 {
			fmt.Fprintf(&b, "  j%d:\n    uses: ./.github/workflows/%s.yml\n", i, p[1])
		}
		f.AddFile("o/a", "s1", ".github/workflows/"+p[0]+".yml", []byte(b.String()))
	}
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	fd := scanOne(t, f, actOnly)
	budget := 0
	for _, e := range fd.Evidence {
		if strings.Contains(e.Detail, "called workflows — not read") {
			budget++
		}
	}
	if fd.Status != model.Unchecked || len(fd.Evidence) >= 60 || budget != 1 || slices.ContainsFunc(fd.Evidence, func(e model.Evidence) bool {
		return strings.Contains(e.Detail, `job ""`)
	}) {
		t.Fatalf("status %v, %d evidence entries, budget note %d times: %+v", fd.Status, len(fd.Evidence), budget, fd.Evidence)
	}
}

func TestScanDoesNotMutateSourceJobs(t *testing.T) {
	f := rerun()
	opt := Options{Repos: []string{"o/a"}, Lookback: 7 * 24 * time.Hour}
	a, err := Run(context.Background(), f, inc, opt)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Run(context.Background(), f, inc, opt)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("second scan differs:\n%+v\n%+v", a, b)
	}
}

// A local step `uses:` may be a composite action that downloads remote actions; a log without
// download records cannot prove it clean.
func TestScanLocalCompositeNoDownloadsIsUnchecked(t *testing.T) {
	f := callFixture("./.github/workflows/deploy.yml", "deploy / release")
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1]
	f.AddFile("o/a", "s1", ".github/workflows/deploy.yml", []byte("on: workflow_call\njobs:\n  release:\n    runs-on: x\n"+
		"    steps:\n      - uses: ./local-composite\n      - run: make release\n"))
	f.Logs[10] = "2026-03-31T01:00:00Z hello\n"
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	if fd := scanOne(t, f, actOnly); fd.Status != model.Unchecked || !hasNote(fd, "job log has no action download records") {
		t.Fatalf("%+v", fd)
	}
}

type countFile struct {
	*sourcetest.Fake
	n *int
}

func (s countFile) File(context.Context, string, string, string, int) ([]byte, error) {
	*s.n++
	return nil, errors.New("boom")
}

func TestScanRemoteCalleeHardErrorCached(t *testing.T) {
	f := callFixture(sharedCall, "deploy / release")
	f.Jobs[1] = []source.Job{{ID: 10, Name: "deploy / release"}, {ID: 11, Name: "deploy / release"}}
	n := 0
	res, err := Run(context.Background(), countFile{f, &n}, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil || len(res.Findings) != 2 || !hasNote(res.Findings[1], "unavailable (boom)") || n != 1 {
		t.Fatalf("File called %d times, %v %+v", n, err, res.Findings)
	}
}

// A cycle cut by the depth cap leaves the exposure incomplete: never CLEAN.
func TestScanDepthCapIsUnchecked(t *testing.T) {
	f := callFixture("./.github/workflows/ci.yml", "deploy / deploy / deploy / deploy / deploy / deploy")
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // workflow only: no npm hit
	f.Logs[10] = "2026-03-31T01:00:00Z Download action repository 'actions/checkout@v4' (SHA:1111111111111111111111111111111111111111)\n"
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	if fd := scanOne(t, f, actOnly); fd.Status != model.Unchecked || !hasNote(fd, "nested more than 10 levels deep") {
		t.Fatalf("%+v", fd)
	}
}

// An unpinned call ref is never read: with no download records it must not be judged CLEAN.
func TestScanUnreadCallNoDownloadsIsUnchecked(t *testing.T) {
	f := callFixture("o/shared/.github/workflows/deploy.yml@main", "deploy / release")
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1]
	f.Logs[10] = "hello\n"
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	if fd := scanOne(t, f, actOnly); fd.Status != model.Unchecked || !hasNote(fd, "job log has no action download records") {
		t.Fatalf("%+v", fd)
	}
}

type cappedSrc struct{ *sourcetest.Fake }

func (s cappedSrc) ListRuns(ctx context.Context, repo string, start, end time.Time) ([]source.Run, error) {
	runs, _ := s.Fake.ListRuns(ctx, repo, start, end)
	return runs, source.ErrRunsCapped
}

func TestScanRunsCapIsUnchecked(t *testing.T) {
	res, err := Run(context.Background(), cappedSrc{fixture()}, inc, Options{Repos: []string{"o/a"}})
	if err != nil || res.Count(model.Affected) != 1 || res.Count(model.Unchecked) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	if fd := res.Findings[1]; fd.Run.Repo != "o/a" || !hasNote(fd, "runs not scanned: API cap of 1000 runs in a window ≤1 min") {
		t.Fatalf("%+v", fd)
	}
}

type logCount struct {
	*sourcetest.Fake
	n *atomic.Int32
}

func (s logCount) JobLog(ctx context.Context, repo string, id int64) (string, error) {
	s.n.Add(1)
	return s.Fake.JobLog(ctx, repo, id)
}

func TestScanRuntimeInstall(t *testing.T) {
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
	f.Jobs[1] = []source.Job{{ID: 10, Name: "x"}, {ID: 11, Name: "gs"}}
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(`on: push
jobs:
  x:
    runs-on: ubuntu-latest
    steps:
      - run: npx -y axios@latest
  gs:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/github-script@v7
        with:
          script: require('child_process').execSync('npx left-pad')
`))
	f.Logs[10] = "2026-03-31T01:00:00Z ##[group]GITHUB_TOKEN Permissions\n2026-03-31T01:00:00Z Contents: write\n2026-03-31T01:00:00Z ##[endgroup]\n"
	npmOnly := &incident.Incident{ID: "t", Window: inc.Window, NPM: inc.NPM}
	src := logCount{f, &atomic.Int32{}}
	res, err := Run(context.Background(), src, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("%v %+v", err, res)
	}
	fd := res.Findings[0]
	if fd.Run.Job != "x" || fd.Status != model.Possible || fd.Evidence[0].Detail != "runs `npx -y axios@latest` at run time" ||
		fd.Exposure == nil || fd.Exposure.TokenPerms["contents"] != "write" {
		t.Fatalf("%+v", fd)
	}
	if src.n.Load() != 2 {
		t.Fatalf("a job that installs at run time needs its log: %d logs read", src.n.Load())
	}
}

func TestScanDownloadAfterFirstStepDoesNotProveDownloads(t *testing.T) {
	const wfYAML = "on: push\njobs:\n  build:\n    runs-on: x\n    steps:\n      - uses: ./.github/actions/setup\n"
	run := "2026-03-31T01:00:00Z ##[group]Run ./.github/actions/setup\n"
	for name, c := range map[string]struct {
		log  string
		want model.Status
	}{
		"good record printed by the job":  {run + "2026-03-31T01:00:01Z Download action repository 'actions/checkout@v4' (SHA:1111111111111111111111111111111111111111)\n", model.Unchecked},
		"bad record after the first step": {run + "2026-03-31T01:00:01Z Download action repository 'tj-actions/changed-files@v45' (SHA:" + actionSHA + ")\n", model.Affected},
	} {
		f := sourcetest.New()
		f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
		f.Jobs[1] = []source.Job{{ID: 10, Name: "build"}}
		f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(wfYAML))
		f.Logs[10] = c.log
		actionsOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
		res, err := Run(context.Background(), f, actionsOnly, Options{Repos: []string{"o/a"}})
		if err != nil || len(res.Findings) != 1 || res.Findings[0].Status != c.want || !hasNote(res.Findings[0], "job log has no action download records") {
			t.Errorf("%s: %v %+v", name, err, res.Findings)
		}
	}
}

func TestScanPackageNamedAtRunTime(t *testing.T) {
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
	f.Jobs[1] = []source.Job{{ID: 10, Name: "x"}}
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  x:\n    runs-on: x\n    steps:\n      - run: npm i -g $TOOL\n"))
	npmOnly := &incident.Incident{ID: "t", Window: inc.Window, NPM: inc.NPM}
	res, err := Run(context.Background(), f, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Status != model.Unchecked ||
		!hasNote(res.Findings[0], "package named at run time: `npm i -g $TOOL`") {
		t.Fatalf("%v %+v", err, res.Findings)
	}
}

// A workflow file over 1 MiB is unreadable: never judged from a partial read.
func TestScanOversizeWorkflowIsUnavailable(t *testing.T) {
	f := fixture()
	f.Trees["o/a@s1"] = nil
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(ciYAML+"#"+strings.Repeat("x", source.MaxWorkflowBytes)))
	f.Logs[10] = "2026-03-31T01:00:00Z log without download records\n"
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	res, err := Run(context.Background(), f, actOnly, Options{Repos: []string{"o/a"}})
	if err != nil || len(res.Findings) != 2 {
		t.Fatalf("%v %+v", err, res.Findings)
	}
	for _, fd := range res.Findings {
		if fd.Status != model.Unchecked || !hasNote(fd, "the workflow file is unavailable") {
			t.Fatalf("%+v", fd)
		}
	}
}

type countBlobs struct {
	*sourcetest.Fake
	n *atomic.Int32
}

func (s countBlobs) Blob(ctx context.Context, repo, sha string, limit int) ([]byte, error) {
	s.n.Add(1)
	return s.Fake.Blob(ctx, repo, sha, limit)
}

// Runs of different commits that share the workflow and lockfile blobs fetch each blob once.
func TestScanParsedBlobsCached(t *testing.T) {
	f := fixture()
	f.Runs["o/a"] = append(f.Runs["o/a"], source.Run{ID: 2, Path: ".github/workflows/ci.yml", HeadSHA: "s2", CreatedAt: t0})
	f.Trees["o/a@s2"] = f.Trees["o/a@s1"]
	f.Jobs[2] = f.Jobs[1]
	var n atomic.Int32
	defer func(n int) { concurrency = n }(concurrency)
	concurrency = 1
	res, err := Run(context.Background(), countBlobs{f, &n}, inc, Options{Repos: []string{"o/a"}})
	if err != nil || res.Count(model.Affected) != 2 || n.Load() != 2 {
		t.Fatalf("%d blob fetches, %v %+v", n.Load(), err, res.Findings)
	}
}

// A called workflow in another owner's repository is not read (its content is not the scanned
// owner's to fetch): UNCHECKED with a note. The owner compares case-insensitively.
func TestScanCalledWorkflowOtherOwnerNotRead(t *testing.T) {
	f := callFixture("evil/shared/.github/workflows/deploy.yml@"+pinned, "deploy / release")
	f.AddFile("evil/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML)) // must not be read
	fd := scanOne(t, f, npmOnly)
	if fd.Status != model.Affected || hasRole(fd) || !hasNote(fd, "called workflow in another owner (evil/shared) not read") {
		t.Fatalf("%+v %+v", fd, fd.Exposure)
	}
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // no npm hit
	f.Logs[10] = "2026-03-31T01:00:00Z Download action repository 'actions/checkout@v4' (SHA:1111111111111111111111111111111111111111)\n"
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: inc.Actions}
	if fd := scanOne(t, f, actOnly); fd.Status != model.Unchecked {
		t.Fatalf("an unread call is never CLEAN: %+v", fd)
	}
	f = callFixture("O/shared/.github/workflows/deploy.yml@"+pinned, "deploy / release")
	f.AddFile("O/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
	if fd := scanOne(t, f, npmOnly); !hasRole(fd) {
		t.Fatalf("same owner, other case: must be read: %+v", fd.Exposure)
	}
}

// A client timeout reading a called workflow in another repository leaves the job UNCHECKED; the scan continues.
func TestScanRemoteCalleeTimeoutIsSoft(t *testing.T) {
	f := callFixture(sharedCall, "deploy / release")
	f.AddFile("o/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
	timeout := fmt.Errorf("Client.Timeout exceeded: %w", context.DeadlineExceeded)
	src := errSrc{Fake: f, blobErr: map[string]error{"o/shared@" + pinned + ":.github/workflows/deploy.yml": timeout}}
	res, err := Run(context.Background(), src, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatalf("a client timeout on a remote callee must not abort the scan: %v", err)
	}
	if fd := res.Findings[0]; fd.Status != model.Affected || !hasNote(fd, "unavailable (Client.Timeout exceeded") {
		t.Fatalf("%+v", fd)
	}
}

type countPublic struct {
	*sourcetest.Fake
	n *int
}

func (s countPublic) RepoPublic(ctx context.Context, repo string) (bool, error) {
	*s.n++
	return s.Fake.RepoPublic(ctx, repo)
}

// A called workflow in another owner's public repository is read; visibility is asked once per repo.
func TestScanCalledWorkflowOtherOwnerPublicRead(t *testing.T) {
	f := callFixture("evil/shared/.github/workflows/deploy.yml@"+pinned, "deploy / release")
	f.Jobs[1] = []source.Job{{ID: 10, Name: "deploy / release"}, {ID: 11, Name: "deploy / release"}}
	f.AddFile("evil/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
	f.Public["evil/shared"] = true
	n := 0
	res, err := Run(context.Background(), countPublic{f, &n}, npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil || len(res.Findings) != 2 || !hasRole(res.Findings[0]) || !hasRole(res.Findings[1]) || n != 1 {
		t.Fatalf("RepoPublic called %d times, %v %+v", n, err, res.Findings)
	}
}

// An unread call in another owner is still matched by its ref: pinned at a compromised SHA it is AFFECTED.
func TestScanCalledWorkflowOtherOwnerCompromisedRef(t *testing.T) {
	f := callFixture("evil/shared/.github/workflows/deploy.yml@"+pinned, "deploy / release")
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1]
	f.Logs[10] = "2026-03-31T01:00:00Z hello\n"
	i := &incident.Incident{ID: "t", Window: inc.Window, Actions: []incident.Action{{Uses: "evil/shared", SHAs: []string{pinned}}}}
	fd := scanOne(t, f, i)
	if fd.Status != model.Affected || !hasNote(fd, "called workflow in another owner (evil/shared) not read") {
		t.Fatalf("%+v", fd)
	}
}

// A github-script step that runs npm may install: lockfile evidence is kept (POSSIBLE: the strict
// install check does not read exec arguments) though the log shows no install.
func TestScanGithubScriptInstallKeepsLockfile(t *testing.T) {
	f := fixture()
	f.Jobs[1] = []source.Job{{ID: 10, Name: "gs"}}
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  gs:\n    runs-on: x\n    steps:\n"+
		"      - uses: actions/github-script@v7\n        with:\n          script: await exec.exec('npm', ['ci'])\n"))
	delete(f.Logs, 10)
	if fd := scanOne(t, f, npmOnly); fd.Status != model.Possible {
		t.Fatalf("%+v", fd)
	}
}

// Without the workflow file run-time installs cannot be read: a clean lockfile is not CLEAN.
func TestScanWorkflowUnavailableRuntimeInstallsUnchecked(t *testing.T) {
	f := fixture()
	f.Jobs[1] = []source.Job{{ID: 10, Name: "build"}}
	f.Runs["o/a"][0].Path = ".github/workflows/gone.yml"
	f.AddFile("o/a", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{}}`))
	f.Logs[10] = "2026-03-31T01:00:00Z ##[group]Run npx -y axios@latest\n"
	fd := scanOne(t, f, npmOnly)
	if fd.Status != model.Unchecked || !hasNote(fd, "workflow file unavailable (not found in the commit tree): run-time installs not checked") {
		t.Fatalf("%+v", fd)
	}
	// a dynamic workflow (dependabot, CodeQL) has no file to read: no note
	f.Runs["o/a"][0].Path = "dynamic/dependabot"
	if res, err := Run(context.Background(), f, npmOnly, Options{Repos: []string{"o/a"}}); err != nil || len(res.Findings) != 0 {
		t.Fatalf("%v %+v", err, res.Findings)
	}
}

// An unpinned call may install anything: with npm packages in the incident the job is UNCHECKED.
func TestScanUnpinnedCallWithNPMIsUnchecked(t *testing.T) {
	f := callFixture("o/shared/.github/workflows/deploy.yml@main", "deploy / release")
	f.AddFile("o/a", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{}}`))
	fd := scanOne(t, f, npmOnly)
	if fd.Status != model.Unchecked || !hasNote(fd, "is not pinned to a SHA — not read") {
		t.Fatalf("%+v", fd)
	}
}

// A job whose log shows no package install is not UNCHECKED for a package.json without a lockfile.
func TestScanNoLockfileWithoutInstallInLog(t *testing.T) {
	rust := func(log, lock string) *sourcetest.Fake {
		f := sourcetest.New()
		f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
		f.Jobs[1] = []source.Job{{ID: 10, Name: "rust"}}
		f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  rust:\n    runs-on: x\n    steps:\n"+
			"      - uses: actions/checkout@v4\n      - uses: dtolnay/rust-toolchain@stable\n      - run: cargo build\n"))
		f.AddFile("o/a", "s1", "bindings/node/package.json", []byte(`{"dependencies":{"@napi-rs/cli":"^2"}}`))
		if lock != "" {
			f.AddFile("o/a", "s1", "package-lock.json", []byte(lock))
		}
		f.Logs[10] = log
		return f
	}
	cargo := "2026-03-31T01:00:00Z    Compiling serde v1.0.0\n2026-03-31T01:00:00Z     Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.20s\n"
	if res, err := Run(context.Background(), rust(cargo, ""), npmOnly, Options{Repos: []string{"o/a"}}); err != nil || len(res.Findings) != 0 {
		t.Fatalf("no install: %v %+v", err, res.Findings)
	}
	for _, l := range []string{"2026-03-31T01:00:00Z npm ci\n", "2026-03-31T01:00:00Z added 12 packages in 1s\n"} {
		if fd := scanOne(t, rust(cargo+l, ""), npmOnly); fd.Status != model.Unchecked || !hasNote(fd, "no lockfile for bindings/node/package.json") {
			t.Fatalf("%q: %+v", l, fd)
		}
	}
	// a lockfile pin does not count for a job whose log shows no install
	if res, err := Run(context.Background(), rust(cargo, `{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`), npmOnly, Options{Repos: []string{"o/a"}}); err != nil || len(res.Findings) != 0 {
		t.Fatalf("pinned, no install: %v %+v", err, res.Findings)
	}
}

func TestInstallLogRe(t *testing.T) {
	for line, want := range map[string]bool{
		"added 312 packages, and audited 313 packages in 4s":                true,
		"added 1 package in 1s":                                             true,
		"up to date, audited 120 packages in 900ms":                         true,
		"[command]/usr/local/bin/npm ci":                                    true,
		"npm i --no-audit":                                                  true,
		"Packages: +245":                                                    true,
		"Progress: resolved 245, reused 240, downloaded 5, added 245, done": true,
		"pnpm i --frozen-lockfile":                                          true,
		"pnpm add left-pad":                                                 true,
		"success Saved lockfile.":                                           true,
		"[1/4] Resolving packages...":                                       true,
		"[2/4] Fetching packages...":                                        true,
		"yarn install v1.22.22":                                             true,
		"➤ YN0000: ┌ Resolution step":                                       true,
		"➤ YN0000: ┌ Fetch step":                                            true,
		"➤ YN0000: ┌ Link step":                                             true,
		"245 packages installed [1.20s]":                                    true,
		"bun install v1.1.0":                                                true,
		"   Compiling serde v1.0.210":                                       false,
		"    Finished `release` profile [optimized] target(s) in 1m 02s":    false,
		"     Running unittests src/lib.rs (target/debug/deps/net-1a2b3c)":  false,
		"Downloaded 42 crates (3.1 MB) in 1.20s":                            false,
		"test result: ok. 12 passed; 0 failed; 0 ignored":                   false,
		"removed 3 packages, and audited 300 packages in 2s":                true,
		"changed 1 package in 800ms":                                        true,
		"audited 1 package in 0.5s":                                         true,
		"up to date in 412ms":                                               true,
		"npm warn config production Use `--omit=dev` instead.":              false,
	} {
		if installLogRe.MatchString(line) != want {
			t.Errorf("%q: want %v", line, want)
		}
	}
}

// Fix round 1: an unidentified job is judged by every job's installs, and a package manager
// called with suppressed output still counts as an install.
func TestScanNoLockfileSilentInstallKept(t *testing.T) {
	fx := func(job, wf, log string) *sourcetest.Fake {
		f := sourcetest.New()
		f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
		f.Jobs[1] = []source.Job{{ID: 10, Name: job}}
		f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(wf))
		f.AddFile("o/a", "s1", "package.json", []byte(`{"dependencies":{"left-pad":"^1"}}`))
		f.Logs[10] = log
		return f
	}
	cargo := "2026-03-31T01:00:00Z    Compiling serde v1.0.0\n"
	yarnWF := "on: push\njobs:\n  web:\n    runs-on: x\n    steps:\n      - run: yarn --silent\n"
	actionWF := "on: push\njobs:\n  web:\n    runs-on: x\n    steps:\n      - uses: ./.github/actions/setup\n"
	for name, f := range map[string]*sourcetest.Fake{
		"unidentified job":   fx("web (matrix 1)", yarnWF, cargo),
		"silent yarn in log": fx("web", actionWF, cargo+"2026-03-31T01:00:00Z ##[group]Run yarn --frozen-lockfile --silent\n"),
		"bun i -s in log":    fx("web", actionWF, cargo+"2026-03-31T01:00:00Z ##[group]Run bun i --silent\n"),
	} {
		if fd := scanOne(t, f, npmOnly); fd.Status != model.Unchecked {
			t.Errorf("%s: %+v", name, fd)
		}
	}
	// token and config names are not package-manager calls
	f := fx("web", actionWF, cargo+"2026-03-31T01:00:00Z   NPM_TOKEN: ***\n2026-03-31T01:00:00Z   npm_config_registry: https://r\n")
	if res, err := Run(context.Background(), f, npmOnly, Options{Repos: []string{"o/a"}}); err != nil || len(res.Findings) != 0 {
		t.Fatalf("env lines: %v %+v", err, res.Findings)
	}
}

// Item 3: a package.json outside the root workspaces is installed only by a job that names its directory.
func TestScanNonWorkspaceManifestNotInstalled(t *testing.T) {
	fx := func(steps, log string) *sourcetest.Fake {
		f := sourcetest.New()
		f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
		f.Jobs[1] = []source.Job{{ID: 10, Name: "test"}}
		f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  test:\n    runs-on: x\n    steps:\n      - uses: actions/checkout@v4\n"+steps))
		f.AddFile("o/a", "s1", "package.json", []byte(`{"private":true,"workspaces":["packages/*","apis/*"],"packageManager":"yarn@4.17.1"}`))
		f.AddFile("o/a", "s1", "yarn.lock", []byte("__metadata:\n  version: 8\n\n\"left-pad@npm:^1.0.0\":\n  version: 1.0.0\n  resolution: \"left-pad@npm:1.0.0\"\n"))
		f.AddFile("o/a", "s1", "packages/a/package.json", []byte(`{"name":"@x/a","dependencies":{"left-pad":"^1.0.0"}}`))
		f.AddFile("o/a", "s1", "examples/x/package.json", []byte(`{"dependencies":{"axios":"latest"}}`))
		f.Logs[10] = log
		return f
	}
	yarnLog := "2026-03-31T01:00:00Z ##[group]Run yarn install\n2026-03-31T01:00:00Z ➤ YN0000: ┌ Resolution step\n2026-03-31T01:00:00Z ➤ YN0000: ┌ Link step\n"
	fd := scanOne(t, fx("      - run: yarn install\n", yarnLog), npmOnly)
	if fd.Status != model.Unchecked || !hasNote(fd, "examples/x/package.json is not installed by this job as far as the workflow and log show; declared axios") {
		t.Fatalf("root install: %+v", fd)
	}
	npmLog := "2026-03-31T01:00:00Z ##[group]Run npm install\n2026-03-31T01:00:00Z added 12 packages in 1s\n"
	fd = scanOne(t, fx("      - run: npm install\n        working-directory: examples/x\n", npmLog), npmOnly)
	if fd.Status != model.Possible {
		t.Fatalf("working-directory: %+v", fd)
	}
}

// A lockfile pin is AFFECTED only for a job that installed from that lockfile (R1).
func TestScanLockfileNeedsInstall(t *testing.T) {
	fx := func(steps, lockfile, log string, logGone bool) *sourcetest.Fake {
		f := sourcetest.New()
		f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
		f.Jobs[1] = []source.Job{{ID: 10, Name: "cla"}}
		f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  cla:\n    runs-on: x\n    steps:\n"+steps))
		f.AddFile("o/a", "s1", lockfile, []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
		f.Logs[10] = log
		f.GoneLogs[10] = logGone
		return f
	}
	action := "      - uses: contributor-assistant/github-action@v2.6.1\n        env: {T: \"${{ secrets.CLA_TOKEN }}\"}\n"
	install := "2026-03-31T01:00:00Z ##[group]Run npm ci\n2026-03-31T01:00:00Z added 12 packages in 1s\n"

	// third-party action only, log read and shows no install: npm hit does not count
	res, err := Run(context.Background(), fx(action, "package-lock.json", "2026-03-31T01:00:00Z CLA ok\n", false), npmOnly, Options{Repos: []string{"o/a"}})
	if err != nil || len(res.Findings) != 0 {
		t.Fatalf("no install in log: %v %+v", err, res.Findings)
	}
	// log unavailable: the action may have installed
	fd := scanOne(t, fx(action, "package-lock.json", "", true), npmOnly)
	if fd.Status != model.Possible || !hasNote(fd, "lockfile pins a bad version; install not confirmed (log unavailable)") {
		t.Fatalf("log gone: %+v", fd)
	}
	// installed, but from another directory than the lockfile's
	fd = scanOne(t, fx("      - run: npm ci\n", "web/package-lock.json", install, false), npmOnly)
	if fd.Status != model.Possible || !hasNote(fd, "install from web not confirmed") {
		t.Fatalf("other dir: %+v", fd)
	}
	// a script may install silently; a toolchain action alone does not
	fd = scanOne(t, fx("      - run: ./build.sh\n", "package-lock.json", "2026-03-31T01:00:00Z build ok\n", false), npmOnly)
	if fd.Status != model.Possible || !hasNote(fd, "lockfile pins a bad version; job runs scripts that may install silently") {
		t.Fatalf("opaque script: %+v", fd)
	}
	rust := fx("      - uses: dtolnay/rust-toolchain@stable\n", "package-lock.json", "2026-03-31T01:00:00Z rustc 1.90.0\n", false)
	if res, err := Run(context.Background(), rust, npmOnly, Options{Repos: []string{"o/a"}}); err != nil || len(res.Findings) != 0 {
		t.Fatalf("toolchain only: %v %+v", err, res.Findings)
	}
	// a test step is no install step
	fd = scanOne(t, fx("      - run: npm test\n", "package-lock.json", "2026-03-31T01:00:00Z > jest\n", false), npmOnly)
	if fd.Status != model.Possible {
		t.Fatalf("npm test: %+v", fd)
	}
	// an unidentified job is judged by every job: a quiet log does not drop the pin
	f := fx(action, "package-lock.json", "2026-03-31T01:00:00Z CLA ok\n", false)
	f.Jobs[1][0].Name = "unknown"
	if fd := scanOne(t, f, npmOnly); fd.Status != model.Possible {
		t.Fatalf("unidentified: %+v", fd)
	}
	// a dropped pin keeps the rest: a package.json without a lockfile in a directory the job names
	f = fx("      - uses: some/action@v1\n        with: {path: web}\n", "package-lock.json", "2026-03-31T01:00:00Z ok\n", false)
	f.AddFile("o/a", "s1", "package.json", []byte(`{"workspaces":["packages/*"]}`))
	f.AddFile("o/a", "s1", "web/package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	if fd := scanOne(t, f, npmOnly); fd.Status != model.Possible || len(fd.Evidence) == 0 ||
		slices.ContainsFunc(fd.Evidence, func(e model.Evidence) bool { return strings.Contains(e.Detail, "package-lock.json at") }) {
		t.Fatalf("rest after a dropped pin: %+v", fd)
	}
	// a package manager called, but no install output and no install step
	fd = scanOne(t, fx(action, "package-lock.json", "2026-03-31T01:00:00Z npm --version\n", false), npmOnly)
	if fd.Status != model.Possible || !hasNote(fd, "package manager called, install not confirmed") {
		t.Fatalf("npm called: %+v", fd)
	}
	// the directory named only inside another word is no link
	fd = scanOne(t, fx(action, "web/package-lock.json", install+"2026-03-31T01:00:00Z webpack 5 compiled\n", false), npmOnly)
	if fd.Status != model.Possible {
		t.Fatalf("substring: %+v", fd)
	}
	// installed from the lockfile's directory
	for name, f := range map[string]*sourcetest.Fake{
		"root lockfile, log":           fx(action, "package-lock.json", install, false),
		"root lockfile, workflow step": fx("      - run: npm ci\n", "package-lock.json", "", true),
		"working-directory":            fx("      - run: npm ci\n        working-directory: web\n", "web/package-lock.json", install, false),
		"dir in log":                   fx(action, "web/package-lock.json", install+"2026-03-31T01:00:00Z   working-directory: web\n", false),
	} {
		if fd := scanOne(t, f, npmOnly); fd.Status != model.Affected {
			t.Errorf("%s: %+v", name, fd)
		}
	}
}

// Secrets of UNCHECKED jobs are listed as not verified, apart from the confirmed list (R2).
func TestScanUncheckedExposure(t *testing.T) {
	f := fixture()
	f.Trees["o/a@s1"] = f.Trees["o/a@s1"][:1] // keep only the workflow file: no npm hit
	f.GoneLogs[10] = true
	actOnly := &incident.Incident{ID: "t", Window: inc.Window, Actions: []incident.Action{{Uses: "x/y", SHAs: []string{actionSHA}}}}
	res, err := Run(context.Background(), f, actOnly, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 || res.Findings[0].Status != model.Unchecked || res.Findings[0].Exposure == nil {
		t.Fatalf("%+v", res.Findings)
	}
	if len(res.Rotation) != 0 || len(res.Unverified) != 1 || res.Unverified[0].Name != "NPM_TOKEN" {
		t.Fatalf("rotation %+v, unverified %+v", res.Rotation, res.Unverified)
	}
}

const m3Workflow = `on: push
jobs:
  build:
    name: Lint
    runs-on: ubuntu-latest
    steps: [{run: echo lint}]
  deploy:
    name: ${{ 'build' }}
    runs-on: ubuntu-latest
    steps:
      - run: npm ci
        env: {NPM_TOKEN: "${{ secrets.NPM_TOKEN }}"}
`

const scanBadLock = `{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`

const scanGoodLock = `{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.0"}}}`

var npmInc = &incident.Incident{ID: "t", Window: inc.Window,
	NPM: []incident.NPMPackage{{Name: "axios", Versions: []string{"1.14.1"}}}}

func runOne(t *testing.T, event, wf, lock, jobName string) *model.Result {
	t.Helper()
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Event: event, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
	f.Jobs[1] = []source.Job{{ID: 10, Name: jobName}}
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(wf))
	f.AddFile("o/a", "s1", "package-lock.json", []byte(lock))
	f.Logs[10] = "2026-03-31T01:00:00Z ##[group]Run npm ci\nadded 1 package in 1s\n"
	res, err := Run(context.Background(), f, npmInc, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestTemplatedNameEqualToOtherJobIDKeepsSecrets(t *testing.T) {
	res := runOne(t, "push", m3Workflow, scanBadLock, "build")
	all := append(slices.Clone(res.Rotation), res.Unverified...)
	if !slices.ContainsFunc(all, func(r model.RotationItem) bool { return r.Name == "NPM_TOKEN" }) {
		t.Errorf("NPM_TOKEN hidden: findings=%+v rotation=%+v", res.Findings, all)
	}
}

func TestPullRequestTargetIsAtLeastUnchecked(t *testing.T) {
	wf := `on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo hi
        env: {NPM_TOKEN: "${{ secrets.NPM_TOKEN }}"}
`
	for _, ev := range []string{"pull_request_target", "workflow_run"} {
		res := runOne(t, ev, wf, scanGoodLock, "build")
		if len(res.Findings) != 1 || res.Findings[0].Status != model.Unchecked {
			t.Fatalf("%s: want an UNCHECKED finding, got %+v", ev, res.Findings)
		}
		if !strings.Contains(fmt.Sprint(res.Findings[0].Evidence), "files read at head_sha (secrets, lockfile) may differ") {
			t.Errorf("%s: no head_sha note: %+v", ev, res.Findings[0].Evidence)
		}
		if !slices.ContainsFunc(res.Unverified, func(r model.RotationItem) bool { return r.Name == "NPM_TOKEN" }) {
			t.Errorf("%s: NPM_TOKEN not in unverified: %+v", ev, res.Unverified)
		}
	}
	if res := runOne(t, "push", wf, scanGoodLock, "build"); len(res.Findings) != 0 {
		t.Errorf("push: %+v", res.Findings)
	}
}

func TestPullRequestTargetPinIsOnlyPossible(t *testing.T) {
	wf := "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{run: npm ci}]\n"
	if res := runOne(t, "push", wf, scanBadLock, "build"); len(res.Findings) != 1 || res.Findings[0].Status != model.Affected {
		t.Fatalf("push control must be AFFECTED: %+v", res.Findings)
	}
	res := runOne(t, "pull_request_target", wf, scanBadLock, "build")
	if len(res.Findings) != 1 || res.Findings[0].Status != model.Possible ||
		!strings.Contains(fmt.Sprint(res.Findings[0].Evidence), "the run used the base branch") {
		t.Fatalf("want POSSIBLE with a note: %+v", res.Findings)
	}
}

// A job that cannot install still keeps its npm evidence under a base-branch event.
func TestBaseEventKeepsNPMEvidenceOfJobWithoutInstall(t *testing.T) {
	wf := "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: [{run: echo hi}]\n"
	for ev, want := range map[string]int{"push": 0, "pull_request_target": 1} {
		f := sourcetest.New()
		f.GoneLogs[10] = true
		f.Runs["o/a"] = []source.Run{{ID: 1, Event: ev, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
		f.Jobs[1] = []source.Job{{ID: 10, Name: "build"}}
		f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(wf))
		f.AddFile("o/a", "s1", "package-lock.json", []byte(scanBadLock))
		res, err := Run(context.Background(), f, npmInc, Options{Repos: []string{"o/a"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != want || want == 1 && !strings.Contains(fmt.Sprint(res.Findings[0].Evidence), "axios@1.14.1") {
			t.Errorf("%s: %+v", ev, res.Findings)
		}
	}
}

// uses: read at head_sha cannot prove an action ran: POSSIBLE under a base-branch event.
func TestBaseEventCapsUsesAtPossible(t *testing.T) {
	wf := "on: pull_request_target\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: tj-actions/changed-files@" + actionSHA + "\n"
	actInc := &incident.Incident{ID: "t", Window: inc.Window, Actions: []incident.Action{{Uses: "tj-actions/changed-files", SHAs: []string{actionSHA}}}}
	for ev, want := range map[string]model.Status{"push": model.Affected, "pull_request_target": model.Possible} {
		f := sourcetest.New()
		f.Runs["o/a"] = []source.Run{{ID: 1, Event: ev, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
		f.Jobs[1] = []source.Job{{ID: 10, Name: "build"}}
		f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(wf))
		res, err := Run(context.Background(), f, actInc, Options{Repos: []string{"o/a"}})
		if err != nil {
			t.Fatal(err)
		}
		if len(res.Findings) != 1 || res.Findings[0].Status < want || ev != "push" && res.Findings[0].Status > model.Unchecked && res.Findings[0].Status != want {
			t.Errorf("%s: want %v, got %+v", ev, want, res.Findings)
		}
	}
}
