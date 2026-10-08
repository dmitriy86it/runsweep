package scan

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
	"github.com/dmitriy86it/runsweep/internal/source"
	"github.com/dmitriy86it/runsweep/internal/source/sourcetest"
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
		res.Findings[1].Status != model.Unchecked || res.Findings[1].Run.Job != "lint" || !hasNote(res.Findings[1], "job log unavailable") {
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
		t.Fatalf("without a workflow every job of an npm-affected run is AFFECTED: %+v", res.Findings)
	}
}

// errSrc injects errors the Fake cannot produce.
type errSrc struct {
	*sourcetest.Fake
	logErr  map[int64]error
	treeErr error
	blobErr map[string]error // blob SHA -> error
}

func (s errSrc) Blob(ctx context.Context, repo, sha string) ([]byte, error) {
	if err := s.blobErr[sha]; err != nil {
		return nil, err
	}
	return s.Fake.Blob(ctx, repo, sha)
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
	if _, err := Run(context.Background(), src, inc, Options{Repos: []string{"o/a"}}); err == nil {
		t.Fatal("want error")
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
	f.Logs[10], f.Logs[11], f.Logs[12] = "", "", ""
	f.Logs[13] = "2026-03-31T01:00:00Z added 312 packages in 4s\n"
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
	f := callFixture("org/shared/.github/workflows/deploy.yml@"+pinned, "deploy / release")
	f.AddFile("org/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
	if fd := scanOne(t, f, npmOnly); !hasRole(fd) {
		t.Fatalf("callee must be read from org/shared@%s: %+v", pinned, fd.Exposure)
	}
}

func TestScanReusableWorkflowByTagNotRead(t *testing.T) {
	f := callFixture("org/shared/.github/workflows/deploy.yml@v1", "deploy / release")
	f.AddFile("org/shared", "v1", ".github/workflows/deploy.yml", []byte(deployYAML)) // must not be read
	fd := scanOne(t, f, npmOnly)
	if fd.Status != model.Affected || hasRole(fd) || !fd.Exposure.InheritAll ||
		!hasNote(fd, "called workflow org/shared/.github/workflows/deploy.yml@v1 is not pinned to a SHA — not read") {
		t.Fatalf("%+v %+v", fd, fd.Exposure)
	}
}

func TestScanNestedReusableWorkflows(t *testing.T) {
	f := callFixture("./.github/workflows/mid.yml", "deploy / inner / release")
	f.AddFile("o/a", "s1", ".github/workflows/mid.yml", []byte("on: workflow_call\njobs:\n  inner:\n    uses: org/shared/.github/workflows/deploy.yml@"+pinned+"\n    secrets: inherit\n"))
	f.AddFile("org/shared", pinned, ".github/workflows/deploy.yml", []byte(deployYAML))
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
	if fd := scanOne(t, f, npmOnly); !hasNote(fd, "nested more than 4 levels deep") {
		t.Fatalf("%+v", fd)
	}
}

func TestScanUnidentifiedCalledJobKeepsEnvironmentSecrets(t *testing.T) {
	f := callFixture("./.github/workflows/deploy.yml", "deploy / nope")
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte("on: push\njobs:\n  deploy:\n    uses: ./.github/workflows/deploy.yml\n"))
	f.AddFile("o/a", "s1", ".github/workflows/deploy.yml", []byte("on: workflow_call\njobs:\n  a:\n    environment: prod\n    runs-on: x\n    steps: [{run: npm ci, env: {T: \"${{ secrets.PROD_TOKEN }}\"}}]\n"))
	if fd := scanOne(t, f, npmOnly); fd.Exposure.JobMatched || !slices.Contains(fd.Exposure.Secrets, "PROD_TOKEN") {
		t.Fatalf("%+v", fd.Exposure)
	}
}
