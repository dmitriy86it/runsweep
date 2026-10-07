package scan

import (
	"context"
	"errors"
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
