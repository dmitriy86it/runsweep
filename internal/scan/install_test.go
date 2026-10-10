package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
	"github.com/runsweep/runsweep/internal/source"
	"github.com/runsweep/runsweep/internal/source/sourcetest"
)

var axiosInc = &incident.Incident{ID: "t", Window: inc.Window,
	NPM: []incident.NPMPackage{{Name: "axios", Versions: []string{"1.14.1"}}}}

const axiosLock = `{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`

// oneJob scans one run of one job "build" whose workflow is wf, with the given files at the root.
func oneJob(t *testing.T, wf, log string, files map[string]string) model.Finding {
	t.Helper()
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: ".github/workflows/ci.yml", HeadSHA: "s1", CreatedAt: t0}}
	f.Jobs[1] = []source.Job{{ID: 10, Name: "build"}}
	f.AddFile("o/a", "s1", ".github/workflows/ci.yml", []byte(wf))
	for p, c := range files {
		f.AddFile("o/a", "s1", p, []byte(c))
	}
	f.Logs[10] = log
	res, err := Run(context.Background(), f, axiosInc, Options{Repos: []string{"o/a"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("want one finding: %+v", res.Findings)
	}
	return res.Findings[0]
}

func runStep(step string) string {
	return "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    env: {PM: npm}\n    steps:\n      - uses: actions/checkout@v4\n      - run: " + step + "\n"
}

// The package manager is a shell variable and the output is silenced: never CLEAN.
func TestScanPackageManagerInVariableIsPossible(t *testing.T) {
	for name, log := range map[string]string{
		"env dump names npm": "2026-03-31T01:00:00Z ##[group]Run $PM ci --silent\n2026-03-31T01:00:00Z env:\n2026-03-31T01:00:00Z   PM: npm\n2026-03-31T01:00:00Z ##[endgroup]\n",
		"nothing in the log": "2026-03-31T01:00:00Z ##[group]Run x\n2026-03-31T01:00:00Z ##[endgroup]\n",
	} {
		fd := oneJob(t, runStep("$PM ci --silent"), log, map[string]string{"package-lock.json": axiosLock})
		if fd.Status != model.Possible {
			t.Errorf("%s: %v %+v", name, fd.Status, fd.Evidence)
		}
	}
}

// npm.cmd is npm: a silenced install is still proof.
func TestScanNPMCmdInstallIsAffected(t *testing.T) {
	log := "2026-03-31T01:00:00Z ##[group]Run npm.cmd ci --silent\n2026-03-31T01:00:00Z ##[endgroup]\n"
	if fd := oneJob(t, runStep("npm.cmd ci --silent"), log, map[string]string{"package-lock.json": axiosLock}); fd.Status != model.Affected {
		t.Errorf("%v %+v", fd.Status, fd.Evidence)
	}
}

// Global installs and mentions are not installs from the lockfile, also when the runner echoes them.
func TestScanMentionsAreNotInstalls(t *testing.T) {
	for _, step := range []string{"npm i -g pnpm", "which yarn", "corepack enable yarn", `echo "run npm ci"`} {
		log := "2026-03-31T01:00:00Z ##[group]Run " + step + "\n2026-03-31T01:00:00Z \x1b[36;1m" + step + "\x1b[0m\n" +
			"2026-03-31T01:00:00Z shell: /usr/bin/bash -e {0}\n2026-03-31T01:00:00Z ##[endgroup]\n2026-03-31T01:00:00Z done\n"
		fd := oneJob(t, runStep(step), log, map[string]string{"package-lock.json": axiosLock})
		if fd.Status == model.Affected {
			t.Errorf("%q: %v %+v", step, fd.Status, fd.Evidence)
		}
	}
}

// Install output proves an install; the echo of the step does not.
func TestInstallLogIgnoresStepEcho(t *testing.T) {
	echo := "2026-03-31T01:00:00Z ##[group]Run npm ci\n2026-03-31T01:00:00Z \x1b[36;1mnpm ci\x1b[0m\n2026-03-31T01:00:00Z ##[endgroup]\n"
	if installLog(echo) {
		t.Error("echo only")
	}
	if !installLog(echo + "2026-03-31T01:00:00Z added 1 package in 1s\n") {
		t.Error("output after the echo")
	}
}

// A script's own "::group::Run tests" is not the runner's echo: install output inside it counts.
func TestInstallLogCountsOutputInsideUserGroup(t *testing.T) {
	log := "2026-03-31T01:00:00Z ##[group]Run tests\n2026-03-31T01:00:00Z added 5 packages in 2s\n2026-03-31T01:00:00Z ##[endgroup]\n"
	if !installLog(log) {
		t.Error("output inside a group")
	}
	multi := "2026-03-31T01:00:00Z ##[group]Run |\n2026-03-31T01:00:00Z \x1b[36;1mnpm i -g x\x1b[0m\n2026-03-31T01:00:00Z \x1b[36;1mnpm ci\x1b[0m\n" +
		"2026-03-31T01:00:00Z shell: /usr/bin/bash -e {0}\n2026-03-31T01:00:00Z ##[endgroup]\n"
	if installLog(multi) {
		t.Error("echo of a multi-line script")
	}
}

// A stale lockfile or package-lock=false never lowers a pin: npm ci installs the lockfile anyway.
func TestScanStaleLockfileKeepsPin(t *testing.T) {
	log := "2026-03-31T01:00:00Z ##[group]Run npm ci\n2026-03-31T01:00:00Z ##[endgroup]\n2026-03-31T01:00:00Z added 1 package in 1s\n"
	lock := `{"lockfileVersion":3,"packages":{"":{"dependencies":{"axios":"^1.14.0"}},"node_modules/axios":{"version":"1.14.1"}}}`
	fd := oneJob(t, runStep("npm ci"), log, map[string]string{"package-lock.json": lock, ".npmrc": "package-lock=false\n", "package.json": `{"dependencies":{"axios":"^1.14.0"}}`})
	if fd.Status != model.Affected || !hasNote(fd, "lockfile may not be what npm installed") {
		t.Errorf("%v %+v", fd.Status, fd.Evidence)
	}
}

// A new install form names the bad package at run time.
func TestScanPnpmInstallPackageIsPossible(t *testing.T) {
	fd := oneJob(t, runStep("pnpm i axios@latest"), "", map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.13.0"}}}`})
	if fd.Status != model.Possible {
		t.Errorf("%v %+v", fd.Status, fd.Evidence)
	}
}

// A 1 MiB run line must not stall the scan.
func TestScanHugeRunLineFinishesFast(t *testing.T) {
	wf := "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - run: \"" + strings.Repeat("npx ", 256*1024) + "\"\n"
	fd := oneJob(t, wf, "", map[string]string{"package-lock.json": `{"lockfileVersion":3,"packages":{}}`})
	if fd.Status != model.Unchecked {
		t.Errorf("%v %+v", fd.Status, fd.Evidence)
	}
}

type cancelSrc struct {
	*sourcetest.Fake
	cancel func()
	logs   int
}

func (c *cancelSrc) JobLog(ctx context.Context, repo string, id int64) (string, error) {
	c.logs++
	c.cancel()
	return c.Fake.JobLog(ctx, repo, id)
}

// Ctrl-C between two jobs of a run stops the run, and the report keeps what was judged.
func TestScanStopsBetweenJobsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	src := &cancelSrc{Fake: fixture(), cancel: cancel}
	res, err := Run(ctx, src, axiosInc, Options{Repos: []string{"o/a"}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v", err)
	}
	if src.logs != 1 || res == nil || len(res.Findings) == 0 {
		t.Errorf("logs %d res %+v", src.logs, res)
	}
}

// A silenced install step is proof from the workflow alone, with a log that shows no output.
func TestScanSilentNPMCiIsAffected(t *testing.T) {
	log := "2026-03-31T01:00:00Z ##[group]Run npm ci --silent\n2026-03-31T01:00:00Z \x1b[36;1mnpm ci --silent\x1b[0m\n2026-03-31T01:00:00Z ##[endgroup]\n"
	if fd := oneJob(t, runStep("npm ci --silent"), log, map[string]string{"package-lock.json": axiosLock}); fd.Status != model.Affected {
		t.Errorf("%v %+v", fd.Status, fd.Evidence)
	}
}

// A JS action that runs npm with silenced output still prints the toolkit's [command] line.
func TestInstallLogCommandLine(t *testing.T) {
	if !installLog("2026-03-31T01:00:00Z [command]/usr/bin/npm ci\n") || !installLog("[command]/usr/bin/npm ci\n") {
		t.Error("[command] line")
	}
	if installLog("2026-03-31T01:00:00Z echo \"[command] npm ci\"\n2026-03-31T01:00:00Z npm ci\n") {
		t.Error("mid-line or bare text")
	}
}
