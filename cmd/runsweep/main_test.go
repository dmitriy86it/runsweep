package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"errors"

	"github.com/dmitriy86it/runsweep/internal/source"
	"github.com/dmitriy86it/runsweep/internal/source/sourcetest"
)

func fakeDeps(f *sourcetest.Fake) deps {
	return deps{
		newSource: func(string) (source.Source, error) { return f, nil },
		token:     func() (string, error) { return "tok", nil },
	}
}

func TestIncidentsCommand(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"incidents"}, &out, &errb, fakeDeps(sourcetest.New())); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "axios-2026-03") {
		t.Fatal(out.String())
	}
}

func TestScanExitCodes(t *testing.T) {
	dir := t.TempDir()
	inc := filepath.Join(dir, "i.yaml")
	if err := os.WriteFile(inc, []byte("id: x\ntitle: x\nwindow: {start: 2026-03-31T00:00:00Z, end: 2026-03-31T02:00:00Z}\nnpm: [{name: axios, versions: [\"1.14.1\"]}]\nrefs: [x]\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: "missing.yml", HeadSHA: "s", CreatedAt: time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)}}
	f.Jobs[1] = []source.Job{{ID: 2, Name: "build"}}
	f.AddFile("o/a", "s", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))

	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", inc, "--repo", "o/a"}, &out, &errb, fakeDeps(f)); code != 1 {
		t.Fatalf("affected must exit 1, got %d: %s", code, errb.String())
	}
	if !strings.Contains(out.String(), "AFFECTED") {
		t.Fatal(out.String())
	}

	out.Reset()
	if code := run([]string{"scan", "--incident", inc, "--repo", "o/clean"}, &out, &errb, fakeDeps(f)); code != 0 {
		t.Fatalf("clean must exit 0, got %d", code)
	}
	if code := run([]string{"scan", "--incident", inc, "--repo", "o/a", "--format", "json"}, &out, &errb, fakeDeps(f)); code != 1 {
		t.Fatal("json format")
	}
}

func TestScanUsageErrors(t *testing.T) {
	var out, errb bytes.Buffer
	d := fakeDeps(sourcetest.New())
	for _, args := range [][]string{
		{"scan", "--incident", "axios-2026-03"},                                   // no --repo/--org
		{"scan", "--incident", "nope", "--repo", "o/a"},                           // unknown incident
		{"scan", "--incident", "axios-2026-03", "--repo", "o/a", "--format", "x"}, // bad format
		{"scan", "--incident", "axios-2026-03", "--repo", "o/a", "--since", "yesterday"},
	} {
		if code := run(args, &out, &errb, d); code != 2 {
			t.Errorf("%v: want exit 2, got %d", args, code)
		}
	}
}

const incYAML = "id: x\ntitle: x\nwindow: {start: 2026-03-31T00:00:00Z, end: 2026-03-31T02:00:00Z}\nnpm: [{name: axios, versions: [\"1.14.1\"]}]\nrefs: [x]\n"

func writeInc(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "i.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func noNetDeps(t *testing.T) deps {
	return deps{
		newSource: func(string) (source.Source, error) { t.Fatal("newSource called"); return nil, nil },
		token:     func() (string, error) { t.Fatal("token called"); return "", nil },
	}
}

func TestBadInputNeverTouchesNetwork(t *testing.T) {
	good := writeInc(t, incYAML)
	bad := writeInc(t, "id: [unclosed\n")
	for _, args := range [][]string{
		{"scan", "--incident", good, "--repo", "../x"},
		{"scan", "--incident", good, "--repo", "a/b/c"},
		{"scan", "--incident", good, "--repo", "a"},
		{"scan", "--incident", good, "--repo", "a/.."},
		{"scan", "--incident", good, "--org", "a/b"},
		{"scan", "--incident", "nope", "--repo", "o/a"},
		{"scan", "--incident", bad, "--repo", "o/a"},
		{"scan", "--incident", good, "--repo", "o/a", "--since", "yesterday"},
		{"scan", "--incident", good, "--repo", "o/a", "--bogus"},
		{"scan", "--repo", "o/a"},
		{"scan", "--incident", good, "--repo", "o/a", "--lookback", "31d"},
		{"scan", "--incident", good, "--repo", "o/a", "--lookback", "-1h"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb, noNetDeps(t)); code != 2 {
			t.Errorf("%v: want 2, got %d", args, code)
		}
	}
}

func TestTokenFailure(t *testing.T) {
	d := deps{token: func() (string, error) { return "", errors.New("no token") }}
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", writeInc(t, incYAML), "--repo", "o/a"}, &out, &errb, d); code != 2 {
		t.Fatalf("got %d", code)
	}
}

func TestPossibleOnlyExitsOne(t *testing.T) {
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: "missing.yml", HeadSHA: "s", CreatedAt: time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)}}
	f.Jobs[1] = []source.Job{{ID: 2, Name: "build"}}
	f.AddFile("o/a", "s", "package.json", []byte(`{"dependencies":{"axios":"^1.14.0"}}`))
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", writeInc(t, incYAML), "--repo", "o/a"}, &out, &errb, fakeDeps(f)); code != 1 {
		t.Fatalf("got %d: %s%s", code, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "POSSIBLE") || strings.Contains(out.String(), "AFFECTED: 1") {
		t.Fatal(out.String())
	}
}

func TestJSONStdoutIsPureJSON(t *testing.T) {
	var out, errb bytes.Buffer
	f := sourcetest.New()
	if code := run([]string{"scan", "--incident", writeInc(t, incYAML), "--repo", "o/a", "--format", "json"}, &out, &errb, fakeDeps(f)); code != 0 {
		t.Fatalf("got %d: %s", code, errb.String())
	}
	var v any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON: %v\n%s", err, out.String())
	}
}

func TestSkippedWarningAndAllSkipped(t *testing.T) {
	inc := writeInc(t, incYAML)
	f := sourcetest.New()
	f.NoAccess["o/a"] = true
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", inc, "--repo", "o/a", "--repo", "o/b"}, &out, &errb, fakeDeps(f)); code != 0 {
		t.Fatalf("partial skip: got %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "warning: 1 repository skipped (see report)") {
		t.Fatal(errb.String())
	}

	f.NoAccess["o/b"] = true
	out.Reset()
	errb.Reset()
	if code := run([]string{"scan", "--incident", inc, "--repo", "o/a", "--repo", "o/b"}, &out, &errb, fakeDeps(f)); code != 2 {
		t.Fatalf("all skipped: got %d", code)
	}
	if !strings.Contains(errb.String(), "no repository could be scanned") || out.Len() == 0 {
		t.Fatalf("stderr=%q stdout=%q", errb.String(), out.String())
	}
}

type cancelSrc struct{ *sourcetest.Fake }

func (cancelSrc) ListRuns(context.Context, string, time.Time, time.Time) ([]source.Run, error) {
	return nil, context.Canceled
}

func TestInterrupted(t *testing.T) {
	d := deps{
		newSource: func(string) (source.Source, error) { return cancelSrc{sourcetest.New()}, nil },
		token:     func() (string, error) { return "tok", nil },
	}
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", writeInc(t, incYAML), "--repo", "o/a"}, &out, &errb, d); code != 2 {
		t.Fatalf("got %d", code)
	}
	if !strings.Contains(errb.String(), "interrupted") {
		t.Fatal(errb.String())
	}
}

func TestAllSkippedWithOrgOverlap(t *testing.T) {
	f := sourcetest.New()
	f.Orgs["o"] = []string{"o/a"}
	f.NoAccess["o/a"] = true
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", writeInc(t, incYAML), "--repo", "o/a", "--org", "o"}, &out, &errb, fakeDeps(f)); code != 2 {
		t.Fatalf("got %d: %s", code, errb.String())
	}
}

func TestEmptyOrgExitsTwo(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", writeInc(t, incYAML), "--org", "o"}, &out, &errb, fakeDeps(sourcetest.New())); code != 2 {
		t.Fatalf("got %d", code)
	}
	if !strings.Contains(errb.String(), "no repositories to scan") || out.Len() == 0 {
		t.Fatalf("stderr=%q stdout=%q", errb.String(), out.String())
	}
}

func TestNoTerminalEscapesInOutput(t *testing.T) {
	evil := "\x1b]0;pwned\x07\x1b[2J"
	f := sourcetest.New()
	f.Orgs["o"] = []string{"o/a" + evil}
	f.Runs["o/a"+evil] = []source.Run{{ID: 1, Path: "missing.yml", HeadSHA: "s", CreatedAt: time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)}}
	f.Jobs[1] = []source.Job{{ID: 2, Name: "build" + evil}}
	f.AddFile("o/a"+evil, "s", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", writeInc(t, incYAML), "--org", "o"}, &out, &errb, fakeDeps(f)); code != 1 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "o/a]0;pwned") {
		t.Fatalf("progress line missing: %q", errb.String())
	}
	if strings.ContainsAny(out.String()+errb.String(), "\x1b\x07") {
		t.Fatalf("escape leaked:\nstdout %q\nstderr %q", out.String(), errb.String())
	}
}

func TestScanWarnings(t *testing.T) {
	const retention = "warning: incident window starts more than 90 days ago; GitHub may have deleted runs — absence of runs is not evidence"
	// old window, one UNCHECKED job (git tree truncated, no lockfile seen)
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: "missing.yml", HeadSHA: "s", CreatedAt: time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)}}
	f.Jobs[1] = []source.Job{{ID: 2, Name: "build"}}
	f.Truncated["o/a@s"] = true
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", writeInc(t, incYAML), "--repo", "o/a"}, &out, &errb, fakeDeps(f)); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	for _, want := range []string{retention, "warning: 1 jobs could not be checked (UNCHECKED)"} {
		if !strings.Contains(errb.String(), want) {
			t.Errorf("stderr lacks %q:\n%s", want, errb.String())
		}
	}
	if !strings.Contains(out.String(), "absence of runs is not evidence") || strings.Contains(errb.String(), "no workflow runs") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", out.String(), errb.String())
	}

	// recent window, no runs
	now := time.Now().UTC()
	recent := fmt.Sprintf("id: x\nwindow: {start: %s, end: %s}\nnpm: [{name: axios, versions: [\"1.14.1\"]}]\n",
		now.Add(-48*time.Hour).Format(time.RFC3339), now.Add(-24*time.Hour).Format(time.RFC3339))
	out.Reset()
	errb.Reset()
	if code := run([]string{"scan", "--incident", writeInc(t, recent), "--repo", "o/a"}, &out, &errb, fakeDeps(f)); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "warning: no workflow runs in the window") ||
		strings.Contains(errb.String()+out.String(), "absence of runs") || strings.Contains(errb.String(), "UNCHECKED") {
		t.Errorf("stdout:\n%s\nstderr:\n%s", out.String(), errb.String())
	}
}

func TestRetentionByWindowStart(t *testing.T) {
	now := time.Now().UTC()
	body := fmt.Sprintf("id: x\nwindow: {start: %s, end: %s}\nnpm: [{name: axios, versions: [\"1.14.1\"]}]\n",
		now.Add(-100*24*time.Hour).Format(time.RFC3339), now.Add(-24*time.Hour).Format(time.RFC3339))
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", writeInc(t, body), "--repo", "o/a"}, &out, &errb, fakeDeps(sourcetest.New())); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "incident window starts more than 90 days ago") {
		t.Fatalf("window started 100 days ago, ended yesterday: want retention warning\n%s", errb.String())
	}
}

func TestParseLookback(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "36h": 36 * time.Hour, "0": 0, "0d": 0, "30d": 30 * 24 * time.Hour, "720h": 720 * time.Hour} {
		if got, err := parseLookback(in); err != nil || got != want {
			t.Errorf("%q: got %v %v, want %v", in, got, err, want)
		}
	}
	for _, in := range []string{"31d", "721h", "-1d", "-1h", "d", "1.5d", "7days", "", "99999999999999d"} {
		if _, err := parseLookback(in); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
}

func TestLookbackFindsReRun(t *testing.T) {
	f := sourcetest.New()
	created := time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC) // two days before the window
	inWindow := time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: "missing.yml", HeadSHA: "s", CreatedAt: created, StartedAt: inWindow, UpdatedAt: inWindow, Attempt: 2}}
	f.Jobs[1] = []source.Job{{ID: 2, Name: "build", Attempt: 2, StartedAt: inWindow}}
	f.AddFile("o/a", "s", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	inc := writeInc(t, incYAML)
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", inc, "--repo", "o/a"}, &out, &errb, fakeDeps(f)); code != 1 {
		t.Fatalf("default lookback must find the re-run: code %d\n%s%s", code, out.String(), errb.String())
	}
	out.Reset()
	if code := run([]string{"scan", "--incident", inc, "--repo", "o/a", "--lookback", "0"}, &out, &errb, fakeDeps(f)); code != 0 {
		t.Fatalf("--lookback 0: code %d\n%s", code, out.String())
	}
}
