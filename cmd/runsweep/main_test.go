package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	if err := os.WriteFile(inc, []byte("id: x\ntitle: x\nwindow: {start: 2026-03-31T00:00:00Z, end: 2026-03-31T02:00:00Z}\nnpm: [{name: axios, versions: [\"1.14.1\"]}]\nrefs: [x]\n"), 0o644); err != nil {
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
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
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
