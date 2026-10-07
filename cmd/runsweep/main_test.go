package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	os.WriteFile(inc, []byte("id: x\ntitle: x\nwindow: {start: 2026-03-31T00:00:00Z, end: 2026-03-31T02:00:00Z}\nnpm: [{name: axios, versions: [\"1.14.1\"]}]\nrefs: [x]\n"), 0o644)

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
