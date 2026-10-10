package incident

import (
	"io/fs"
	"net/url"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
)

const valid = `
id: test-1
title: test
window: {start: 2026-03-31T00:21:00Z, end: 2026-03-31T03:30:00Z}
npm:
  - {name: axios, versions: ["1.14.1"]}
actions:
  - {uses: tj-actions/changed-files, shas: ["0123456789abcdef0123456789abcdef01234567"]}
refs: [https://example.com]
`

func TestParseValid(t *testing.T) {
	inc, err := Parse([]byte(valid))
	if err != nil {
		t.Fatal(err)
	}
	if inc.ID != "test-1" || inc.NPM[0].Versions[0] != "1.14.1" || inc.Window.End.Hour() != 3 {
		t.Fatalf("%+v", inc)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"window order":  strings.Replace(valid, "end: 2026-03-31T03:30:00Z", "end: 2026-03-30T00:00:00Z", 1),
		"short sha":     strings.Replace(valid, "0123456789abcdef0123456789abcdef01234567", "0123abc", 1),
		"no shas":       strings.Replace(valid, `shas: ["0123456789abcdef0123456789abcdef01234567"]`, "shas: []", 1),
		"unknown field": valid + "\nfoo: bar\n",
		"no targets":    "id: x\nwindow: {start: 2026-01-01T00:00:00Z, end: 2026-01-02T00:00:00Z}\n",
		"no id":         strings.Replace(valid, "id: test-1", "", 1),
		"bad yaml":      "id: [",
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestBadYAMLHasLine(t *testing.T) {
	_, err := Parse([]byte("id: x\nwindow: {start: nope, end: 2026-01-02T00:00:00Z}\n"))
	if err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("want line number, got %v", err)
	}
}

func TestPresetsLoad(t *testing.T) {
	ps, err := Presets()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) < 3 {
		t.Fatalf("want >= 3 presets, got %d", len(ps))
	}
	if _, err := Load("axios-2026-03"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("no-such-incident"); err == nil {
		t.Fatal("expected unknown incident error")
	}
}

// The axios attack dropped plain-crypto-js (OSV MAL-2026-2306); the preset must list both versions.
func TestAxiosPresetHasDropper(t *testing.T) {
	inc, err := Load("axios-2026-03")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range inc.NPM {
		if p.Name == "plain-crypto-js" && slices.Equal(p.Versions, []string{"4.2.0", "4.2.1"}) {
			return
		}
	}
	t.Fatalf("plain-crypto-js 4.2.0, 4.2.1 missing: %+v", inc.NPM)
}

// Every built-in preset: valid, named after its file, and backed by at least two
// independent sources (https refs on distinct hosts).
func TestPresetFilesRule(t *testing.T) {
	files, err := fs.Glob(presetFS, "presets/*.yaml")
	if err != nil || len(files) == 0 {
		t.Fatal(files, err)
	}
	for _, f := range files {
		b, _ := presetFS.ReadFile(f)
		inc, err := Parse(b)
		if err != nil {
			t.Errorf("%s: %v", f, err)
			continue
		}
		if want := strings.TrimSuffix(path.Base(f), ".yaml"); inc.ID != want {
			t.Errorf("%s: id %q must match the file name", f, inc.ID)
		}
		hosts := map[string]bool{}
		for _, r := range inc.Refs {
			u, err := url.Parse(r)
			if err != nil || u.Scheme != "https" || u.Host == "" || strings.ContainsAny(r, " \t") {
				t.Errorf("%s: ref %q is not an https URL", f, r)
				continue
			}
			hosts[strings.TrimPrefix(u.Hostname(), "www.")] = true
		}
		if len(hosts) < 2 {
			t.Errorf("%s: refs must name at least 2 independent sources (distinct hosts), got %v", f, inc.Refs)
		}
	}
}

func TestLoadFile(t *testing.T) {
	if _, err := Load("../../examples/drill.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestWildcardVersion(t *testing.T) {
	if _, err := Parse([]byte(strings.Replace(valid, `versions: ["1.14.1"]`, `versions: ["*"]`, 1))); err != nil {
		t.Fatalf("\"*\" alone must be valid: %v", err)
	}
	if _, err := Parse([]byte(strings.Replace(valid, `versions: ["1.14.1"]`, `versions: ["*", "1.14.1"]`, 1))); err == nil {
		t.Fatal("\"*\" mixed with versions must be rejected")
	}
}

// A bare name is only a preset id, even when a file of that name exists; a file needs a '/' or
// a .yaml/.yml suffix.
func TestLoadBareNameIsPresetOnly(t *testing.T) {
	t.Chdir(t.TempDir())
	if err := os.WriteFile("axios-2026-03", []byte("not: [an incident"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("mine", []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if inc, err := Load("axios-2026-03"); err != nil || inc.ID != "axios-2026-03" {
		t.Fatalf("%v %v", inc, err)
	}
	if _, err := Load("mine"); err == nil || !strings.Contains(err.Error(), `unknown incident "mine"`) || !strings.Contains(err.Error(), "use ./mine for a file") {
		t.Fatalf("%v", err)
	}
	if _, err := Load("./mine"); err == nil || strings.Contains(err.Error(), "unknown incident") {
		t.Fatalf("a path must be read as a file: %v", err)
	}
	if _, err := Load("MINE.YML"); err == nil || strings.Contains(err.Error(), "unknown incident") {
		t.Fatalf(".YML is a file suffix too: %v", err)
	}
}
