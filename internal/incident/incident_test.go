package incident

import (
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

func TestPresetsValidAndSourced(t *testing.T) {
	ps, err := Presets()
	if err != nil {
		t.Fatal(err)
	}
	if len(ps) < 3 {
		t.Fatalf("want >= 3 presets, got %d", len(ps))
	}
	for _, p := range ps {
		if len(p.Refs) == 0 {
			t.Errorf("%s: every preset needs refs to primary sources", p.ID)
		}
	}
	if _, err := Load("axios-2026-03"); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("no-such-incident"); err == nil {
		t.Fatal("expected unknown incident error")
	}
}

func TestLoadFile(t *testing.T) {
	if _, err := Load("../../examples/drill.yaml"); err != nil {
		t.Fatal(err)
	}
}
