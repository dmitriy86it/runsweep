package actions

import (
	"os"
	"strings"
	"testing"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
)

const sha = "0e58ed8671d6b60d0890c21b07f8835ace038e67"

var bad = []incident.Action{{Uses: "tj-actions/changed-files", SHAs: []string{sha}}}

func TestParseDownloadsRealLog(t *testing.T) {
	b, err := os.ReadFile("testdata/job.log")
	if err != nil {
		t.Fatal(err)
	}
	ds := ParseDownloads(string(b))
	if len(ds) == 0 || len(ds[0].SHA) != 40 || ds[0].Uses == "" {
		t.Fatalf("%+v", ds)
	}
}

func TestMatchLog(t *testing.T) {
	log := "2025-03-14T18:01:02.1234567Z Download action repository 'tj-actions/changed-files@v45' (SHA:" + sha + ")\n" +
		"2025-03-14T18:01:02.2Z Download action repository 'actions/checkout@v4' (SHA:11bd71901bbe5b1630ceea73d27597364c9af683)\n"
	st, ev := MatchLog(log, bad)
	if st != model.Affected || len(ev) != 1 {
		t.Fatalf("%v %+v", st, ev)
	}
	st, _ = MatchLog("2025-03-14T18:01:02Z Download action repository 'TJ-Actions/Changed-Files/sub@v45' (SHA:"+sha+")", bad)
	if st != model.Affected {
		t.Fatal("owner/repo match must be case-insensitive and ignore subpaths")
	}
	if st, _ := MatchLog("nothing here", bad); st != model.Clean {
		t.Fatal(st)
	}
}

func TestMatchUses(t *testing.T) {
	cases := map[string]model.Status{
		"tj-actions/changed-files@v45":               model.Possible, // mutable ref, log gone
		"tj-actions/changed-files@" + sha:            model.Affected,
		"tj-actions/changed-files@" + sha[:39] + "f": model.Clean, // pinned to another SHA
		"actions/checkout@v4":                        model.Clean,
		"./.github/actions/local":                    model.Clean,
		"docker://alpine:3":                          model.Clean,
	}
	for uses, want := range cases {
		if st, _ := MatchUses([]string{uses}, bad); st != want {
			t.Errorf("%s: got %v want %v", uses, st, want)
		}
	}
}

func TestMatchCallsWording(t *testing.T) {
	call := "tj-actions/changed-files/.github/workflows/x.yml@" + sha
	st, ev := MatchCalls([]string{call, "tj-actions/changed-files/.github/workflows/x.yml@v1"}, bad)
	if st != model.Affected || len(ev) != 2 || ev[0].Detail != "reusable workflow "+call+" at compromised SHA" ||
		strings.Contains(ev[0].Detail+ev[1].Detail, "log unavailable") {
		t.Fatalf("%v %+v", st, ev)
	}
}

func TestMatchLogSHAOnce(t *testing.T) {
	_, ev := MatchLog("2025-03-14T18:01:02Z Download action repository 'tj-actions/changed-files@"+sha+"' (SHA:"+sha+")\n"+
		"2025-03-14T18:01:02Z Download action repository 'tj-actions/changed-files@v45' (SHA:"+sha+")\n", bad)
	if len(ev) != 2 || ev[0].Detail != "job log: downloaded tj-actions/changed-files@"+sha ||
		ev[1].Detail != "job log: downloaded tj-actions/changed-files@v45 (SHA "+sha+")" {
		t.Fatalf("%+v", ev)
	}
}
