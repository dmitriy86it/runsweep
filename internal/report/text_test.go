package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
)

func TestText(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Text(&b, inc, res, false); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.golden.txt", b.Bytes())
}

func TestTextColor(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Text(&b, inc, res, true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\x1b[31mAFFECTED\x1b[0m   o/app", "\x1b[34mUNCHECKED\x1b[0m  o/old", "\x1b[33mPOSSIBLE\x1b[0m 0"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in\n%q", want, b.String())
		}
	}
	if strings.Count(b.String(), "\x1b[") != 2*5 { // 3 in the counts line, 2 findings
		t.Errorf("color outside status words:\n%q", b.String())
	}
}

func TestTextNoColorNoEscapes(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Text(&b, inc, res, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "\x1b") {
		t.Errorf("escape with color=false:\n%q", b.String())
	}
}

func TestTextAttemptOneHidden(t *testing.T) {
	inc, res := sample()
	res.Findings[0].Run.Attempt = 1
	for i := range res.Rotation {
		res.Rotation[i].Runs[0].Attempt = 1
	}
	var b bytes.Buffer
	if err := Text(&b, inc, res, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "attempt") {
		t.Errorf("attempt shown for attempt 1:\n%s", b.String())
	}
}

func TestTextEmptyAndRetention(t *testing.T) {
	var b bytes.Buffer
	res := &model.Result{RetentionWarning: true}
	if err := Text(&b, &incident.Incident{ID: "x"}, res, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"runsweep · x\n", " UTC · 0 runs · 0 jobs scanned · lookback 0d", "Warning: " + RetentionNote, "  Nothing to rotate.\n", "  No affected jobs found.\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in\n%s", want, b.String())
		}
	}
}

func TestTextStripsTerminalEscapes(t *testing.T) {
	inc, res := sample()
	evil := "\x1b]0;pwned\x07\x1b[2J\u0085\u202e\u2066"
	inc.ID, inc.Title = evil, evil
	for i := range res.Findings {
		f := &res.Findings[i]
		f.Run.Repo, f.Run.Workflow, f.Run.Job = evil, evil, evil
		for j := range f.Evidence {
			f.Evidence[j].Detail = evil
		}
	}
	for i := range res.Rotation {
		it := &res.Rotation[i]
		it.Name, it.Reason = evil, evil
		for j := range it.Runs {
			it.Runs[j].Repo, it.Runs[j].Job = evil, evil
		}
	}
	res.Skipped[0].Repo, res.Skipped[0].Reason = evil, evil
	var b bytes.Buffer
	if err := Text(&b, inc, res, true); err != nil {
		t.Fatal(err)
	}
	out := strings.NewReplacer("\x1b[31m", "", "\x1b[33m", "", "\x1b[34m", "", "\x1b[0m", "").Replace(b.String())
	if strings.ContainsAny(out, "\x1b\x07\u0085\u202e\u2066") {
		t.Fatalf("control characters leaked: %q", out)
	}
}

func TestTextSingular(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, &incident.Incident{ID: "x"}, &model.Result{RunsScanned: 1, JobsScanned: 1}, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), " UTC · 1 run · 1 job scanned · ") {
		t.Fatal(b.String())
	}
}

func TestTextSeenInAttempt(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Text(&b, inc, res, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "seen in: o/app#42 build attempt 2\n") {
		t.Fatal(b.String())
	}
}

func TestTextSeenInOneRepoDropsRepo(t *testing.T) {
	inc, res := sample()
	res.ReposTargeted = 1
	var b bytes.Buffer
	if err := Text(&b, inc, res, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "seen in: #42 build attempt 2\n") || !strings.Contains(b.String(), "AFFECTED   o/app") {
		t.Fatal(b.String())
	}
	if res.Rotation[0].Runs[0].Repo != "o/app" {
		t.Fatal("Text modified the result")
	}
}

func TestRepoLevelFindingHasNoRunNumber(t *testing.T) {
	inc, res := sample()
	res.Findings = []model.Finding{{Run: model.RunRef{Repo: "o/big"}, Status: model.Unchecked,
		Evidence: []model.Evidence{{Kind: "note", Detail: "runs not scanned: API cap of 1000 runs in a window ≤1 min"}}}}
	for name, render := range map[string]func(*bytes.Buffer) error{
		"text": func(b *bytes.Buffer) error { return Text(b, inc, res, false) },
		"md":   func(b *bytes.Buffer) error { return Markdown(b, inc, res) },
	} {
		var b bytes.Buffer
		if err := render(&b); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(b.String(), "#0") || strings.Contains(b.String(), "| 0 |") {
			t.Errorf("%s: run number shown for a repo-level finding:\n%s", name, b.String())
		}
	}
}
