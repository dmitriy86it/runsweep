package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
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

func TestTextEmptyAndRetention(t *testing.T) {
	var b bytes.Buffer
	res := &model.Result{RetentionWarning: true}
	if err := Text(&b, &incident.Incident{ID: "x"}, res, false); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"runsweep · x · ", "lookback 0d", "Warning: " + RetentionNote, "  Nothing to rotate.\n", "  No affected jobs found.\n"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in\n%s", want, b.String())
		}
	}
}

func TestTextStripsTerminalEscapes(t *testing.T) {
	inc, res := sample()
	evil := "\x1b]0;pwned\x07\x1b[2J\u0085\u202e\u2066"
	inc.Title = evil
	res.Findings[0].Run.Job = evil
	res.Findings[0].Evidence[0].Detail = evil
	res.Rotation[1].Name = evil
	res.Rotation[1].Reason = evil
	res.Rotation[1].Runs[0].Repo = evil
	res.Skipped[0].Reason = evil
	var b bytes.Buffer
	if err := Text(&b, inc, res, true); err != nil {
		t.Fatal(err)
	}
	out := strings.NewReplacer("\x1b[31m", "", "\x1b[33m", "", "\x1b[34m", "", "\x1b[0m", "").Replace(b.String())
	if strings.ContainsAny(out, "\x1b\x07\u0085\u202e\u2066") {
		t.Fatalf("control characters leaked: %q", out)
	}
}
