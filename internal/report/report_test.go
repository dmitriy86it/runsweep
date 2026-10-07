package report

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sample() (*incident.Incident, *model.Result) {
	t0 := time.Date(2026, 3, 31, 0, 21, 0, 0, time.UTC)
	inc := &incident.Incident{ID: "axios-2026-03", Title: "axios malicious release", Window: incident.Window{Start: t0, End: t0.Add(3 * time.Hour)},
		Refs: []string{"https://osv.dev/vulnerability/MAL-2026-2307"}}
	run := model.RunRef{Repo: "o/app", RunID: 42, Workflow: ".github/workflows/ci.yml", HeadSHA: "abcdef1234567",
		RunURL: "https://github.com/o/app/actions/runs/42", CreatedAt: t0.Add(time.Hour), JobID: 7, Job: "build",
		JobURL: "https://github.com/o/app/actions/runs/42/job/7"}
	res := &model.Result{IncidentID: inc.ID, Start: inc.Window.Start, End: inc.Window.End, RunsScanned: 3, JobsScanned: 5,
		Findings: []model.Finding{
			{Run: run, Status: model.Affected, Evidence: []model.Evidence{{Kind: "npm", Detail: "axios@1.14.1 in package-lock.json at abcdef1"}},
				Exposure: &model.Exposure{Secrets: []string{"NPM_TOKEN"}, IDTokenWrite: true, JobMatched: true}},
			// run-level finding: jobs list unavailable, no job name
			{Run: model.RunRef{Repo: "o/old", RunID: 9, Workflow: ".github/workflows/ci.yml"}, Status: model.Unchecked,
				Evidence: []model.Evidence{{Kind: "note", Detail: "jobs unavailable: deleted by GitHub retention (HTTP 410)"}}},
		},
		Rotation: []model.RotationItem{
			{Name: "OIDC token (id-token: write)", Tier: 1, Reason: "review cloud roles", Runs: []model.RunRef{run}},
			{Name: "NPM_TOKEN", Tier: 2, Reason: "rotate", Runs: []model.RunRef{run}},
		},
		Skipped: []model.Skip{{Repo: "o/private", Reason: "no access (HTTP 403/404)"}},
	}
	return inc, res
}

func golden(t *testing.T, name string, got []byte) {
	path := "testdata/" + name
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s mismatch; run `go test ./internal/report -update` and review the diff\n%s", name, got)
	}
}

func TestMarkdown(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.golden.md", b.Bytes())
}

func TestJSON(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	golden(t, "report.golden.json", b.Bytes())
}

func TestMarkdownEscapesCells(t *testing.T) {
	inc, res := sample()
	evil := "a|b\n| X | injected |\r\n`c`"
	res.Findings[0].Run.Job = evil
	res.Findings[0].Evidence[0].Detail = evil
	res.Rotation[1].Name = evil
	res.Rotation[1].Runs[0].Job = evil
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "injected") {
			if !strings.HasPrefix(line, "| ") || strings.Contains(line, "\r") || !strings.Contains(line, `a\|b \| X \| injected`) {
				t.Fatalf("unescaped row: %q", line)
			}
		}
	}
	if strings.Contains(out, "\r") || strings.Contains(out, "`c`") {
		t.Fatalf("CR or backtick leaked:\n%s", out)
	}
	if strings.Contains(out, "\n| X |") {
		t.Fatalf("row injected:\n%s", out)
	}
}
