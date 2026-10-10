package report

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sample() (*incident.Incident, *model.Result) {
	t0 := time.Date(2026, 3, 31, 0, 21, 0, 0, time.UTC)
	inc := &incident.Incident{ID: "axios-2026-03", Title: "axios malicious release", Window: incident.Window{Start: t0, End: t0.Add(3 * time.Hour)},
		Refs: []string{"https://osv.dev/vulnerability/MAL-2026-2307"}}
	run := model.RunRef{Repo: "o/app", RunID: 42, Workflow: ".github/workflows/ci.yml", HeadSHA: "abcdef1234567",
		RunURL: "https://github.com/o/app/actions/runs/42", CreatedAt: t0.Add(time.Hour), JobID: 7, Job: "build",
		JobURL: "https://github.com/o/app/actions/runs/42/job/7", Attempt: 2}
	res := &model.Result{IncidentID: inc.ID, Start: inc.Window.Start, End: inc.Window.End, ReposTargeted: 3, RunsScanned: 3, JobsScanned: 5,
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
		Unverified: []model.RotationItem{
			{Name: "DEPLOY_KEY", Tier: 2, Reason: "rotate", Runs: []model.RunRef{{Repo: "o/app", RunID: 43, Job: "publish"}}},
		},
		Skipped:  []model.Skip{{Repo: "o/private", Reason: "no access (HTTP 403/404)"}},
		Lookback: 7 * 24 * time.Hour,
	}
	return inc, res
}

func golden(t *testing.T, name string, got []byte) {
	path := "testdata/" + name
	if *update {
		if err := os.WriteFile(path, got, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path) //nolint:gosec // G304: fixed testdata path
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

func TestMarkdownNoInjection(t *testing.T) {
	inc, res := sample()
	evil := "[x](http://e) <img src=x onerror=1> @user o/r#1"
	inc.Title = "t\n`x`"
	inc.Refs = []string{"a](http://e)"}
	res.Findings[0].Run.Job = evil
	res.Findings[0].Run.RunURL = "https://evil.example/x"
	res.Findings[0].Evidence[0].Detail = evil
	res.Skipped[0].Reason = evil
	res.Rotation[1].Runs[0].Job = evil
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "](") && !strings.Contains(line, "](https://github.com/") && !strings.Contains(line, "`") {
			t.Fatalf("bare link: %q", line)
		}
		for _, bad := range []string{"<img", "](http://e)", "@user"} {
			// every occurrence must be inside a code span: odd number of backticks before it
			for i := strings.Index(line, bad); i >= 0; {
				if strings.Count(line[:i], "`")%2 == 0 {
					t.Fatalf("%q outside code span: %q", bad, line)
				}
				j := strings.Index(line[i+1:], bad)
				if j < 0 {
					break
				}
				i += 1 + j
			}
		}
	}
	if strings.Contains(out, "(https://evil") {
		t.Fatal("non-github run URL linked")
	}
	// table row count unchanged: header + separator + 2 findings
	n := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "| AFFECTED") || strings.HasPrefix(line, "| UNCHECKED") {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("finding rows = %d", n)
	}
}

func TestJSONEmptyAndUTC(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, &incident.Incident{ID: "x"}, &model.Result{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"findings": []`, `"rotation": []`, `"unverified_rotation": []`, `"skipped": []`} {
		if !strings.Contains(b.String(), want) {
			t.Fatalf("missing %s in\n%s", want, b.String())
		}
	}
	inc, res := sample()
	z := time.FixedZone("x", 2*3600)
	inc.Window.Start = inc.Window.Start.In(z)
	res.Start = res.Start.In(z)
	res.Findings[0].Run.CreatedAt = res.Findings[0].Run.CreatedAt.In(z)
	res.Findings[1].Evidence = nil
	b.Reset()
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "+02:00") || strings.Contains(b.String(), `"evidence": null`) {
		t.Fatalf("not normalized:\n%s", b.String())
	}
	if res.Findings[1].Evidence != nil {
		t.Fatal("caller's Result mutated")
	}
}

func TestMarkdownStripsTerminalEscapes(t *testing.T) {
	inc, res := sample()
	evil := "\x1b]0;pwned\x07\x1b[2J\u0085  \x7f"
	inc.Title = evil
	inc.Refs = []string{evil}
	res.Findings[0].Run.Job = evil
	res.Skipped[0].Repo = evil
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\x1b\x07\u0085  \x7f") {
		t.Fatalf("control characters leaked: %q", b.String())
	}
}

func TestMarkdownRetentionWarning(t *testing.T) {
	inc, res := sample()
	res.RetentionWarning = true
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "jobs scanned: 5\n\nWarning: incident window starts more than 90 days ago; GitHub may have deleted runs — absence of runs is not evidence.\n") {
		t.Fatal(b.String())
	}
}

func TestCleanDropsBidi(t *testing.T) {
	in := "a\u200eb\u200fc\u202ad\u202ee\u2066f\u2069g\u2067h\u2068i"
	if got := Clean(in); got != "abcdefghi" {
		t.Fatalf("%q", got)
	}
}

func TestCleanDropsInvisibleFillers(t *testing.T) {
	in := "a\u115fb\u1160c\u3164d\uffa0e\u2800f\ufe0fg\U000e0100h"
	if got := Clean(in); got != "abcdefgh" {
		t.Fatalf("%q", got)
	}
}

func TestJSONEscapesC1(t *testing.T) {
	inc, res := sample()
	res.Findings[0].Evidence[0].Detail = "x\u0085y\u009bz"
	var b bytes.Buffer
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\u0085\u009b") || !strings.Contains(b.String(), `x\u0085y\u009bz`) {
		t.Fatalf("C1 not escaped: %q", b.String())
	}
	var v any
	if err := json.Unmarshal(b.Bytes(), &v); err != nil {
		t.Fatal(err)
	}
}

func TestMarkdownAttempt(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "| [42](https://github.com/o/app/actions/runs/42) attempt 2 |") {
		t.Fatal(b.String())
	}
	res.Findings[0].Run.Attempt = 1
	for i := range res.Rotation {
		res.Rotation[i].Runs[0].Attempt = 1
	}
	b.Reset()
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "attempt") {
		t.Fatalf("first attempt must not be labelled:\n%s", b.String())
	}
}

func TestJSONEscapesBidiRoundTrip(t *testing.T) {
	inc, res := sample()
	in := "привет\u0085a\u200eb\u200fc\u202ad\u202ee\u2066f\u2069g"
	res.Findings[0].Evidence[0].Detail = in
	var b bytes.Buffer
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\u0085\u200e\u200f\u202a\u202e\u2066\u2069") || !strings.Contains(b.String(), `\u200e`) {
		t.Fatalf("not escaped: %q", b.String())
	}
	var v struct {
		Findings []struct{ Evidence []model.Evidence } `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &v); err != nil || v.Findings[0].Evidence[0].Detail != in {
		t.Fatalf("%v %q", err, v.Findings[0].Evidence[0].Detail)
	}
	b.Reset()
	res.Findings[0].Evidence[0].Detail = "привет\u0085"
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b.Bytes(), &v); err != nil || v.Findings[0].Evidence[0].Detail != "привет\u0085" {
		t.Fatalf("%v %q", err, v.Findings[0].Evidence[0].Detail)
	}
}

func TestSeenInAttempt(t *testing.T) {
	inc, res := sample()
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "`o/app#42 build attempt 2`") {
		t.Fatal(b.String())
	}
}

// Every format character (zero-width, BOM, soft hyphen, ...) and the tag block U+E0000–E007F are
// dropped from terminal text and escaped in JSON, so hidden text never reaches a reader.
func TestFormatCharsAndTags(t *testing.T) {
	in := "a\u200bb\ufeffc\u00add\u2060e\U000E0041f\U000E0000g\U000E007Fh\u061ci\tj\nk"
	if got := Clean(in); got != "abcdefghij k" {
		t.Fatalf("Clean: %q", got)
	}
	inc, res := sample()
	res.Findings[0].Evidence[0].Detail = in
	var b bytes.Buffer
	if err := JSON(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\u200b\ufeff\u00ad\u2060\U000E0041\U000E0000\U000E007F\u061c") || !strings.Contains(b.String(), `e\udb40\udc41f`) {
		t.Fatalf("not escaped: %q", b.String())
	}
	var v struct {
		Findings []struct{ Evidence []model.Evidence } `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &v); err != nil || v.Findings[0].Evidence[0].Detail != in {
		t.Fatalf("%v %q", err, v.Findings[0].Evidence[0].Detail)
	}
}

func TestMarkdownOnlyUnverified(t *testing.T) {
	inc, res := sample()
	res.Rotation, res.Findings = nil, res.Findings[:1] // no job with unknown secrets
	var b bytes.Buffer
	if err := Markdown(&b, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "## Rotate first\n\nNothing confirmed to rotate; 1 secret in jobs that could not be checked.\n\n"+
		"## Not verified — could not rule out exposure\n\n| # |") || strings.Contains(b.String(), "Nothing to rotate") {
		t.Fatal(b.String())
	}
}

// An incomplete scan with findings still shows them and what could not be verified; only the
// lines that read as "all clear" are dropped.
func TestIncompleteKeepsFindings(t *testing.T) {
	inc, res := sample()
	res.Incomplete, res.Error, res.Rotation = true, "o/b: HTTP 401", nil
	for name, render := range map[string]func(*bytes.Buffer) error{
		"text": func(b *bytes.Buffer) error { return Text(b, inc, res, false) },
		"md":   func(b *bytes.Buffer) error { return Markdown(b, inc, res) },
	} {
		var b bytes.Buffer
		if err := render(&b); err != nil {
			t.Fatal(err)
		}
		s := b.String()
		if !strings.HasPrefix(s, "Scan incomplete: o/b: HTTP 401\n") || !strings.Contains(s, unverifiedTitle) ||
			!strings.Contains(s, "DEPLOY_KEY") || !strings.Contains(s, "axios@1.14.1 in package-lock.json") || strings.Contains(s, "Nothing") {
			t.Errorf("%s:\n%s", name, s)
		}
	}
}

// Jobs whose secrets are unknown are never summed up as "Nothing to rotate.".
func TestSecretsUnknownReplacesNothingToRotate(t *testing.T) {
	inc, res := sample() // o/old#9: jobs unavailable, no exposure
	res.Rotation, res.Unverified = nil, nil
	const line = "Secrets unknown for 1 job (workflow file, job list or run not available); review them manually: "
	var txt, md, js bytes.Buffer
	if err := Text(&txt, inc, res, false); err != nil {
		t.Fatal(err)
	}
	if err := Markdown(&md, inc, res); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&js, inc, res); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(txt.String(), "  "+line+"o/old#9.\n") || strings.Contains(txt.String(), "Nothing to rotate") {
		t.Errorf("text:\n%s", txt.String())
	}
	if !strings.Contains(md.String(), line+"`o/old#9`.\n") || strings.Contains(md.String(), "Nothing to rotate") {
		t.Errorf("md:\n%s", md.String())
	}
	if !strings.Contains(js.String(), `"secrets_unknown_jobs": 1`) {
		t.Errorf("json:\n%s", js.String())
	}
	// an exposure whose secrets are unknown counts too; a known one does not
	res.Findings[1].Exposure = &model.Exposure{SecretsUnknown: true}
	res.Findings = append(res.Findings, model.Finding{Status: model.Unchecked, Exposure: &model.Exposure{}})
	if n := len(secretsUnknown(res)); n != 1 {
		t.Errorf("got %d", n)
	}
}
