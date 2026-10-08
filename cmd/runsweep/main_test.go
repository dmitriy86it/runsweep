package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"errors"

	"github.com/dmitriy86it/runsweep/internal/importer"
	"github.com/dmitriy86it/runsweep/internal/incident"
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
	for _, want := range []string{retention, "warning: 1 job could not be checked (UNCHECKED)", "o/a: 1 run to check\n"} {
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

func TestNoRetentionWarningAt89Days(t *testing.T) {
	now := time.Now().UTC()
	body := fmt.Sprintf("id: x\nwindow: {start: %s, end: %s}\nnpm: [{name: axios, versions: [\"1.14.1\"]}]\n",
		now.Add(-89*24*time.Hour).Format(time.RFC3339), now.Add(-24*time.Hour).Format(time.RFC3339))
	var out, errb bytes.Buffer
	if code := run([]string{"scan", "--incident", writeInc(t, body), "--repo", "o/a"}, &out, &errb, fakeDeps(sourcetest.New())); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if strings.Contains(errb.String()+out.String(), "more than 90 days ago") {
		t.Fatalf("window started 89 days ago: no retention warning\n%s", errb.String())
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

// affectedFake has one AFFECTED job (axios@1.14.1 in the lockfile).
func affectedFake() *sourcetest.Fake {
	f := sourcetest.New()
	f.Runs["o/a"] = []source.Run{{ID: 1, Path: "missing.yml", HeadSHA: "s", CreatedAt: time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)}}
	f.Jobs[1] = []source.Job{{ID: 2, Name: "build"}}
	f.AddFile("o/a", "s", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	return f
}

func TestFormatDefault(t *testing.T) {
	inc := writeInc(t, incYAML)
	tty := fakeDeps(affectedFake())
	tty.isTerminal = func(io.Writer) bool { return true }
	for _, tc := range []struct {
		name      string
		d         deps
		args      []string
		env       map[string]string
		prefix    string
		wantColor bool
	}{
		{"pipe defaults to md", fakeDeps(affectedFake()), nil, nil, "# runsweep: ", false},
		{"terminal defaults to text", tty, nil, map[string]string{"TERM": "xterm-256color"}, "runsweep · ", true},
		{"NO_COLOR", tty, nil, map[string]string{"NO_COLOR": "1", "TERM": "xterm-256color"}, "runsweep · ", false},
		{"TERM=dumb", tty, nil, map[string]string{"TERM": "dumb"}, "runsweep · ", false},
		{"explicit md on a terminal", tty, []string{"--format", "md"}, nil, "# runsweep: ", false},
		{"explicit text in a pipe", fakeDeps(affectedFake()), []string{"--format", "text"}, nil, "runsweep · ", false},
		{"explicit json on a terminal", tty, []string{"--format", "json"}, nil, "{", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("NO_COLOR", "")
			t.Setenv("TERM", "")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			var out, errb bytes.Buffer
			args := append([]string{"scan", "--incident", inc, "--repo", "o/a"}, tc.args...)
			if code := run(args, &out, &errb, tc.d); code != 1 {
				t.Fatalf("code %d: %s", code, errb.String())
			}
			if !strings.HasPrefix(out.String(), tc.prefix) {
				t.Fatalf("want prefix %q:\n%s", tc.prefix, out.String())
			}
			if got := strings.Contains(out.String(), "\x1b[31mAFFECTED\x1b[0m"); got != tc.wantColor {
				t.Fatalf("color = %v, want %v:\n%q", got, tc.wantColor, out.String())
			}
			if !tc.wantColor && strings.Contains(out.String(), "\x1b") {
				t.Fatalf("escape sequence without color:\n%q", out.String())
			}
		})
	}
}

func TestIsTerminal(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if isTerminal(f) || isTerminal(&bytes.Buffer{}) {
		t.Fatal("a regular file or a buffer is not a terminal")
	}
}

// fixtureImporter serves the importer's recorded OSV and npm registry responses.
func fixtureImporter(t *testing.T) func() *importer.Client {
	t.Helper()
	dir := filepath.Join("..", "..", "internal", "importer", "testdata")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.EscapedPath()
		file := ""
		if id, ok := strings.CutPrefix(p, "/osv/v1/vulns/"); ok {
			file = filepath.Join(dir, "osv", id+".json")
		} else if name, ok := strings.CutPrefix(p, "/npm/"); ok {
			file = filepath.Join(dir, "npm", name+".json")
		}
		b, err := os.ReadFile(file) //nolint:gosec // G304: test fixture path
		if file == "" || err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(b) //nolint:gosec // G705: test server replays fixture files
	}))
	t.Cleanup(srv.Close)
	return func() *importer.Client {
		c := importer.New()
		c.HTTP, c.OSVBase, c.NPMBase = srv.Client(), srv.URL+"/osv", srv.URL+"/npm"
		return c
	}
}

// noNetImporter fails the test on any HTTP request.
func noNetImporter(t *testing.T) func() *importer.Client {
	return func() *importer.Client {
		c := importer.New()
		c.HTTP = &http.Client{Transport: roundTrip(func(r *http.Request) (*http.Response, error) {
			t.Errorf("unexpected request %s", r.URL)
			return nil, errors.New("no network in this test")
		})}
		return c
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestImportFromStdin(t *testing.T) {
	d := deps{newImporter: fixtureImporter(t), stdin: strings.NewReader("# axios and a 2024 package\n\nMAL-2026-2307\n  MAL-2025-125  # netflixdesign\n")}
	var out, errb bytes.Buffer
	if code := run([]string{"incidents", "import"}, &out, &errb, d); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	inc, err := incident.Parse(out.Bytes())
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if len(inc.NPM) != 1 || inc.NPM[0].Name != "axios" || len(inc.Refs) != 2 || inc.Refs[1] != "https://osv.dev/vulnerability/MAL-2025-125" {
		t.Fatalf("%+v", inc)
	}
	if strings.Contains(out.String(), "npm registry 1/2") || !strings.Contains(errb.String(), "npm registry 1/2: axios") {
		t.Fatalf("progress must go to stderr only\nstdout:\n%s\nstderr:\n%s", out.String(), errb.String())
	}
}

func TestImportStdinRejectsGarbage(t *testing.T) {
	d := deps{newImporter: noNetImporter(t), stdin: strings.NewReader("MAL-2026-2307\nhttps://evil/\n")}
	var out, errb bytes.Buffer
	if code := run([]string{"incidents", "import"}, &out, &errb, d); code != 2 || !strings.Contains(errb.String(), "stdin line 2") {
		t.Fatalf("code %d: %s", code, errb.String())
	}
}

func TestImportOutputFileIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "incident.yaml")
	if err := os.WriteFile(path, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	d := deps{newImporter: fixtureImporter(t)}
	var out, errb bytes.Buffer
	if code := run([]string{"incidents", "import", "GHSA-35jh-r3h4-6jhm", "-o", path}, &out, &errb, d); code != 2 ||
		!strings.Contains(errb.String(), "nothing to import") {
		t.Fatalf("range-only record: code %d: %s", code, errb.String())
	}
	if b, _ := os.ReadFile(path); string(b) != "old\n" { //nolint:gosec // G304: test temp path
		t.Fatalf("failed import must leave the file alone, got %q", b)
	}
	if code := run([]string{"incidents", "import", "MAL-2026-2307", "-o", path}, &out, &errb, d); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("with -o stdout must stay empty: %q", out.String())
	}
	if _, err := incident.Load(path); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

func TestImportActionOnly(t *testing.T) {
	d := deps{newImporter: noNetImporter(t)}
	act := "tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67"
	var out, errb bytes.Buffer
	if code := run([]string{"incidents", "import", "--action", act}, &out, &errb, d); code != 2 ||
		!strings.Contains(errb.String(), "pass --since and --until for action-only incidents") {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"incidents", "import", "--action", act, "--since", "2025-03-14T16:00:00Z", "--until", "2025-03-15T14:00:00Z", "--id", "tj"}, &out, &errb, d); code != 0 {
		t.Fatalf("code %d: %s", code, errb.String())
	}
	if inc, err := incident.Parse(out.Bytes()); err != nil || inc.Actions[0].Uses != "tj-actions/changed-files" {
		t.Fatalf("%v\n%s", err, out.String())
	}
}

func TestImportUsageErrorsNeverTouchNetwork(t *testing.T) {
	for _, args := range [][]string{
		{"incidents", "import"}, // nothing at all (stdin nil)
		{"incidents", "import", "../x"},
		{"incidents", "import", "--package", "axios"},
		{"incidents", "import", "--package", "npm:../x"},
		{"incidents", "import", "--action", "o/r@abc"},
		{"incidents", "import", "--action", "o/r/x@0e58ed8671d6b60d0890c21b07f8835ace038e67", "--since", "2025-03-14T16:00:00Z", "--until", "2025-03-15T14:00:00Z"},
		{"incidents", "import", "MAL-2026-2307", "--since", "yesterday"},
		{"incidents", "import", "MAL-2026-2307", "--id", "../x"},
		{"incidents", "import", "MAL-2026-2307", "--bogus"},
	} {
		var out, errb bytes.Buffer
		if code := run(args, &out, &errb, deps{newImporter: noNetImporter(t)}); code != 2 {
			t.Errorf("%v: want 2, got %d", args, code)
		}
	}
}
