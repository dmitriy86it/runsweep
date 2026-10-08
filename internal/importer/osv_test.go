package importer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fixtures serves testdata/osv and testdata/npm the way api.osv.dev and registry.npmjs.org do.
// extra (may be nil) answers first; return false to fall through.
func fixtures(t *testing.T, extra func(w http.ResponseWriter, r *http.Request) bool) (*Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	c, _ := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if extra != nil && extra(w, r) {
			return
		}
		var file string
		p := r.URL.EscapedPath()
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/osv/v1/vulns/"):
			file = filepath.Join("testdata", "osv", strings.TrimPrefix(p, "/osv/v1/vulns/")+".json")
		case r.Method == http.MethodPost && p == "/osv/v1/query":
			var q struct {
				Package struct{ Name string } `json:"package"`
			}
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &q)
			file = filepath.Join("testdata", "osv", "query-"+q.Package.Name+".json")
			if _, err := os.Stat(file); err != nil {
				_, _ = fmt.Fprint(w, `{}`) // what OSV answers for a package it does not know
				return
			}
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/npm/"):
			file = filepath.Join("testdata", "npm", strings.TrimPrefix(p, "/npm/")+".json")
		}
		b, err := os.ReadFile(file) //nolint:gosec // G304: test fixture path
		if file == "" || err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = fmt.Fprint(w, `{"error":"Not found"}`)
			return
		}
		_, _ = w.Write(b) //nolint:gosec // G705: test server replays fixture files
	}))
	return c, &calls
}

func TestValidators(t *testing.T) {
	for _, s := range []string{"MAL-2026-2307", "GHSA-mrrh-fwg8-r2c3", "CVE-2025-30066", "GO-2026-4919", "PYSEC-2026-2"} {
		if !ValidID(s) {
			t.Errorf("ValidID(%q) = false", s)
		}
	}
	for _, s := range []string{"", "mal-1", "MAL-2026-1/../x", "MAL-2026-1?x", "MAL-", "MAL-2026-1\n"} {
		if ValidID(s) {
			t.Errorf("ValidID(%q) = true", s)
		}
	}
	for _, s := range []string{"axios", "@tanstack/react-router", "lodash.merge", "a-b_c~d"} {
		if !ValidNPMName(s) {
			t.Errorf("ValidNPMName(%q) = false", s)
		}
	}
	// Names from OSV: real malicious packages break npm's current rules.
	for _, s := range []string{"axios", "AdultJS", "--legacy-peer-deps", "@_wnpm/wnpm-cli", "@scope/Name"} {
		if !safeNPMName(s) {
			t.Errorf("safeNPMName(%q) = false", s)
		}
	}
	for _, s := range []string{"", "../x", "@scope/../x", "@../x", "..", ".", "@scope/", "x y", "x\n", "@a/b/c", "a/b", strings.Repeat("a", 215)} {
		if safeNPMName(s) {
			t.Errorf("safeNPMName(%q) = true", s)
		}
	}
	for _, s := range []string{"", "../x", "@scope/../x", "A", "@scope/", "x y", "x\n", "@a/b/c", ".hidden", strings.Repeat("a", 215)} {
		if ValidNPMName(s) {
			t.Errorf("ValidNPMName(%q) = true", s)
		}
	}
	for _, s := range []string{"1.14.1", "0.0.1-security", "v45.0.7", "1.0.0+build.1"} {
		if !validVersion(s) {
			t.Errorf("validVersion(%q) = false", s)
		}
	}
	for _, s := range []string{"", "latest", "1.0", `1.0.0"]`, "1.0.0\n# x"} {
		if validVersion(s) {
			t.Errorf("validVersion(%q) = true", s)
		}
	}
	for _, s := range []string{"o/..", "../r", "o/r/x", "o", "o/r\n"} {
		if ValidRepo(s) {
			t.Errorf("ValidRepo(%q) = true", s)
		}
	}
}

func TestVulnMAL(t *testing.T) {
	c, _ := fixtures(t, nil)
	v, err := c.Vuln(context.Background(), "MAL-2025-125")
	if err != nil {
		t.Fatal(err)
	}
	a := v.Affected[0]
	if a.Package.Ecosystem != "npm" || a.Package.Name != "netflixdesign" || fmt.Sprint(a.Versions) != "[1.0.1]" {
		t.Fatalf("%+v", v)
	}
}

func TestVulnErrors(t *testing.T) {
	c, calls := fixtures(t, nil)
	if _, err := c.Vuln(context.Background(), "../etc/passwd"); err == nil || calls.Load() != 0 {
		t.Fatalf("invalid id must fail before any request: %v, %d calls", err, calls.Load())
	}
	if _, err := c.Vuln(context.Background(), "MAL-2099-1"); err == nil || !strings.Contains(err.Error(), "no record MAL-2099-1") {
		t.Fatalf("want not-found error, got %v", err)
	}
}

func TestQueryMALFollowsPagesAndKeepsOnlyMAL(t *testing.T) {
	var tokens []string
	c, _ := fixtures(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/osv/v1/query" {
			return false
		}
		var q struct {
			Token string `json:"page_token"`
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &q)
		tokens = append(tokens, q.Token)
		if q.Token == "" { // OSV may answer with only a token when the query hit its time limit
			_, _ = fmt.Fprint(w, `{"next_page_token":"p2"}`)
			return true
		}
		page, _ := os.ReadFile(filepath.Join("testdata", "osv", "query-axios.json"))
		_, _ = w.Write(page)
		return true
	})
	vs, err := c.QueryMAL(context.Background(), "axios")
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 1 || vs[0].ID != "MAL-2026-2307" { // the GHSA record on the same page is not malware
		t.Fatalf("%+v", vs)
	}
	if fmt.Sprint(tokens) != "[ p2]" {
		t.Fatalf("page tokens sent: %q", tokens)
	}
}

func TestQueryMALPageCap(t *testing.T) {
	c, calls := fixtures(t, func(w http.ResponseWriter, _ *http.Request) bool {
		_, _ = fmt.Fprint(w, `{"next_page_token":"again"}`)
		return true
	})
	if _, err := c.QueryMAL(context.Background(), "axios"); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("want page cap error, got %v", err)
	}
	if calls.Load() != maxPages {
		t.Fatalf("calls %d", calls.Load())
	}
}

func TestQueryMALRejectsBadName(t *testing.T) {
	c, calls := fixtures(t, nil)
	if _, err := c.QueryMAL(context.Background(), "../x"); err == nil || calls.Load() != 0 {
		t.Fatalf("%v, %d calls", err, calls.Load())
	}
}

func vulnFixture(t *testing.T, id string) *Vuln {
	t.Helper()
	c, _ := fixtures(t, nil)
	v, err := c.Vuln(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAddVuln(t *testing.T) {
	f := newFound()
	if !f.addVuln(vulnFixture(t, "MAL-2026-2307")) || fmt.Sprint(sortedVersions(f.npm["axios"])) != "[0.30.4 1.14.1]" {
		t.Fatalf("axios: %v", f.npm)
	}
	if !f.addVuln(vulnFixture(t, "MAL-2026-2300")) || len(f.npm["eslint-validator"]) != 0 || segText(f.ranges["eslint-validator"]) != "[0, ∞)" {
		t.Fatal("open range-only entry must be left to the registry, without invented versions")
	}
	if !f.addVuln(vulnFixture(t, "GHSA-35jh-r3h4-6jhm")) || len(f.npm["lodash"]) != 0 || segText(f.ranges["lodash"]) != "[0, 4.17.21)" {
		t.Fatal("closed range-only entry is left to the registry, without invented versions")
	}
	if !f.addVuln(vulnFixture(t, "GHSA-mrrh-fwg8-r2c3")) || len(f.actions) != 0 {
		t.Fatal("GitHub Actions advisory must not become an action SHA")
	}
	if f.addVuln(vulnFixture(t, "CVE-2025-30066")) {
		t.Fatal("CVE record without package entries must not count (its versions are git tags)")
	}
	for _, want := range []string{
		"GHSA-mrrh-fwg8-r2c3: affects tj-actions/changed-files introduced 0, fixed 46.0.1 — pass the compromised commit with --action tj-actions/changed-files@SHA",
	} {
		if !slices.Contains(f.notes, want) || !slices.Contains(f.warns, want) {
			t.Fatalf("missing %q\nnotes %q\nwarns %q", want, f.notes, f.warns)
		}
	}
	if slices.ContainsFunc(f.notes, func(n string) bool { return strings.Contains(n, "add manually") }) {
		t.Fatalf("range-only entries need no manual note: %q", f.notes)
	}
	if len(f.refs) != 5 || f.refs[0] != "https://osv.dev/vulnerability/MAL-2026-2307" {
		t.Fatalf("refs %v", f.refs)
	}
}

func TestAddVulnRejectsHostileStrings(t *testing.T) {
	// Not a fixture: a record crafted to try YAML/comment injection through OSV fields.
	var v Vuln
	if err := json.Unmarshal([]byte(`{"id":"MAL-0000-1","affected":[
		{"package":{"ecosystem":"npm","name":"evil\n- {name: x"},"versions":["1.0.0"]},
		{"package":{"ecosystem":"npm","name":"ok-name"},"versions":["1.0.0\"]}\nrefs: [x]","2.0.0"]},
		{"package":{"ecosystem":"GitHub Actions","name":"o/r\n#"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0\nx"}]}]},
		{"package":{"ecosystem":"GitHub Actions","name":"o/r"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0\nx"}]}]}]}`), &v); err != nil {
		t.Fatal(err)
	}
	f := newFound()
	f.addVuln(&v)
	if len(f.npm) != 1 || fmt.Sprint(sortedVersions(f.npm["ok-name"])) != "[2.0.0]" {
		t.Fatalf("npm %v", f.npm)
	}
	for _, n := range f.notes {
		if strings.ContainsAny(n, "\n\r") {
			t.Fatalf("raw newline reached a note: %q", n)
		}
	}
	if !strings.Contains(strings.Join(f.notes, "|"), "introduced ?") {
		t.Fatalf("unsafe range event must be masked: %q", f.notes)
	}
}

func TestVersionOrder(t *testing.T) {
	v := []string{"x", "1.10.0", "1.9.0", "0.0.1-security", "1.2.0-beta", "1.2.0", "v0.5.0"}
	sort.Slice(v, func(i, j int) bool { return versionLess(v[i], v[j]) })
	if got := fmt.Sprint(v); got != "[0.0.1-security v0.5.0 1.2.0-beta 1.2.0 1.9.0 1.10.0 x]" {
		t.Fatal(got)
	}
}

func TestAddAction(t *testing.T) {
	f := newFound()
	for _, s := range []string{"tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67", "tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67"} {
		if err := f.addAction(s); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.actions["tj-actions/changed-files"]) != 1 {
		t.Fatalf("duplicates must collapse: %v", f.actions)
	}
	for _, s := range []string{"o/r", "o/r@0E58ED8671D6B60D0890C21B07F8835ACE038E67", "o/r@0e58ed8", "o/r/x@0e58ed8671d6b60d0890c21b07f8835ace038e67", "../r@0e58ed8671d6b60d0890c21b07f8835ace038e67"} {
		if err := f.addAction(s); err == nil {
			t.Errorf("%q: want error", s)
		}
	}
}

func TestAddVulnRecordsOpenRange(t *testing.T) {
	f := newFound()
	f.addVuln(vulnFixture(t, "MAL-2022-1122"))
	if fmt.Sprint(sortedVersions(f.npm["arpan-package"])) != "[2.0.5]" || segText(f.ranges["arpan-package"]) != "[0, ∞)" {
		t.Fatalf("npm %v ranges %v", f.npm, f.ranges)
	}
	f = newFound()
	f.addVuln(vulnFixture(t, "MAL-2026-2307")) // explicit versions, no ranges
	if len(f.ranges) != 0 {
		t.Fatalf("ranges %v", f.ranges)
	}
}

func TestAddVulnDedupesRefsAndChecksID(t *testing.T) {
	f := newFound()
	v := vulnFixture(t, "MAL-2026-2307")
	f.addVuln(v)
	f.addVuln(v)
	if len(f.refs) != 1 {
		t.Fatalf("refs %v", f.refs)
	}
	if f.addVuln(&Vuln{ID: "bad\nid", Affected: v.Affected}) || len(f.refs) != 1 {
		t.Fatal("record with invalid id must be ignored")
	}
}

func TestSegments(t *testing.T) {
	for events, want := range map[string]string{
		`{"introduced":"0"},{"fixed":"1.0.0"},{"introduced":"2.0.0"}`: "[0, 1.0.0), [2.0.0, ∞)",
		`{"introduced":"1.0.0"},{"last_affected":"1.2.0"}`:            "[1.0.0, 1.2.0]",
		`{"introduced":"1.0.0"},{"limit":"1.2.0"}`:                    "[1.0.0, 1.2.0)",
		`{"introduced":"2.x"}`:                                        "[0, ∞)",
		`{"introduced":"1.0.0"},{"fixed":"bad\nx"}`:                   "[1.0.0, ∞)",
	} {
		var a Affected
		if err := json.Unmarshal([]byte(`{"ranges":[{"type":"SEMVER","events":[`+events+`]}]}`), &a); err != nil {
			t.Fatal(err)
		}
		segs, _ := segments(a)
		if got := segText(segs); got != want {
			t.Errorf("%s: got %q, want %q", events, got, want)
		}
	}
}

func TestExpandRange(t *testing.T) {
	pt := func(vs ...string) PkgTimes {
		p := PkgTimes{Found: true, Times: map[string]time.Time{}, Published: map[string]bool{}}
		for _, v := range vs {
			p.Times[v] = time.Unix(0, 0)
		}
		return p
	}
	for events, want := range map[string]string{
		`{"introduced":"0"},{"fixed":"1.0.0"},{"introduced":"2.0.0"}`: "[0.5.0 1.0.0-rc.1 2.1.0]",
		`{"introduced":"0.5.0"},{"last_affected":"1.2.0"}`:            "[0.5.0 1.0.0-rc.1 1.2.0]",
	} {
		var a Affected
		_ = json.Unmarshal([]byte(`{"ranges":[{"type":"SEMVER","events":[`+events+`]}]}`), &a)
		f := newFound()
		f.ranges["p"], _ = segments(a)
		f.expand("p", pt("0.5.0", "1.0.0-rc.1", "1.2.0", "2.1.0"))
		if got := fmt.Sprint(sortedVersions(f.npm["p"])); got != want {
			t.Errorf("%s: got %s, want %s", events, got, want)
		}
	}
}

func TestAddVulnUnparsableIntroducedAndVPrefix(t *testing.T) {
	var v Vuln
	_ = json.Unmarshal([]byte(`{"id":"MAL-0000-2","affected":[
		{"package":{"ecosystem":"npm","name":"a"},"ranges":[{"type":"SEMVER","events":[{"introduced":"2.x"}]}]},
		{"package":{"ecosystem":"npm","name":"b"},"versions":["v1.2.3"]}]}`), &v)
	f := newFound()
	f.addVuln(&v)
	notes := strings.Join(f.notes, "\n")
	if segText(f.ranges["a"]) != "[0, ∞)" || !strings.Contains(notes, "a: unparsable range event (introduced 2.x) — read as 0 / no end, the wider choice") {
		t.Fatalf("ranges %v notes %q", f.ranges, f.notes)
	}
	if !f.npm["b"]["1.2.3"] || f.npm["b"]["v1.2.3"] || !strings.Contains(notes, `b: version "v1.2.3" listed as "1.2.3"`) {
		t.Fatalf("npm %v notes %q", f.npm, f.notes)
	}
}
