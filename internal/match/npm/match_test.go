package npm

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
	"github.com/dmitriy86it/runsweep/internal/source"
	"github.com/dmitriy86it/runsweep/internal/source/sourcetest"
)

var bad = []incident.NPMPackage{{Name: "axios", Versions: []string{"1.14.1"}}}

func TestMatchMonorepo(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.0.0"}}}`))
	f.AddFile("o/r", "s1", "apps/web/pnpm-lock.yaml", []byte("lockfileVersion: '9.0'\npackages:\n  axios@1.14.1:\n    resolution: {integrity: x}\n"))
	f.AddFile("o/r", "s1", "node_modules/x/package-lock.json", []byte(`garbage`))
	r, err := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if err != nil {
		t.Fatal(err)
	}
	if r.Status != model.Affected || !strings.Contains(r.Evidence[0].Detail, "apps/web/pnpm-lock.yaml") {
		t.Fatalf("%+v", r)
	}
}

func TestMatchPackageJSONWithoutLockfileIsPossible(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{}}`))
	f.AddFile("o/r", "s1", "tools/package.json", []byte(`{"devDependencies":{"axios":"^1.0.0"}}`))
	r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Possible || !strings.Contains(r.Evidence[0].Detail, "tools/package.json") {
		t.Fatalf("%+v", r)
	}
}

func TestMatchCleanAndTruncated(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.13.0"}}}`))
	r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Clean {
		t.Fatalf("%+v", r)
	}
	f.Truncated["o/r@s1"] = true
	r, _ = new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Unchecked {
		t.Fatalf("truncated tree must not be reported clean: %+v", r)
	}
}

func TestMatchBrokenLockfileIsNote(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{broken`))
	r, err := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if err != nil || r.Status != model.Unchecked {
		t.Fatalf("%+v %v", r, err)
	}
}

func TestMatchDeclared(t *testing.T) {
	cases := map[string]struct {
		pkgJSON string
		want    model.Status
		detail  string
	}{
		"bom":              {"\uFEFF" + `{"dependencies":{"axios":"^1"}}`, model.Possible, "axios declared in app/package.json"},
		"non-string value": {`{"dependencies":{"x":{"a":1},"axios":"^1"}}`, model.Possible, "axios declared"},
		"alias to bad":     {`{"dependencies":{"http":"npm:axios@^1"}}`, model.Possible, "axios declared"},
		"scoped alias":     {`{"dependencies":{"s":"npm:@s/p@^1"}}`, model.Possible, "@s/p declared"},
		"unparseable":      {`{"dependencies":`, model.Unchecked, "cannot parse app/package.json"},
		"no lockfile":      {`{"dependencies":{"left-pad":"^1"}}`, model.Unchecked, "no lockfile for app/package.json"},
	}
	badPkgs := append([]incident.NPMPackage{{Name: "@s/p", Versions: []string{"1.0.0"}}}, bad...)
	for name, c := range cases {
		f := sourcetest.New()
		f.AddFile("o/r", "s1", "app/package.json", []byte(c.pkgJSON))
		r, err := new(Cache).Match(context.Background(), f, "o/r", "s1", badPkgs)
		if err != nil || r.Status != c.want || (c.detail != "" && !strings.Contains(r.Evidence[0].Detail, c.detail)) {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
}

func TestMatchStaleLockfile(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.0.0"}}}`))
	f.AddFile("o/r", "s1", "package.json", []byte(`{"dependencies":{"axios":"^1","left-pad":"^1"}}`))
	r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Possible || !strings.Contains(r.Evidence[0].Detail, "axios declared in package.json but not in lockfile package-lock.json") {
		t.Fatalf("%+v", r)
	}
	// Present in the lockfile at a good version: clean.
	f = sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.13.0"}}}`))
	f.AddFile("o/r", "s1", "package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	if r, _ = new(Cache).Match(context.Background(), f, "o/r", "s1", bad); r.Status != model.Clean {
		t.Fatalf("%+v", r)
	}
}

func TestMatchFailedLockfileStillChecksPackageJSON(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "yarn.lock", []byte(`garbage`))
	f.AddFile("o/r", "s1", "package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Possible {
		t.Fatalf("%+v", r)
	}
}

func TestMatchNodeModulesSegment(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "x_node_modules/app/package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	f.AddFile("o/r", "s1", "a/node_modules/b/package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Possible || len(r.Evidence) != 2 || !strings.Contains(r.Evidence[0].Detail, "x_node_modules/app/package.json") ||
		r.Evidence[1].Detail != "no lockfile for x_node_modules/app/package.json — transitive dependencies unknown" {
		t.Fatalf("%+v", r)
	}
}

func TestMatchTruncatedAlwaysNoted(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	f.Truncated["o/r@s1"] = true
	r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	last := r.Evidence[len(r.Evidence)-1]
	if r.Status != model.Possible || last.Kind != "note" || !strings.Contains(last.Detail, "truncated") {
		t.Fatalf("%+v", r)
	}
}

func TestMatchWorkspaceRootLockfile(t *testing.T) {
	ws := []byte(`{"dependencies":{"axios":"^1"}}`)
	lock := func(pkgs string) []byte { return []byte(`{"lockfileVersion":3,"packages":{` + pkgs + `}}`) }
	cases := map[string]struct {
		files  map[string][]byte
		want   model.Status
		detail string
	}{
		"root covers":          {map[string][]byte{"package-lock.json": lock(`"node_modules/axios":{"version":"1.13.0"}`), "packages/web/package.json": ws}, model.Clean, ""},
		"root lacks":           {map[string][]byte{"package-lock.json": lock(``), "packages/web/package.json": ws}, model.Possible, "not in lockfile package-lock.json"},
		"nested wins":          {map[string][]byte{"package-lock.json": lock(`"node_modules/axios":{"version":"1.13.0"}`), "packages/web/package-lock.json": lock(``), "packages/web/package.json": ws}, model.Possible, "not in lockfile packages/web/package-lock.json"},
		"nearest unparsed":     {map[string][]byte{"package-lock.json": lock(`"node_modules/axios":{"version":"1.13.0"}`), "packages/web/package-lock.json": []byte(`{broken`), "packages/web/package.json": ws}, model.Possible, "without a lockfile"},
		"sibling dir no cover": {map[string][]byte{"apps/package-lock.json": lock(`"node_modules/axios":{"version":"1.13.0"}`), "packages/web/package.json": ws}, model.Possible, "without a lockfile"},
	}
	for name, c := range cases {
		f := sourcetest.New()
		for p, b := range c.files {
			f.AddFile("o/r", "s1", p, b)
		}
		r, err := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
		ok := err == nil && r.Status == c.want
		if ok && c.detail != "" {
			ok = slices.ContainsFunc(r.Evidence, func(e model.Evidence) bool { return e.Kind == "npm" && strings.Contains(e.Detail, c.detail) })
		}
		if !ok {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
}

func TestMatchEvidenceDeterministic(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{
		"node_modules/a":{"version":"1.0.0"},"node_modules/b":{"version":"1.0.0"},"node_modules/c":{"version":"1.0.0"},
		"node_modules/d":{"version":"1.0.0"},"node_modules/x/node_modules/a":{"version":"2.0.0"},"node_modules/e":{"version":"1.0.0"}}}`))
	var bad []incident.NPMPackage
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		bad = append(bad, incident.NPMPackage{Name: n, Versions: []string{"1.0.0", "2.0.0"}})
	}
	var first []model.Evidence
	for i := range 20 {
		r, err := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = r.Evidence
		} else if !slices.Equal(first, r.Evidence) {
			t.Fatalf("evidence order changed:\n%v\n%v", first, r.Evidence)
		}
	}
	if len(first) != 6 || !strings.HasPrefix(first[0].Detail, "a@1.0.0 ") || !strings.HasPrefix(first[1].Detail, "a@2.0.0 ") {
		t.Fatalf("%v", first)
	}
}

func TestMatchWildcardVersion(t *testing.T) {
	anyVer := []incident.NPMPackage{{Name: "axios", Versions: []string{"*"}}}
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"0.1.0"}}}`))
	f.AddFile("o/r", "s1", "tools/package.json", []byte(`{"devDependencies":{"axios":"^1.0.0"}}`))
	r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", anyVer)
	if r.Status != model.Affected || r.Evidence[0].Detail != "axios@0.1.0 in package-lock.json at s1 (any version listed as malicious)" {
		t.Fatalf("%+v", r)
	}
	f = sourcetest.New()
	f.AddFile("o/r", "s1", "package.json", []byte(`{"dependencies":{"axios":"^1.0.0"}}`))
	r, _ = new(Cache).Match(context.Background(), f, "o/r", "s1", anyVer)
	if r.Status != model.Possible {
		t.Fatalf("declared only: %+v", r)
	}
}

func hasDetail(r Result, s string) bool {
	return slices.ContainsFunc(r.Evidence, func(e model.Evidence) bool { return strings.Contains(e.Detail, s) })
}

func TestMatchNoLockfile(t *testing.T) {
	const noLock = "no lockfile for app/package.json — transitive dependencies unknown"
	for name, c := range map[string]struct {
		files map[string]string
		want  model.Status
		note  bool
	}{
		"no lockfile":        {map[string]string{"app/package.json": `{"dependencies":{"left-pad":"^1"}}`}, model.Unchecked, true},
		"direct dep wins":    {map[string]string{"app/package.json": `{"dependencies":{"axios":"^1"}}`}, model.Possible, true},
		"no deps":            {map[string]string{"app/package.json": `{"name":"x"}`}, model.Clean, false},
		"root lockfile":      {map[string]string{"app/package.json": `{"dependencies":{"left-pad":"^1"}}`, "yarn.lock": "__metadata:\n  version: 8\n"}, model.Clean, false},
		"same-dir lockfile":  {map[string]string{"app/package.json": `{"dependencies":{"left-pad":"^1"}}`, "app/package-lock.json": `{"packages":{"":{}}}`}, model.Clean, false},
		"sibling lockfile":   {map[string]string{"app/package.json": `{"dependencies":{"left-pad":"^1"}}`, "web/package-lock.json": `{"packages":{"":{}}}`}, model.Unchecked, true},
		"unsupported counts": {map[string]string{"app/package.json": `{"dependencies":{"left-pad":"^1"}}`, "bun.lock": "{}"}, model.Unchecked, false},
	} {
		f := sourcetest.New()
		for p, b := range c.files {
			f.AddFile("o/r", "s1", p, []byte(b))
		}
		r, err := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
		if err != nil || r.Status != c.want || hasDetail(r, noLock) != c.note {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
}

func TestMatchUnsupportedLockfile(t *testing.T) {
	for _, name := range []string{"bun.lock", "bun.lockb", "deno.lock", ".pnp.cjs"} {
		f := sourcetest.New()
		f.AddFile("o/r", "s1", "web/"+name, []byte("x"))
		r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
		if r.Status != model.Unchecked || !hasDetail(r, "web/"+name) {
			t.Errorf("%s: %+v", name, r)
		}
		// next to a supported lockfile, that lockfile is read but may be stale: UNCHECKED, hits kept
		stale := "web/" + name + " present but not read — web/package-lock.json may be stale"
		f.AddFile("o/r", "s1", "web/package-lock.json", []byte(`{"packages":{"":{}}}`))
		f.AddFile("o/r", "s1", "node_modules/x/"+name, []byte("x"))
		if r, _ = new(Cache).Match(context.Background(), f, "o/r", "s1", bad); r.Status != model.Unchecked || !hasDetail(r, stale) || hasDetail(r, "node_modules") {
			t.Errorf("%s with package-lock: %+v", name, r)
		}
		f = sourcetest.New()
		f.AddFile("o/r", "s1", "web/"+name, []byte("x"))
		f.AddFile("o/r", "s1", "web/package-lock.json", []byte(`{"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
		if r, _ = new(Cache).Match(context.Background(), f, "o/r", "s1", bad); r.Status != model.Affected || !hasDetail(r, stale) {
			t.Errorf("%s with a bad package-lock: %+v", name, r)
		}
	}
}

// A package-lock entry runsweep cannot read does not hide a bad package in the same file.
func TestMatchPackageLockBadEntryKeepsHits(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/@scope/":{"version":"1.0.0"},"node_modules/axios":{"version":"1.14.1"}}}`))
	r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Affected || !hasDetail(r, "axios@1.14.1 in package-lock.json") || !hasDetail(r, "cannot parse package-lock.json") {
		t.Fatalf("%+v", r)
	}
}

func TestMatchPnpmUnknownKeyKeepsHits(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "pnpm-lock.yaml", []byte("lockfileVersion: '9.0'\npackages:\n  axios@1.14.1:\n    resolution: {integrity: x}\n  foo@https://codeload.github.com/a/b/tar.gz/abc:\n    resolution: {tarball: x}\n"))
	r, _ := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Affected || !hasDetail(r, "foo@https://codeload.github.com/a/b/tar.gz/abc") {
		t.Fatalf("%+v", r)
	}
}

// countBlobs counts Blob calls and fails the blobs in tooBig with source.ErrIncomplete.
type countBlobs struct {
	*sourcetest.Fake
	n      int
	tooBig map[string]bool
}

func (c *countBlobs) Blob(ctx context.Context, repo, sha string, limit int) ([]byte, error) {
	c.n++
	if c.tooBig[sha] {
		return nil, source.ErrIncomplete
	}
	return c.Fake.Blob(ctx, repo, sha, limit)
}

func TestMatchCachesParsedFiles(t *testing.T) {
	f := &countBlobs{Fake: sourcetest.New()}
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	f.AddFile("o/r", "s1", "tools/package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	f.Trees["o/r@s2"] = f.Trees["o/r@s1"] // another commit, same blobs
	c := new(Cache)
	for _, sha := range []string{"s1", "s2", "s1"} {
		if r, err := c.Match(context.Background(), f, "o/r", sha, bad); err != nil || r.Status != model.Affected {
			t.Fatalf("%+v %v", r, err)
		}
	}
	if f.n != 1 {
		t.Fatalf("want the lockfile fetched once (package.json not needed once AFFECTED), got %d fetches", f.n)
	}
}

// A lockfile over the size cap is unreadable like a broken one: UNCHECKED, and the other lockfiles still count.
func TestMatchOversizeLockfileIsUnchecked(t *testing.T) {
	f := &countBlobs{Fake: sourcetest.New(), tooBig: map[string]bool{"o/r@s1:big/yarn.lock": true}}
	f.AddFile("o/r", "s1", "big/yarn.lock", []byte("x"))
	r, err := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if err != nil || r.Status != model.Unchecked || !strings.Contains(r.Evidence[0].Detail, "cannot parse big/yarn.lock") {
		t.Fatalf("%+v %v", r, err)
	}
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	if r, err = new(Cache).Match(context.Background(), f, "o/r", "s1", bad); err != nil || r.Status != model.Affected {
		t.Fatalf("%+v %v", r, err)
	}
}

// Past 500 lockfiles and package.json files the rest are not read: UNCHECKED, but what was read still counts.
func TestMatchTooManyManifests(t *testing.T) {
	f := &countBlobs{Fake: sourcetest.New()}
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`))
	for i := range 500 {
		f.AddFile("o/r", "s1", fmt.Sprintf("p%d/package-lock.json", i), []byte(`{"lockfileVersion":3,"packages":{}}`))
	}
	r, err := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if err != nil || r.Status != model.Affected || f.n != 500 || !slices.ContainsFunc(r.Evidence, func(e model.Evidence) bool {
		return e.Detail == "too many manifests (501) — not all read"
	}) {
		t.Fatalf("%d fetches, %v, %+v", f.n, err, r)
	}
	f.Trees["o/r@s1"] = f.Trees["o/r@s1"][1:] // no hit: the unread manifest leaves it UNCHECKED
	f.AddFile("o/r", "s1", "package.json", []byte(`{}`))
	if r, _ = new(Cache).Match(context.Background(), f, "o/r", "s1", bad); r.Status != model.Unchecked {
		t.Fatalf("%+v", r)
	}
}
