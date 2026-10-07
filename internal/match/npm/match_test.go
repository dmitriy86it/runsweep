package npm

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
	"github.com/dmitriy86it/runsweep/internal/source/sourcetest"
)

var bad = []incident.NPMPackage{{Name: "axios", Versions: []string{"1.14.1"}}}

func TestMatchMonorepo(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.0.0"}}}`))
	f.AddFile("o/r", "s1", "apps/web/pnpm-lock.yaml", []byte("lockfileVersion: '9.0'\npackages:\n  axios@1.14.1:\n    resolution: {integrity: x}\n"))
	f.AddFile("o/r", "s1", "node_modules/x/package-lock.json", []byte(`garbage`))
	r, err := Match(context.Background(), f, "o/r", "s1", bad)
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
	r, _ := Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Possible || !strings.Contains(r.Evidence[0].Detail, "tools/package.json") {
		t.Fatalf("%+v", r)
	}
}

func TestMatchCleanAndTruncated(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.13.0"}}}`))
	r, _ := Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Clean {
		t.Fatalf("%+v", r)
	}
	f.Truncated["o/r@s1"] = true
	r, _ = Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Unchecked {
		t.Fatalf("truncated tree must not be reported clean: %+v", r)
	}
}

func TestMatchBrokenLockfileIsNote(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{broken`))
	r, err := Match(context.Background(), f, "o/r", "s1", bad)
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
		"clean":            {`{"dependencies":{"left-pad":"^1"}}`, model.Clean, ""},
	}
	badPkgs := append([]incident.NPMPackage{{Name: "@s/p", Versions: []string{"1.0.0"}}}, bad...)
	for name, c := range cases {
		f := sourcetest.New()
		f.AddFile("o/r", "s1", "app/package.json", []byte(c.pkgJSON))
		r, err := Match(context.Background(), f, "o/r", "s1", badPkgs)
		if err != nil || r.Status != c.want || (c.detail != "" && !strings.Contains(r.Evidence[0].Detail, c.detail)) {
			t.Errorf("%s: %+v %v", name, r, err)
		}
	}
}

func TestMatchStaleLockfile(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/left-pad":{"version":"1.0.0"}}}`))
	f.AddFile("o/r", "s1", "package.json", []byte(`{"dependencies":{"axios":"^1","left-pad":"^1"}}`))
	r, _ := Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Possible || !strings.Contains(r.Evidence[0].Detail, "axios declared in package.json but not in lockfile package-lock.json") {
		t.Fatalf("%+v", r)
	}
	// Present in the lockfile at a good version: clean.
	f = sourcetest.New()
	f.AddFile("o/r", "s1", "package-lock.json", []byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.13.0"}}}`))
	f.AddFile("o/r", "s1", "package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	if r, _ = Match(context.Background(), f, "o/r", "s1", bad); r.Status != model.Clean {
		t.Fatalf("%+v", r)
	}
}

func TestMatchFailedLockfileStillChecksPackageJSON(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "yarn.lock", []byte(`garbage`))
	f.AddFile("o/r", "s1", "package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	r, _ := Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Possible {
		t.Fatalf("%+v", r)
	}
}

func TestMatchNodeModulesSegment(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "x_node_modules/app/package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	f.AddFile("o/r", "s1", "a/node_modules/b/package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	r, _ := Match(context.Background(), f, "o/r", "s1", bad)
	if r.Status != model.Possible || len(r.Evidence) != 1 || !strings.Contains(r.Evidence[0].Detail, "x_node_modules/app/package.json") {
		t.Fatalf("%+v", r)
	}
}

func TestMatchTruncatedAlwaysNoted(t *testing.T) {
	f := sourcetest.New()
	f.AddFile("o/r", "s1", "package.json", []byte(`{"dependencies":{"axios":"^1"}}`))
	f.Truncated["o/r@s1"] = true
	r, _ := Match(context.Background(), f, "o/r", "s1", bad)
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
		r, err := Match(context.Background(), f, "o/r", "s1", bad)
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
		r, err := Match(context.Background(), f, "o/r", "s1", bad)
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
