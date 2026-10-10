package npm

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/runsweep/runsweep/internal/model"
	"github.com/runsweep/runsweep/internal/source/sourcetest"
)

func hasPkg(pkgs []Pkg, name, v string) bool { return slices.Contains(pkgs, Pkg{name, v}) }

// npm (JavaScript) reads keys case-sensitively; encoding/json folds case.
func TestPackageLockKeysAreCaseSensitive(t *testing.T) {
	pkgs, err := ParsePackageLock([]byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1","Version":"1.14.0"}}}`))
	if err != nil || !hasPkg(pkgs, "axios", "1.14.1") || hasPkg(pkgs, "axios", "1.14.0") {
		t.Errorf("%v %v", pkgs, err)
	}
	// an entry with only "Version" has no version for npm: unreadable, never read as 1.14.0
	pkgs, err = ParsePackageLock([]byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"Version":"1.14.0"}}}`))
	if err == nil || len(pkgs) != 0 {
		t.Errorf("%v %v", pkgs, err)
	}
	if _, err = ParsePackageLock([]byte(`{"Packages":{"node_modules/axios":{"version":"1.14.1"}}}`)); err == nil {
		t.Error("\"Packages\" is not \"packages\"")
	}
	pkgs, err = ParsePackageLock([]byte(`{"lockfileVersion":1,"dependencies":{"axios":{"version":"1.14.1","Version":"1.14.0","Dependencies":{"x":{"version":"9.9.9"}}}}}`))
	if err != nil || !hasPkg(pkgs, "axios", "1.14.1") || len(pkgs) != 1 {
		t.Errorf("v1: %v %v", pkgs, err)
	}
}

// npm ci installs the resolved tarball, whatever the version field says.
func TestPackageLockResolvedTarball(t *testing.T) {
	pkgs, err := ParsePackageLock([]byte(`{"lockfileVersion":3,"packages":{
	  "node_modules/axios":{"version":"1.14.0","resolved":"https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"},
	  "node_modules/notaxios":{"version":"1.14.1","resolved":"https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"},
	  "node_modules/@babel/core":{"version":"7.0.0","resolved":"https://registry.npmjs.org/@babel/core/-/core-7.0.0.tgz"},
	  "node_modules/gitdep":{"version":"1.0.0","resolved":"git+ssh://git@github.com/o/gitdep.git#abc"},
	  "node_modules/filedep":{"version":"1.0.0","resolved":"file:../filedep"}}}`))
	// a mismatch is reported as the tarball npm installs, and the file counts as not fully read
	if err == nil || !strings.Contains(err.Error(), "resolved") {
		t.Errorf("mismatch must be noted: %v", err)
	}
	for _, p := range []Pkg{{"axios", "1.14.1"}, {"@babel/core", "7.0.0"}, {"gitdep", "1.0.0"}, {"filedep", "1.0.0"}} {
		if !hasPkg(pkgs, p.Name, p.Version) {
			t.Errorf("missing %v in %v", p, pkgs)
		}
	}
	if hasPkg(pkgs, "axios", "1.14.0") || len(pkgSet(pkgs)) != 4 {
		t.Errorf("%v", pkgs)
	}
	// lockfileVersion 1
	pkgs, err = ParsePackageLock([]byte(`{"lockfileVersion":1,"dependencies":{"axios":{"version":"1.14.0","resolved":"https://registry.npmjs.org/axios/-/axios-1.14.1.tgz"}}}`))
	if err == nil || !hasPkg(pkgs, "axios", "1.14.1") || hasPkg(pkgs, "axios", "1.14.0") {
		t.Errorf("v1: %v %v", pkgs, err)
	}
	// a registry tarball URL that names no readable package@version: unreadable
	_, err = ParsePackageLock([]byte(`{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.0","resolved":"https://registry.npmjs.org/axios/-/other.tgz"}}}`))
	if err == nil || !strings.Contains(err.Error(), "resolved") {
		t.Errorf("err %v", err)
	}
}

// lockfileVersion 2 carries both sections; npm 6 reads dependencies.
func TestPackageLockV2ReadsBothSections(t *testing.T) {
	for _, lock := range []string{
		`{"lockfileVersion":2,"packages":{"":{"name":"x"},"node_modules/axios":{"version":"1.14.0"}},"dependencies":{"axios":{"version":"1.14.1"}}}`,
		`{"lockfileVersion":2,"packages":{"":{"name":"x"}},"dependencies":{"axios":{"version":"1.14.1"}}}`,
	} {
		pkgs, err := ParsePackageLock([]byte(lock))
		if err != nil || !hasPkg(pkgs, "axios", "1.14.1") {
			t.Errorf("%v %v", pkgs, err)
		}
	}
}

func TestPnpmTarballAndEmptyLock(t *testing.T) {
	pkgs, err := ParsePnpmLock([]byte("lockfileVersion: '9.0'\npackages:\n  axios@1.14.0:\n    resolution: {tarball: https://registry.npmjs.org/axios/-/axios-1.14.1.tgz}\n" +
		"  gh@1.0.0:\n    resolution: {tarball: 'https://codeload.github.com/o/gh/tar.gz/abc'}\n"))
	if err == nil || !hasPkg(pkgs, "axios", "1.14.1") || hasPkg(pkgs, "axios", "1.14.0") || !hasPkg(pkgs, "gh", "1.0.0") {
		t.Errorf("%v %v", pkgs, err)
	}
	if _, err = ParsePnpmLock([]byte("lockfileVersion: '9.0'\npackages:\n  axios@1.14.0:\n    resolution: {tarball: https://registry.npmjs.org/axios/-/other.tgz}\n")); err == nil {
		t.Error("unreadable registry tarball")
	}
	// no dependencies at all is not an error
	pkgs, err = ParsePnpmLock([]byte("lockfileVersion: '9.0'\nimporters:\n  .: {}\n"))
	if err != nil || len(pkgs) != 0 {
		t.Errorf("%v %v", pkgs, err)
	}
	if _, err = ParsePnpmLock([]byte("lockfileVersion: '9.0'\n")); err == nil {
		t.Error("neither importers nor packages")
	}
}

func matchFiles(t *testing.T, files map[string]string) Result {
	t.Helper()
	f := sourcetest.New()
	for p, c := range files {
		f.AddFile("o/r", "s1", p, []byte(c))
	}
	r, err := new(Cache).Match(context.Background(), f, "o/r", "s1", bad)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const badRootLock = `{"lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"axios":"^1.14.0"}},"node_modules/axios":{"version":"1.14.1"}}}`

// A fixture named like the bad package does not stand for a workspace member.
func TestFixtureNameDoesNotHideMissingFromLock(t *testing.T) {
	r := matchFiles(t, map[string]string{
		"package.json":                    `{"name":"app","dependencies":{"axios":"^1.14.0"}}`,
		"package-lock.json":               `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/lodash":{"version":"4.17.21"}}}`,
		"test/fixtures/fake/package.json": `{"name":"axios","version":"0.0.0"}`,
	})
	if r.Status != model.Possible {
		t.Errorf("%v %+v", r.Status, r.Evidence)
	}
	// a real workspace member of that name is the local package
	r = matchFiles(t, map[string]string{
		"package.json":            `{"name":"app","workspaces":["packages/*"],"dependencies":{"axios":"*"}}`,
		"package-lock.json":       `{"lockfileVersion":3,"packages":{"":{"name":"app","dependencies":{"axios":"*"}},"node_modules/axios":{"resolved":"packages/a","link":true},"packages/a":{"name":"axios"}}}`,
		"packages/a/package.json": `{"name":"axios"}`,
	})
	if r.Status != model.Clean {
		t.Errorf("workspace member: %v %+v", r.Status, r.Evidence)
	}
}

// A stale lockfile that pins a bad version keeps the pin (npm ci installs it) and gains a note.
func TestStaleLockfileKeepsPin(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"package-lock=false": {"package.json": `{"dependencies":{"axios":"^1.14.0"}}`, "package-lock.json": badRootLock, ".npmrc": "registry=https://r.example\n; c\n package-lock = false # no lock\n"},
		"range differs":      {"package.json": `{"dependencies":{"axios":"^1.14.1"}}`, "package-lock.json": badRootLock},
		"dependency missing": {"package.json": `{"dependencies":{"axios":"^1.14.0","left-pad":"^1"}}`, "package-lock.json": badRootLock},
		"dev dependency":     {"package.json": `{"dependencies":{"axios":"^1.14.0"},"devDependencies":{"jest":"^29"}}`, "package-lock.json": badRootLock},
	} {
		r := matchFiles(t, files)
		if r.Status != model.Affected || len(r.Pins) != 1 || len(r.Pinned) != 1 ||
			!slices.ContainsFunc(r.Evidence, func(e model.Evidence) bool {
				return strings.Contains(e.Detail, "lockfile may not be what npm installed")
			}) {
			t.Errorf("%s: %v %+v", name, r.Status, r.Evidence)
		}
	}
	// nothing bad is pinned: npm may resolve the declared package fresh
	r := matchFiles(t, map[string]string{
		"package.json":      `{"dependencies":{"axios":"^1.14.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"axios":"^1.14.0"}},"node_modules/axios":{"version":"1.14.0"}}}`,
		".npmrc":            "package-lock=false\n",
	})
	if r.Status != model.Unchecked || len(r.Pins) != 0 {
		t.Errorf("%v %+v", r.Status, r.Evidence)
	}
}

func TestLockfileNpmUsesIsAffected(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"consistent":              {"package.json": `{"name":"app","dependencies":{"axios":"^1.14.0"}}`, "package-lock.json": badRootLock},
		"no package.json":         {"package-lock.json": badRootLock},
		"lockfile without root":   {"package.json": `{"dependencies":{"axios":"^1.14.0"}}`, "package-lock.json": axiosPlainLock},
		"npmrc keeps the lock":    {"package.json": `{"dependencies":{"axios":"^1.14.0"}}`, "package-lock.json": badRootLock, ".npmrc": "package-lock=true\n"},
		"npmrc of another folder": {"package.json": `{"dependencies":{"axios":"^1.14.0"}}`, "package-lock.json": badRootLock, "web/.npmrc": "package-lock=false\n"},
	} {
		if r := matchFiles(t, files); r.Status != model.Affected || len(r.Pins) != 1 {
			t.Errorf("%s: %v %+v", name, r.Status, r.Evidence)
		}
	}
}

// A stale lockfile matters only when the incident package is involved.
func TestStaleLockfileWithoutBadPackageIsClean(t *testing.T) {
	r := matchFiles(t, map[string]string{
		"package.json":      `{"dependencies":{"left-pad":"^1.1"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"left-pad":"^1.0"}},"node_modules/left-pad":{"version":"1.0.0"}}}`,
	})
	if r.Status != model.Clean {
		t.Errorf("%v %+v", r.Status, r.Evidence)
	}
	// the incident package is declared and the lock is out of date: npm install may resolve it fresh
	r = matchFiles(t, map[string]string{
		"package.json":      `{"dependencies":{"axios":"^1.14.0"}}`,
		"package-lock.json": `{"lockfileVersion":3,"packages":{"":{"dependencies":{"axios":"^1.13.0"}},"node_modules/axios":{"version":"1.13.0"}}}`,
	})
	if r.Status != model.Unchecked {
		t.Errorf("%v %+v", r.Status, r.Evidence)
	}
}

const axiosPlainLock = `{"lockfileVersion":3,"packages":{"node_modules/axios":{"version":"1.14.1"}}}`
