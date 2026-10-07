package npm

import (
	"context"
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
