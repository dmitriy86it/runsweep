package npm

import (
	"os"
	"path/filepath"
	"testing"
)

// fuzzLock seeds f with the testdata files matching glob plus extra, then checks that parse never
// panics and returns no package without a name, even with an error.
func fuzzLock(f *testing.F, glob string, parse func([]byte) ([]Pkg, error), extra ...string) {
	files, _ := filepath.Glob(filepath.Join("testdata", glob))
	for _, p := range files {
		b, err := os.ReadFile(p) //nolint:gosec // G304: testdata glob
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}
	for _, s := range extra {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		pkgs, _ := parse(b) // on an error, pkgs is what could be read
		for _, p := range pkgs {
			if p.Name == "" {
				t.Fatalf("empty package name: %+v", p)
			}
		}
	})
}

func FuzzParsePackageLock(f *testing.F) {
	fuzzLock(f, "package-lock-*.json", ParsePackageLock, `{}`, `{"packages":{"node_modules/a":{"version":"1"}}}`)
}

func FuzzParsePnpmLock(f *testing.F) {
	fuzzLock(f, "pnpm-lock-*.yaml", ParsePnpmLock, `lockfileVersion: '9.0'`, "packages:\n  /a@1.0.0: {}\n")
}

func FuzzParseYarnLock(f *testing.F) {
	fuzzLock(f, "yarn-*.lock", ParseYarnLock, "a@^1:\n  version \"1.0.0\"\n", "\"@s/a@npm:1\":\n  version: 1.0.0\n")
}
