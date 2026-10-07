package npm

import (
	"maps"
	"os"
	"testing"
)

func pkgSet(pkgs []Pkg) map[Pkg]bool {
	m := make(map[Pkg]bool)
	for _, p := range pkgs {
		m[p] = true
	}
	return m
}

func TestParsers(t *testing.T) {
	cases := []struct {
		file string
		want []Pkg
	}{
		{"package-lock-v3.json", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}, {"axios", "0.30.4"}, {"is-number", "7.0.0"}}},
		{"package-lock-v1.json", []Pkg{{"axios", "1.14.1"}, {"follow-redirects", "1.15.0"}, {"is-number", "7.0.0"}}},
		{"pnpm-lock-v9.yaml", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}, {"react-dom", "18.2.0"}}},
		{"pnpm-lock-v6.yaml", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}}},
		{"pnpm-lock-v5.yaml", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}}},
		{"yarn-v1.lock", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}, {"is-number", "7.0.0"}, {"foo", "1.2.3"}, {"left-pad", "1.3.0"}, {"version", "1.5.0"}}},
		{"yarn-berry.lock", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}, {"is-number", "7.0.0"}, {"foo", "1.0.0"}, {"left-pad", "1.3.0"}, {"version", "1.5.0"}}},
	}
	names := map[string]string{"package-lock-v3.json": "package-lock.json", "package-lock-v1.json": "package-lock.json",
		"pnpm-lock-v9.yaml": "pnpm-lock.yaml", "pnpm-lock-v6.yaml": "pnpm-lock.yaml", "pnpm-lock-v5.yaml": "pnpm-lock.yaml",
		"yarn-v1.lock": "yarn.lock", "yarn-berry.lock": "yarn.lock"}
	for _, c := range cases {
		b, err := os.ReadFile("testdata/" + c.file)
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseLockfile("sub/"+names[c.file], b)
		if err != nil {
			t.Fatalf("%s: %v", c.file, err)
		}
		// Compare exact sets: all wanted packages present, no extra packages (excluding root/link)
		gotSet := pkgSet(got)
		wantSet := pkgSet(c.want)
		if !maps.Equal(gotSet, wantSet) {
			t.Errorf("%s: got %v, want %v", c.file, got, c.want)
		}
	}
}

func TestIsLockfile(t *testing.T) {
	for p, want := range map[string]bool{"a/package-lock.json": true, "npm-shrinkwrap.json": true, "x/pnpm-lock.yaml": true,
		"yarn.lock": true, "package.json": false, "node_modules/x/package-lock.json": false} {
		if IsLockfile(p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
}

func TestParseLockfileGarbage(t *testing.T) {
	if _, err := ParseLockfile("package-lock.json", []byte("{not json")); err == nil {
		t.Fatal("expected error")
	}
}

// TestYarnEmptyAfterNpm tests that foo@npm: (empty after colon) doesn't panic
func TestYarnEmptyAfterNpm(t *testing.T) {
	input := []byte(`# yarn lockfile v1
foo@npm::
  version "1.0.0"
`)
	_, err := ParseYarnLock(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestMalformedInputsPanic tests that various malformed inputs don't panic
func TestMalformedInputsPanic(t *testing.T) {
	malformed := []string{
		":",
		"@:",
		`@npm:
  version`,
		`x@npm:@
  version: 1`,
	}
	for _, input := range malformed {
		// Test yarn parser
		_, err := ParseYarnLock([]byte(input))
		if err != nil && err.Error() == "EOF" {
			t.Logf("yarn %q: acceptable EOF", input)
		}

		// Test pnpm parser (also processes yaml)
		_, err = ParsePnpmLock([]byte(input))
		if err != nil && err.Error() == "EOF" {
			t.Logf("pnpm %q: acceptable EOF", input)
		}
	}
}
