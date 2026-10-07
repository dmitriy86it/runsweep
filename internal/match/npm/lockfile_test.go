package npm

import (
	"os"
	"slices"
	"testing"
)

func has(pkgs []Pkg, name, ver string) bool {
	return slices.Contains(pkgs, Pkg{name, ver})
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
		{"yarn-v1.lock", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}}},
		{"yarn-berry.lock", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}}},
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
		for _, w := range c.want {
			if !has(got, w.Name, w.Version) {
				t.Errorf("%s: missing %v in %v", c.file, w, got)
			}
		}
		if has(got, "web", "") || has(got, "app", "") {
			t.Errorf("%s: root/link entries must be skipped: %v", c.file, got)
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
