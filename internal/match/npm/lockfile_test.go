package npm

import (
	"maps"
	"os"
	"strings"
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
		{"yarn-v1.lock", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}, {"is-number", "7.0.0"}, {"foo", "1.2.3"}, {"left-pad", "1.3.0"}, {"version", "1.5.0"}, {"is-odd", "1.0.0"}, {"is-even", "1.0.0"}, {"indent-test", "2.0.0"}}},
		{"yarn-berry.lock", []Pkg{{"axios", "1.14.1"}, {"@scope/pkg", "2.0.0"}, {"is-number", "7.0.0"}, {"foo", "1.0.0"}, {"left-pad", "1.3.0"}, {"version", "1.5.0"}, {"is-odd", "1.0.0"}, {"is-even", "1.0.0"}, {"indent-test", "2.0.0"}}},
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
		"__metadata:\n  version: 8\nfoo: [\n",
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

// TestPerSpecQuoteTrimNecessary verifies that the per-spec quote trim is critical.
// This test documents that removing the Trim(spec, `"`) at lockfile.go:156 would fail:
// "is-odd@^3.0.0", "is-even@^1.0.0": would split to ["is-odd@^3.0.0", " "is-even@^1.0.0"]
// Without per-spec trim, second spec remains "is-even@^1.0.0 and extracts as "is-even (missing package).
func TestPerSpecQuoteTrimNecessary(t *testing.T) {
	input := []byte(`# yarn lockfile v1

"is-odd@^3.0.0", "is-even@^1.0.0":
  version "1.0.0"
`)
	got, err := ParseYarnLock(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gotSet := pkgSet(got)
	wantSet := pkgSet([]Pkg{{"is-odd", "1.0.0"}, {"is-even", "1.0.0"}})
	if !maps.Equal(gotSet, wantSet) {
		t.Errorf("per-spec trim regression: got %v, want %v", got, []Pkg{{"is-odd", "1.0.0"}, {"is-even", "1.0.0"}})
	}
	// Verify both packages are present (not just one)
	if len(got) != 2 {
		t.Errorf("expected exactly 2 packages, got %d: %v", len(got), got)
	}
}

func TestYarnV1CRLF(t *testing.T) {
	b, err := os.ReadFile("testdata/yarn-v1.lock")
	if err != nil {
		t.Fatal(err)
	}
	want, err := ParseYarnLock(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, nl := range []string{"\r\n", "\r"} {
		got, err := ParseYarnLock([]byte(strings.ReplaceAll(string(b), "\n", nl)))
		if err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(pkgSet(got), pkgSet(want)) || len(want) == 0 {
			t.Errorf("%q: got %v, want %v", nl, got, want)
		}
	}
}

func TestYarnBerryYAML(t *testing.T) {
	cases := map[string]struct {
		in   string
		want []Pkg
	}{
		"4-space indent":          {"__metadata:\n    version: 8\n\n\"x@npm:^1.0.0\":\n    version: \"1.2.3\"  # comment\n    resolution: \"x@npm:1.2.3\"\n", []Pkg{{"x", "1.2.3"}}},
		"flow mapping":            {"__metadata:\n  version: 8\n\"x@npm:^1.0.0\": {version: 1.2.3, resolution: \"x@npm:1.2.3\"}\n", []Pkg{{"x", "1.2.3"}}},
		"alias resolution":        {"__metadata:\n  version: 8\n\"alias@npm:^1.0.0\":\n  version: 1.0.0\n  resolution: \"real-pkg@npm:1.0.0\"\n", []Pkg{{"real-pkg", "1.0.0"}}},
		"scoped + patch":          {"__metadata:\n  version: 8\n\"@s/p@npm:^1\":\n  version: 1.0.0\n  resolution: \"@s/p@npm:1.0.0\"\n\"q@patch:q@npm%3A^2#~builtin<compat/q>\":\n  version: 2.0.0\n  resolution: \"q@patch:q@npm%3A2.0.0#~builtin<compat/q>::version=2.0.0\"\n", []Pkg{{"@s/p", "1.0.0"}, {"q", "2.0.0"}}},
		"workspace":               {"__metadata:\n  version: 8\n\"w@workspace:.\":\n  version: 0.0.0-use.local\n  resolution: \"w@workspace:.\"\n", nil},
		"flow document":           {`{"__metadata": {version: 8}, "evil@npm:^1": {version: 6.6.6, resolution: "evil@npm:6.6.6"}}`, []Pkg{{"evil", "6.6.6"}}},
		"use.local but npm":       {"__metadata:\n  version: 8\n\"evil@npm:^1\":\n  version: 0.0.0-use.local\n  resolution: \"evil@npm:6.6.6\"\n", []Pkg{{"evil", "6.6.6"}}},
		"workspace substring":     {"__metadata:\n  version: 8\n\"x@https://h/@workspace:/x.tgz\":\n  version: 1.0.0\n  resolution: \"x@https://h/@workspace:/x.tgz\"\n", []Pkg{{"x", "1.0.0"}}},
		"npm version wins":        {"__metadata:\n  version: 8\n\"evil@npm:^1\":\n  version: 1.0.0\n  resolution: \"evil@npm:6.6.6\"\n", []Pkg{{"evil", "6.6.6"}}},
		"no resolution use.local": {"__metadata:\n  version: 8\n\"w@workspace:.\":\n  version: 0.0.0-use.local\n", nil},
		"crlf":                    {"__metadata:\r\n  version: 8\r\n\"x@npm:^1\":\r\n  version: 1.2.3\r\n  resolution: \"x@npm:1.2.3\"\r\n", []Pkg{{"x", "1.2.3"}}},
	}
	for name, c := range cases {
		got, err := ParseYarnLock([]byte(c.in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !maps.Equal(pkgSet(got), pkgSet(c.want)) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
}

func TestYarnBerryDuplicateKey(t *testing.T) {
	in := "__metadata:\n  version: 8\n\"x@npm:^1\":\n  version: 1.0.0\n\"x@npm:^1\":\n  version: 6.6.6\n"
	if _, err := ParseYarnLock([]byte(in)); err == nil {
		t.Fatal("expected duplicate-key error")
	}
}

func TestYarnBerryBadYAML(t *testing.T) {
	if _, err := ParseYarnLock([]byte("__metadata:\n  version: 8\nfoo: [\n")); err == nil {
		t.Fatal("expected yaml error")
	}
}

func TestYarnNoV1HeaderNoMetadata(t *testing.T) {
	if _, err := ParseYarnLock([]byte("foo: bar\n")); err == nil {
		t.Fatal("expected error for non-v1, non-berry file")
	}
}

// Routing must mirror yarn berry's LEGACY_REGEXP: v1 only if the header is reached through
// leading "#" lines from the very first byte of the raw file.
func TestYarnV1HeaderRouting(t *testing.T) {
	evil := "\"evil@npm:^1\": {version: 1.0.0, resolution: \"evil@npm:6.6.6\"}"
	v1Body := "axios@^1:\n  version \"1.14.1\"\n"
	cases := map[string]struct {
		in   string
		want []Pkg // nil with wantErr
		err  bool
	}{
		"header after __metadata is yaml": {"__metadata:\n  version: 8\n# yarn lockfile v1\n" + evil + "\n", []Pkg{{"evil", "6.6.6"}}, false},
		"leading comment then header":     {"# THIS IS AN AUTOGENERATED FILE.\n# yarn lockfile v1\n\n\n" + v1Body, []Pkg{{"axios", "1.14.1"}}, false},
		"case and spacing":                {"#  Yarn\tLockfile V1\n\n" + v1Body, []Pkg{{"axios", "1.14.1"}}, false},
		"bom before header is yaml":       {"\uFEFF# yarn lockfile v1\n__metadata:\n  version: 8\n" + evil + "\n", []Pkg{{"evil", "6.6.6"}}, false},
		"lone cr header is yaml":          {"# yarn lockfile v1\r__metadata:\r  version: 8\r" + evil + "\r", []Pkg{{"evil", "6.6.6"}}, false},
		"blank line before header":        {"\n# yarn lockfile v1\n" + v1Body, []Pkg{{"axios", "1.14.1"}}, false}, // berry can't, classic can
		"kelvin sign is not k":            {"# yarn loc\u212Afile v1\n" + v1Body, nil, true},
	}
	for name, c := range cases {
		got, err := ParseYarnLock([]byte(c.in))
		if (err != nil) != c.err {
			t.Errorf("%s: err %v, want err %v", name, err, c.err)
			continue
		}
		if !maps.Equal(pkgSet(got), pkgSet(c.want)) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
}

// Every entry with a version must yield a package or an error — never vanish.
func TestYarnNoSilentDrop(t *testing.T) {
	meta := "__metadata:\n  version: 8\n"
	cases := map[string]struct {
		in   string
		want []Pkg
		err  bool
	}{
		"nameless resolution falls back to key": {meta + "\"evil@npm:^1\":\n  version: 6.6.6\n  resolution: \"evil\"\n", []Pkg{{"evil", "6.6.6"}}, false},
		"nameless resolution and key":           {meta + "\"\":\n  version: 6.6.6\n  resolution: \"evil\"\n", nil, true},
		"berry entry without version":           {meta + "\"evil@https://h/e.tgz\":\n  resolution: \"evil@https://h/e.tgz\"\n", nil, true},
		"berry null entry":                      {meta + "\"evil@npm:^1\":\n", nil, true},
		"patch resolves inner package":          {meta + "\"x@patch:x@npm%3A^1#p\":\n  version: 1.0.0\n  resolution: \"x@patch:evil@npm%3A6.6.6#~builtin<compat/x>::version=6.6.6&hash=1\"\n", []Pkg{{"evil", "6.6.6"}}, false},
		"npm archiveUrl params":                 {meta + "\"evil@npm:^1\":\n  version: 1.0.0\n  resolution: \"evil@npm:6.6.6::__archiveUrl=https%3A%2F%2Fh%2Fe.tgz\"\n", []Pkg{{"evil", "6.6.6"}}, false},
		"v1 resolved tarball wins":              {"# yarn lockfile v1\n\naxios@^1:\n  version \"1.13.0\"\n  resolved \"https://registry.yarnpkg.com/axios/-/axios-1.14.1.tgz#abc\"\n", []Pkg{{"axios", "1.13.0"}, {"axios", "1.14.1"}}, false},
		"v1 scoped encoded tarball":             {"# yarn lockfile v1\n\n\"@s/p@^1\":\n  version \"1.0.0\"\n  resolved \"https://r.example/api/npm/@s%2fp/-/p-6.6.6.tgz\"\n", []Pkg{{"@s/p", "1.0.0"}, {"@s/p", "6.6.6"}}, false},
		"v1 entry without version":              {"# yarn lockfile v1\n\nevil@^1:\n  resolved \"https://h/e.tgz\"\n", nil, true},
		"v1 with metadata uses resolution":      {"# yarn lockfile v1\n\n__metadata:\n  version: 8\n\n\"evil@npm:^1\":\n  version \"0.0.0-use.local\"\n  resolution \"evil@npm:6.6.6\"\n", []Pkg{{"evil", "6.6.6"}}, false},
		"v1 with metadata keeps both":           {"# yarn lockfile v1\n\n__metadata:\n  version: 8\n\n\"evil@npm:^1\":\n  version \"1.0.0\"\n  resolution \"evil@npm:6.6.6\"\n", []Pkg{{"evil", "1.0.0"}, {"evil", "6.6.6"}}, false},
	}
	for name, c := range cases {
		got, err := ParseYarnLock([]byte(c.in))
		if (err != nil) != c.err {
			t.Errorf("%s: err %v, want err %v", name, err, c.err)
			continue
		}
		if !maps.Equal(pkgSet(got), pkgSet(c.want)) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
}

func TestYarnV1FailClosed(t *testing.T) {
	cases := map[string]struct {
		in   string
		want []Pkg
		err  bool
	}{
		"trailing space header":   {"# yarn lockfile v1\n\naxios@^1: \n  version \"1.14.1\"  \n", []Pkg{{"axios", "1.14.1"}}, false},
		"whitespace-only line":    {"# yarn lockfile v1\n   \naxios@^1:\n  version \"1.14.1\"\n", []Pkg{{"axios", "1.14.1"}}, false},
		"unrecognised top line":   {"# yarn lockfile v1\n\naxios@^1 {\n  version \"1.14.1\"\n", nil, true},
		"tab-indented field":      {"# yarn lockfile v1\n\naxios@^1:\n\tversion \"1.14.1\"\n", nil, true},
		"indented before header":  {"# yarn lockfile v1\n  version \"1.14.1\"\naxios@^1:\n  version \"1.14.1\"\n", nil, true},
		"odd indent":              {"# yarn lockfile v1\n\naxios@^1:\n v\n  version \"1.14.1\"\n", nil, true},
		"duplicate version":       {"# yarn lockfile v1\n\naxios@^1:\n  version \"1.13.0\"\n  version \"1.14.1\"\n", nil, true},
		"nested version not dupe": {"# yarn lockfile v1\n\nx@^1:\n  version \"1.0.0\"\n  dependencies:\n    version \"^2\"\n", []Pkg{{"x", "1.0.0"}}, false},
	}
	for name, c := range cases {
		got, err := ParseYarnLock([]byte(c.in))
		if (err != nil) != c.err {
			t.Errorf("%s: err %v, want err %v", name, err, c.err)
			continue
		}
		if !maps.Equal(pkgSet(got), pkgSet(c.want)) {
			t.Errorf("%s: got %v, want %v", name, got, c.want)
		}
	}
}

func TestIsLockfileNodeModulesSegment(t *testing.T) {
	for p, want := range map[string]bool{"x_node_modules/app/package-lock.json": true, "a/node_modules/b/yarn.lock": false, "node_modules/yarn.lock": false} {
		if IsLockfile(p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
}

func TestLockfileFailClosed(t *testing.T) {
	for name, c := range map[string]struct{ path, body string }{
		"package-lock without packages or dependencies": {"package-lock.json", `{"lockfileVersion":3}`},
		"package-lock null":                             {"package-lock.json", `null`},
		"package-lock v1 empty name":                    {"package-lock.json", `{"dependencies":{"":{"version":"1.0.0"}}}`},
		"package-lock v3 empty name":                    {"package-lock.json", `{"packages":{"node_modules/":{"version":"1.0.0"}}}`},
		"pnpm without packages":                         {"pnpm-lock.yaml", "lockfileVersion: '9.0'\n"},
		"pnpm packages garbage":                         {"pnpm-lock.yaml", "packages: hello\n"},
		"pnpm file: tarball":                            {"pnpm-lock.yaml", "packages:\n  axios@file:vendor/axios-1.14.1.tgz:\n    resolution: {}\n"},
		"pnpm unknown key":                              {"pnpm-lock.yaml", "packages:\n  github.com/a/b/abc:\n    resolution: {}\n"},
		"berry locator too deep": {"yarn.lock", "__metadata:\n  version: 8\n\"x@npm:1\":\n  version: 1.0.0\n  resolution: \"" +
			strings.Repeat("x@patch:", 17) + "x@npm:1.0.0\"\n"},
	} {
		if _, err := ParseLockfile(c.path, []byte(c.body)); err == nil {
			t.Errorf("%s: want a parse error", name)
		}
	}
	for name, c := range map[string]struct{ path, body string }{
		"package-lock v1 empty deps": {"package-lock.json", `{"lockfileVersion":1,"dependencies":{}}`},
		"pnpm empty file":            {"pnpm-lock.yaml", ""},
		"pnpm local keys":            {"pnpm-lock.yaml", "packages:\n  file:../x:\n    resolution: {}\n  z@file:packages/z:\n    resolution: {}\n  /y@link:../y:\n    resolution: {}\n"},
		"berry locator 16 deep": {"yarn.lock", "__metadata:\n  version: 8\n\"x@npm:1\":\n  version: 1.0.0\n  resolution: \"" +
			strings.Repeat("x@patch:", 15) + "x@npm:1.0.0\"\n"},
	} {
		if _, err := ParseLockfile(c.path, []byte(c.body)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}
