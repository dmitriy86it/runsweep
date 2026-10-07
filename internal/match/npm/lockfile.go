// Package npm finds packages in npm/pnpm/yarn lockfiles.
package npm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

type Pkg struct{ Name, Version string }

// IsLockfile reports whether p is a lockfile runsweep understands (outside node_modules).
func IsLockfile(p string) bool {
	if strings.Contains(p, "node_modules/") {
		return false
	}
	switch path.Base(p) {
	case "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock":
		return true
	}
	return false
}

// ParseLockfile dispatches on the file's base name.
func ParseLockfile(p string, b []byte) ([]Pkg, error) {
	switch path.Base(p) {
	case "package-lock.json", "npm-shrinkwrap.json":
		return ParsePackageLock(b)
	case "pnpm-lock.yaml":
		return ParsePnpmLock(b)
	case "yarn.lock":
		return ParseYarnLock(b)
	}
	return nil, fmt.Errorf("not a lockfile: %s", p)
}

type depV1 struct {
	Version      string           `json:"version"`
	Dependencies map[string]depV1 `json:"dependencies"`
}

func ParsePackageLock(b []byte) ([]Pkg, error) {
	var lf struct {
		Packages map[string]struct {
			Name    string `json:"name"`
			Version string `json:"version"`
			Link    bool   `json:"link"`
		} `json:"packages"`
		Dependencies map[string]depV1 `json:"dependencies"`
	}
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("package-lock: %w", err)
	}
	var out []Pkg
	if len(lf.Packages) > 0 { // lockfileVersion 2 and 3
		for key, p := range lf.Packages {
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 || p.Link || p.Version == "" {
				continue
			}
			name := key[i+len("node_modules/"):]
			if p.Name != "" { // npm alias: key is the alias, name is the real package
				name = p.Name
			}
			out = append(out, Pkg{name, p.Version})
		}
		return out, nil
	}
	var walk func(map[string]depV1)
	walk = func(deps map[string]depV1) {
		for name, d := range deps {
			v := d.Version
			if real, ok := strings.CutPrefix(v, "npm:"); ok { // alias "npm:real@1.2.3"
				if at := strings.LastIndex(real, "@"); at > 0 {
					name, v = real[:at], real[at+1:]
				}
			}
			out = append(out, Pkg{name, v})
			walk(d.Dependencies)
		}
	}
	walk(lf.Dependencies)
	return out, nil
}

var (
	pnpmV5 = regexp.MustCompile(`^(@[^/]+/[^/]+|[^@/][^/]*)/(\d[^_/]*)(?:_.*)?$`) // /name/1.0.0_peer
	pnpmV6 = regexp.MustCompile(`^(@[^/@]+/[^@]+|[^@][^@]*)@(\d[^_(]*)`)          // name@1.0.0(peer)
)

func ParsePnpmLock(b []byte) ([]Pkg, error) {
	var lf struct {
		Packages map[string]yaml.Node `yaml:"packages"`
	}
	if err := yaml.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("pnpm-lock: %w", err)
	}
	var out []Pkg
	for key := range lf.Packages {
		k := strings.TrimPrefix(key, "/")
		if i := strings.IndexByte(k, '('); i >= 0 {
			k = k[:i]
		}
		if m := pnpmV5.FindStringSubmatch(k); m != nil {
			out = append(out, Pkg{m[1], m[2]})
		} else if m := pnpmV6.FindStringSubmatch(k); m != nil {
			out = append(out, Pkg{m[1], m[2]})
		}
	}
	return out, nil
}

// yarnV1Header mirrors yarn berry's LEGACY_REGEXP, /^(#.*(\r?\n))*?#\s+yarn\s+lockfile\s+v1\r?\n/i,
// with JS semantics spelled out: "." excludes \r \n U+2028 U+2029, \s is the JS whitespace set,
// and the case folding is ASCII-only (Go's (?i) would also fold U+212A KELVIN SIGN to k).
// It is matched against the raw bytes: a BOM or lone-\r line ending makes yarn parse the file as YAML.
var yarnV1Header = func() *regexp.Regexp {
	ws := `[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]+`
	return regexp.MustCompile(`\A(?:#[^\r\n\x{2028}\x{2029}]*\r?\n)*?#` + ws + `[yY][aA][rR][nN]` + ws +
		`[lL][oO][cC][kK][fF][iI][lL][eE]` + ws + `[vV]1\r?\n`)
}()

// yarnV1Anywhere is what yarn classic would accept: it ignores the header and parses v1 syntax regardless.
var yarnV1Anywhere = regexp.MustCompile(`(?m)^# yarn lockfile v1$`)

type yarnEntry struct {
	key                           string
	Version, Resolution, Resolved string
}

// ParseYarnLock handles yarn v1 (line scanner) and berry (YAML). The file is read as berry would
// read it; only a file berry cannot use (not YAML, or no __metadata) that has a v1 header falls
// back to the v1 scanner, as yarn classic would parse it. Every non-workspace entry yields a
// package or an error.
func ParseYarnLock(raw []byte) ([]Pkg, error) {
	b := bytes.TrimPrefix(raw, []byte("\uFEFF"))
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	b = bytes.ReplaceAll(b, []byte("\r"), []byte("\n"))
	if !yarnV1Header.Match(raw) {
		pkgs, err := parseYarnBerry(b)
		if err == nil || !yarnV1Anywhere.Match(b) {
			return pkgs, err
		}
	}
	entries, err := scanYarnV1(b)
	if err != nil {
		return nil, err
	}
	out, err := yarnClassicPkgs(entries)
	if err != nil || !slices.ContainsFunc(entries, func(e yarnEntry) bool { return e.key == "__metadata" }) {
		return out, err
	}
	// Berry parses v1 syntax too and, given __metadata, installs from the resolution field;
	// yarn classic reads the version field. Report both.
	more, err := yarnBerryPkgs(entries)
	if err != nil {
		return nil, err
	}
	seen := map[Pkg]bool{}
	for _, p := range out {
		seen[p] = true
	}
	for _, p := range more {
		if !seen[p] {
			out = append(out, p)
		}
	}
	return out, nil
}

// scanYarnV1 collects each top-level entry's first 2-space-indented version, resolution and resolved.
func scanYarnV1(b []byte) ([]yarnEntry, error) {
	var out []yarnEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Header line: not indented, ends with ":"
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			out = append(out, yarnEntry{key: strings.Trim(strings.TrimSuffix(line, ":"), `" `)})
			continue
		}
		// Field line: exactly 2-space indent (line[0:2]=="  " && line[2]!=' '), first match wins
		if len(out) == 0 || len(line) < 3 || line[0:2] != "  " || line[2] == ' ' {
			continue
		}
		e := &out[len(out)-1]
		t := strings.TrimSpace(line)
		for _, f := range []struct {
			name string
			dst  *string
		}{{"version", &e.Version}, {"resolution", &e.Resolution}, {"resolved", &e.Resolved}} {
			if *f.dst == "" && (strings.HasPrefix(t, f.name+" ") || strings.HasPrefix(t, f.name+":")) {
				*f.dst = strings.Trim(strings.TrimSpace(strings.TrimLeft(strings.TrimPrefix(t, f.name), ": ")), `"`)
			}
		}
	}
	return out, sc.Err()
}

// yarnClassicPkgs applies yarn v1 semantics: names from the entry key, version from the version
// field. Yarn classic actually downloads the resolved URL, so a registry tarball there is reported too.
func yarnClassicPkgs(entries []yarnEntry) ([]Pkg, error) {
	var out []Pkg
	for _, e := range entries {
		if e.key == "__metadata" || e.Version == "0.0.0-use.local" { // workspace
			continue
		}
		names := yarnKeyNames(e.key)
		if len(names) == 0 || e.Version == "" {
			return nil, fmt.Errorf("yarn.lock: entry %q has no package name or version", e.key)
		}
		for _, n := range names {
			out = append(out, Pkg{n, e.Version})
		}
		if p, ok := registryTarball(e.Resolved); ok && !slices.Contains(out[len(out)-len(names):], p) {
			out = append(out, p)
		}
	}
	return out, nil
}

var tarballURL = regexp.MustCompile(`/((?:@[^/]+/)?[^/]+)/-/([^/#?]+)\.tgz(?:[#?].*)?$`)

// registryTarball extracts name and version from a registry tarball URL such as
// https://registry.yarnpkg.com/@scope/pkg/-/pkg-2.0.0.tgz#sha1.
func registryTarball(u string) (Pkg, bool) {
	m := tarballURL.FindStringSubmatch(u)
	if m == nil {
		return Pkg{}, false
	}
	name, err := url.PathUnescape(m[1])
	if err != nil {
		return Pkg{}, false
	}
	v, ok := strings.CutPrefix(m[2], path.Base(name)+"-")
	return Pkg{name, v}, ok && v != ""
}

func parseYarnBerry(b []byte) ([]Pkg, error) {
	var lf map[string]*yarnEntry
	if err := yaml.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("yarn berry lock: %w", err)
	}
	if _, ok := lf["__metadata"]; !ok {
		return nil, fmt.Errorf("yarn.lock: neither a v1 header nor a berry __metadata key")
	}
	var entries []yarnEntry
	for key, e := range lf {
		if e == nil { // yarn would crash reading .resolution of null
			return nil, fmt.Errorf("yarn.lock: entry %q is empty", key)
		}
		e.key = key
		entries = append(entries, *e)
	}
	return yarnBerryPkgs(entries)
}

// yarnBerryPkgs applies berry semantics: the resolution locator decides what is installed.
func yarnBerryPkgs(entries []yarnEntry) ([]Pkg, error) {
	var out []Pkg
	for _, e := range entries {
		if e.key == "__metadata" {
			continue
		}
		version := e.Version
		var names []string
		if e.Resolution != "" {
			name, v, workspace := berryLocator(e.Resolution)
			if workspace {
				continue
			}
			if v != "" {
				version = v
			}
			if name != "" {
				names = []string{name}
			}
		} else if version == "0.0.0-use.local" {
			continue
		}
		if len(names) == 0 { // no or nameless resolution: fall back to the key's specs
			names = yarnKeyNames(e.key)
		}
		if len(names) == 0 || version == "" {
			return nil, fmt.Errorf("yarn.lock: entry %q has no package name or version", e.key)
		}
		for _, n := range names {
			out = append(out, Pkg{n, version})
		}
	}
	return out, nil
}

// berryLocator parses a berry resolution locator: "name@npm:1.2.3[::params]", "@scope/name@npm:1.2.3",
// "name@patch:<urlencoded inner locator>#<patch>[::params]" (the inner package is what gets installed).
// version is set only for npm: references; name is "" if the locator has no name.
func berryLocator(res string) (name, version string, workspace bool) {
	at := strings.Index(res[1:], "@")
	if at < 0 {
		return "", "", false
	}
	name, ref := res[:at+1], res[at+2:]
	switch {
	case strings.HasPrefix(ref, "workspace:"):
		return name, "", true
	case strings.HasPrefix(ref, "npm:"):
		v, _, _ := strings.Cut(ref[len("npm:"):], "::")
		return name, v, false
	case strings.HasPrefix(ref, "patch:"):
		src, _, _ := strings.Cut(ref[len("patch:"):], "#")
		if inner, err := url.PathUnescape(src); err == nil && inner != "" {
			if n, v, ws := berryLocator(inner); n != "" {
				return n, v, ws
			}
		}
	}
	return name, "", false
}

// yarnKeyNames returns the real package names of a lockfile key's comma-separated specs.
func yarnKeyNames(key string) []string {
	var out []string
	for _, spec := range strings.Split(key, ",") {
		// Trim quotes from each spec individually (yarn v1 quotes each spec separately)
		if n := extractYarnPackageName(strings.Trim(strings.TrimSpace(spec), `"`)); n != "" && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// extractYarnPackageName extracts the real package name from a yarn spec.
// Handles aliases (foo@npm:bar@^1 -> bar), scoped packages (@scope/pkg@1.0.0 -> @scope/pkg),
// and regular names (axios@^1.0.0 -> axios).
func extractYarnPackageName(spec string) string {
	if spec == "" {
		return ""
	}
	// Find first "@" at index > 0 (separates package name from version range)
	at := strings.Index(spec[1:], "@")
	if at < 0 {
		// No @ found, bare name
		return spec
	}
	at++ // adjust for substring offset
	name := spec[:at]
	remainder := spec[at+1:] // skip the "@"

	// Check if this is an alias (starts with "npm:")
	if strings.HasPrefix(remainder, "npm:") {
		// Extract what comes after "npm:"
		afterNpm := remainder[4:] // skip "npm:"

		// Guard: if afterNpm is empty or too short, return original name
		if len(afterNpm) <= 1 {
			return name
		}

		// If there's an "@" at index > 0, it means there's a real package name
		// e.g., "npm:is-number@^7" -> extract "is-number"
		// For scoped: "npm:@scope/pkg@range" -> find @ at index > 0 in afterNpm
		if i := strings.Index(afterNpm[1:], "@"); i >= 0 {
			return afterNpm[:i+1]
		}

		// No second @, so this is not an alias (e.g., "@scope/pkg@npm:^2.0.0")
		// Return the original package name
		return name
	}

	return name
}
