// Package npm finds packages in npm/pnpm/yarn lockfiles.
package npm

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"path"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"
)

// Pkg is a resolved npm package name and version.
type Pkg struct{ Name, Version string }

// IsLockfile reports whether p is a lockfile runsweep understands (outside node_modules).
func IsLockfile(p string) bool {
	if InNodeModules(p) {
		return false
	}
	switch path.Base(p) {
	case "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock":
		return true
	}
	return false
}

// IsUnsupportedLockfile reports whether p is a lockfile runsweep cannot read (outside node_modules).
func IsUnsupportedLockfile(p string) bool {
	switch path.Base(p) {
	case "bun.lock", "bun.lockb", "deno.lock", ".pnp.cjs":
		return !InNodeModules(p)
	}
	return false
}

// InNodeModules reports whether p has a node_modules path segment.
func InNodeModules(p string) bool {
	return p == "node_modules" || strings.HasPrefix(p, "node_modules/") || strings.Contains(p, "/node_modules/")
}

// ParseLockfile dispatches on the file's base name. Packages come back sorted and distinct.
func ParseLockfile(p string, b []byte) ([]Pkg, error) {
	pkgs, _, err := parseLockfile(p, b)
	return pkgs, err
}

// parseLockfile also returns the root specs of a package-lock (see parsePackageLock).
func parseLockfile(p string, b []byte) (pkgs []Pkg, root []string, err error) {
	switch path.Base(p) {
	case "package-lock.json", "npm-shrinkwrap.json":
		pkgs, root, err = parsePackageLock(b)
	case "pnpm-lock.yaml":
		pkgs, err = ParsePnpmLock(b)
	case "yarn.lock":
		pkgs, err = ParseYarnLock(b)
	default:
		return nil, nil, fmt.Errorf("not a lockfile: %s", p)
	}
	slices.SortFunc(pkgs, func(a, b Pkg) int { return cmp.Or(cmp.Compare(a.Name, b.Name), cmp.Compare(a.Version, b.Version)) })
	return slices.Compact(pkgs), root, err
}

// ParsePackageLock extracts packages from a package-lock.json, from both `packages` and
// `dependencies` (lockfileVersion 2 has both; npm 6 reads the second). An entry without a package
// name (or a version, in lockfileVersion 2 and 3) is an error; the other packages are returned
// with it. Keys are read case-sensitively, as npm does: encoding/json would fold "Version" into
// "version". A registry tarball in `resolved` that names another package or version is reported
// too, because npm installs the tarball.
func ParsePackageLock(b []byte) ([]Pkg, error) {
	pkgs, _, err := parsePackageLock(b)
	return pkgs, err
}

// parsePackageLock also returns the dependency specs of the root package of lockfileVersion 2 and 3
// (nil without a root entry).
func parsePackageLock(b []byte) (out []Pkg, root []string, err error) {
	var lf map[string]any
	if err := json.Unmarshal(b, &lf); err != nil {
		return nil, nil, fmt.Errorf("package-lock: %w", err)
	}
	packages, _ := lf["packages"].(map[string]any)
	deps, _ := lf["dependencies"].(map[string]any)
	if packages == nil && deps == nil {
		return nil, nil, fmt.Errorf("package-lock: neither packages nor dependencies")
	}
	// malformed entries (no package name, a scope without a name, no version, a registry tarball
	// URL that cannot be read): the file is not fully read
	unnamed, unreadable := 0, 0
	add := func(name, version, resolved string) {
		pkg := Pkg{name, version}
		if tarballLike.MatchString(resolved) {
			// npm installs the tarball: what it names is the package, and a mismatch is noted as unreadable
			if t, ok := registryTarball(resolved); !ok || t != pkg {
				unreadable++
				if ok {
					pkg = t
				}
			}
		}
		out = append(out, pkg)
	}
	for key, v := range packages { // lockfileVersion 2 and 3
		if key == "" {
			root = rootSpecs(v)
			continue
		}
		i := strings.LastIndex(key, "node_modules/")
		p, isObj := v.(map[string]any)
		if i < 0 || link(p) {
			continue
		}
		name := key[i+len("node_modules/"):]
		if n := str(p, "name"); n != "" { // npm alias: key is the alias, name is the real package
			name = n
		}
		if !isObj || !validName(name) || str(p, "version") == "" {
			unnamed++
			continue
		}
		add(name, str(p, "version"), str(p, "resolved"))
	}
	var walk func(map[string]any)
	walk = func(deps map[string]any) {
		for name, v := range deps {
			d, _ := v.(map[string]any)
			ver := str(d, "version")
			if target, ok := strings.CutPrefix(ver, "npm:"); ok { // alias "npm:real@1.2.3"
				if at := strings.LastIndex(target, "@"); at > 0 {
					name, ver = target[:at], target[at+1:]
				}
			}
			if name == "" {
				unnamed++
			} else {
				add(name, ver, str(d, "resolved"))
			}
			nested, _ := d["dependencies"].(map[string]any)
			walk(nested)
		}
	}
	walk(deps)
	return out, root, lockErr(unnamed, unreadable)
}

// tarballLike matches a registry tarball URL: its path ends in /-/<file>.tgz.
var tarballLike = regexp.MustCompile(`/-/[^/#?]*\.tgz(?:[#?].*)?$`)

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func link(m map[string]any) bool {
	l, _ := m["link"].(bool)
	return l
}

// rootSpecs lists the dependency specs of a package-lock root entry as depSpecs does for a package.json.
func rootSpecs(v any) []string {
	m, _ := v.(map[string]any)
	return depSpecs(func(kind string) map[string]any {
		o, _ := m[kind].(map[string]any)
		return o
	})
}

var depKinds = []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"}

// depSpecs flattens the four dependency maps (kind -> name -> spec) into sorted "kind name spec"
// strings; a spec that is not a string reads as "?". It is never nil.
func depSpecs(kind func(string) map[string]any) []string {
	out := []string{}
	for _, k := range depKinds {
		for name, v := range kind(k) {
			spec, ok := v.(string)
			if !ok {
				spec = "?"
			}
			out = append(out, k+" "+name+" "+spec)
		}
	}
	slices.Sort(out)
	return out
}

// validName reports whether name is a package name: not empty, and a scoped name has both parts.
func validName(name string) bool {
	if scope, rest, ok := strings.Cut(name, "/"); ok {
		return strings.HasPrefix(scope, "@") && len(scope) > 1 && rest != "" && !strings.Contains(rest, "/")
	}
	return name != "" && name[0] != '@'
}

func lockErr(unnamed, unreadable int) error {
	switch {
	case unnamed > 0 && unreadable > 0:
		return fmt.Errorf("package-lock: %d entries without a package name or version, %d with a resolved URL that names no or another package@version", unnamed, unreadable)
	case unnamed > 0:
		return fmt.Errorf("package-lock: %d entries without a package name or version", unnamed)
	case unreadable > 0:
		return fmt.Errorf("package-lock: %d entries with a resolved URL that names no or another package@version", unreadable)
	}
	return nil
}

var (
	pnpmV5      = regexp.MustCompile(`^(@[^/]+/[^/]+|[^@/][^/]*)/(\d[^_/]*)(?:_.*)?$`) // /name/1.0.0_peer
	pnpmV6      = regexp.MustCompile(`^(@[^/@]+/[^@]+|[^@][^@]*)@(\d[^_(]*)`)          // name@1.0.0(peer)
	pnpmLocal   = regexp.MustCompile(`^(?:[^:]*@)?(?:file|link):`)                     // in-repo package: name@file:../x, link:../x
	pnpmTarball = regexp.MustCompile(`(?i)\.(?:tgz|tar\.gz|tar)$`)                     // file: tarball: an installed package of unknown version
)

// ParsePnpmLock extracts packages from a pnpm-lock.yaml. A key it cannot read is an error that
// names it; the packages read from the other keys are returned with it.
func ParsePnpmLock(b []byte) ([]Pkg, error) {
	var lf struct {
		Packages  map[string]yaml.Node `yaml:"packages"`
		Importers map[string]yaml.Node `yaml:"importers"`
	}
	if err := yaml.Unmarshal(b, &lf); err != nil {
		return nil, fmt.Errorf("pnpm-lock: %w", err)
	}
	// a project without dependencies has importers and no packages
	if len(lf.Packages) == 0 && len(lf.Importers) == 0 && len(bytes.TrimSpace(b)) > 0 {
		return nil, fmt.Errorf("pnpm-lock: no packages")
	}
	var out []Pkg
	var unknown []string
	for key, node := range lf.Packages {
		k := strings.TrimPrefix(key, "/")
		if i := strings.IndexByte(k, '('); i >= 0 {
			k = k[:i]
		}
		var res struct{ Resolution struct{ Tarball string } }
		_ = node.Decode(&res) // a shape it cannot read has no tarball
		var pkg Pkg
		if m := pnpmV5.FindStringSubmatch(k); m != nil {
			pkg = Pkg{m[1], m[2]}
		} else if m := pnpmV6.FindStringSubmatch(k); m != nil {
			pkg = Pkg{m[1], m[2]}
		}
		if pkg != (Pkg{}) {
			out = append(out, pkg)
			// pnpm installs the tarball of `resolution`, whatever the key says
			if tb := res.Resolution.Tarball; tarballLike.MatchString(tb) {
				if t, ok := registryTarball(tb); !ok || t != pkg {
					unknown = append(unknown, key)
					if ok {
						out[len(out)-1] = t // pnpm installs the tarball
					}
				}
			}
		} else if !pnpmLocal.MatchString(k) || pnpmTarball.MatchString(k) {
			unknown = append(unknown, key)
		}
	}
	if len(unknown) > 0 {
		return out, fmt.Errorf("pnpm-lock: %d package keys not understood, e.g. %q", len(unknown), slices.Min(unknown))
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

// scanYarnV1 collects each top-level entry's 2-space-indented version, resolution and resolved.
// Any line it cannot classify, or a repeated version, is an error: fail closed.
func scanYarnV1(b []byte) ([]yarnEntry, error) {
	var out []yarnEntry
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := strings.TrimRight(sc.Text(), " ")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Header line: not indented, ends with ":"
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			out = append(out, yarnEntry{key: strings.Trim(strings.TrimSuffix(line, ":"), `" `)})
			continue
		}
		if !strings.HasPrefix(line, " ") || len(out) == 0 {
			return nil, fmt.Errorf("yarn.lock v1: unexpected line %q", line)
		}
		// Indent is in 2-space steps (yarn rejects odd indents); only 2-space lines are entry fields
		if indent := len(line) - len(strings.TrimLeft(line, " ")); indent%2 != 0 {
			return nil, fmt.Errorf("yarn.lock v1: odd indentation in %q", line)
		} else if indent != 2 {
			continue
		}
		e := &out[len(out)-1]
		t := strings.TrimSpace(line)
		for _, f := range []struct {
			name string
			dst  *string
		}{{"version", &e.Version}, {"resolution", &e.Resolution}, {"resolved", &e.Resolved}} {
			if strings.HasPrefix(t, f.name+" ") || strings.HasPrefix(t, f.name+":") {
				if *f.dst != "" {
					if f.name == "version" {
						return nil, fmt.Errorf("yarn.lock v1: entry %q has two versions", e.key)
					}
					continue
				}
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
			name, v, workspace, err := berryLocator(e.Resolution, 1)
			if err != nil {
				return nil, fmt.Errorf("yarn.lock: entry %q: %w", e.key, err)
			}
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
// version is set only for npm: references; name is "" if the locator has no name. Patch locators
// nest at most maxLocatorDepth deep.
func berryLocator(res string, depth int) (name, version string, workspace bool, err error) {
	if depth > maxLocatorDepth {
		return "", "", false, fmt.Errorf("resolution nested more than %d deep", maxLocatorDepth)
	}
	at := strings.Index(res[1:], "@")
	if at < 0 {
		return "", "", false, nil
	}
	name, ref := res[:at+1], res[at+2:]
	switch {
	case strings.HasPrefix(ref, "workspace:"):
		return name, "", true, nil
	case strings.HasPrefix(ref, "npm:"):
		v, _, _ := strings.Cut(ref[len("npm:"):], "::")
		return name, v, false, nil
	case strings.HasPrefix(ref, "patch:"):
		src, _, _ := strings.Cut(ref[len("patch:"):], "#")
		if inner, err := url.PathUnescape(src); err == nil && inner != "" {
			n, v, ws, err := berryLocator(inner, depth+1)
			if err != nil || n != "" {
				return n, v, ws, err
			}
		}
	}
	return name, "", false, nil
}

const maxLocatorDepth = 16

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
