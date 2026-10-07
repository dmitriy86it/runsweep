// Package npm finds packages in npm/pnpm/yarn lockfiles.
package npm

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
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

// ParseYarnLock handles yarn v1 and berry.
func ParseYarnLock(b []byte) ([]Pkg, error) {
	var out []Pkg
	var names map[string]bool // tracks distinct real package names for current entry
	var version string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Header line: not indented, ends with ":"
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			// Emit any pending entry
			if version != "" && names != nil {
				for name := range names {
					out = append(out, Pkg{name, version})
				}
			}

			headerContent := strings.TrimSuffix(line, ":")
			headerContent = strings.Trim(headerContent, `" `)

			// Skip __metadata
			if headerContent == "__metadata" {
				names = nil
				version = ""
				continue
			}

			// Parse all comma-separated specs
			specs := strings.Split(headerContent, ",")
			names = make(map[string]bool)
			for _, spec := range specs {
				spec = strings.TrimSpace(spec)
				if name := extractYarnPackageName(spec); name != "" {
					names[name] = true
				}
			}
			version = ""
			continue
		}
		// Version line: indented, starts with "version"
		t := strings.TrimSpace(line)
		if names != nil && len(names) > 0 && (strings.HasPrefix(t, "version ") || strings.HasPrefix(t, "version:")) {
			v := strings.Trim(strings.TrimSpace(strings.TrimLeft(strings.TrimPrefix(t, "version"), ": ")), `"`)
			// Skip workspace entries
			if v != "0.0.0-use.local" {
				version = v
			} else {
				names = nil
			}
		}
	}
	// Emit final pending entry
	if version != "" && names != nil {
		for name := range names {
			out = append(out, Pkg{name, version})
		}
	}
	return out, sc.Err()
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
