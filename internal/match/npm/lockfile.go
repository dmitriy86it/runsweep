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

// ParseYarnLock handles yarn v1 and berry. npm aliases are reported under the alias name.
func ParseYarnLock(b []byte) ([]Pkg, error) {
	var out []Pkg
	var name string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(line, ":") {
			spec := strings.Trim(strings.SplitN(strings.TrimSuffix(line, ":"), ",", 2)[0], `" `)
			name = ""
			if at := strings.LastIndex(strings.SplitN(spec, "@npm:", 2)[0], "@"); at > 0 {
				name = spec[:at]
			} else if i := strings.Index(spec, "@npm:"); i > 0 {
				name = spec[:i]
			}
			if spec == "__metadata" {
				name = ""
			}
			continue
		}
		t := strings.TrimSpace(line)
		if name != "" && (strings.HasPrefix(t, "version ") || strings.HasPrefix(t, "version:")) {
			v := strings.Trim(strings.TrimSpace(strings.TrimLeft(strings.TrimPrefix(t, "version"), ": ")), `"`)
			out = append(out, Pkg{name, v})
			name = ""
		}
	}
	return out, sc.Err()
}
