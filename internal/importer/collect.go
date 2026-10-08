package importer

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// found accumulates what the importer extracted from OSV records and flags.
type found struct {
	npm     map[string]map[string]bool // package -> versions
	actions map[string]map[string]bool // owner/repo -> commit SHAs
	notes   []string                   // YAML comment lines (without "# ")
	warns   []string                   // stderr warnings
	refs    []string
	seen    map[string]bool // OSV ids already added
}

func newFound() *found {
	return &found{npm: map[string]map[string]bool{}, actions: map[string]map[string]bool{}, seen: map[string]bool{}}
}

// both records the same text as a YAML note and a warning.
func (f *found) both(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	f.notes = append(f.notes, s)
	f.warns = append(f.warns, s)
}

// addVuln takes npm versions and GitHub Actions hints from one OSV record.
// It reports whether the record had any npm or GitHub Actions entry.
func (f *found) addVuln(v *Vuln) bool {
	f.seen[v.ID] = true
	f.refs = append(f.refs, "https://osv.dev/vulnerability/"+v.ID)
	useful := false
	for _, a := range v.Affected {
		switch a.Package.Ecosystem {
		case "npm":
			useful = true
			name := a.Package.Name
			if !ValidNPMName(name) {
				f.both("%s: skipped invalid npm package name %q", v.ID, name)
				continue
			}
			if len(a.Versions) == 0 {
				f.both("%s: %s affected by range only (%s) — versions not listed, add manually", v.ID, name, rangeText(a))
				continue
			}
			for _, ver := range a.Versions {
				if !validVersion(ver) {
					f.both("%s: %s: skipped invalid version %q", v.ID, name, ver)
					continue
				}
				f.addNPM(name, ver)
			}
		case "GitHub Actions":
			useful = true
			if !ValidRepo(a.Package.Name) {
				f.both("%s: skipped invalid action name %q", v.ID, a.Package.Name)
				continue
			}
			f.both("%s: affects %s %s — pass the compromised commit with --action %s@SHA", v.ID, a.Package.Name, rangeText(a), a.Package.Name)
		}
	}
	return useful
}

func (f *found) addNPM(name, ver string) {
	if f.npm[name] == nil {
		f.npm[name] = map[string]bool{}
	}
	f.npm[name][ver] = true
}

// addAction parses owner/repo@sha40.
func (f *found) addAction(s string) error {
	repo, sha, _ := strings.Cut(s, "@")
	if !ValidRepo(repo) || !shaRe.MatchString(sha) {
		return fmt.Errorf("--action %q: want owner/repo@<40 lowercase hex>", s)
	}
	if f.actions[repo] == nil {
		f.actions[repo] = map[string]bool{}
	}
	f.actions[repo][sha] = true
	return nil
}

// versionLess orders by numeric major.minor.patch, then by the whole string.
func versionLess(a, b string) bool {
	na, oka := triple(a)
	nb, okb := triple(b)
	switch {
	case oka && okb && na != nb:
		return slices.Compare(na[:], nb[:]) < 0
	case oka != okb:
		return oka // parseable versions first
	}
	return a < b
}

func triple(v string) ([3]int, bool) {
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	var n [3]int
	if len(parts) != 3 {
		return n, false
	}
	for i, p := range parts {
		x, err := strconv.Atoi(p)
		if err != nil {
			return n, false
		}
		n[i] = x
	}
	return n, true
}

func sortedVersions(m map[string]bool) []string {
	var out []string
	for v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return versionLess(out[i], out[j]) })
	return out
}
