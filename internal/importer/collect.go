package importer

import (
	"cmp"
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
	ranges  map[string][]segment // package -> OSV range spans to fill from the registry
	seen    map[string]bool      // OSV ids already added
}

func newFound() *found {
	return &found{ranges: map[string][]segment{}, npm: map[string]map[string]bool{}, actions: map[string]map[string]bool{}, seen: map[string]bool{}}
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
	if !ValidID(v.ID) {
		return false
	}
	if !f.seen[v.ID] {
		f.refs = append(f.refs, "https://osv.dev/vulnerability/"+v.ID)
	}
	f.seen[v.ID] = true
	useful := false
	for _, a := range v.Affected {
		switch a.Package.Ecosystem {
		case "npm":
			useful = true
			name := a.Package.Name
			if !safeNPMName(name) {
				f.both("%s: skipped invalid npm package name %q", v.ID, name)
				continue
			}
			segs, badRange := segments(a)
			if badRange {
				f.notes = append(f.notes, fmt.Sprintf("%s: %s: unparsable range event (%s) — read as 0 / no end, the wider choice", v.ID, name, rangeText(a)))
			}
			// Listed versions are trusted unless the range never ends; then the registry adds the rest.
			if len(a.Versions) == 0 || slices.ContainsFunc(segs, func(s segment) bool { return s.to == "" }) {
				f.ranges[name] = append(f.ranges[name], segs...)
			}
			if len(a.Versions) == 0 {
				if len(segs) > 0 { // the registry fills the versions in
					if f.npm[name] == nil {
						f.npm[name] = map[string]bool{}
					}
					continue
				}
				// D-007: no version and no usable span still means malicious; widen to every version.
				f.npm[name] = map[string]bool{"*": true}
				f.both("%s: %s affected by range only (%s) with no usable start — every version treated as malicious", v.ID, name, rangeText(a))
				continue
			}
			for _, ver := range a.Versions {
				if !validVersion(ver) {
					f.both("%s: %s: skipped invalid version %q", v.ID, name, ver)
					continue
				}
				if t, ok := strings.CutPrefix(ver, "v"); ok {
					f.notes = append(f.notes, fmt.Sprintf("%s: %s: version %q listed as %q (npm versions have no v prefix)", v.ID, name, ver, t))
					ver = t
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

// versionLess orders by SemVer precedence (versionCmp), ties by the whole string.
func versionLess(a, b string) bool {
	c := versionCmp(a, b)
	return c < 0 || c == 0 && a < b
}

// versionCmp compares by SemVer 2.0 §11 precedence, ignoring a leading "v" and
// "+build" metadata. Unparsable versions sort after parsable ones, as strings.
func versionCmp(a, b string) int {
	na, oka := triple(a)
	nb, okb := triple(b)
	switch {
	case oka != okb:
		if oka {
			return -1
		}
		return 1
	case !oka:
		return strings.Compare(a, b)
	}
	if c := slices.Compare(na[:], nb[:]); c != 0 {
		return c
	}
	pa, pb := prerelease(a), prerelease(b)
	switch {
	case pa == pb:
		return 0
	case pa == "": // a release is higher than its prereleases
		return 1
	case pb == "":
		return -1
	}
	ia, ib := strings.Split(pa, "."), strings.Split(pb, ".")
	for i := range min(len(ia), len(ib)) {
		x, y := ia[i], ib[i]
		xn, yn := numeric(x), numeric(y)
		var c int
		switch {
		case xn && yn: // no leading zeros in SemVer: longer is larger
			c = cmp.Or(cmp.Compare(len(x), len(y)), strings.Compare(x, y))
		case xn:
			c = -1
		case yn:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	return cmp.Compare(len(ia), len(ib))
}

func prerelease(v string) string {
	v, _, _ = strings.Cut(v, "+")
	_, p, _ := strings.Cut(v, "-")
	return p
}

func numeric(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
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

// expand adds to f.npm[name] every registry version inside one of its OSV
// range spans. Versions without a publish time count only while still listed.
func (f *found) expand(name string, pt PkgTimes) {
	add := func(v string) {
		if _, ok := triple(v); !ok || !validVersion(v) {
			return
		}
		if slices.ContainsFunc(f.ranges[name], func(s segment) bool { return s.has(v) }) {
			f.addNPM(name, v)
		}
	}
	for v := range pt.Times {
		add(v)
	}
	for v := range pt.Published {
		add(v)
	}
}
