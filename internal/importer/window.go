package importer

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	waveSlack   = 7 * 24 * time.Hour // versions published this long before the wave start are dropped
	maxExamples = 20
)

var errNoTimes = errors.New("window unknown: the npm registry has no publish time for any listed version; pass --since and --until")

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func ceilMinute(t time.Time) time.Time {
	if r := t.Truncate(time.Minute); !r.Equal(t) {
		return r.Add(time.Minute)
	}
	return t
}

// computeWindow drops stray old packages (unless keepAll) from npm and derives
// the window from registry times. Packages are clustered by their earliest bad
// publish time, split at gaps over 7 days; the largest cluster (the latest on a
// tie) is the wave, and clusters before it are dropped whole. A package is
// never partly dropped.
func computeWindow(npm map[string]map[string]bool, times map[string]PkgTimes, keepAll bool, now time.Time) (time.Time, time.Time, []string, error) {
	var notes []string
	type pkg struct {
		name  string
		first time.Time
	}
	var pkgs []pkg
	for _, name := range sortedKeys(npm) {
		pt := times[name]
		if !pt.Found {
			notes = append(notes, fmt.Sprintf("%s: not in the npm registry (HTTP 404); versions kept, publish time unknown", name))
			continue
		}
		var first time.Time
		for _, v := range sortedVersions(npm[name]) {
			t, ok := pt.Times[v]
			if !ok {
				notes = append(notes, fmt.Sprintf("%s@%s: no valid publish time in registry; kept", name, v))
				continue
			}
			if first.IsZero() || t.Before(first) {
				first = t
			}
		}
		if !first.IsZero() {
			pkgs = append(pkgs, pkg{name, first})
		}
	}
	if len(pkgs) == 0 {
		return time.Time{}, time.Time{}, notes, errNoTimes
	}
	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].first.Before(pkgs[j].first) })
	mainStart, mainLen, cur := 0, 0, 0
	for i := 1; i <= len(pkgs); i++ {
		if i == len(pkgs) || pkgs[i].first.Sub(pkgs[i-1].first) > waveSlack {
			if i-cur >= mainLen {
				mainStart, mainLen = cur, i-cur
			}
			cur = i
		}
	}

	type drop struct {
		at  time.Time
		ref string
	}
	var dropped []drop
	if keepAll {
		notes = append(notes, "--keep-all: nothing dropped by publish time")
	} else {
		for _, p := range pkgs[:mainStart] {
			// A package with any version at or after the wave start, or with an unknown time, is kept whole.
			var found []drop
			old := true
			for _, v := range sortedVersions(npm[p.name]) {
				t, ok := times[p.name].Times[v]
				if !ok || !t.Before(pkgs[mainStart].first) {
					old = false
					break
				}
				found = append(found, drop{t, p.name + "@" + v})
			}
			if old {
				dropped = append(dropped, found...)
				delete(npm, p.name)
			}
		}
	}
	if len(dropped) > 0 {
		sort.Slice(dropped, func(i, j int) bool { return dropped[i].at.Before(dropped[j].at) })
		notes = append(notes, fmt.Sprintf("dropped %d version(s) of packages published in earlier clusters, more than 7 days before the wave starting %s (%d packages; --keep-all keeps them):",
			len(dropped), pkgs[mainStart].first.UTC().Format(time.RFC3339), mainLen))
		for _, d := range dropped[:min(len(dropped), maxExamples)] {
			notes = append(notes, fmt.Sprintf("  %s (published %s)", d.ref, d.at.UTC().Format(time.RFC3339)))
		}
		if len(dropped) > maxExamples {
			notes = append(notes, fmt.Sprintf("  … and %d more", len(dropped)-maxExamples))
		}
	}

	var start time.Time
	var startRef string
	var end time.Time
	var endNote string
	var live, unknown []string
	for _, name := range sortedKeys(npm) {
		pt := times[name]
		for _, v := range sortedVersions(npm[name]) {
			if t, ok := pt.Times[v]; ok && (start.IsZero() || t.Before(start)) {
				start, startRef = t, name+"@"+v
			}
			if pt.Published[v] {
				live = append(live, name+"@"+v)
			}
		}
		switch {
		case !pt.Found:
			unknown = append(unknown, name)
		case !pt.Unpublished.IsZero():
			if pt.Unpublished.After(end) {
				end, endNote = pt.Unpublished, fmt.Sprintf("%s time.unpublished.time = %s", name, pt.Unpublished.UTC().Format(time.RFC3339Nano))
			}
		case !pt.Modified.IsZero():
			if pt.Modified.After(end) {
				end, endNote = pt.Modified, fmt.Sprintf("%s time.modified = %s (upper bound: npm exposes no per-version removal time)", name, pt.Modified.UTC().Format(time.RFC3339Nano))
			}
		default:
			unknown = append(unknown, name)
		}
	}
	notes = append(notes, fmt.Sprintf("start: earliest npm publish time among kept versions: %s = %s (rounded down to the minute)",
		startRef, start.UTC().Format(time.RFC3339Nano)))
	start = start.UTC().Truncate(time.Minute)
	if len(live) > 0 || len(unknown) > 0 {
		end = now
		why := []string{}
		if len(live) > 0 {
			why = append(why, "still published: "+examples(live))
		}
		if len(unknown) > 0 {
			why = append(why, "removal time unknown: "+examples(unknown))
		}
		endNote = "import time; " + strings.Join(why, "; ")
	} else {
		endNote = "latest removal: " + endNote
	}
	end = ceilMinute(end.UTC())
	if !end.After(start) {
		end = start.Add(time.Minute)
	}
	notes = append(notes, "end: "+endNote+" (rounded up to the minute)")
	return start, end, notes, nil
}

func examples(s []string) string {
	if len(s) > 5 {
		return strings.Join(s[:5], ", ") + fmt.Sprintf(" and %d more", len(s)-5)
	}
	return strings.Join(s, ", ")
}
