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

// computeWindow drops versions published before W − 7d (unless keepAll) from npm
// and derives the window from registry times. W is the median (lower middle) of
// each package's earliest bad publish; for one or two packages that is the minimum.
func computeWindow(npm map[string]map[string]bool, times map[string]PkgTimes, keepAll bool, now time.Time) (time.Time, time.Time, []string, error) {
	var notes []string
	var earliest []time.Time
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
				notes = append(notes, fmt.Sprintf("%s@%s: unpublished, publish time unknown; kept", name, v))
				continue
			}
			if first.IsZero() || t.Before(first) {
				first = t
			}
		}
		if !first.IsZero() {
			earliest = append(earliest, first)
		}
	}
	if len(earliest) == 0 {
		return time.Time{}, time.Time{}, notes, errNoTimes
	}
	sort.Slice(earliest, func(i, j int) bool { return earliest[i].Before(earliest[j]) })
	wave := earliest[(len(earliest)-1)/2]
	cut := wave.Add(-waveSlack)

	type drop struct {
		at  time.Time
		ref string
	}
	var dropped []drop
	if keepAll {
		notes = append(notes, "--keep-all: no version dropped by publish time")
	} else {
		for _, name := range sortedKeys(npm) {
			for v := range npm[name] {
				if t, ok := times[name].Times[v]; ok && t.Before(cut) {
					dropped = append(dropped, drop{t, name + "@" + v})
					delete(npm[name], v)
				}
			}
			if len(npm[name]) == 0 {
				delete(npm, name)
			}
		}
	}
	if len(dropped) > 0 {
		sort.Slice(dropped, func(i, j int) bool { return dropped[i].at.Before(dropped[j].at) })
		notes = append(notes, fmt.Sprintf("dropped %d version(s) published before %s (wave start %s minus 7 days; --keep-all keeps them):",
			len(dropped), cut.UTC().Format(time.RFC3339), wave.UTC().Format(time.RFC3339)))
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
