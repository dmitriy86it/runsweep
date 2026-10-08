package importer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

var importNow = time.Date(2026, 10, 8, 12, 0, 30, 0, time.UTC)

func TestTimesUnpublishedPackage(t *testing.T) {
	c, _ := fixtures(t, nil)
	pt, err := c.Times(context.Background(), "netflixdesign")
	if err != nil {
		t.Fatal(err)
	}
	if !pt.Found || len(pt.Published) != 0 || pt.Times["1.0.1"].Format(time.RFC3339Nano) != "2024-12-29T15:34:45.832Z" ||
		pt.Unpublished.Format(time.RFC3339Nano) != "2025-05-23T02:38:28.113Z" || pt.Modified.IsZero() {
		t.Fatalf("%+v", pt)
	}
}

func TestTimesRemovedVersionKeepsTime(t *testing.T) {
	c, _ := fixtures(t, nil)
	pt, err := c.Times(context.Background(), "server-hemera-mongo")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pt.Times["0.0.12"]; !ok || pt.Published["0.0.12"] || !pt.Published["0.0.11"] || !pt.Unpublished.IsZero() {
		t.Fatalf("%+v", pt)
	}
	if _, ok := pt.Times["created"]; ok {
		t.Fatal("created is not a version")
	}
}

func TestTimesScopedNameIsEscaped(t *testing.T) {
	var path string
	c, _ := fixtures(t, func(_ http.ResponseWriter, r *http.Request) bool { path = r.URL.EscapedPath(); return false })
	pt, err := c.Times(context.Background(), "@pinecone-experience/messages")
	if err != nil {
		t.Fatal(err)
	}
	if path != "/npm/@pinecone-experience%2Fmessages" || !pt.Published["99.9.1"] {
		t.Fatalf("path %q %+v", path, pt)
	}
}

func TestTimes404IsNotAnError(t *testing.T) {
	c, _ := fixtures(t, nil)
	pt, err := c.Times(context.Background(), "no-such-package")
	if err != nil || pt.Found {
		t.Fatalf("%+v %v", pt, err)
	}
	if _, err := c.Times(context.Background(), "../x"); err == nil {
		t.Fatal("invalid name must be rejected")
	}
}

// window runs computeWindow over registry fixtures for name@version lists.
func window(t *testing.T, keepAll bool, refs ...string) (map[string]map[string]bool, time.Time, time.Time, []string, error) {
	t.Helper()
	c, _ := fixtures(t, nil)
	f := newFound()
	for _, r := range refs {
		i := strings.LastIndex(r, "@")
		f.addNPM(r[:i], r[i+1:])
	}
	times := map[string]PkgTimes{}
	for name := range f.npm {
		pt, err := c.Times(context.Background(), name)
		if err != nil {
			t.Fatal(err)
		}
		times[name] = pt
	}
	start, end, notes, err := computeWindow(f.npm, times, keepAll, importNow)
	return f.npm, start, end, notes, err
}

func rfc(t time.Time) string { return t.Format(time.RFC3339) }

func TestWindowDropsOldPackageBeforeWave(t *testing.T) {
	// netflixdesign (2024-12-29) sits in an earlier cluster, over 7 days before the 2026-10 wave: dropped whole.
	npm, start, end, notes, err := window(t, false,
		"netflixdesign@1.0.1", "@pinecone-experience/messages@99.9.1", "abbishal-poc-as-dependency@1.3.0", "abbishal-poc-as-dependency@1.3.1")
	if err != nil {
		t.Fatal(err)
	}
	if npm["netflixdesign"] != nil || len(npm) != 2 {
		t.Fatalf("npm %v", npm)
	}
	if rfc(start) != "2026-10-05T16:06:00Z" || rfc(end) != "2026-10-08T12:01:00Z" {
		t.Fatalf("window %s..%s", rfc(start), rfc(end))
	}
	all := strings.Join(notes, "\n")
	for _, want := range []string{
		"dropped 1 version(s) of packages published in earlier clusters, more than 7 days before the wave starting 2026-10-05T16:06:41Z (2 packages; --keep-all keeps them):",
		"  netflixdesign@1.0.1 (published 2024-12-29T15:34:45Z)",
		"end: import time; still published: @pinecone-experience/messages@99.9.1, abbishal-poc-as-dependency@1.3.0, abbishal-poc-as-dependency@1.3.1",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing note %q in\n%s", want, all)
		}
	}
}

func TestWindowKeepAll(t *testing.T) {
	npm, start, _, notes, err := window(t, true, "netflixdesign@1.0.1", "@pinecone-experience/messages@99.9.1", "abbishal-poc-as-dependency@1.3.0")
	if err != nil {
		t.Fatal(err)
	}
	if npm["netflixdesign"] == nil || rfc(start) != "2024-12-29T15:34:00Z" || !strings.Contains(strings.Join(notes, "\n"), "--keep-all") {
		t.Fatalf("%v %s %q", npm, rfc(start), notes)
	}
}

func TestWindowEndFromUnpublish(t *testing.T) {
	_, start, end, notes, err := window(t, false, "netflixdesign@1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if rfc(start) != "2024-12-29T15:34:00Z" || rfc(end) != "2025-05-23T02:39:00Z" ||
		!strings.Contains(strings.Join(notes, "\n"), "end: latest removal: netflixdesign time.unpublished.time = 2025-05-23T02:38:28.113Z") {
		t.Fatalf("%s..%s %q", rfc(start), rfc(end), notes)
	}
}

func TestWindowEndFromModifiedWhenAllRemoved(t *testing.T) {
	// Both packages are still in the registry but the bad versions are gone from "versions".
	_, start, end, notes, err := window(t, true, "axios@1.14.1", "axios@0.30.4", "server-hemera-mongo@0.0.12")
	if err != nil {
		t.Fatal(err)
	}
	if rfc(start) != "2026-03-31T00:21:00Z" || rfc(end) != "2026-09-18T13:54:00Z" {
		t.Fatalf("%s..%s", rfc(start), rfc(end))
	}
	if !strings.Contains(strings.Join(notes, "\n"), "axios time.modified = 2026-09-18T13:53:57.367Z (upper bound") {
		t.Fatalf("%q", notes)
	}
}

func TestWindowUnknownTimes(t *testing.T) {
	// A version missing from "time", and a package the registry no longer has at all: both kept, end = now.
	npm, _, end, notes, err := window(t, false, "server-hemera-mongo@0.0.12", "server-hemera-mongo@0.0.99", "gone-package@1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if !npm["server-hemera-mongo"]["0.0.99"] || !npm["gone-package"]["1.0.0"] || rfc(end) != "2026-10-08T12:01:00Z" {
		t.Fatalf("%v %s", npm, rfc(end))
	}
	all := strings.Join(notes, "\n")
	for _, want := range []string{
		"gone-package: not in the npm registry (HTTP 404); versions kept, publish time unknown",
		"server-hemera-mongo@0.0.99: no valid publish time in registry; kept",
		"removal time unknown: gone-package",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("missing %q in\n%s", want, all)
		}
	}
	if _, _, _, _, err := window(t, false, "gone-package@1.0.0"); !errors.Is(err, errNoTimes) {
		t.Fatalf("no publish time at all: want errNoTimes, got %v", err)
	}
}

// synth builds n packages p0..p(n-1) published gap apart from base, one version each.
func synth(n int, base time.Time, gap time.Duration, prefix string, npm map[string]map[string]bool, times map[string]PkgTimes) {
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("%s%d", prefix, i)
		npm[name] = map[string]bool{"1.0.0": true}
		times[name] = PkgTimes{Found: true, Times: map[string]time.Time{"1.0.0": base.Add(time.Duration(i) * gap)}, Published: map[string]bool{"1.0.0": true}}
	}
}

func TestWindowGapClusters(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	day := 24 * time.Hour
	cases := []struct {
		name  string
		build func(npm map[string]map[string]bool, times map[string]PkgTimes)
		want  int
	}{
		{"continuous 20-day wave", func(n map[string]map[string]bool, m map[string]PkgTimes) { synth(11, base, 2*day, "w", n, m) }, 11},
		{"old stray before wave", func(n map[string]map[string]bool, m map[string]PkgTimes) {
			synth(1, base.AddDate(-2, 0, 0), 0, "old", n, m)
			synth(5, base, day, "w", n, m)
		}, 5},
		{"stray after wave keeps wave", func(n map[string]map[string]bool, m map[string]PkgTimes) {
			synth(10, base, day, "w", n, m)
			synth(1, base.Add(39*day), 0, "late", n, m)
		}, 11},
	}
	for _, c := range cases {
		npm, times := map[string]map[string]bool{}, map[string]PkgTimes{}
		c.build(npm, times)
		if _, _, _, err := computeWindow(npm, times, false, importNow); err != nil || len(npm) != c.want {
			t.Errorf("%s: kept %d, want %d (%v)", c.name, len(npm), c.want, err)
		}
	}
}

func TestWindowNeverSplitsPackage(t *testing.T) {
	base := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	npm := map[string]map[string]bool{"mixed": {"1.0.0": true, "2.0.0": true}}
	times := map[string]PkgTimes{"mixed": {Found: true, Published: map[string]bool{"1.0.0": true, "2.0.0": true},
		Times: map[string]time.Time{"1.0.0": base.AddDate(-1, 0, 0), "2.0.0": base}}}
	synth(3, base, time.Hour, "w", npm, times)
	if _, _, _, err := computeWindow(npm, times, false, importNow); err != nil || len(npm["mixed"]) != 2 {
		t.Fatalf("%v %v", npm["mixed"], err)
	}
}

func TestTimesNullIsNotATime(t *testing.T) {
	c, _ := fixtures(t, func(w http.ResponseWriter, _ *http.Request) bool {
		_, _ = fmt.Fprint(w, `{"time":{"1.0.0":null,"2.0.0":"2026-10-05T16:00:00Z","modified":null},"versions":{"1.0.0":{},"2.0.0":{}}}`)
		return true
	})
	pt, err := c.Times(context.Background(), "hostile")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := pt.Times["1.0.0"]; ok || !pt.Modified.IsZero() {
		t.Fatalf("%+v", pt)
	}
	npm := map[string]map[string]bool{"hostile": {"1.0.0": true, "2.0.0": true}}
	_, _, notes, err := computeWindow(npm, map[string]PkgTimes{"hostile": pt}, false, importNow)
	if err != nil || !npm["hostile"]["1.0.0"] || !strings.Contains(strings.Join(notes, "\n"), "hostile@1.0.0: no valid publish time in registry; kept") {
		t.Fatalf("%v %v %q", npm, err, notes)
	}
}
