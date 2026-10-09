package importer

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/runsweep/runsweep/internal/incident"
)

var update = flag.Bool("update", false, "rewrite golden files")

func importWith(t *testing.T, c *Client, o Options) ([]byte, []string, error) {
	t.Helper()
	var warns []string
	o.Now = importNow
	o.Warnf = func(f string, a ...any) { warns = append(warns, fmt.Sprintf(f, a...)) }
	out, err := c.Import(context.Background(), o)
	return out, warns, err
}

func TestImportGolden(t *testing.T) {
	c, _ := fixtures(t, nil)
	out, _, err := importWith(t, c, Options{
		IDs:      []string{"MAL-2026-17631", "MAL-2026-17653", "MAL-2025-125", "CVE-2025-30066"},
		Packages: []string{"axios"},
		Actions:  []string{"tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67"},
	})
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "import.golden.yaml")
	if *update {
		if err := os.WriteFile(golden, out, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden) //nolint:gosec // G304: fixed testdata path
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("golden mismatch (run go test ./internal/importer -run Golden -update):\n%s", out)
	}
}

func TestImportRoundTrip(t *testing.T) {
	c, _ := fixtures(t, nil)
	out, _, err := importWith(t, c, Options{IDs: []string{"MAL-2026-2307"}, Title: "q\"uote\nnew line   #hash", ID: "axios-test"})
	if err != nil {
		t.Fatal(err)
	}
	inc, err := incident.Parse(out)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	if inc.ID != "axios-test" || inc.Title != "q\"uote\nnew line   #hash" || len(inc.NPM) != 1 ||
		strings.Join(inc.NPM[0].Versions, ",") != "0.30.4,1.14.1" || inc.Refs[0] != "https://osv.dev/vulnerability/MAL-2026-2307" {
		t.Fatalf("%+v", inc)
	}
	if inc.Window.Start.Format(time.RFC3339) != "2026-03-31T00:21:00Z" || inc.Window.End.Format(time.RFC3339) != "2026-09-18T13:54:00Z" {
		t.Fatalf("window %+v", inc.Window)
	}
}

func TestImportDefaultIDAndTitle(t *testing.T) {
	c, _ := fixtures(t, nil)
	out, _, err := importWith(t, c, Options{IDs: []string{"MAL-2026-17631", "MAL-2026-17653", "MAL-2025-125", "MAL-2026-2307"}, KeepAll: true})
	if err != nil {
		t.Fatal(err)
	}
	inc, _ := incident.Parse(out)
	if inc.ID != "import-2024-12-29" || inc.Title != "Imported from OSV: MAL-2026-17631, MAL-2026-17653, MAL-2025-125 +1 more" {
		t.Fatalf("%q %q", inc.ID, inc.Title)
	}
}

func TestImportNothing(t *testing.T) {
	c, _ := fixtures(t, nil)
	// Range-only lodash entries: no registry fixture (404), so every version and no publish time.
	_, warns, err := importWith(t, c, Options{IDs: []string{"GHSA-35jh-r3h4-6jhm"}})
	if !errors.Is(err, errNoTimes) {
		t.Fatalf("range-only record without registry data: want errNoTimes, got %v", err)
	}
	if !strings.Contains(strings.Join(warns, "|"), "lodash: removed from npm, versions unknown") {
		t.Fatalf("warns %q", warns)
	}
	if _, _, err := importWith(t, c, Options{Packages: []string{"left-pad"}}); !errors.Is(err, ErrNothing) {
		t.Fatalf("package without MAL records: want ErrNothing, got %v", err)
	}
}

func TestImportActionOnly(t *testing.T) {
	c, calls := fixtures(t, nil)
	sha := "tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67"
	if _, _, err := importWith(t, c, Options{Actions: []string{sha}, Since: importNow.Add(-time.Hour)}); err == nil ||
		!strings.Contains(err.Error(), "pass --since and --until for action-only incidents") {
		t.Fatalf("want window error, got %v", err)
	}
	out, _, err := importWith(t, c, Options{Actions: []string{sha, sha}, Since: importNow.Add(-time.Hour), Until: importNow, ID: "tj"})
	if err != nil {
		t.Fatal(err)
	}
	inc, _ := incident.Parse(out)
	if len(inc.Actions) != 1 || len(inc.Actions[0].SHAs) != 1 || calls.Load() != 0 {
		t.Fatalf("%+v, %d requests", inc, calls.Load())
	}
}

func TestImportRejectsBadFlagsBeforeNetwork(t *testing.T) {
	c, calls := fixtures(t, nil)
	for _, o := range []Options{
		{IDs: []string{"../x"}},
		{Packages: []string{"../x"}},
		{Actions: []string{"o/r@0E58ED8671D6B60D0890C21B07F8835ACE038E67"}},
		{Actions: []string{"o/r"}},
		{IDs: []string{"MAL-2026-2307"}, ID: "Bad ID"},
	} {
		if _, _, err := importWith(t, c, o); err == nil {
			t.Errorf("%+v: want error", o)
		}
	}
	if calls.Load() != 0 {
		t.Fatalf("%d requests", calls.Load())
	}
}

func TestImportSinceUntilOverride(t *testing.T) {
	c, _ := fixtures(t, nil)
	since, until := time.Date(2026, 3, 31, 0, 0, 0, 0, time.UTC), time.Date(2026, 3, 31, 4, 0, 0, 0, time.UTC)
	out, _, err := importWith(t, c, Options{IDs: []string{"MAL-2026-2307"}, Since: since, Until: until})
	if err != nil {
		t.Fatal(err)
	}
	inc, _ := incident.Parse(out)
	if !inc.Window.Start.Equal(since) || !inc.Window.End.Equal(until) || !bytes.Contains(out, []byte("# end overridden with --until")) {
		t.Fatalf("%+v\n%s", inc.Window, out)
	}
}

func TestImportHostileRecordStaysValidYAML(t *testing.T) {
	c, _ := fixtures(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/osv/v1/vulns/MAL-0000-1" {
			return false
		}
		// Not a fixture: a record crafted to try YAML injection through OSV fields.
		_, _ = w.Write([]byte(`{"id":"MAL-0000-1","affected":[
			{"package":{"ecosystem":"npm","name":"evil\nrefs: [x]"},"versions":["1.0.0"]},
			{"package":{"ecosystem":"npm","name":"axios"},"versions":["1.14.1\"]}\nid: pwned","1.14.1"]}]}`))
		return true
	})
	out, warns, err := importWith(t, c, Options{IDs: []string{"MAL-0000-1"}})
	if err != nil {
		t.Fatal(err)
	}
	inc, err := incident.Parse(out)
	if err != nil || inc.ID == "pwned" || len(inc.NPM) != 1 || len(inc.NPM[0].Versions) != 1 {
		t.Fatalf("%v %+v\n%s", err, inc, out)
	}
	if len(warns) != 2 {
		t.Fatalf("want 2 warnings (bad name, bad version), got %q", warns)
	}
}

func TestImportExpandsOpenRange(t *testing.T) {
	c, _ := fixtures(t, nil)
	out, _, err := importWith(t, c, Options{IDs: []string{"MAL-2022-1122"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`{name: "arpan-package", versions: ["0.0.1-security", "2.0.5"]}`,
		"# arpan-package: OSV range [0, ∞) — registry versions in range included",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestImportOpenRangeRegistryMissing(t *testing.T) {
	c, _ := fixtures(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasPrefix(r.URL.Path, "/npm/") {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		return false
	})
	out, warns, err := importWith(t, c, Options{IDs: []string{"MAL-2022-1122"}, Since: importNow.Add(-time.Hour), Until: importNow})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`{name: "arpan-package", versions: ["*"]}`, "# arpan-package: OSV range [0, ∞) — removed from npm, versions unknown — every version treated as malicious"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %q in\n%s", want, out)
		}
	}
	if !strings.Contains(strings.Join(warns, "|"), "arpan-package: removed from npm, versions unknown — every version treated as malicious") {
		t.Fatalf("warns %q", warns)
	}
}

func TestImportActionHintNeedsWindow(t *testing.T) {
	c, _ := fixtures(t, nil)
	sha := "tj-actions/changed-files@0e58ed8671d6b60d0890c21b07f8835ace038e67"
	for _, o := range []Options{
		{IDs: []string{"GHSA-mrrh-fwg8-r2c3"}, Actions: []string{sha}},
		{IDs: []string{"GHSA-mrrh-fwg8-r2c3"}, Actions: []string{sha}, Since: importNow.Add(-time.Hour)},
	} {
		if _, _, err := importWith(t, c, o); err == nil || !strings.Contains(err.Error(), "pass --since and --until for action-only incidents") {
			t.Errorf("%+v: want window error, got %v", o, err)
		}
	}
	out, _, err := importWith(t, c, Options{IDs: []string{"GHSA-mrrh-fwg8-r2c3"}, Actions: []string{sha}, Since: importNow.Add(-time.Hour), Until: importNow})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := incident.Parse(out); err != nil {
		t.Fatal(err)
	}
}

func TestImportExpandsRangeOnlyOpenEntry(t *testing.T) {
	c, _ := fixtures(t, nil)
	out, _, err := importWith(t, c, Options{IDs: []string{"MAL-2026-2300"}, KeepAll: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`{name: "eslint-validator", versions: ["0.0.1-security", "1.0.0", "1.0.1", "1.0.2", "1.0.3", "1.0.4"]}`,
		"# eslint-validator: OSV range [0, ∞) — registry versions in range included",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "add manually") {
		t.Errorf("open range-only entry needs no manual note:\n%s", out)
	}
}

func TestImportOpenRangeOnlyRegistryMissing(t *testing.T) {
	c, _ := fixtures(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasPrefix(r.URL.Path, "/npm/") {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		return false
	})
	if _, _, err := importWith(t, c, Options{IDs: []string{"MAL-2026-2300"}}); !errors.Is(err, errNoTimes) {
		t.Fatalf("want errNoTimes, got %v", err)
	}
	out, warns, err := importWith(t, c, Options{IDs: []string{"MAL-2026-2300"}, Since: importNow.Add(-time.Hour), Until: importNow})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `{name: "eslint-validator", versions: ["*"]}`) {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(strings.Join(warns, "|"), "eslint-validator: removed from npm, versions unknown") {
		t.Fatalf("warns %q", warns)
	}
}

func TestImportAliasAlreadyImported(t *testing.T) {
	c, _ := fixtures(t, nil)
	out, warns, err := importWith(t, c, Options{IDs: []string{"GHSA-mrrh-fwg8-r2c3", "CVE-2025-30066", "MAL-2026-2307"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "# CVE-2025-30066: no npm or GitHub Actions entries; alias GHSA-mrrh-fwg8-r2c3 already imported") {
		t.Errorf("missing note:\n%s", out)
	}
	for _, w := range warns {
		if strings.HasPrefix(w, "CVE-2025-30066") {
			t.Errorf("unexpected warning %q", w)
		}
	}
}

func TestImportRegistry404WithExplicitWindow(t *testing.T) {
	c, _ := fixtures(t, func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasPrefix(r.URL.Path, "/npm/") {
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		return false
	})
	since, until := importNow.Add(-48*time.Hour), importNow.Add(-time.Hour)
	out, _, err := importWith(t, c, Options{IDs: []string{"MAL-2026-2307"}, Since: since, Until: until})
	if err != nil {
		t.Fatal(err)
	}
	inc, err := incident.Parse(out)
	if err != nil || !inc.Window.Start.Equal(since) || !inc.Window.End.Equal(until) {
		t.Fatalf("%v %+v", err, inc)
	}
}

func TestSameIncident(t *testing.T) {
	a := &incident.Incident{ID: "x", Title: "t", Refs: []string{"r"}, NPM: []incident.NPMPackage{{Name: "n", Versions: []string{"1.0.0"}}}}
	b := *a
	if err := sameIncident(a, &b); err != nil {
		t.Fatal(err)
	}
	b.NPM = []incident.NPMPackage{{Name: "n", Versions: []string{"1.0.1"}}}
	if sameIncident(a, &b) == nil {
		t.Fatal("version change not detected")
	}
}

func TestRenderNotesStripLineBreaks(t *testing.T) {
	inc := &incident.Incident{ID: "x", Title: "t", Refs: []string{"https://osv.dev/vulnerability/X-1"}}
	out := string(render(inc, []string{"a\rb\u2028c\u2029d\ne"}, importNow))
	if !strings.Contains(out, "# a b c d e\n") {
		t.Fatalf("%s", out)
	}
}

func TestImportWarnsDroppedCluster(t *testing.T) {
	c, _ := fixtures(t, nil)
	out, warns, err := importWith(t, c, Options{IDs: []string{"MAL-2025-125", "MAL-2026-2307"}})
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(warns, "\n")
	if !strings.Contains(all, "dropped 1 version(s) of packages published in earlier clusters") || !strings.Contains(all, "netflixdesign@1.0.1") {
		t.Fatalf("warns %q", warns)
	}
	if !strings.Contains(string(out), "#   netflixdesign@1.0.1 (published") {
		t.Fatalf("drop must stay in the comments:\n%s", out)
	}
}

// rangeRecord serves a crafted (not captured) OSV record for eslint-validator, whose
// captured registry document has 0.0.1-security and 1.0.0..1.0.4.
func rangeRecord(t *testing.T, events string) *Client {
	t.Helper()
	c, _ := fixtures(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/osv/v1/vulns/MAL-0000-3" {
			return false
		}
		_, _ = w.Write([]byte(`{"id":"MAL-0000-3","affected":[{"package":{"ecosystem":"npm","name":"eslint-validator"},"ranges":[{"type":"SEMVER","events":[` + events + `]}]}]}`))
		return true
	})
	return c
}

func TestImportSegmentedRange(t *testing.T) {
	c := rangeRecord(t, `{"introduced":"0"},{"fixed":"1.0.1"},{"introduced":"1.0.3"}`)
	out, _, err := importWith(t, c, Options{IDs: []string{"MAL-0000-3"}, KeepAll: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`{name: "eslint-validator", versions: ["0.0.1-security", "1.0.0", "1.0.3", "1.0.4"]}`,
		"# eslint-validator: OSV range [0, 1.0.1), [1.0.3, ∞) — registry versions in range included",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

func TestImportNothingInRange(t *testing.T) {
	c := rangeRecord(t, `{"introduced":"5.0.0"},{"last_affected":"5.1.0"}`)
	out, warns, err := importWith(t, c, Options{IDs: []string{"MAL-0000-3"}, Since: importNow.Add(-time.Hour), Until: importNow})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `{name: "eslint-validator", versions: ["*"]}`) ||
		!strings.Contains(string(out), "# eslint-validator: OSV range [5.0.0, 5.1.0] — no registry version falls in the OSV range — every version treated as malicious") {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(strings.Join(warns, "|"), "eslint-validator: no registry version falls in the OSV range — every version treated as malicious") {
		t.Fatalf("warns %q", warns)
	}
}

func TestImportNoUsableRangeIsEveryVersion(t *testing.T) {
	c, _ := fixtures(t, func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/osv/v1/vulns/MAL-0000-4" {
			return false
		}
		// Not a fixture: one entry with only a fixed event, one with a listed version.
		_, _ = w.Write([]byte(`{"id":"MAL-0000-4","affected":[
			{"package":{"ecosystem":"npm","name":"eslint-validator"},"ranges":[{"type":"SEMVER","events":[{"fixed":"1.0.1"}]}]},
			{"package":{"ecosystem":"npm","name":"eslint-validator"},"versions":["1.0.0"]}]}`))
		return true
	})
	out, warns, err := importWith(t, c, Options{IDs: []string{"MAL-0000-4"}, Since: importNow.Add(-time.Hour), Until: importNow})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `{name: "eslint-validator", versions: ["*"]}`) {
		t.Fatalf("%s", out)
	}
	if !strings.Contains(strings.Join(warns, "|"), "eslint-validator affected by range only (fixed 1.0.1) with no usable start — every version treated as malicious") {
		t.Fatalf("warns %q", warns)
	}
}
