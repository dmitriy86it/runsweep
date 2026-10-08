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

	"github.com/dmitriy86it/runsweep/internal/incident"
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
		IDs:      []string{"MAL-2026-17631", "MAL-2026-17653", "MAL-2025-125", "CVE-2025-30066", "MAL-2026-2300"},
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
	_, warns, err := importWith(t, c, Options{IDs: []string{"MAL-2026-2300"}})
	if !errors.Is(err, ErrNothing) {
		t.Fatalf("range-only record: want ErrNothing, got %v", err)
	}
	if len(warns) == 0 {
		t.Fatal("range-only record must be reported on stderr")
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
