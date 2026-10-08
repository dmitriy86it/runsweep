package scan

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dmitriy86it/runsweep/internal/gh"
	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/cassette"
	"gopkg.in/dnaeon/go-vcr.v4/pkg/recorder"
)

// TestDemoCassette replays a real scan of dmitriy86it/runsweep-demo against examples/drill.yaml.
// Record with: RUNSWEEP_RECORD=1 GITHUB_TOKEN=$(gh auth token) go test ./internal/scan -run Demo
func TestDemoCassette(t *testing.T) {
	mode := recorder.ModeReplayOnly
	if os.Getenv("RUNSWEEP_RECORD") == "1" {
		mode = recorder.ModeRecordOnly
	}
	r, err := recorder.New("testdata/cassettes/demo",
		recorder.WithMode(mode),
		recorder.WithSkipRequestLatency(true),
		recorder.WithMatcher(func(r *http.Request, i cassette.Request) bool {
			if isBlob(r.URL) { // signed log URLs are stored without their query
				r = r.Clone(r.Context())
				r.URL.RawQuery, r.Form = "", nil
			}
			return match(r, i)
		}),
		recorder.WithHook(func(i *cassette.Interaction) error {
			delete(i.Request.Headers, "Authorization")
			delete(i.Response.Headers, "Set-Cookie")
			delete(i.Response.Headers, "Vary") // lists "Authorization"; keeps the cassette grep-clean
			// Drop the SAS signature of job-log URLs from the request and the API redirect.
			if u, err := url.Parse(i.Request.URL); err == nil && isBlob(u) {
				u.RawQuery = ""
				i.Request.URL, i.Request.Form = u.String(), nil
			}
			for k, loc := range i.Response.Headers["Location"] {
				if u, err := url.Parse(loc); err == nil && isBlob(u) {
					u.RawQuery = ""
					i.Response.Headers["Location"][k] = u.String()
				}
			}
			return nil
		}, recorder.BeforeSaveHook), // AfterCaptureHook would also rewrite the live redirect and break the log download
	)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Stop() }()
	// The same client serves API calls and the signed log download, so both are recorded.
	c, err := gh.New(&http.Client{Transport: r}, os.Getenv("GITHUB_TOKEN"), "")
	if err != nil {
		t.Fatal(err)
	}
	inc, err := incident.Load("../../examples/drill.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer func(n int) { concurrency = n }(concurrency)
	concurrency = 1
	res, err := Run(context.Background(), c, inc, Options{Repos: []string{"dmitriy86it/runsweep-demo"}, Lookback: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if a, p, u := res.Count(model.Affected), res.Count(model.Possible), res.Count(model.Unchecked); a != 3 || p != 0 || u != 0 {
		t.Fatalf("affected/possible/unchecked = %d/%d/%d, want 3/0/0", a, p, u)
	}
	want := []model.RotationItem{
		{Name: "aws role arn:aws:iam::123456789012:role/demo-deploy", Tier: 1},
		{Name: "DEMO_NPM_TOKEN", Tier: 2},
		{Name: "DEMO_SLACK_WEBHOOK", Tier: 3},
	}
	if len(res.Rotation) != len(want) {
		t.Fatalf("rotation = %+v, want %+v", res.Rotation, want)
	}
	for k, w := range want {
		if g := res.Rotation[k]; g.Name != w.Name || g.Tier != w.Tier {
			t.Errorf("rotation[%d] = %q tier %d, want %q tier %d", k, g.Name, g.Tier, w.Name, w.Tier)
		}
	}
	both := slices.ContainsFunc(res.Findings, func(f model.Finding) bool {
		has := func(kind, sub string) bool {
			return slices.ContainsFunc(f.Evidence, func(e model.Evidence) bool {
				return e.Kind == kind && strings.Contains(e.Detail, sub)
			})
		}
		return has("npm", "is-number@7.0.0") && has("action", "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1")
	})
	if !both {
		t.Errorf("no finding carries both npm and action evidence: %+v", res.Findings)
	}
}

var match = cassette.NewDefaultMatcher(cassette.WithIgnoreAuthorization())

func isBlob(u *url.URL) bool { return strings.HasSuffix(u.Hostname(), ".blob.core.windows.net") }
