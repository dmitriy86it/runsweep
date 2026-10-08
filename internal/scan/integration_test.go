package scan

import (
	"context"
	"net/http"
	"os"
	"testing"

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
		recorder.WithMatcher(cassette.NewDefaultMatcher(cassette.WithIgnoreAuthorization())),
		recorder.WithHook(func(i *cassette.Interaction) error {
			delete(i.Request.Headers, "Authorization")
			delete(i.Response.Headers, "Set-Cookie")
			delete(i.Response.Headers, "Vary") // lists "Authorization"; keeps the cassette grep-clean
			return nil
		}, recorder.AfterCaptureHook),
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
	res, err := Run(context.Background(), c, inc, Options{Repos: []string{"dmitriy86it/runsweep-demo"}, Concurrency: 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Count(model.Affected) == 0 || res.Count(model.Unchecked) != 0 || len(res.Rotation) != 3 || res.Rotation[0].Tier != 1 {
		t.Fatalf("%+v", res)
	}
}
