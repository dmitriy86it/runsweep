package workflow

import (
	"os"
	"strings"
	"testing"
)

func FuzzWorkflowParse(f *testing.F) {
	f.Add([]byte("jobs:\n  build:\n    name: Build ${{ matrix.os }}\n    runs-on: x\n    steps:\n      - run: npm ci\n"), "Build (ubuntu, 20)")
	f.Add([]byte("jobs:\n  a:\n    uses: ./.github/workflows/b.yml\n    secrets: inherit\n  b: {name: a}\n"), "a / c")
	f.Add([]byte("x: &a [*a]\n"), "")
	f.Fuzz(func(t *testing.T, b []byte, apiName string) {
		wf, err := Parse(b)
		if err != nil {
			return
		}
		j, ok := wf.FindJob(apiName)
		if !ok {
			return
		}
		if wf.Jobs[j.ID] != j {
			t.Fatalf("FindJob(%q) returned job %q not in wf.Jobs", apiName, j.ID)
		}
		_ = wf.Exposure(j)
	})
}

func FuzzParseCall(f *testing.F) {
	f.Add("./.github/workflows/x.yml")
	f.Add("o/r/.github/workflows/x.yml@0123456789abcdef0123456789abcdef01234567")
	f.Add("o/r/.github/workflows/x.yml@main")
	f.Fuzz(func(t *testing.T, uses string) {
		c, ok := ParseCall(uses)
		if ok && !workflowPath(c.Path) {
			t.Fatalf("ParseCall(%q) ok with path %q", uses, c.Path)
		}
	})
}

func FuzzParseTokenPerms(f *testing.F) {
	b, err := os.ReadFile("../match/actions/testdata/job.log")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(b))
	f.Add("2026-01-01T00:00:00.0000000Z ##[group]GITHUB_TOKEN Permissions\nContents: read\n##[endgroup]\n")
	f.Add("Z \n")
	f.Fuzz(func(t *testing.T, log string) {
		for k, v := range ParseTokenPerms(log) {
			if k != strings.TrimSpace(k) || k != strings.ToLower(k) || v != strings.TrimSpace(v) {
				t.Fatalf("untrimmed or mixed-case permission %q: %q", k, v)
			}
		}
	})
}
