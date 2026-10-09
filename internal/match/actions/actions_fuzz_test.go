package actions

import (
	"os"
	"testing"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
)

func FuzzMatchLog(f *testing.F) {
	b, err := os.ReadFile("testdata/job.log")
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(b))
	f.Add("Download action repository 'o/r@v1' (SHA:0123456789abcdef0123456789abcdef01234567)\n")
	f.Add("##[group]Download immutable action package 'o/r@v1'\nSource commit SHA: 0123456789abcdef0123456789abcdef01234567\n")
	bad := []incident.Action{{Uses: "o/r", SHAs: []string{"0123456789abcdef0123456789abcdef01234567"}}}
	f.Fuzz(func(t *testing.T, log string) {
		for _, d := range ParseDownloads(log) {
			if d.SHA != "" && validSHA(d.SHA) == "" {
				t.Fatalf("malformed SHA kept: %+v", d)
			}
		}
		st, ev := MatchLog(log, bad)
		if st != model.Clean && len(ev) == 0 {
			t.Fatalf("status %v without evidence", st)
		}
	})
}
