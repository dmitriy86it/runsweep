// Package actions matches compromised GitHub Action SHAs.
package actions

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
)

// Download is a compromised action download found in a job log.
type Download struct{ Uses, Ref, SHA string }

var downloadRe = regexp.MustCompile(`Download action repository '([^'@]+)@([^']+)' \(SHA:([0-9a-f]{40})\)`)
var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ParseDownloads extracts the resolved SHA of every action a job downloaded.
func ParseDownloads(log string) []Download {
	var out []Download
	for _, m := range downloadRe.FindAllStringSubmatch(log, -1) {
		out = append(out, Download{Uses: m[1], Ref: m[2], SHA: m[3]})
	}
	return out
}

// repoKey normalizes "Owner/Repo/sub/path" to "owner/repo".
func repoKey(uses string) string {
	parts := strings.SplitN(strings.ToLower(uses), "/", 3)
	if len(parts) < 2 {
		return ""
	}
	return parts[0] + "/" + parts[1]
}

func badSHAs(bad []incident.Action) map[string]map[string]bool {
	m := map[string]map[string]bool{}
	for _, a := range bad {
		k := repoKey(a.Uses)
		if m[k] == nil {
			m[k] = map[string]bool{}
		}
		for _, s := range a.SHAs {
			m[k][s] = true
		}
	}
	return m
}

// MatchLog returns AFFECTED when the job log shows a compromised SHA was downloaded.
func MatchLog(log string, bad []incident.Action) (model.Status, []model.Evidence) {
	b := badSHAs(bad)
	st, ev := model.Clean, []model.Evidence(nil)
	for _, d := range ParseDownloads(log) {
		if b[repoKey(d.Uses)][d.SHA] {
			st = model.Affected
			ev = append(ev, model.Evidence{Kind: "action", Detail: fmt.Sprintf("job log: downloaded %s@%s (SHA %s)", d.Uses, d.Ref, d.SHA)})
		}
	}
	return st, ev
}

// MatchUses is the fallback when the log is gone: judge by `uses:` in the workflow.
func MatchUses(uses []string, bad []incident.Action) (model.Status, []model.Evidence) {
	b := badSHAs(bad)
	st, ev := model.Clean, []model.Evidence(nil)
	for _, u := range uses {
		name, ref, ok := strings.Cut(u, "@")
		if !ok || strings.HasPrefix(u, "./") || strings.HasPrefix(u, "docker://") {
			continue
		}
		shas := b[repoKey(name)]
		if shas == nil {
			continue
		}
		switch {
		case shas[ref]:
			st = model.Affected
			ev = append(ev, model.Evidence{Kind: "action", Detail: fmt.Sprintf("workflow pins %s to compromised SHA (log unavailable)", u)})
		case shaRe.MatchString(ref):
			// pinned to a different, known-good SHA
		default:
			st = model.Worse(st, model.Possible)
			ev = append(ev, model.Evidence{Kind: "action", Detail: fmt.Sprintf("workflow uses %s (mutable ref); job log unavailable, resolved SHA unknown", u)})
		}
	}
	return st, ev
}
