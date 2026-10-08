// Package actions matches compromised GitHub Action SHAs.
package actions

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
)

// Download is an action download recorded in a job log.
type Download struct{ Uses, Ref, SHA string }

// downloadRe matches the runner's own download records, anchored to whole lines so that job output
// merely containing the text does not count: "Download action repository 'o/r@ref' (SHA:…)" and the
// immutable action package group, whose "Source commit SHA: …" line follows its Version and Digest
// lines (actions/runner ActionManager.cs). Records appear in "Set up job" and, for the nested
// actions of a local composite action, inside that action's step.
var downloadRe = func() *regexp.Regexp {
	ts := `(?:\d{4}-\d\d-\d\dT[\d:.]+Z )?`
	return regexp.MustCompile(`(?m)^(?:\x{feff})?` + ts + `(?:` +
		`Download action repository '([^'@]+)@([^']+)' \(SHA:([0-9a-f]{40})\)` + `|` +
		`##\[group\]Download immutable action package '([^'@]+)@([^']+)'\r?\n` +
		`(?:` + ts + `(?:Version|Digest): [^\r\n]*\r?\n)*` + ts + `Source commit SHA: ([0-9a-f]{40})` +
		`)\r?$`)
}()
var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// ParseDownloads extracts the resolved SHA of every action a job downloaded, in log order.
func ParseDownloads(log string) []Download {
	var out []Download
	for _, m := range downloadRe.FindAllStringSubmatch(log, -1) {
		if m[1] != "" {
			out = append(out, Download{Uses: m[1], Ref: m[2], SHA: m[3]})
		} else {
			out = append(out, Download{Uses: m[4], Ref: m[5], SHA: m[6]})
		}
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
			detail := fmt.Sprintf("job log: downloaded %s@%s", d.Uses, d.Ref)
			if d.Ref != d.SHA {
				detail += " (SHA " + d.SHA + ")"
			}
			ev = append(ev, model.Evidence{Kind: "action", Detail: detail})
		}
	}
	return st, ev
}

// MatchUses is the fallback when the log is gone: judge by `uses:` in the workflow.
func MatchUses(uses []string, bad []incident.Action) (model.Status, []model.Evidence) {
	return matchRefs(uses, bad, "workflow pins %s to compromised SHA (log unavailable)",
		"workflow uses %s (mutable ref); job log unavailable, resolved SHA unknown")
}

// MatchCalls matches the reusable-workflow refs a job called, which the runner log never lists.
func MatchCalls(calls []string, bad []incident.Action) (model.Status, []model.Evidence) {
	return matchRefs(calls, bad, "reusable workflow %s at compromised SHA", "reusable workflow %s (mutable ref); resolved SHA unknown")
}

func matchRefs(uses []string, bad []incident.Action, pinned, mutable string) (model.Status, []model.Evidence) {
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
			ev = append(ev, model.Evidence{Kind: "action", Detail: fmt.Sprintf(pinned, u)})
		case shaRe.MatchString(ref):
			// pinned to a different, known-good SHA
		default:
			st = model.Worse(st, model.Possible)
			ev = append(ev, model.Evidence{Kind: "action", Detail: fmt.Sprintf(mutable, u)})
		}
	}
	return st, ev
}
