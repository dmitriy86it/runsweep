// Package actions matches compromised GitHub Action SHAs.
package actions

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
)

// Download is an action download recorded in a job log.
type Download struct{ Uses, Ref, SHA string }

// The runner's own download records (actions/runner ActionManager.cs), matched as whole lines after
// the timestamp, so that job output merely containing the text does not count:
// "Download action repository 'o/r@ref' (SHA:…)", and the immutable action package group, whose
// "Source commit SHA: …" line must be one of the 3 lines after the header. Records appear in "Set up job"
// and, for the nested actions of a local composite action, inside that action's step.
var (
	tsRe        = regexp.MustCompile(`^(?:\x{feff})?(?:\d{4}-\d\d-\d\dT[\d:.]+Z )?`)
	downloadRe  = regexp.MustCompile(`^Download action repository '([^'@]+)@([^']*)' \(SHA:([^)]*)\)$`)
	immutableRe = regexp.MustCompile(`^##\[group\]Download immutable action package '([^'@]+)@([^']*)'$`)
)

// validSHA returns s if it is a full commit SHA, else "".
func validSHA(s string) string {
	if model.CommitSHA.MatchString(s) {
		return s
	}
	return ""
}

// ParseDownloads extracts every action download a job log records, in log order. A record whose
// SHA is missing or malformed has SHA "".
func ParseDownloads(log string) []Download {
	var out []Download
	group, left := -1, 0 // the open immutable record and how many lines may still carry its SHA
	for line := range strings.Lines(log) {
		line = strings.TrimRight(line, "\r\n")
		line = line[len(tsRe.FindString(line)):]
		if m := downloadRe.FindStringSubmatch(line); m != nil {
			out, group = append(out, Download{Uses: m[1], Ref: m[2], SHA: validSHA(m[3])}), -1
		} else if m := immutableRe.FindStringSubmatch(line); m != nil {
			out, group, left = append(out, Download{Uses: m[1], Ref: m[2]}), len(out), 3 // Version, Digest, SHA
		} else if group >= 0 {
			left--
			if v, ok := strings.CutPrefix(line, "Source commit SHA:"); ok {
				out[group].SHA, group = validSHA(strings.TrimSpace(v)), -1
			} else if left == 0 || strings.HasPrefix(line, "##[endgroup]") {
				group = -1
			}
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

// anySHA reports whether sha is a compromised commit of any incident action: a fork shares its
// upstream's commits, so a full SHA matches under any owner/repo.
func anySHA(b map[string]map[string]bool, sha string) bool {
	return sha != "" && slices.ContainsFunc(slices.Collect(maps.Values(b)), func(s map[string]bool) bool { return s[sha] })
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
		if d.SHA == "" && b[repoKey(d.Uses)] != nil {
			st = model.Worse(st, model.Unchecked)
			ev = append(ev, model.Evidence{Kind: "note", Detail: fmt.Sprintf("download record without a commit SHA: %s@%s", d.Uses, d.Ref)})
			continue
		}
		if anySHA(b, d.SHA) {
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
		if shas == nil && !anySHA(b, ref) {
			continue
		}
		switch {
		case anySHA(b, ref):
			st = model.Affected
			ev = append(ev, model.Evidence{Kind: "action", Detail: fmt.Sprintf(pinned, u)})
		case model.CommitSHA.MatchString(ref):
			// pinned to a different, known-good SHA
		default:
			st = model.Worse(st, model.Possible)
			ev = append(ev, model.Evidence{Kind: "action", Detail: fmt.Sprintf(mutable, u)})
		}
	}
	return st, ev
}
