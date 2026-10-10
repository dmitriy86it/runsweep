// Package report renders scan results.
package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
)

var tierNames = map[int]string{1: "1 · cloud", 2: "2 · publish/deploy", 3: "3 · third-party", 4: "4 · GITHUB_TOKEN"}

const limits = `## Limits

- GitHub deletes workflow runs, checks and logs after the repository's retention period (default 90 days). Older runs cannot be checked and show as UNCHECKED or are absent.
- Which secrets a job could read is derived from the workflow file at the run's commit; GitHub's API does not expose it directly.
- Priority by secret name is a name-based heuristic. Review the list; do not treat it as complete.
- A job whose log was unavailable is reported UNCHECKED: actions used via composite actions (and reusable workflows that are neither local nor pinned to a SHA) can only be seen in the log. Job logs over 64 MB count as unavailable.
- Lockfiles are assumed to be written by npm, pnpm or yarn; hand-edited lockfiles may be misread. bun.lock, bun.lockb, deno.lock and .pnp.cjs are not read: their directory is at least UNCHECKED, even next to a lockfile that is read (it may be stale).
- A lockfile that pins a bad version, or a missing, unread or unsupported lockfile, does not mark a job whose log shows no package install and whose workflow installs none. A pin is AFFECTED only for a job that installed from that lockfile (the root one or one in a directory its steps or log name); a job that may have installed it is POSSIBLE. A dependency on a package of the same repository (a workspace) is not reported as missing from the lockfile.
- An install whose output is fully suppressed inside a JS action or a called script is not seen.
- A lockfile in a directory that declares workspaces covers only its members. A package.json that no lockfile covers, below the root, is POSSIBLE only for a job whose steps or log name its directory; otherwise UNCHECKED.
- Packages named on the command line (npm i axios) are found only in the workflow's own run: steps, not in scripts it calls or in local composite actions.
- Only repositories the token can see are scanned.
- Pull request runs are checked at the pull request's head commit, not the merge commit.
- Container images are not checked.
- Re-runs of runs created more than the lookback period (default 7 days) before the window are not scanned; use --lookback 30d for full coverage.
- Called workflows are read when local or pinned to a commit SHA, and in the scanned repository's owner or a public repository; others are judged from the caller job, at least UNCHECKED for another owner's private repository.
- Workflow files over 1 MiB, lockfiles or package.json over 32 MB, and those past the first 500 of a commit are not read; the job is at least UNCHECKED.
- npm and GitHub Actions only.
`

// unverifiedTitle heads what UNCHECKED jobs could read.
const unverifiedTitle = "Not verified — could not rule out exposure"

// nothingToRotate is the line for an empty Rotate first list, or "" when it has items: with
// unverified items it says nothing is confirmed instead of nothing to rotate.
func nothingToRotate(r *model.Result, indent, end string) string {
	switch {
	case len(r.Rotation) > 0:
		return ""
	case len(r.Unverified) > 0:
		return fmt.Sprintf("%sNothing confirmed to rotate; %s in jobs that could not be checked.%s", indent, count(len(r.Unverified), "secret"), end)
	}
	return indent + "Nothing to rotate." + end
}

// RetentionNote explains why an old window can look clean.
const RetentionNote = "incident window starts more than 90 days ago; GitHub may have deleted runs — absence of runs is not evidence"

// Markdown renders the scan result as a Markdown report.
func Markdown(w io.Writer, inc *incident.Incident, r *model.Result) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# runsweep: %s (%s)\n\n", code(inc.Title), code(inc.ID))
	fmt.Fprintf(&b, "Window: %s → %s UTC · runs scanned: %d · jobs scanned: %d\n\n",
		r.Start.UTC().Format("2006-01-02 15:04:05"), r.End.UTC().Format("2006-01-02 15:04:05"), r.RunsScanned, r.JobsScanned)
	if r.RetentionWarning {
		b.WriteString("Warning: " + RetentionNote + ".\n\n")
	}
	fmt.Fprintf(&b, "**AFFECTED: %d · POSSIBLE: %d · UNCHECKED: %d**\n\n",
		r.Count(model.Affected), r.Count(model.Possible), r.Count(model.Unchecked))

	b.WriteString("## Rotate first\n\n")
	b.WriteString(nothingToRotate(r, "", "\n\n"))
	items := func(list []model.RotationItem) {
		if len(list) == 0 {
			return
		}
		b.WriteString("| # | Secret / role | Priority | Why | Seen in |\n|---|---|---|---|---|\n")
		for i, it := range list {
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n", i+1, code(it.Name), tier(it.Tier), cell(it.Reason), seenIn(it.Runs, code))
		}
		b.WriteString("\n")
	}
	items(r.Rotation)
	if len(r.Unverified) > 0 {
		b.WriteString("## " + unverifiedTitle + "\n\n")
		items(r.Unverified)
	}

	b.WriteString("## Findings\n\n")
	if len(r.Findings) == 0 {
		b.WriteString("No affected jobs found.\n\n")
	} else {
		b.WriteString("| Status | Repo | Workflow / job | Run | Evidence |\n|---|---|---|---|---|\n")
		for _, f := range r.Findings {
			var ev []string
			for _, e := range f.Evidence {
				ev = append(ev, code(e.Detail))
			}
			job := f.Run.Workflow
			if f.Run.Job != "" {
				job += " / " + f.Run.Job
			}
			run := ""
			if f.Run.RunID != 0 { // 0: a repository-level finding (runs cap)
				run = link(fmt.Sprint(f.Run.RunID), f.Run.RunURL)
			}
			if f.Run.Attempt > 1 {
				run += fmt.Sprintf(" attempt %d", f.Run.Attempt)
			}
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", f.Status, code(f.Run.Repo), code(job), run, strings.Join(ev, "; "))
		}
		b.WriteString("\n")
	}

	if len(r.Skipped) > 0 {
		b.WriteString("## Skipped repositories\n\n")
		for _, s := range r.Skipped {
			fmt.Fprintf(&b, "- %s — %s\n", code(s.Repo), code(s.Reason))
		}
		b.WriteString("\nThe token needs read access to Actions, Contents and Metadata for these repositories.\n\n")
	}
	if len(inc.Refs) > 0 {
		b.WriteString("## Incident sources\n\n")
		for _, ref := range inc.Refs {
			fmt.Fprintf(&b, "- %s\n", code(ref))
		}
		b.WriteString("\n")
	}
	b.WriteString(limits)
	_, err := io.WriteString(w, b.String())
	return err
}

// JSON renders the scan result as JSON.
func JSON(w io.Writer, inc *incident.Incident, r *model.Result) error {
	c := *inc
	c.Window.Start, c.Window.End = c.Window.Start.UTC(), c.Window.End.UTC()
	inc = &c
	r = normalize(r)
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetIndent("", "  ")
	if err := enc.Encode(struct {
		Incident *incident.Incident `json:"incident"`
		*model.Result
	}{inc, r}); err != nil {
		return err
	}
	_, err := w.Write(escapeRe.ReplaceAllFunc(b.Bytes(), func(m []byte) []byte {
		r, _ := utf8.DecodeRune(m)
		if r1, r2 := utf16.EncodeRune(r); r1 != utf8.RuneError { // outside the BMP: a surrogate pair
			return fmt.Appendf(nil, `\u%04x\u%04x`, r1, r2)
		}
		return fmt.Appendf(nil, `\u%04x`, r)
	}))
	return err
}

// escapeRe matches C1 control characters, format characters (Cf: bidi controls, zero-width
// characters, ...) and the tag block, which encoding/json leaves unescaped.
var escapeRe = regexp.MustCompile(`[\x{80}-\x{9f}\p{Cf}\x{e0000}-\x{e007f}]`)

// seenIn lists up to three runs, each rendered by wrap, then "+N more".
func seenIn(runs []model.RunRef, wrap func(string) string) string {
	var parts []string
	for i, r := range runs {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("+%d more", len(runs)-3))
			break
		}
		s := strings.TrimSpace(fmt.Sprintf("%s#%d %s", r.Repo, r.RunID, r.Job))
		if r.Attempt > 1 {
			s += fmt.Sprintf(" attempt %d", r.Attempt)
		}
		parts = append(parts, wrap(s))
	}
	return strings.Join(parts, ", ")
}

// link renders a Markdown link only for plain github.com URLs; anything else is plain text.
func link(text, url string) string {
	if !strings.HasPrefix(url, "https://github.com/") || strings.ContainsAny(url, " ()|<>\r\n\t`") {
		return text
	}
	return "[" + text + "](" + url + ")"
}

func tier(n int) string {
	if s, ok := tierNames[n]; ok {
		return s
	}
	return fmt.Sprint(n)
}

// cell keeps text in one table cell: line breaks flattened, pipes escaped, control characters dropped.
func cell(s string) string { return strings.ReplaceAll(Clean(s), "|", `\|`) }

var newlines = strings.NewReplacer("\r\n", " ", "\n", " ", "\r", " ")

// Clean makes repo-derived text safe for a terminal: CR/LF become spaces; C0/C1 controls, DEL,
// Unicode line/paragraph separators, format characters (Cf: bidi controls, zero-width characters,
// ...) and the tag block are dropped (no escape sequences reach the terminal, no text reordering,
// no hidden text).
func Clean(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r < 0x20, r >= 0x7f && r <= 0x9f, r == 0x2028, r == 0x2029, unicode.Is(unicode.Cf, r), r >= 0xe0000 && r <= 0xe007f:
			return -1
		}
		return r
	}, newlines.Replace(s))
}

// code renders untrusted text as an inline code span, which GFM does not interpret
// (no links, images, HTML, mentions or autolinks). Empty input gives an empty cell.
func code(s string) string {
	if s == "" {
		return ""
	}
	return "`" + cell(strings.ReplaceAll(s, "`", "'")) + "`"
}

// normalize returns a copy with nil slices made empty and times in UTC; the input is not modified.
func normalize(r *model.Result) *model.Result {
	c := *r
	c.Start, c.End = r.Start.UTC(), r.End.UTC()
	runs := func(in []model.RunRef) []model.RunRef {
		out := make([]model.RunRef, len(in))
		for i, x := range in {
			x.CreatedAt = x.CreatedAt.UTC()
			out[i] = x
		}
		return out
	}
	c.Findings = make([]model.Finding, len(r.Findings))
	for i, f := range r.Findings {
		f.Run.CreatedAt = f.Run.CreatedAt.UTC()
		f.Evidence = append([]model.Evidence{}, f.Evidence...)
		if f.Exposure != nil {
			e := *f.Exposure
			e.Secrets = append([]string{}, e.Secrets...)
			f.Exposure = &e
		}
		c.Findings[i] = f
	}
	items := func(in []model.RotationItem) []model.RotationItem {
		out := make([]model.RotationItem, len(in))
		for i, it := range in {
			it.Runs = runs(it.Runs)
			out[i] = it
		}
		return out
	}
	c.Rotation, c.Unverified = items(r.Rotation), items(r.Unverified)
	c.Skipped = append([]model.Skip{}, r.Skipped...)
	return &c
}
