// Package report renders scan results.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
)

var tierNames = map[int]string{1: "1 · cloud", 2: "2 · publish/deploy", 3: "3 · third-party", 4: "4 · GITHUB_TOKEN"}

const limits = `## Limits

- GitHub deletes workflow runs, checks and logs after the repository's retention period (default 90 days). Older runs cannot be checked and show as UNCHECKED or are absent.
- Which secrets a job could read is derived from the workflow file at the run's commit; GitHub's API does not expose it directly.
- Priority by secret name is a name-based heuristic. Review the list; do not treat it as complete.
- A job whose log was unavailable is reported UNCHECKED: actions used via composite actions or reusable workflows can only be seen in the log.
- Lockfiles are assumed to be written by npm, pnpm or yarn; hand-edited lockfiles may be misread.
`

// Markdown renders the scan result as a Markdown report.
func Markdown(w io.Writer, inc *incident.Incident, r *model.Result) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# runsweep: %s (%s)\n\n", code(inc.Title), code(inc.ID))
	fmt.Fprintf(&b, "Window: %s → %s UTC · runs scanned: %d · jobs scanned: %d\n\n",
		r.Start.UTC().Format("2006-01-02 15:04:05"), r.End.UTC().Format("2006-01-02 15:04:05"), r.RunsScanned, r.JobsScanned)
	fmt.Fprintf(&b, "**AFFECTED: %d · POSSIBLE: %d · UNCHECKED: %d**\n\n",
		r.Count(model.Affected), r.Count(model.Possible), r.Count(model.Unchecked))

	b.WriteString("## Rotate first\n\n")
	if len(r.Rotation) == 0 {
		b.WriteString("Nothing to rotate.\n\n")
	} else {
		b.WriteString("| # | Secret / role | Priority | Why | Seen in |\n|---|---|---|---|---|\n")
		for i, it := range r.Rotation {
			fmt.Fprintf(&b, "| %d | %s | %s | %s | %s |\n", i+1, code(it.Name), tier(it.Tier), cell(it.Reason), seenIn(it.Runs))
		}
		b.WriteString("\n")
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
			fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", f.Status, code(f.Run.Repo), code(job), link(fmt.Sprint(f.Run.RunID), f.Run.RunURL), strings.Join(ev, "; "))
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
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(struct {
		Incident *incident.Incident `json:"incident"`
		*model.Result
	}{inc, r})
}

func seenIn(runs []model.RunRef) string {
	var parts []string
	for i, r := range runs {
		if i == 3 {
			parts = append(parts, fmt.Sprintf("+%d more", len(runs)-3))
			break
		}
		parts = append(parts, code(fmt.Sprintf("%s#%d %s", r.Repo, r.RunID, r.Job)))
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

// cellEscaper flattens line breaks and escapes pipes so text stays in one table cell.
var cellEscaper = strings.NewReplacer("|", `\|`, "\r\n", " ", "\n", " ", "\r", " ")

func cell(s string) string { return cellEscaper.Replace(s) }

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
	c.Rotation = make([]model.RotationItem, len(r.Rotation))
	for i, it := range r.Rotation {
		it.Runs = runs(it.Runs)
		c.Rotation[i] = it
	}
	c.Skipped = append([]model.Skip{}, r.Skipped...)
	return &c
}
