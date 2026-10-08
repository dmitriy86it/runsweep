package report

import (
	"fmt"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
)

var statusColors = map[model.Status]string{model.Affected: "\x1b[31m", model.Possible: "\x1b[33m", model.Unchecked: "\x1b[34m"}

// Text renders a short terminal summary of the scan result; the full report is --format md.
// With color, status words are wrapped in ANSI colors; everything from the repository or the
// API goes through Clean first.
func Text(w io.Writer, inc *incident.Incident, r *model.Result, color bool) error {
	paint := func(s model.Status) string {
		if c, ok := statusColors[s]; ok && color {
			return c + s.String() + "\x1b[0m"
		}
		return s.String()
	}
	var b strings.Builder
	name := Clean(inc.ID)
	if t := Clean(inc.Title); t != "" {
		name = t + " (" + name + ")"
	}
	fmt.Fprintf(&b, "runsweep · %s\n", name)
	fmt.Fprintf(&b, "%s → %s UTC · %s · %s scanned · lookback %s\n",
		r.Start.UTC().Format("2006-01-02 15:04:05"), r.End.UTC().Format("2006-01-02 15:04:05"),
		count(r.RunsScanned, "run"), count(r.JobsScanned, "job"), days(r.Lookback))
	if r.RetentionWarning {
		b.WriteString("Warning: " + RetentionNote + "\n")
	}
	fmt.Fprintf(&b, "\n%s %d   %s %d   %s %d\n\n", paint(model.Affected), r.Count(model.Affected),
		paint(model.Possible), r.Count(model.Possible), paint(model.Unchecked), r.Count(model.Unchecked))

	b.WriteString("Rotate first\n")
	if len(r.Rotation) == 0 {
		b.WriteString("  Nothing to rotate.\n")
	}
	width := 0
	for _, it := range r.Rotation {
		width = max(width, utf8.RuneCountInString(Clean(it.Name)))
	}
	for i, it := range r.Rotation {
		fmt.Fprintf(&b, "  %-3d%-*s  %s\n", i+1, width, Clean(it.Name), tier(it.Tier))
		fmt.Fprintf(&b, "     %s\n     seen in: %s\n", Clean(it.Reason), seenIn(it.Runs, Clean))
	}

	b.WriteString("\nFindings\n")
	if len(r.Findings) == 0 {
		b.WriteString("  No affected jobs found.\n")
	}
	width = 0
	for _, f := range r.Findings {
		width = max(width, utf8.RuneCountInString(Clean(f.Run.Repo)))
	}
	for _, f := range r.Findings {
		job := f.Run.Workflow
		if f.Run.Job != "" {
			job += " / " + f.Run.Job
		}
		attempt := ""
		if f.Run.Attempt > 1 {
			attempt = fmt.Sprintf(" attempt %d", f.Run.Attempt)
		}
		fmt.Fprintf(&b, "  %s%s%-*s  %s  #%d%s\n", paint(f.Status), strings.Repeat(" ", 11-len(f.Status.String())),
			width, Clean(f.Run.Repo), Clean(job), f.Run.RunID, attempt)
		for _, e := range f.Evidence {
			fmt.Fprintf(&b, "%13s%s\n", "", Clean(e.Detail))
		}
	}

	if len(r.Skipped) > 0 {
		var parts []string
		for _, s := range r.Skipped {
			parts = append(parts, Clean(s.Repo)+" ("+Clean(s.Reason)+")")
		}
		b.WriteString("\nSkipped repositories: " + strings.Join(parts, ", ") + "\n")
	}
	b.WriteString("\nLimits: see --format md\nFull report: --format md\n")
	_, err := io.WriteString(w, b.String())
	return err
}

// count renders "1 run", "2 runs".
func count(n int, noun string) string {
	if n != 1 {
		noun += "s"
	}
	return fmt.Sprintf("%d %s", n, noun)
}

// days renders whole days as "7d", anything else as a Go duration.
func days(d time.Duration) string {
	if d%(24*time.Hour) == 0 {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	return d.String()
}
