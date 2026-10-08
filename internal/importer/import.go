package importer

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dmitriy86it/runsweep/internal/incident"
)

// ErrNothing means no npm version and no action was found.
var ErrNothing = errors.New("nothing to import: no npm versions and no --action")

var incidentIDRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Options says what to import.
type Options struct {
	IDs      []string // OSV ids
	Packages []string // npm package names: every MAL-* record OSV has for them
	Actions  []string // owner/repo@sha
	ID       string   // default import-<window start date>
	Title    string   // default "Imported from OSV: <first 3 ids>[ +N more]"
	Since    time.Time
	Until    time.Time
	KeepAll  bool
	Now      time.Time
	Warnf    func(format string, args ...any) // warnings
	Logf     func(format string, args ...any) // progress
}

// Import builds an incident YAML from OSV and the npm registry. The result has
// passed incident.Parse (and so Validate).
func (c *Client) Import(ctx context.Context, o Options) ([]byte, error) {
	if o.Warnf == nil {
		o.Warnf = func(string, ...any) {}
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.ID != "" && !incidentIDRe.MatchString(o.ID) {
		return nil, fmt.Errorf("--id %q: want lowercase letters, digits, '.', '_' or '-'", o.ID)
	}
	f := newFound()
	for _, a := range o.Actions {
		if err := f.addAction(a); err != nil {
			return nil, err
		}
	}
	for _, id := range o.IDs {
		if !ValidID(id) {
			return nil, fmt.Errorf("invalid OSV id %q", id)
		}
	}
	for _, p := range o.Packages {
		if !ValidNPMName(p) {
			return nil, fmt.Errorf("--package npm:%s: invalid npm package name", p)
		}
	}
	if len(f.actions) > 0 && len(o.IDs) == 0 && len(o.Packages) == 0 && (o.Since.IsZero() || o.Until.IsZero()) {
		return nil, errors.New("window unknown: pass --since and --until for action-only incidents")
	}

	var ids []string // in the order given, for the default title
	addID := func(v *Vuln) bool {
		if f.seen[v.ID] {
			return true
		}
		ids = append(ids, v.ID)
		return f.addVuln(v)
	}
	for _, id := range o.IDs {
		if f.seen[id] {
			continue
		}
		v, err := c.Vuln(ctx, id)
		if err != nil {
			return nil, err
		}
		if addID(v) {
			continue
		}
		// A CVE record usually has no package entries; its GHSA/MAL aliases do.
		useful := false
		for _, al := range v.Aliases {
			if (strings.HasPrefix(al, "GHSA-") || strings.HasPrefix(al, "MAL-")) && ValidID(al) && !f.seen[al] {
				av, err := c.Vuln(ctx, al)
				if err != nil {
					return nil, err
				}
				useful = addID(av) || useful
				f.notes = append(f.notes, fmt.Sprintf("%s: no npm or GitHub Actions entries; followed alias %s", id, al))
			}
		}
		if !useful {
			f.both("%s: no npm or GitHub Actions entries", id)
		}
	}
	for _, p := range o.Packages {
		vs, err := c.QueryMAL(ctx, p)
		if err != nil {
			return nil, err
		}
		if len(vs) == 0 {
			f.both("%s: OSV has no MAL-* record", p)
		}
		for i := range vs {
			addID(&vs[i])
		}
	}
	for _, w := range f.warns {
		o.Warnf("%s", w)
	}
	if len(f.npm) == 0 && len(f.actions) == 0 {
		return nil, ErrNothing
	}

	var win incident.Window
	if len(f.npm) > 0 {
		times := map[string]PkgTimes{}
		names := sortedKeys(f.npm)
		for i, name := range names {
			o.Logf("npm registry %d/%d: %s", i+1, len(names), name)
			pt, err := c.Times(ctx, name)
			if err != nil {
				return nil, err
			}
			times[name] = pt
			if from, ok := f.open[name]; ok {
				if pt.Found {
					f.expandOpen(name, pt)
					f.notes = append(f.notes, fmt.Sprintf("%s: open range from %s — all registry versions included", name, from))
				} else {
					msg := fmt.Sprintf("%s: open range from %s — registry unavailable; later versions may also be malicious, check manually", name, from)
					f.notes = append(f.notes, msg)
					o.Warnf("%s", msg)
				}
			}
		}
		start, end, notes, err := computeWindow(f.npm, times, o.KeepAll, o.Now)
		if err != nil && (o.Since.IsZero() || o.Until.IsZero()) {
			return nil, err
		}
		f.notes = append(f.notes, notes...)
		win = incident.Window{Start: start, End: end}
	}
	if !o.Since.IsZero() {
		win.Start = o.Since.UTC()
		f.notes = append(f.notes, "start overridden with --since")
	}
	if !o.Until.IsZero() {
		win.End = o.Until.UTC()
		f.notes = append(f.notes, "end overridden with --until")
	}

	inc := &incident.Incident{ID: o.ID, Title: o.Title, Window: win, Refs: f.refs}
	if inc.ID == "" {
		inc.ID = "import-" + win.Start.Format("2006-01-02")
	}
	if inc.Title == "" {
		inc.Title = "Imported from OSV: " + strings.Join(ids[:min(3, len(ids))], ", ")
		if len(ids) > 3 {
			inc.Title += fmt.Sprintf(" +%d more", len(ids)-3)
		}
		if len(ids) == 0 {
			inc.Title = "Imported incident"
		}
	}
	for _, name := range sortedKeys(f.npm) {
		inc.NPM = append(inc.NPM, incident.NPMPackage{Name: name, Versions: sortedVersions(f.npm[name])})
	}
	for _, repo := range sortedKeys(f.actions) {
		inc.Actions = append(inc.Actions, incident.Action{Uses: repo, SHAs: sortedKeys(f.actions[repo])})
	}
	out := render(inc, f.notes, o.Now)
	if _, err := incident.Parse(out); err != nil {
		return nil, fmt.Errorf("generated incident is invalid: %w", err)
	}
	return out, nil
}

// render writes inc in the preset style. Every string comes from a validated
// field or goes through strconv.Quote, whose escapes YAML double-quoted scalars accept.
func render(inc *incident.Incident, notes []string, now time.Time) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "id: %s\n", strconv.Quote(inc.ID))
	fmt.Fprintf(&b, "title: %s\n", strconv.Quote(inc.Title))
	fmt.Fprintf(&b, "# Generated by `runsweep incidents import` from api.osv.dev and registry.npmjs.org at %s.\n", now.UTC().Format(time.RFC3339))
	b.WriteString("# Before contributing as a preset: add an independent source to refs and check the window.\n")
	for _, n := range notes {
		fmt.Fprintf(&b, "# %s\n", strings.ReplaceAll(n, "\n", " "))
	}
	fmt.Fprintf(&b, "window: {start: %s, end: %s}\n", inc.Window.Start.UTC().Format(time.RFC3339), inc.Window.End.UTC().Format(time.RFC3339))
	if len(inc.NPM) > 0 {
		b.WriteString("npm:\n")
		for _, p := range inc.NPM {
			fmt.Fprintf(&b, "  - {name: %s, versions: [%s]}\n", strconv.Quote(p.Name), quoteAll(p.Versions))
		}
	}
	if len(inc.Actions) > 0 {
		b.WriteString("actions:\n")
		for _, a := range inc.Actions {
			fmt.Fprintf(&b, "  - {uses: %s, shas: [%s]}\n", a.Uses, quoteAll(a.SHAs))
		}
	}
	b.WriteString("refs:\n")
	for _, r := range inc.Refs {
		fmt.Fprintf(&b, "  - %s\n", r)
	}
	return b.Bytes()
}

func quoteAll(s []string) string {
	q := make([]string, len(s))
	for i, x := range s {
		q[i] = strconv.Quote(x)
	}
	return strings.Join(q, ", ")
}
