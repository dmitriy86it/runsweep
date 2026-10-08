// Package incident loads and validates incident definitions.
package incident

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// Window is the time span in which a compromised artifact was served.
type Window struct {
	Start time.Time `yaml:"start" json:"start"`
	End   time.Time `yaml:"end" json:"end"`
}

// UnmarshalYAML parses RFC3339 times itself so errors carry the YAML line.
func (w *Window) UnmarshalYAML(n *yaml.Node) error {
	var raw struct {
		Start yaml.Node `yaml:"start"`
		End   yaml.Node `yaml:"end"`
	}
	if err := n.Decode(&raw); err != nil {
		return err
	}
	for _, f := range []struct {
		n   *yaml.Node
		dst *time.Time
	}{{&raw.Start, &w.Start}, {&raw.End, &w.End}} {
		if f.n.Kind == 0 {
			continue // missing: Validate reports it
		}
		t, err := time.Parse(time.RFC3339, f.n.Value)
		if err != nil {
			return fmt.Errorf("line %d: window time %q is not RFC3339", f.n.Line, f.n.Value)
		}
		*f.dst = t
	}
	return nil
}

// NPMPackage is a compromised npm package version. Versions ["*"] means every version.
type NPMPackage struct {
	Name     string   `yaml:"name" json:"name"`
	Versions []string `yaml:"versions" json:"versions"`
}

// Action is a compromised GitHub Action reference.
type Action struct {
	Uses string   `yaml:"uses" json:"uses"` // owner/repo
	SHAs []string `yaml:"shas" json:"shas"`
}

// Incident describes a supply-chain incident to scan for.
type Incident struct {
	ID      string              `yaml:"id" json:"id"`
	Title   string              `yaml:"title" json:"title"`
	Window  Window              `yaml:"window" json:"window"`
	NPM     []NPMPackage        `yaml:"npm" json:"npm,omitempty"`
	Actions []Action            `yaml:"actions" json:"actions,omitempty"`
	IOCs    map[string][]string `yaml:"iocs" json:"iocs,omitempty"`
	Refs    []string            `yaml:"refs" json:"refs"`
}

//go:embed presets/*.yaml
var presetFS embed.FS

var shaRe = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Parse decodes and validates one incident. Unknown fields are errors.
func Parse(b []byte) (*Incident, error) {
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var inc Incident
	if err := dec.Decode(&inc); err != nil {
		return nil, fmt.Errorf("incident yaml: %w", err)
	}
	return &inc, inc.Validate()
}

// Validate reports whether the incident definition is usable.
func (i *Incident) Validate() error {
	var errs []error
	if i.ID == "" {
		errs = append(errs, errors.New("id is required"))
	}
	if i.Window.Start.IsZero() || i.Window.End.IsZero() || !i.Window.Start.Before(i.Window.End) {
		errs = append(errs, errors.New("window: start and end are required and start must be before end"))
	}
	if len(i.NPM) == 0 && len(i.Actions) == 0 {
		errs = append(errs, errors.New("at least one of npm or actions is required"))
	}
	for _, p := range i.NPM {
		if p.Name == "" || len(p.Versions) == 0 {
			errs = append(errs, fmt.Errorf("npm %q: name and versions are required", p.Name))
		}
		if len(p.Versions) > 1 && slices.Contains(p.Versions, "*") {
			errs = append(errs, fmt.Errorf("npm %q: \"*\" (any version) must be the only version", p.Name))
		}
	}
	for _, a := range i.Actions {
		if strings.Count(a.Uses, "/") < 1 {
			errs = append(errs, fmt.Errorf("actions %q: uses must be owner/repo", a.Uses))
		}
		if len(a.SHAs) == 0 {
			errs = append(errs, fmt.Errorf("actions %q: at least one sha is required", a.Uses))
		}
		for _, s := range a.SHAs {
			if !shaRe.MatchString(s) {
				errs = append(errs, fmt.Errorf("actions %q: sha %q must be 40 lowercase hex chars", a.Uses, s))
			}
		}
	}
	return errors.Join(errs...)
}

// Load reads a file when ref looks like a path (has a '/' or the OS separator, or ends in
// .yaml/.yml); anything else is only a built-in preset id, so a stray file in the working directory
// cannot shadow a preset.
func Load(ref string) (*Incident, error) {
	if strings.ContainsAny(ref, "/"+string(os.PathSeparator)) || strings.HasSuffix(ref, ".yaml") || strings.HasSuffix(ref, ".yml") {
		b, err := os.ReadFile(ref) //nolint:gosec // G304: path is the user-supplied --incident argument
		if err != nil {
			return nil, err
		}
		return Parse(b)
	}
	b, err := presetFS.ReadFile("presets/" + ref + ".yaml")
	if err != nil {
		return nil, fmt.Errorf("unknown incident %q (see `runsweep incidents`; use ./%s.yaml for a file)", ref, ref)
	}
	return Parse(b)
}

// Presets returns all built-in incidents sorted by id.
func Presets() ([]*Incident, error) {
	files, err := fs.Glob(presetFS, "presets/*.yaml")
	if err != nil {
		return nil, err
	}
	var out []*Incident
	for _, f := range files {
		b, _ := presetFS.ReadFile(f)
		inc, err := Parse(b)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, inc)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].ID < out[b].ID })
	return out, nil
}
