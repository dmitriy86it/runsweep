package importer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// maxPages bounds OSV query pagination; OSV pages at 1000 vulns or 20 s.
const maxPages = 50

var (
	idRe       = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[A-Za-z0-9._-]{1,100}$`)
	npmNameRe  = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$`)
	versionRe  = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$`)
	repoRe     = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	eventRe    = regexp.MustCompile(`^[0-9A-Za-z.+_-]{1,64}$`)
	safeNameRe = regexp.MustCompile(`^(@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+$`)
	shaRe      = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// ValidID reports whether s looks like an OSV id (MAL-…, GHSA-…, CVE-…).
func ValidID(s string) bool { return idRe.MatchString(s) }

// ValidNPMName reports whether s is a valid npm package name.
func ValidNPMName(s string) bool { return len(s) <= 214 && npmNameRe.MatchString(s) }

// safeNPMName accepts names found in OSV data. Real malicious packages break
// npm's current naming rules (AdultJS, --legacy-peer-deps, @_wnpm/wnpm-cli), so this only
// excludes what could alter a URL path or a YAML/comment line. ValidNPMName stays for user input.
func safeNPMName(s string) bool {
	if len(s) > 214 || !safeNameRe.MatchString(s) {
		return false
	}
	scope, name, ok := strings.Cut(s, "/")
	if !ok {
		scope, name = "", s
	}
	return scope != "@." && scope != "@.." && name != "." && name != ".."
}

func validVersion(s string) bool { return len(s) <= 128 && versionRe.MatchString(s) }

// ValidRepo reports whether s is owner/repo without path tricks.
func ValidRepo(s string) bool {
	o, r, _ := strings.Cut(s, "/")
	return repoRe.MatchString(s) && o != "." && o != ".." && r != "." && r != ".."
}

// Vuln is the part of an OSV record the importer reads.
type Vuln struct {
	ID       string     `json:"id"`
	Aliases  []string   `json:"aliases"`
	Affected []Affected `json:"affected"`
}

// Affected is one affected[] entry.
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Versions []string `json:"versions"`
	Ranges   []struct {
		Type   string              `json:"type"`
		Events []map[string]string `json:"events"`
	} `json:"ranges"`
}

// Vuln fetches one OSV record by id.
func (c *Client) Vuln(ctx context.Context, id string) (*Vuln, error) {
	if !ValidID(id) {
		return nil, fmt.Errorf("invalid OSV id %q", id)
	}
	b, err := c.fetch(ctx, c.OSVBase+"/v1/vulns/"+url.PathEscape(id), nil)
	if errors.Is(err, errNotFound) {
		return nil, fmt.Errorf("OSV has no record %s", id)
	}
	if err != nil {
		return nil, err
	}
	var v Vuln
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("OSV %s: %w", id, err)
	}
	if v.ID != id {
		return nil, fmt.Errorf("OSV returned %q for %s", v.ID, id)
	}
	return &v, nil
}

// QueryMAL returns the malicious-package (MAL-*) records OSV has for an npm package, following pagination.
func (c *Client) QueryMAL(ctx context.Context, name string) ([]Vuln, error) {
	if !ValidNPMName(name) {
		return nil, fmt.Errorf("invalid npm package name %q", name)
	}
	var out []Vuln
	token := ""
	for page := 0; page < maxPages; page++ {
		q := map[string]any{"package": map[string]string{"ecosystem": "npm", "name": name}}
		if token != "" {
			q["page_token"] = token
		}
		body, _ := json.Marshal(q)
		b, err := c.fetch(ctx, c.OSVBase+"/v1/query", body)
		if err != nil {
			return nil, err
		}
		var r struct {
			Vulns []Vuln `json:"vulns"`
			Next  string `json:"next_page_token"`
		}
		if err := json.Unmarshal(b, &r); err != nil {
			return nil, fmt.Errorf("OSV query %s: %w", name, err)
		}
		for _, v := range r.Vulns {
			if strings.HasPrefix(v.ID, "MAL-") && ValidID(v.ID) {
				out = append(out, v)
			}
		}
		if r.Next == "" {
			return out, nil
		}
		token = r.Next
	}
	return nil, fmt.Errorf("OSV query %s: more than %d pages", name, maxPages)
}

// segment is one affected span of an OSV range: [from, to), or [from, to] when
// incl (last_affected); to == "" means no end. from "0" means every version.
type segment struct {
	from, to string
	incl     bool
}

// segments reads every span of a's non-GIT ranges. `fixed` and `limit` end a span
// exclusively, `last_affected` inclusively; a span still open at the end never ends.
// An unparsable introduced reads as "0" and an unparsable end as no end (bad is set).
func segments(a Affected) (segs []segment, bad bool) {
	ok := func(v string) bool {
		_, parsed := triple(v)
		return eventRe.MatchString(v) && parsed
	}
	for _, r := range a.Ranges {
		if r.Type == "GIT" {
			continue
		}
		var cur segment
		open := false
		for _, ev := range r.Events {
			if v, has := ev["introduced"]; has && !open { // a repeated introduced keeps the earlier, wider start
				if v != "0" && !ok(v) {
					v, bad = "0", true
				}
				cur, open = segment{from: v}, true
			}
			for _, k := range []string{"fixed", "limit", "last_affected"} {
				v, has := ev[k]
				if !has || !open {
					continue
				}
				if !ok(v) {
					bad = true
					continue // no usable end: the span stays open
				}
				cur.to, cur.incl, open = v, k == "last_affected", false
				segs = append(segs, cur)
			}
		}
		if open {
			segs = append(segs, cur)
		}
	}
	return segs, bad
}

func (s segment) has(v string) bool {
	return (s.from == "0" || !versionLess(v, s.from)) &&
		(s.to == "" || versionLess(v, s.to) || s.incl && !versionLess(s.to, v))
}

func segText(segs []segment) string {
	out := make([]string, len(segs))
	for i, s := range segs {
		switch {
		case s.to == "":
			out[i] = "[" + s.from + ", ∞)"
		case s.incl:
			out[i] = "[" + s.from + ", " + s.to + "]"
		default:
			out[i] = "[" + s.from + ", " + s.to + ")"
		}
	}
	return strings.Join(out, ", ")
}

// rangeText renders range events for a comment, keeping only safe tokens.
func rangeText(a Affected) string {
	var parts []string
	for _, r := range a.Ranges {
		for _, ev := range r.Events {
			for _, k := range []string{"introduced", "fixed", "last_affected", "limit"} {
				if v, ok := ev[k]; ok {
					if !eventRe.MatchString(v) {
						v = "?"
					}
					parts = append(parts, k+" "+v)
				}
			}
		}
	}
	if len(parts) == 0 {
		return "(no range events)"
	}
	return strings.Join(parts, ", ")
}
