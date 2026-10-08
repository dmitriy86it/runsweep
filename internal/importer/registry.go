package importer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"time"
)

// PkgTimes is what the npm registry document says about a package's versions.
type PkgTimes struct {
	Found       bool                 // false: the registry answered 404
	Times       map[string]time.Time // version -> publish time; removed versions keep their entry
	Published   map[string]bool      // versions still listed under "versions"
	Modified    time.Time            // time.modified
	Unpublished time.Time            // time.unpublished.time; zero unless the whole package was unpublished
}

// Times fetches the full registry document of an npm package (the abbreviated
// install document has no "time" field).
func (c *Client) Times(ctx context.Context, name string) (PkgTimes, error) {
	if !ValidNPMName(name) {
		return PkgTimes{}, fmt.Errorf("invalid npm package name %q", name)
	}
	b, err := c.fetch(ctx, c.NPMBase+"/"+url.PathEscape(name), nil) // "@scope%2Fname"
	if errors.Is(err, errNotFound) {
		return PkgTimes{}, nil
	}
	if err != nil {
		return PkgTimes{}, err
	}
	var doc struct {
		Time     map[string]json.RawMessage `json:"time"`
		Versions map[string]json.RawMessage `json:"versions"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return PkgTimes{}, fmt.Errorf("npm registry %s: %w", name, err)
	}
	pt := PkgTimes{Found: true, Times: map[string]time.Time{}, Published: map[string]bool{}}
	for v := range doc.Versions {
		pt.Published[v] = true
	}
	for k, raw := range doc.Time {
		if k == "unpublished" {
			var u struct {
				Time time.Time `json:"time"`
			}
			if json.Unmarshal(raw, &u) == nil {
				pt.Unpublished = u.Time
			}
			continue
		}
		var t time.Time
		if json.Unmarshal(raw, &t) != nil {
			continue // not a timestamp: ignore
		}
		switch k {
		case "created":
		case "modified":
			pt.Modified = t
		default:
			pt.Times[k] = t
		}
	}
	return pt, nil
}
