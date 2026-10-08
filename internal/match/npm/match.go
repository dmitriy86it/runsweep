package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
	"github.com/dmitriy86it/runsweep/internal/source"
)

// Fetcher is the part of source.Source the matcher needs.
type Fetcher interface {
	Tree(ctx context.Context, repo, sha string) ([]source.TreeEntry, bool, error)
	Blob(ctx context.Context, repo, blobSHA string, limit int) ([]byte, error)
}

// Result is the outcome of matching lockfile packages against an incident.
type Result struct {
	Status   model.Status
	Evidence []model.Evidence
}

// maxManifests caps the lockfiles and package.json files read per commit tree.
const maxManifests = 500

// Cache keeps the parsed lockfiles and package.json files of one scan by file name and blob SHA,
// so a file shared by many commits is fetched and parsed once. The zero value is ready to use.
type Cache struct{ m sync.Map }

// parsed is a cached parse: pkgs of a lockfile or names of a package.json, or why it is unreadable.
type parsed struct {
	pkgs  []Pkg
	names []string
	err   error
}

// load returns the parse of tree entry e; a file over the size cap is unreadable, like a parse error.
func (c *Cache) load(ctx context.Context, f Fetcher, repo string, e source.TreeEntry, parse func([]byte) parsed) (parsed, error) {
	key := path.Base(e.Path) + "@" + e.SHA
	if v, ok := c.m.Load(key); ok {
		return v.(parsed), nil
	}
	b, err := f.Blob(ctx, repo, e.SHA, source.MaxManifestBytes)
	var p parsed
	switch {
	case errors.Is(err, source.ErrIncomplete):
		p.err = err
	case err != nil:
		return p, err
	default:
		source.Parse(func() { p = parse(b) })
	}
	c.m.Store(key, p)
	return p, nil
}

// Match checks every lockfile in repo@sha for bad versions. A package.json that lists a bad
// package and has no lockfile in its directory yields POSSIBLE; one with dependencies and no
// lockfile there or above, or a lockfile runsweep cannot read, yields UNCHECKED.
func (c *Cache) Match(ctx context.Context, f Fetcher, repo, sha string, bad []incident.NPMPackage) (Result, error) {
	var r Result
	entries, truncated, err := f.Tree(ctx, repo, sha)
	if err != nil {
		return r, err
	}
	isPkgJSON := func(p string) bool { return path.Base(p) == "package.json" && !InNodeModules(p) }
	manifests := 0
	for _, e := range entries {
		if IsLockfile(e.Path) || isPkgJSON(e.Path) {
			manifests++
		}
	}
	reads := 0 // manifests read so far; past maxManifests the rest are skipped
	badVer := map[string]map[string]bool{}
	for _, p := range bad {
		badVer[p.Name] = map[string]bool{}
		for _, v := range p.Versions {
			badVer[p.Name][v] = true
		}
	}
	lockNames := map[string]map[string]bool{} // dir -> package names in its successfully parsed lockfiles
	lockPaths := map[string]string{}          // dir -> a lockfile path, for evidence
	failedDirs := map[string]bool{}           // dirs with a lockfile that failed to parse or is unsupported
	for _, e := range entries {
		if !IsLockfile(e.Path) {
			continue
		}
		dir := path.Dir(e.Path)
		if reads++; reads > maxManifests {
			failedDirs[dir] = true // not read: its package.json files count as unlocked
			continue
		}
		p, err := c.load(ctx, f, repo, e, func(b []byte) parsed {
			pkgs, err := ParseLockfile(e.Path, b) // on an error, pkgs is what could be read (pnpm)
			return parsed{pkgs: pkgs, err: err}
		})
		if err != nil {
			return r, err
		}
		pkgs, err := p.pkgs, p.err
		if err != nil {
			r.Status = model.Worse(r.Status, model.Unchecked)
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("cannot parse %s: %v", e.Path, err)})
			failedDirs[dir] = true
		} else if lockNames[dir] == nil {
			lockNames[dir], lockPaths[dir] = map[string]bool{}, e.Path
		}
		for _, p := range pkgs {
			if err == nil {
				lockNames[dir][p.Name] = true
			}
			switch {
			case badVer[p.Name]["*"]:
				r.Status = model.Affected
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "npm", Detail: fmt.Sprintf("%s@%s in %s at %s (any version listed as malicious)", p.Name, p.Version, e.Path, short(sha))})
			case badVer[p.Name][p.Version]:
				r.Status = model.Affected
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "npm", Detail: fmt.Sprintf("%s@%s in %s at %s", p.Name, p.Version, e.Path, short(sha))})
			}
		}
	}
	for _, e := range entries {
		if dir := path.Dir(e.Path); IsUnsupportedLockfile(e.Path) && lockNames[dir] == nil {
			r.Status = model.Worse(r.Status, model.Unchecked)
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("unsupported lockfile %s — packages not checked", e.Path)})
			failedDirs[dir] = true
		}
	}
	if r.Status != model.Affected {
		for _, e := range entries {
			if !isPkgJSON(e.Path) {
				continue
			}
			if reads++; reads > maxManifests {
				continue
			}
			p, err := c.load(ctx, f, repo, e, func(b []byte) parsed {
				names, err := declared(b)
				return parsed{names: names, err: err}
			})
			if err != nil {
				return r, err
			}
			names, err := p.names, p.err
			if err != nil {
				r.Status = model.Worse(r.Status, model.Unchecked)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("cannot parse %s: %v", e.Path, err)})
				continue
			}
			// Covering lockfile: nearest ancestor dir with one (workspaces lock at the root).
			// If the nearest one failed to parse, treat the package.json as unlocked.
			dir := path.Dir(e.Path)
			for lockNames[dir] == nil && !failedDirs[dir] && dir != "." && dir != "/" {
				dir = path.Dir(dir)
			}
			for _, name := range names {
				if _, ok := badVer[name]; !ok {
					continue
				}
				var detail string
				switch {
				case lockNames[dir] == nil:
					detail = fmt.Sprintf("%s declared in %s without a lockfile — installed version unknown", name, e.Path)
				case !lockNames[dir][name]:
					detail = fmt.Sprintf("%s declared in %s but not in lockfile %s — install would resolve it fresh", name, e.Path, lockPaths[dir])
				default:
					continue
				}
				r.Status = model.Worse(r.Status, model.Possible)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "npm", Detail: detail})
			}
			if lockNames[dir] == nil && !failedDirs[dir] && len(names) > 0 {
				r.Status = model.Worse(r.Status, model.Unchecked)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("no lockfile for %s — transitive dependencies unknown", e.Path)})
			}
		}
	}
	if manifests > maxManifests {
		r.Status = model.Worse(r.Status, model.Unchecked)
		r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("too many manifests (%d) — not all read", manifests)})
	}
	if truncated {
		r.Status = model.Worse(r.Status, model.Unchecked)
		r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: "git tree truncated by GitHub; some lockfiles were not checked"})
	}
	return r, nil
}

// declared returns the sorted, distinct dependency names of a package.json, including the real
// package behind an "npm:<real>@<range>" alias.
func declared(pkgJSON []byte) ([]string, error) {
	var p struct {
		Dependencies, DevDependencies, OptionalDependencies, PeerDependencies map[string]json.RawMessage
	}
	if err := json.Unmarshal(bytes.TrimPrefix(pkgJSON, []byte("\uFEFF")), &p); err != nil {
		return nil, err
	}
	var out []string
	for _, m := range []map[string]json.RawMessage{p.Dependencies, p.DevDependencies, p.OptionalDependencies, p.PeerDependencies} {
		for name, raw := range m {
			out = append(out, name)
			var spec string
			if json.Unmarshal(raw, &spec) != nil {
				continue
			}
			if target, ok := strings.CutPrefix(spec, "npm:"); ok && target != "" {
				if at := strings.Index(target[1:], "@"); at >= 0 { // "@scope/pkg@^1" -> "@scope/pkg"
					target = target[:at+1]
				}
				out = append(out, target)
			}
		}
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
