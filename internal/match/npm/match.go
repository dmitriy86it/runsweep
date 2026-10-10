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

	"github.com/runsweep/runsweep/internal/incident"
	"github.com/runsweep/runsweep/internal/model"
	"github.com/runsweep/runsweep/internal/source"
	"go.yaml.in/yaml/v3"
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
	// Unlocked: bad packages declared in a package.json below the root that no lockfile covers;
	// whether that is POSSIBLE depends on the job installing it (Resolve).
	Unlocked []Unlocked
	// Pinned: directories of the lockfiles that pin a bad version (the AFFECTED evidence).
	Pinned []string
}

// Unlocked is a bad package declared in Dir/package.json with no covering lockfile.
type Unlocked struct {
	Dir, Pkg, Detail string
}

// Resolve folds r.Unlocked into the status: POSSIBLE where installed(Dir), otherwise UNCHECKED
// with a note that the job does not seem to install it.
func (r Result) Resolve(installed func(dir string) bool) Result {
	out := Result{Status: r.Status, Evidence: slices.Clone(r.Evidence), Pinned: r.Pinned}
	for _, u := range r.Unlocked {
		if installed(u.Dir) {
			out.Status = model.Worse(out.Status, model.Possible)
			out.Evidence = append(out.Evidence, model.Evidence{Kind: "npm", Detail: u.Detail})
		} else {
			out.Status = model.Worse(out.Status, model.Unchecked)
			out.Evidence = append(out.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("%s/package.json is not installed by this job as far as the workflow and log show; declared %s", u.Dir, u.Pkg)})
		}
	}
	return out
}

// maxManifests caps the lockfiles and package.json files read per commit tree.
const maxManifests = 500

// Cache keeps the parsed lockfiles and package.json files of one scan by file name and blob SHA,
// so a file shared by many commits is fetched and parsed once. The zero value is ready to use.
type Cache struct{ m sync.Map }

// parsed is a cached parse: pkgs of a lockfile, a package.json or pnpm-workspace.yaml manifest,
// or why it is unreadable.
type parsed struct {
	pkgs []Pkg
	m    manifest
	err  error
}

// manifest is what a package.json (or pnpm-workspace.yaml: ws only) tells about its directory.
type manifest struct {
	name  string   // own package name
	deps  []string // sorted, distinct dependency names
	ws    []string // workspace globs
	hasWS bool     // workspaces declared: the directory's lockfile covers only its members
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
			pkgs, err := ParseLockfile(e.Path, b) // on an error, pkgs is what could be read (pnpm, package-lock)
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
			default:
				continue
			}
			if !slices.Contains(r.Pinned, dir) {
				r.Pinned = append(r.Pinned, dir)
			}
		}
	}
	for _, e := range entries {
		if !IsUnsupportedLockfile(e.Path) {
			continue
		}
		r.Status = model.Worse(r.Status, model.Unchecked)
		// next to a supported lockfile: that one was read, but the project may install with the other
		if dir := path.Dir(e.Path); lockNames[dir] != nil {
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("%s present but not read — %s may be stale", e.Path, lockPaths[dir])})
		} else {
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("unsupported lockfile %s — packages not checked", e.Path)})
			failedDirs[dir] = true
		}
	}
	if r.Status != model.Affected {
		type pkgJSON struct {
			path  string
			names []string
		}
		var read []pkgJSON
		local := map[string]bool{}  // names of the tree's own packages (workspaces); yarn v1 does not lock them
		ws := map[string][]string{} // dir -> workspace globs; absent: its lockfile covers everything below
		pnpmWS := map[string]bool{} // dirs with a pnpm-workspace.yaml
		for _, e := range entries {
			if path.Base(e.Path) != "pnpm-workspace.yaml" || InNodeModules(e.Path) {
				continue
			}
			p, err := c.load(ctx, f, repo, e, func(b []byte) parsed {
				var y struct{ Packages []string }
				err := yaml.Unmarshal(b, &y)
				return parsed{m: manifest{ws: y.Packages, hasWS: true}, err: err}
			})
			if err != nil {
				return r, err
			}
			pnpmWS[path.Dir(e.Path)] = true // package.json workspaces next to it are ignored
			if p.err == nil {               // unreadable: keep the ancestor rule
				ws[path.Dir(e.Path)] = p.m.ws
			}
		}
		for _, e := range entries {
			if !isPkgJSON(e.Path) {
				continue
			}
			if reads++; reads > maxManifests {
				continue
			}
			p, err := c.load(ctx, f, repo, e, func(b []byte) parsed {
				m, err := declared(b)
				return parsed{m: m, err: err}
			})
			if err != nil {
				return r, err
			}
			if p.err != nil {
				r.Status = model.Worse(r.Status, model.Unchecked)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("cannot parse %s: %v", e.Path, p.err)})
				continue
			}
			read = append(read, pkgJSON{e.Path, p.m.deps})
			if p.m.name != "" && manifests <= maxManifests { // past the cap not every local name is known
				local[p.m.name] = true
			}
			if d := path.Dir(e.Path); p.m.hasWS && !pnpmWS[d] {
				ws[d] = append(ws[d], p.m.ws...)
			}
		}
		for _, pj := range read {
			names := pj.names
			// Covering lockfile: nearest ancestor dir with one (workspaces lock at the root), if that
			// dir declares no workspaces or pj is a member; else none ("" is no dir).
			// If the nearest one failed to parse, treat the package.json as unlocked.
			pdir := path.Dir(pj.path)
			dir := pdir
			for lockNames[dir] == nil && !failedDirs[dir] && dir != "." && dir != "/" {
				dir = path.Dir(dir)
			}
			if globs, ok := ws[dir]; ok && dir != pdir && !member(globs, strings.TrimPrefix(pdir, dir+"/")) {
				dir = ""
			}
			unlocked := lockNames[dir] == nil && !failedDirs[dir] && pdir != "."
			for _, name := range names {
				if _, ok := badVer[name]; !ok {
					continue
				}
				var detail string
				switch {
				case lockNames[dir] == nil:
					detail = fmt.Sprintf("%s declared in %s without a lockfile — installed version unknown", name, pj.path)
				case !lockNames[dir][name] && !local[name]:
					detail = fmt.Sprintf("%s declared in %s but not in lockfile %s — install would resolve it fresh", name, pj.path, lockPaths[dir])
				default:
					continue
				}
				if unlocked {
					r.Unlocked = append(r.Unlocked, Unlocked{Dir: pdir, Pkg: name, Detail: detail})
					continue
				}
				r.Status = model.Worse(r.Status, model.Possible)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "npm", Detail: detail})
			}
			if lockNames[dir] == nil && !failedDirs[dir] && len(names) > 0 {
				r.Status = model.Worse(r.Status, model.Unchecked)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("no lockfile for %s — transitive dependencies unknown", pj.path)})
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

// member reports whether rel (a dir relative to the workspace root) matches the workspace globs:
// `*` within a segment, `**` across segments, a leading `!` excludes. A hidden segment is never
// a member, and a negation runsweep cannot evaluate (braces, bad pattern) excludes everything.
func member(globs []string, rel string) bool {
	segs := strings.Split(rel, "/")
	if slices.ContainsFunc(segs, func(s string) bool { return strings.HasPrefix(s, ".") }) {
		return false
	}
	in := false
	for _, g := range globs {
		neg := strings.HasPrefix(g, "!")
		pat := strings.Split(strings.Trim(strings.TrimPrefix(strings.TrimPrefix(g, "!"), "./"), "/"), "/")
		if neg && (strings.Contains(g, "{") || slices.ContainsFunc(pat, func(p string) bool {
			_, err := path.Match(p, "")
			return err != nil
		})) {
			return false
		}
		if globMatch(pat, segs) {
			if neg {
				return false
			}
			in = true
		}
	}
	return in
}

// globMatch matches path segments against pattern segments in O(len(pat)·len(segs)).
func globMatch(pat, segs []string) bool {
	ok := make([]bool, len(segs)+1) // ok[j]: the pattern so far matches segs[:j]
	ok[0] = true
	for _, p := range pat {
		next := make([]bool, len(segs)+1)
		for j := range next {
			if p == "**" {
				next[j] = ok[j] || j > 0 && next[j-1]
			} else if j > 0 && ok[j-1] {
				next[j], _ = path.Match(p, segs[j-1])
			}
		}
		ok = next
	}
	return ok[len(segs)]
}

// declared returns what a package.json declares: its own name, its sorted, distinct dependency
// names (including the real package behind an "npm:<real>@<range>" alias) and its workspaces.
func declared(pkgJSON []byte) (manifest, error) {
	var p struct {
		Name, Workspaces                                                      json.RawMessage
		Dependencies, DevDependencies, OptionalDependencies, PeerDependencies map[string]json.RawMessage
	}
	if err := json.Unmarshal(bytes.TrimPrefix(pkgJSON, []byte("\uFEFF")), &p); err != nil {
		return manifest{}, err
	}
	var m manifest
	_ = json.Unmarshal(p.Name, &m.name) // a non-string name is no local package
	var obj struct{ Packages []string }
	if json.Unmarshal(p.Workspaces, &m.ws) == nil {
		m.hasWS = m.ws != nil
	} else if json.Unmarshal(p.Workspaces, &obj) == nil && obj.Packages != nil {
		m.ws, m.hasWS = obj.Packages, true
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
	m.deps = slices.Compact(out)
	return m, nil
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
