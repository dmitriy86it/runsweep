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
	// Pinned: directories of the lockfiles that pin a bad version; Pins: that evidence, also in Evidence.
	Pinned []string
	Pins   []model.Evidence
	rest   model.Status // Status without the pins
}

// mark raises the status for evidence other than a pin.
func (r *Result) mark(s model.Status) {
	r.Status, r.rest = model.Worse(r.Status, s), model.Worse(r.rest, s)
}

// WithoutPins returns r without the lockfile pins: the status and evidence of everything else.
func (r Result) WithoutPins() Result {
	ev := slices.DeleteFunc(slices.Clone(r.Evidence), func(e model.Evidence) bool { return slices.Contains(r.Pins, e) })
	return Result{Status: r.rest, Evidence: ev, Unlocked: r.Unlocked, rest: r.rest}
}

// Unlocked is a bad package declared in Dir/package.json with no covering lockfile.
type Unlocked struct {
	Dir, Pkg, Detail string
}

// Resolve folds r.Unlocked into the status: POSSIBLE where installed(Dir), otherwise UNCHECKED
// with a note that the job does not seem to install it.
func (r Result) Resolve(installed func(dir string) bool) Result {
	out := Result{Status: r.Status, Evidence: slices.Clone(r.Evidence), Pinned: r.Pinned, Pins: r.Pins, rest: r.rest}
	for _, u := range r.Unlocked {
		if installed(u.Dir) {
			out.mark(model.Possible)
			out.Evidence = append(out.Evidence, model.Evidence{Kind: "npm", Detail: u.Detail})
		} else {
			out.mark(model.Unchecked)
			out.Evidence = append(out.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("%s/package.json is not installed by this job as far as the workflow and log show; declared %s", u.Dir, u.Pkg)})
		}
	}
	return out
}

// stale checks a package-lock.json for npm re-resolving instead of installing it: `package-lock=false`
// in the .npmrc of its folder, or a package.json beside it whose dependency specs differ from those
// the lockfile was made for (npm install resolves the difference and its dependencies fresh, so a
// bad version may come in transitively). It returns why, or "".
func (c *Cache) stale(ctx context.Context, f Fetcher, repo string, lock source.TreeEntry, root []string,
	byPath map[string]source.TreeEntry) (string, error) {
	if b := path.Base(lock.Path); b != "package-lock.json" && b != "npm-shrinkwrap.json" {
		return "", nil
	}
	dir := path.Dir(lock.Path)
	if rc, ok := byPath[path.Join(dir, ".npmrc")]; ok {
		p, err := c.load(ctx, f, repo, rc, func(b []byte) parsed { return parsed{noLock: npmrcNoLock(b)} })
		if err != nil {
			return "", err
		}
		if p.noLock {
			return rc.Path + " sets package-lock=false", nil
		}
	}
	pj, ok := byPath[path.Join(dir, "package.json")]
	if !ok || root == nil {
		return "", nil
	}
	p, err := c.load(ctx, f, repo, pj, func(b []byte) parsed {
		m, err := declared(b)
		return parsed{m: m, err: err}
	})
	if err != nil || p.err != nil || slices.Equal(p.m.specs, root) {
		return "", err
	}
	return pj.Path + " and the lockfile disagree on dependencies", nil
}

// npmrcNoLock reports whether an .npmrc sets package-lock=false (the last assignment wins).
func npmrcNoLock(b []byte) bool {
	off := false
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == ';' || line[0] == '#' {
			continue
		}
		k, v, _ := strings.Cut(line, "=")
		if k = strings.TrimSpace(k); k == "package-lock" || k == "package_lock" {
			v, _, _ = strings.Cut(v, " #")
			v, _, _ = strings.Cut(v, " ;")
			off = strings.EqualFold(strings.Trim(strings.TrimSpace(v), `"'`), "false")
		}
	}
	return off
}

// maxManifests caps the lockfiles and package.json files read per commit tree.
const maxManifests = 500

// Cache keeps the parsed lockfiles and package.json files of one scan by file name and blob SHA,
// so a file shared by many commits is fetched and parsed once. The zero value is ready to use.
type Cache struct{ m sync.Map }

// parsed is a cached parse: pkgs of a lockfile, a package.json or pnpm-workspace.yaml manifest,
// or why it is unreadable.
type parsed struct {
	pkgs   []Pkg
	root   []string // dependency specs of a package-lock root entry; nil without one
	m      manifest
	noLock bool // .npmrc turns the lockfile off (package-lock=false)
	err    error
}

// manifest is what a package.json (or pnpm-workspace.yaml: ws only) tells about its directory.
type manifest struct {
	name  string   // own package name
	deps  []string // sorted, distinct dependency names
	specs []string // dependency specs, see depSpecs
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
// lockfile there or above, or a lockfile runsweep cannot read, yields UNCHECKED. Once a lockfile
// pins a bad version, package.json files are not read.
func (c *Cache) Match(ctx context.Context, f Fetcher, repo, sha string, bad []incident.NPMPackage) (Result, error) {
	return c.match(ctx, f, repo, sha, bad, false)
}

// MatchAll is Match that also reads the package.json files when a lockfile pins a bad version,
// so WithoutPins tells what the rest of the tree gives.
func (c *Cache) MatchAll(ctx context.Context, f Fetcher, repo, sha string, bad []incident.NPMPackage) (Result, error) {
	return c.match(ctx, f, repo, sha, bad, true)
}

func (c *Cache) match(ctx context.Context, f Fetcher, repo, sha string, bad []incident.NPMPackage, all bool) (Result, error) {
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
	byPath := make(map[string]source.TreeEntry, len(entries))
	for _, e := range entries {
		byPath[e.Path] = e
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
			pkgs, root, err := parseLockfile(e.Path, b) // on an error, pkgs is what could be read (pnpm, package-lock)
			return parsed{pkgs: pkgs, root: root, err: err}
		})
		if err != nil {
			return r, err
		}
		pkgs, err := p.pkgs, p.err
		var stale string
		pinned := len(r.Pins)
		if err == nil {
			if stale, err = c.stale(ctx, f, repo, e, p.root, byPath); err != nil {
				return r, err
			}
		}
		err = p.err
		if err != nil {
			r.mark(model.Unchecked)
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("cannot parse %s: %v", e.Path, err)})
			failedDirs[dir] = true
		} else if lockNames[dir] == nil {
			lockNames[dir], lockPaths[dir] = map[string]bool{}, e.Path
		}
		for _, p := range pkgs {
			if err == nil {
				lockNames[dir][p.Name] = true
			}
			var pin model.Evidence
			switch {
			case badVer[p.Name]["*"]:
				pin = model.Evidence{Kind: "npm", Detail: fmt.Sprintf("%s@%s in %s at %s (any version listed as malicious)", p.Name, p.Version, e.Path, short(sha))}
			case badVer[p.Name][p.Version]:
				pin = model.Evidence{Kind: "npm", Detail: fmt.Sprintf("%s@%s in %s at %s", p.Name, p.Version, e.Path, short(sha))}
			default:
				continue
			}
			r.Status = model.Affected
			r.Evidence, r.Pins = append(r.Evidence, pin), append(r.Pins, pin)
			if !slices.Contains(r.Pinned, dir) {
				r.Pinned = append(r.Pinned, dir)
			}
		}
		// The pin keeps its status: npm ci installs the lockfile and npm install keeps what still
		// satisfies package.json. Without a pin, a lockfile npm may not use is UNCHECKED.
		hasPin := len(r.Pins) > pinned
		if stale != "" {
			if !hasPin {
				r.mark(model.Unchecked)
			}
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("%s: %s — lockfile may not be what npm installed", e.Path, stale)})
		}
	}
	for _, e := range entries {
		if !IsUnsupportedLockfile(e.Path) {
			continue
		}
		r.mark(model.Unchecked)
		// next to a supported lockfile: that one was read, but the project may install with the other
		if dir := path.Dir(e.Path); lockNames[dir] != nil {
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("%s present but not read — %s may be stale", e.Path, lockPaths[dir])})
		} else {
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("unsupported lockfile %s — packages not checked", e.Path)})
			failedDirs[dir] = true
		}
	}
	if len(r.Pins) == 0 || all { // a pin makes the job AFFECTED; the rest is read only when asked
		type pkgJSON struct {
			path, name string
			names      []string
		}
		var read []pkgJSON
		local := map[string]bool{}  // names of workspace members; yarn v1 does not lock them
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
				r.mark(model.Unchecked)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("cannot parse %s: %v", e.Path, p.err)})
				continue
			}
			read = append(read, pkgJSON{e.Path, p.m.name, p.m.deps})
			if d := path.Dir(e.Path); p.m.hasWS && !pnpmWS[d] {
				ws[d] = append(ws[d], p.m.ws...)
			}
		}
		// Covering lockfile: nearest ancestor dir with one (workspaces lock at the root), if that
		// dir declares no workspaces or pdir is a member; else none ("" is no dir). member: pdir is a
		// workspace member of that dir. If the nearest one failed to parse, treat the package.json as unlocked.
		cover := func(pdir string) (dir string, member_ bool) {
			dir = pdir
			for lockNames[dir] == nil && !failedDirs[dir] && dir != "." && dir != "/" {
				dir = path.Dir(dir)
			}
			if globs, ok := ws[dir]; ok && dir != pdir {
				if !member(globs, strings.TrimPrefix(pdir, dir+"/")) {
					return "", false
				}
				return dir, true
			}
			return dir, false
		}
		for _, pj := range read {
			if _, isMember := cover(path.Dir(pj.path)); isMember && pj.name != "" && manifests <= maxManifests { // past the cap not every local name is known
				local[pj.name] = true
			}
		}
		for _, pj := range read {
			names := pj.names
			pdir := path.Dir(pj.path)
			dir, _ := cover(pdir)
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
				r.mark(model.Possible)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "npm", Detail: detail})
			}
			if lockNames[dir] == nil && !failedDirs[dir] && len(names) > 0 {
				r.mark(model.Unchecked)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("no lockfile for %s — transitive dependencies unknown", pj.path)})
			}
		}
	}
	if manifests > maxManifests {
		r.mark(model.Unchecked)
		r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("too many manifests (%d) — not all read", manifests)})
	}
	if truncated {
		r.mark(model.Unchecked)
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
	var p map[string]json.RawMessage // keys are case-sensitive, as in npm
	if err := json.Unmarshal(bytes.TrimPrefix(pkgJSON, []byte("\uFEFF")), &p); err != nil {
		return manifest{}, err
	}
	var m manifest
	_ = json.Unmarshal(p["name"], &m.name) // a non-string name is no local package
	var obj struct{ Packages []string }
	if json.Unmarshal(p["workspaces"], &m.ws) == nil {
		m.hasWS = m.ws != nil
	} else if json.Unmarshal(p["workspaces"], &obj) == nil && obj.Packages != nil {
		m.ws, m.hasWS = obj.Packages, true
	}
	kinds := map[string]map[string]any{}
	for _, k := range depKinds {
		if raw, ok := p[k]; ok {
			var deps map[string]any
			if err := json.Unmarshal(raw, &deps); err != nil {
				return manifest{}, err
			}
			kinds[k] = deps
		}
	}
	m.specs = depSpecs(func(k string) map[string]any { return kinds[k] })
	var out []string
	for _, deps := range kinds {
		for name, v := range deps {
			out = append(out, name)
			spec, _ := v.(string)
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
