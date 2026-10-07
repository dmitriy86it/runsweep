package npm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
	"github.com/dmitriy86it/runsweep/internal/source"
)

// Fetcher is the part of source.Source the matcher needs.
type Fetcher interface {
	Tree(ctx context.Context, repo, sha string) ([]source.TreeEntry, bool, error)
	Blob(ctx context.Context, repo, blobSHA string) ([]byte, error)
}

type Result struct {
	Status   model.Status
	Evidence []model.Evidence
}

// Match checks every lockfile in repo@sha for bad versions. A package.json that
// lists a bad package and has no lockfile in its directory yields POSSIBLE.
func Match(ctx context.Context, f Fetcher, repo, sha string, bad []incident.NPMPackage) (Result, error) {
	var r Result
	entries, truncated, err := f.Tree(ctx, repo, sha)
	if err != nil {
		return r, err
	}
	badVer := map[string]map[string]bool{}
	for _, p := range bad {
		badVer[p.Name] = map[string]bool{}
		for _, v := range p.Versions {
			badVer[p.Name][v] = true
		}
	}
	lockNames := map[string]map[string]bool{} // dir -> package names in its successfully parsed lockfiles
	lockPaths := map[string]string{}          // dir -> a lockfile path, for evidence
	for _, e := range entries {
		if !IsLockfile(e.Path) {
			continue
		}
		b, err := f.Blob(ctx, repo, e.SHA)
		if err != nil {
			return r, err
		}
		pkgs, err := ParseLockfile(e.Path, b)
		if err != nil {
			r.Status = model.Worse(r.Status, model.Unchecked)
			r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("cannot parse %s: %v", e.Path, err)})
			continue
		}
		dir := path.Dir(e.Path)
		if lockNames[dir] == nil {
			lockNames[dir], lockPaths[dir] = map[string]bool{}, e.Path
		}
		for _, p := range pkgs {
			lockNames[dir][p.Name] = true
			if badVer[p.Name][p.Version] {
				r.Status = model.Affected
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "npm", Detail: fmt.Sprintf("%s@%s in %s at %s", p.Name, p.Version, e.Path, short(sha))})
			}
		}
	}
	if r.Status != model.Affected {
		for _, e := range entries {
			if path.Base(e.Path) != "package.json" || InNodeModules(e.Path) {
				continue
			}
			b, err := f.Blob(ctx, repo, e.SHA)
			if err != nil {
				return r, err
			}
			names, err := declared(b)
			if err != nil {
				r.Status = model.Worse(r.Status, model.Unchecked)
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: fmt.Sprintf("cannot parse %s: %v", e.Path, err)})
				continue
			}
			dir := path.Dir(e.Path)
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
		}
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
			if real, ok := strings.CutPrefix(spec, "npm:"); ok && real != "" {
				if at := strings.Index(real[1:], "@"); at >= 0 { // "@scope/pkg@^1" -> "@scope/pkg"
					real = real[:at+1]
				}
				out = append(out, real)
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
