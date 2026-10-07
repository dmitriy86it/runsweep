package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"path"
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
	lockDirs := map[string]bool{}
	for _, e := range entries {
		if !IsLockfile(e.Path) {
			continue
		}
		lockDirs[path.Dir(e.Path)] = true
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
		for _, p := range pkgs {
			if badVer[p.Name][p.Version] {
				r.Status = model.Affected
				r.Evidence = append(r.Evidence, model.Evidence{Kind: "npm", Detail: fmt.Sprintf("%s@%s in %s at %s", p.Name, p.Version, e.Path, short(sha))})
			}
		}
	}
	if r.Status != model.Affected {
		for _, e := range entries {
			if path.Base(e.Path) != "package.json" || strings.Contains(e.Path, "node_modules/") || lockDirs[path.Dir(e.Path)] {
				continue
			}
			b, err := f.Blob(ctx, repo, e.SHA)
			if err != nil {
				return r, err
			}
			for _, name := range declared(b) {
				if _, ok := badVer[name]; ok {
					r.Status = model.Worse(r.Status, model.Possible)
					r.Evidence = append(r.Evidence, model.Evidence{Kind: "npm", Detail: fmt.Sprintf("%s declared in %s without a lockfile — installed version unknown", name, e.Path)})
				}
			}
		}
	}
	if truncated && r.Status == model.Clean {
		r.Status = model.Unchecked
		r.Evidence = append(r.Evidence, model.Evidence{Kind: "note", Detail: "git tree truncated by GitHub; some lockfiles were not checked"})
	}
	return r, nil
}

func declared(pkgJSON []byte) []string {
	var p struct {
		Dependencies, DevDependencies, OptionalDependencies, PeerDependencies map[string]string
	}
	if json.Unmarshal(pkgJSON, &p) != nil {
		return nil
	}
	var out []string
	for _, m := range []map[string]string{p.Dependencies, p.DevDependencies, p.OptionalDependencies, p.PeerDependencies} {
		for name := range m {
			out = append(out, name)
		}
	}
	return out
}

func short(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}
