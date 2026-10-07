// Package rotate turns exposures into a prioritized rotation list.
package rotate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/dmitriy86it/runsweep/internal/model"
)

// Name-based tiers are a heuristic; the report says so.
var (
	cloudRe   = regexp.MustCompile(`(?i)(AWS|AZURE|ARM_|GCP|GOOGLE|GCLOUD|GKE|SERVICE_ACCOUNT|DIGITALOCEAN|CLOUDFLARE|HCLOUD|OCI_)`)
	publishRe = regexp.MustCompile(`(?i)(NPM|NODE_AUTH|PYPI|TWINE|DOCKER|REGISTRY|GHCR|PAT|GH_TOKEN|DEPLOY|SSH|KUBE|HELM|SIGN|GPG|COSIGN|RELEASE|PUBLISH|CARGO|RUBYGEMS|NUGET)`)
)

func Tier(secret string) int {
	switch {
	case cloudRe.MatchString(secret):
		return 1
	case publishRe.MatchString(secret):
		return 2
	}
	return 3
}

var reasons = map[int]string{
	1: "cloud credentials — rotate now and review cloud audit logs for the incident window",
	2: "publish/deploy credentials — rotate; check registries and deploy targets for unexpected releases",
	3: "third-party service credentials — rotate",
}

func Plan(findings []model.Finding) []model.RotationItem {
	items := map[string]*model.RotationItem{}
	add := func(name string, tier int, reason string, run model.RunRef) {
		it, ok := items[name]
		if !ok {
			it = &model.RotationItem{Name: name, Tier: tier, Reason: reason}
			items[name] = it
		}
		if tier < it.Tier {
			it.Tier, it.Reason = tier, reason
		}
		it.Runs = append(it.Runs, run)
	}
	for _, f := range findings {
		if f.Status < model.Possible || f.Exposure == nil {
			continue
		}
		e := f.Exposure
		for _, r := range e.CloudRoles {
			add(fmt.Sprintf("%s role %s", r.Provider, r.Role), 1,
				"OIDC role the job could assume — no static secret to rotate; review cloud audit logs for the window and tighten the trust policy", f.Run)
		}
		if e.IDTokenWrite && len(e.CloudRoles) == 0 {
			add("OIDC token (id-token: write)", 1,
				"job could mint OIDC tokens — find every cloud role trusting this repo and review its audit logs for the window", f.Run)
		}
		if e.InheritAll {
			add("ALL repository and organization secrets (secrets: inherit)", 1,
				"reusable workflow received every secret — list them in repo/org settings and rotate", f.Run)
		}
		for _, s := range e.Secrets {
			t := Tier(s)
			add(s, t, reasons[t], f.Run)
		}
		var writes []string
		for scope, level := range e.TokenPerms {
			if level == "write" {
				writes = append(writes, scope)
			}
		}
		if len(writes) > 0 {
			sort.Strings(writes)
			add("GITHUB_TOKEN", 4, "expires when the job ends (no rotation), but had write access to: "+
				strings.Join(writes, ", ")+" — check for pushes, releases or package publishes in the window", f.Run)
		}
	}
	out := make([]model.RotationItem, 0, len(items))
	for _, it := range items {
		out = append(out, *it)
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Tier != out[b].Tier {
			return out[a].Tier < out[b].Tier
		}
		return out[a].Name < out[b].Name
	})
	return out
}
