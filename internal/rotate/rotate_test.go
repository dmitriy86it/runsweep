package rotate

import (
	"strings"
	"testing"

	"github.com/dmitriy86it/runsweep/internal/model"
)

func TestTier(t *testing.T) {
	for name, want := range map[string]int{
		"AWS_SECRET_ACCESS_KEY":   1,
		"GCP_SA_KEY":              1,
		"MINIO_SECRET_ACCESS_KEY": 1,
		"NPM_TOKEN":               2,
		"DOCKERHUB_PASSWORD":      2,
		"DEPLOY_SSH_KEY":          2,
		"PERSONAL_ACCESS_TOKEN":   2,
		"VAULT_TOKEN":             2,
		"TF_API_TOKEN":            2,
		"APP_PRIVATE_KEY":         2,
		"PULUMI_ACCESS_TOKEN":     2,
		"DB_PASSWORD":             2,
		"GH_PAT":                  2,
		"KUBECONFIG":              2,
		"SLACK_WEBHOOK":           3,
		"SENTRY_DSN":              3,
		"SNYK_TOKEN":              3,
		"OPENAI_API_KEY":          3,
	} {
		if got := Tier(name); got != want {
			t.Errorf("%s: %d want %d", name, got, want)
		}
	}
}

func TestPlan(t *testing.T) {
	run1 := model.RunRef{Repo: "o/a", RunID: 1, Job: "build"}
	run2 := model.RunRef{Repo: "o/b", RunID: 2, Job: "deploy"}
	uncheckedRun := model.RunRef{Repo: "o/c"}
	fs := []model.Finding{
		{Run: run1, Status: model.Affected, Exposure: &model.Exposure{Secrets: []string{"NPM_TOKEN", "SLACK_WEBHOOK"},
			TokenPerms: map[string]string{"contents": "write"}}},
		{Run: run2, Status: model.Possible, Exposure: &model.Exposure{Secrets: []string{"NPM_TOKEN"}, IDTokenWrite: true,
			CloudRoles: []model.CloudRole{{Provider: "aws", Role: "arn:aws:iam::1:role/deploy"}}, InheritAll: true}},
		{Run: uncheckedRun, Status: model.Unchecked},
	}
	p := Plan(fs)
	if len(p) < 5 {
		t.Fatalf("%+v", p)
	}
	if p[0].Tier != 1 || p[1].Tier != 1 || (p[0].Name != "aws role arn:aws:iam::1:role/deploy" && p[1].Name != "aws role arn:aws:iam::1:role/deploy") {
		t.Fatalf("cloud role and inherited secrets must come first: %+v", p[:2])
	}
	var npm *model.RotationItem
	for i := range p {
		if p[i].Name == "NPM_TOKEN" {
			npm = &p[i]
		}
	}
	if npm == nil || len(npm.Runs) != 2 {
		t.Fatalf("NPM_TOKEN must aggregate both runs: %+v", npm)
	}
	// Assert UNCHECKED run does not appear in any item
	for i := range p {
		for _, run := range p[i].Runs {
			if run.Repo == uncheckedRun.Repo && run.RunID == uncheckedRun.RunID {
				t.Fatalf("UNCHECKED finding should not contribute: %+v", p[i])
			}
		}
	}
	last := p[len(p)-1]
	if last.Tier != 4 || last.Name != "GITHUB_TOKEN" {
		t.Fatalf("GITHUB_TOKEN with write perms goes last: %+v", last)
	}
}

func TestOIDCToken(t *testing.T) {
	run := model.RunRef{Repo: "o/a", RunID: 1, Job: "build"}
	fs := []model.Finding{
		{Run: run, Status: model.Possible, Exposure: &model.Exposure{IDTokenWrite: true}},
	}
	p := Plan(fs)
	if len(p) != 1 {
		t.Fatalf("expected 1 item, got %d: %+v", len(p), p)
	}
	if p[0].Name != "OIDC token (id-token: write)" || p[0].Tier != 1 {
		t.Fatalf("should have OIDC token tier 1: %+v", p[0])
	}
	if len(p[0].Runs) != 1 || p[0].Runs[0].Repo != "o/a" {
		t.Fatalf("should have one run: %+v", p[0])
	}
}

func TestGitHubTokenInSecrets(t *testing.T) {
	run := model.RunRef{Repo: "o/a", RunID: 1, Job: "build"}
	fs := []model.Finding{
		{Run: run, Status: model.Affected, Exposure: &model.Exposure{
			Secrets:    []string{"GITHUB_TOKEN"},
			TokenPerms: map[string]string{"contents": "write"},
		}},
	}
	p := Plan(fs)
	if len(p) != 1 {
		t.Fatalf("expected 1 item (only tier-4 GITHUB_TOKEN), got %d: %+v", len(p), p)
	}
	if p[0].Tier != 4 || p[0].Name != "GITHUB_TOKEN" {
		t.Fatalf("should have tier-4 GITHUB_TOKEN: %+v", p[0])
	}
	if !strings.Contains(p[0].Reason, "contents") {
		t.Fatalf("reason should mention contents: %s", p[0].Reason)
	}
}

func TestDuplicateRuns(t *testing.T) {
	run := model.RunRef{Repo: "o/a", RunID: 1, JobID: 100, Job: "build"}
	fs := []model.Finding{
		{Run: run, Status: model.Affected, Exposure: &model.Exposure{Secrets: []string{"NPM_TOKEN", "NPM_TOKEN"}}},
		{Run: run, Status: model.Affected, Exposure: &model.Exposure{Secrets: []string{"NPM_TOKEN"}}},
	}
	p := Plan(fs)
	var npm *model.RotationItem
	for i := range p {
		if p[i].Name == "NPM_TOKEN" {
			npm = &p[i]
		}
	}
	if npm == nil || len(npm.Runs) != 1 {
		t.Fatalf("NPM_TOKEN should have 1 run (deduplicated): %+v", npm)
	}
}

func TestRunsSorted(t *testing.T) {
	run3 := model.RunRef{Repo: "o/c", RunID: 3, Job: "job"}
	run1 := model.RunRef{Repo: "o/a", RunID: 1, Job: "job"}
	run2 := model.RunRef{Repo: "o/b", RunID: 2, Job: "job"}
	fs := []model.Finding{
		{Run: run3, Status: model.Affected, Exposure: &model.Exposure{Secrets: []string{"SECRET"}}},
		{Run: run1, Status: model.Affected, Exposure: &model.Exposure{Secrets: []string{"SECRET"}}},
		{Run: run2, Status: model.Affected, Exposure: &model.Exposure{Secrets: []string{"SECRET"}}},
	}
	p := Plan(fs)
	var item *model.RotationItem
	for i := range p {
		if p[i].Name == "SECRET" {
			item = &p[i]
		}
	}
	if item == nil || len(item.Runs) != 3 {
		t.Fatalf("expected 3 runs: %+v", item)
	}
	if item.Runs[0].Repo != "o/a" || item.Runs[1].Repo != "o/b" || item.Runs[2].Repo != "o/c" {
		t.Fatalf("runs should be sorted by Repo: %+v", item.Runs)
	}
}
