package rotate

import (
	"testing"

	"github.com/dmitriy86it/runsweep/internal/model"
)

func TestTier(t *testing.T) {
	for name, want := range map[string]int{"AWS_SECRET_ACCESS_KEY": 1, "GCP_SA_KEY": 1, "NPM_TOKEN": 2,
		"DOCKERHUB_PASSWORD": 2, "DEPLOY_SSH_KEY": 2, "SLACK_WEBHOOK": 3, "SENTRY_DSN": 3} {
		if got := Tier(name); got != want {
			t.Errorf("%s: %d want %d", name, got, want)
		}
	}
}

func TestPlan(t *testing.T) {
	run1 := model.RunRef{Repo: "o/a", RunID: 1, Job: "build"}
	run2 := model.RunRef{Repo: "o/b", RunID: 2, Job: "deploy"}
	fs := []model.Finding{
		{Run: run1, Status: model.Affected, Exposure: &model.Exposure{Secrets: []string{"NPM_TOKEN", "SLACK_WEBHOOK"},
			TokenPerms: map[string]string{"contents": "write"}}},
		{Run: run2, Status: model.Possible, Exposure: &model.Exposure{Secrets: []string{"NPM_TOKEN"}, IDTokenWrite: true,
			CloudRoles: []model.CloudRole{{Provider: "aws", Role: "arn:aws:iam::1:role/deploy"}}, InheritAll: true}},
		{Run: model.RunRef{Repo: "o/c"}, Status: model.Unchecked},
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
	last := p[len(p)-1]
	if last.Tier != 4 || last.Name != "GITHUB_TOKEN" {
		t.Fatalf("GITHUB_TOKEN with write perms goes last: %+v", last)
	}
}
