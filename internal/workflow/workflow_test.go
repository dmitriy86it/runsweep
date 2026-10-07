package workflow

import (
	"os"
	"slices"
	"testing"
)

const wf = `
name: CI
on: push
permissions: {contents: read}
env:
  GLOBAL: ${{ secrets.SENTRY_DSN }}
jobs:
  build:
    name: Build ${{ matrix.node }}
    runs-on: ubuntu-latest
    strategy: {matrix: {node: [18, 20]}}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
      - run: npm ci
        env: {NODE_AUTH_TOKEN: "${{ secrets.NPM_TOKEN }}"}
  deploy:
    runs-on: ubuntu-latest
    permissions: {id-token: write, contents: read}
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::123456789012:role/deploy
          aws-region: eu-west-1
      - run: ./deploy.sh ${{ secrets['SLACK_WEBHOOK'] }} ${{ secrets.GITHUB_TOKEN }}
  release:
    uses: org/shared/.github/workflows/release.yml@main
    secrets: inherit
`

func TestParseAndExposure(t *testing.T) {
	w, err := Parse([]byte(wf))
	if err != nil {
		t.Fatal(err)
	}
	b := w.Jobs["build"]
	if !b.InstallsNPM() || w.Jobs["deploy"].InstallsNPM() {
		t.Fatal("InstallsNPM")
	}
	e := w.Exposure(b)
	if !slices.Equal(e.Secrets, []string{"NPM_TOKEN", "SENTRY_DSN"}) || e.IDTokenWrite || !e.JobMatched {
		t.Fatalf("build: %+v", e)
	}
	d := w.Exposure(w.Jobs["deploy"])
	if !d.IDTokenWrite || len(d.CloudRoles) != 1 || d.CloudRoles[0].Role != "arn:aws:iam::123456789012:role/deploy" {
		t.Fatalf("deploy: %+v", d)
	}
	if !slices.Contains(d.Secrets, "SLACK_WEBHOOK") || slices.Contains(d.Secrets, "GITHUB_TOKEN") {
		t.Fatalf("deploy secrets: %v", d.Secrets)
	}
	if !w.Exposure(w.Jobs["release"]).InheritAll {
		t.Fatal("secrets: inherit")
	}
	all := w.ExposureAll()
	if all.JobMatched || !all.InheritAll || !all.IDTokenWrite || len(all.Secrets) != 3 {
		t.Fatalf("all: %+v", all)
	}
}

func TestFindJob(t *testing.T) {
	w, _ := Parse([]byte(wf))
	for api, want := range map[string]string{
		"Build 18":                 "build",
		"Build ${{ matrix.node }}": "build",
		"deploy":                   "deploy",
		"deploy (eu, prod)":        "deploy",
		"release / publish":        "release",
	} {
		j, ok := w.FindJob(api)
		if !ok || j.ID != want {
			t.Errorf("%q -> %v %v, want %s", api, j, ok, want)
		}
	}
	if _, ok := w.FindJob("unknown"); ok {
		t.Error("unknown job must not match")
	}
}

func TestWriteAllGivesIDToken(t *testing.T) {
	w, _ := Parse([]byte("on: push\npermissions: write-all\njobs:\n  a:\n    runs-on: x\n    steps: [{run: echo}]\n"))
	if !w.Exposure(w.Jobs["a"]).IDTokenWrite {
		t.Fatal("write-all includes id-token: write")
	}
}

func TestParseTokenPerms(t *testing.T) {
	log := "2026-10-01T10:00:00.0000000Z ##[group]GITHUB_TOKEN Permissions\n" +
		"2026-10-01T10:00:00.0000000Z Contents: write\n" +
		"2026-10-01T10:00:00.0000000Z Metadata: read\n" +
		"2026-10-01T10:00:00.0000000Z ##[endgroup]\n"
	p := ParseTokenPerms(log)
	if p["contents"] != "write" || p["metadata"] != "read" || len(p) != 2 {
		t.Fatalf("%v", p)
	}
	b, _ := os.ReadFile("../match/actions/testdata/job.log")
	if len(ParseTokenPerms(string(b))) == 0 {
		t.Fatal("real log fixture must yield token permissions")
	}
}
