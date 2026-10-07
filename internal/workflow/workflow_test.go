package workflow

import (
	"os"
	"slices"
	"testing"
	"time"
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

const wf2 = `
on: push
x-perms: &p {id-token: write}
x-defaults: &defaults {runs-on: x, permissions: {id-token: write}}
jobs:
  a:
    runs-on: x
    env: &common {T: "${{ secrets.aliased }}"}
    steps: [{run: "echo ${{ toJSON(secrets) }}"}]
  br:
    runs-on: x
    steps: [{run: "echo ${{ secrets[format('{0}_KEY', matrix.env)] }}"}]
  b:
    runs-on: x
    permissions: *p
    env: *common
    steps: [{run: "echo ${{ secrets.npm_token }} ${{ secrets.github_token }}"}]
  m:
    <<: *defaults
    steps: [{run: echo}]
  t1:
    name: Test ${{ matrix.os }}
    runs-on: x
    steps: [{run: echo}]
  t2:
    name: Test e2e ${{ matrix.browser }}
    runs-on: x
    steps: [{run: echo}]
  lint:
    runs-on: x
    steps: [{run: echo}]
  lf:
    name: lint / format
    runs-on: x
    steps: [{run: echo}]
  g:
    runs-on: x
    steps:
      - uses: google-github-actions/auth@v2
        with: {workload_identity_provider: projects/1/wip, service_account: sa@p.iam}
`

func TestHardening(t *testing.T) {
	w, err := Parse([]byte(wf2))
	if err != nil {
		t.Fatal(err)
	}
	if !w.Exposure(w.Jobs["a"]).InheritAll || !w.Exposure(w.Jobs["br"]).InheritAll {
		t.Error("dynamic secret access must mean all secrets")
	}
	b := w.Exposure(w.Jobs["b"])
	if !b.IDTokenWrite || !slices.Equal(b.Secrets, []string{"ALIASED", "NPM_TOKEN"}) || b.InheritAll {
		t.Errorf("alias/upper/GITHUB_TOKEN: %+v", b)
	}
	if !w.Exposure(w.Jobs["m"]).IDTokenWrite {
		t.Error("merge key permissions")
	}
	if len(w.Jobs["g"].CloudRoles) != 2 {
		t.Errorf("gcp roles: %v", w.Jobs["g"].CloudRoles)
	}
	if len(w.ExposureAll().CloudRoles) != 2 {
		t.Error("ExposureAll cloud roles")
	}
	for i := 0; i < 50; i++ {
		w, _ := Parse([]byte(wf2))
		for api, want := range map[string]string{
			"Test e2e chrome": "t2", "Test linux": "t1", "lint / format": "lf",
			"lint": "lint", "lint / other": "lint", "Test e2e chrome (a, b)": "t2",
		} {
			if j, ok := w.FindJob(api); !ok || j.ID != want {
				t.Fatalf("%q -> %v %v, want %s", api, j, ok, want)
			}
		}
		if j, ok := w.FindJob("Testing (x)"); ok {
			t.Fatalf("Testing matched %s", j.ID)
		}
	}
}

func TestAliasedWorkflowEnvAndSteps(t *testing.T) {
	w, err := Parse([]byte("on: push\nenv: {K: '${{ toJSON(secrets) }}'}\nx: &s [{run: npx foo}]\njobs:\n  a: {runs-on: x, steps: *s}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !w.Exposure(w.Jobs["a"]).InheritAll || !w.Jobs["a"].InstallsNPM() {
		t.Fatal("workflow-level dynamic / aliased steps")
	}
}

func TestInstallsNPMConservative(t *testing.T) {
	for run, want := range map[string]bool{
		"npx cypress run": true, "cd x && pnpm test": true, "yarn": true, "bunx foo": true,
		"NODE_ENV=production npm ci": true, "if x; then npm ci; fi": true,
		"for d in a b; do npm ci; done": true, "time npm ci": true, "env npm ci": true,
		"ls | xargs npm ci": true, "x=`npm ci`": true, "docker run x npm ci": true,
		"npmrc-tool": false, "./scripts/yarnish": false, "go test ./...": false,
	} {
		j := &Job{Runs: []string{run}}
		if j.InstallsNPM() != want {
			t.Errorf("%q: want %v", run, want)
		}
	}
	if !(&Job{Uses: []string{"cypress-io/github-action@v6"}}).InstallsNPM() {
		t.Error("cypress action")
	}
}

func TestParseTokenPermsNoGroup(t *testing.T) {
	if len(ParseTokenPerms("hello\nContents: write\n")) != 0 {
		t.Fatal("no group, no perms")
	}
}

func parseWithin(t *testing.T, src string) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { _, err := Parse([]byte(src)); done <- err }()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatal("Parse hangs")
		return nil
	}
}

func TestYAMLBombs(t *testing.T) {
	if parseWithin(t, "x: &a [*a]\njobs: {}\n") == nil {
		t.Error("alias cycle must error")
	}
	if parseWithin(t, "on: push\nenv: &e {A: *e}\njobs: {}\n") == nil {
		t.Error("map alias cycle must error")
	}
	bomb := "a: &a [x,x,x,x,x,x,x,x,x]\n"
	prev := "a"
	for _, n := range []string{"b", "c", "d", "e", "f", "g", "h", "i", "j"} {
		bomb += n + ": &" + n + " [*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + "]\n"
		prev = n
	}
	_ = parseWithin(t, bomb+"jobs: {}\n") // error or fast success, never a hang
}

func TestExpressionOnlyName(t *testing.T) {
	w, err := Parse([]byte("on: push\njobs:\n  lint: {runs-on: x, steps: [{run: echo}]}\n  mx: {name: '${{ matrix.n }}', runs-on: x, steps: [{run: echo}]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if j, ok := w.FindJob("lint / other"); !ok || j.ID != "lint" {
		t.Errorf("lint / other -> %v %v", j, ok)
	}
	if _, ok := w.FindJob("random thing"); ok {
		t.Error("expression-only name must not match")
	}
}

func TestWholeSecretsContext(t *testing.T) {
	for _, e := range []string{
		"${{ secrets }}", "${{ fromJSON(toJSON(secrets)) }}", "${{ toJson( secrets ) }}", "${{ join(secrets, ',') }}",
		"${{ SECRETS[format('{0}', x)] }}",
	} {
		w, err := Parse([]byte("on: push\njobs:\n  a: {runs-on: x, steps: [{run: \"echo " + e + "\"}]}\n"))
		if err != nil {
			t.Fatal(err)
		}
		if !w.Exposure(w.Jobs["a"]).InheritAll {
			t.Errorf("%s must expose all secrets", e)
		}
	}
	w, _ := Parse([]byte("on: push\njobs:\n  a: {runs-on: x, steps: [{run: \"echo ${{ secrets.A }} ${{ secrets['B'] }}\"}]}\n"))
	if e := w.Exposure(w.Jobs["a"]); e.InheritAll || !slices.Equal(e.Secrets, []string{"A", "B"}) {
		t.Errorf("named access: %+v", e)
	}
}

func TestCloudRolesDedupeAndCopy(t *testing.T) {
	step := "steps: [{uses: 'aws-actions/configure-aws-credentials@v4', with: {role-to-assume: r1}}]"
	w, err := Parse([]byte("on: push\njobs:\n  a: {runs-on: x, " + step + "}\n  b: {runs-on: x, " + step + "}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if n := len(w.ExposureAll().CloudRoles); n != 1 {
		t.Errorf("dedupe: %d", n)
	}
	e := w.Exposure(w.Jobs["a"])
	e.CloudRoles[0].Role = "mutated"
	if w.Jobs["a"].CloudRoles[0].Role != "r1" {
		t.Error("Exposure aliases job slice")
	}
}
