package workflow

import (
	"fmt"
	"os"
	"slices"
	"strings"
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

// A name the regexp engine rejects (invalid UTF-8) or an overlong one never panics or matches.
func TestFindJobBadTemplateName(t *testing.T) {
	long := strings.Repeat("x", 1025) + " ${{ matrix.n }}"
	w := &Workflow{Jobs: map[string]*Job{"bad": {ID: "bad", Name: "a\xff ${{ matrix.n }}"}, "long": {ID: "long", Name: long}}}
	if j, ok := w.FindJob("a\xff 1"); ok {
		t.Fatalf("matched %v", j)
	}
	if j, ok := w.FindJob(strings.Repeat("x", 1025) + " 1"); ok {
		t.Fatalf("matched %v", j)
	}
}

// A short template must not take the match from an overlong one that is not compared.
func TestFindJobOverlongTemplateIsAmbiguous(t *testing.T) {
	long := "build " + strings.Repeat("x", 1100) + " ${{ matrix.n }}"
	w := &Workflow{Jobs: map[string]*Job{"a": {ID: "a", Name: "build ${{ matrix.n }}"}, "b": {ID: "b", Name: long}}}
	if j, ok := w.findStaged("build " + strings.Repeat("x", 1100) + " 1"); j != nil || !ok {
		t.Fatalf("want ambiguous, got %v %v", j, ok)
	}
}

// Templated names are compiled once per workflow, not on every FindJob.
func TestFindJobCompilesOnce(t *testing.T) {
	w := &Workflow{Jobs: map[string]*Job{}}
	for i := range 200 {
		id := fmt.Sprintf("j%d", i)
		w.Jobs[id] = &Job{ID: id, Name: fmt.Sprintf("Job %d ${{ matrix.n }}", i)}
	}
	w.FindJob("Job 7 linux")
	// compiling costs dozens of allocations per job; matching alone stays under one per job
	if n := testing.AllocsPerRun(5, func() { w.FindJob("Job 7 linux") }); n >= 200 {
		t.Fatalf("%v allocations per FindJob", n)
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
	if !(&Job{Scripts: []string{"await exec.exec('npm', ['ci'])"}}).InstallsNPM() {
		t.Error("github-script running npm installs")
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
	// the expression-only name may evaluate to "lint": the ID hit is no longer certain
	if j, ok := w.FindJob("lint / other"); ok {
		t.Errorf("lint / other -> %v", j)
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

func TestMayInstallNPM(t *testing.T) {
	for name, tc := range map[string]struct {
		j    Job
		want bool
	}{
		"checkout+echo":   {Job{Uses: []string{"actions/checkout@v4", "actions/setup-node@v4", "actions/cache@v4"}, Runs: []string{"echo hi"}}, false},
		"local action":    {Job{Uses: []string{"actions/checkout@v4", "./.github/actions/setup"}}, true},
		"reusable":        {Job{Uses: []string{"./.github/workflows/build.yml"}}, true},
		"third-party":     {Job{Uses: []string{"some/action@v1"}}, true},
		"make":            {Job{Runs: []string{"make test"}}, true},
		"bash -c":         {Job{Runs: []string{"bash -c 'x'"}}, true},
		"script":          {Job{Runs: []string{"./scripts/build"}}, true},
		"sh file":         {Job{Runs: []string{"ci/run.sh"}}, true},
		"python":          {Job{Runs: []string{"python3 build.py"}}, true},
		"npm":             {Job{Runs: []string{"npm ci"}}, true},
		"go":              {Job{Runs: []string{"go test ./..."}}, false},
		"echo":            {Job{Runs: []string{"echo done"}}, false},
		"docker build":    {Job{Runs: []string{"docker build ."}}, true},
		"compose":         {Job{Runs: []string{"docker-compose up"}}, true},
		"podman":          {Job{Runs: []string{"podman build ."}}, true},
		"buildah":         {Job{Runs: []string{"buildah bud ."}}, true},
		"mvn":             {Job{Runs: []string{"mvn -B package"}}, true},
		"mvnw":            {Job{Runs: []string{"./mvnw verify"}}, true},
		"gradle":          {Job{Runs: []string{"gradle build"}}, true},
		"gradlew":         {Job{Runs: []string{"./gradlew build"}}, true},
		"sbt":             {Job{Runs: []string{"sbt test"}}, true},
		"bazel":           {Job{Runs: []string{"bazel build //..."}}, true},
		"dotnet":          {Job{Runs: []string{"dotnet build"}}, true},
		"composer":        {Job{Runs: []string{"composer install"}}, true},
		"github-script":   {Job{Uses: []string{"actions/github-script@v7"}}, false},
		"script exec":     {Job{Uses: []string{"actions/github-script@v7"}, Scripts: []string{"await exec.exec('make', ['x'])"}}, true},
		"script spawn":    {Job{Uses: []string{"actions/github-script@v7"}, Scripts: []string{"require('child_process').spawnSync(tool)"}}, true},
		"script template": {Job{Uses: []string{"actions/github-script@v7"}, Scripts: []string{"await $`make`"}}, true},
		"script npm":      {Job{Uses: []string{"actions/github-script@v7"}, Scripts: []string{"run('npm', ['ci'])"}}, true},
		"script api":      {Job{Uses: []string{"actions/github-script@v7"}, Scripts: []string{"await github.rest.issues.create({})"}}, false},
		"turbo in a pipe": {Job{Runs: []string{"echo x | turbo run build"}}, true},
	} {
		if got := tc.j.MayInstallNPM(); got != tc.want {
			t.Errorf("%s: want %v", name, tc.want)
		}
	}
}

func TestParseCall(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	for uses, want := range map[string]Call{
		"./.github/workflows/build.yml":                    {Path: ".github/workflows/build.yml"},
		"org/shared/.github/workflows/release.yaml@" + sha: {Repo: "org/shared", Path: ".github/workflows/release.yaml", SHA: sha},
	} {
		if got, ok := ParseCall(uses); !ok || got != want {
			t.Errorf("%q -> %+v %v, want %+v", uses, got, ok, want)
		}
	}
	for _, uses := range []string{
		"org/shared/.github/workflows/release.yml@main",
		"org/shared/.github/workflows/release.yml@v1",
		"org/shared/.github/workflows/release.yml",
		"org/shared/.github/workflows/release.yml@" + sha[:7],
		"../x/.github/workflows/a.yml@" + sha,
		"org/shared/.github/workflows/../../a.yml@" + sha,
		"./.github/workflows/../secrets.yml",
		"./scripts/x.yml",
		"actions/checkout@" + sha,
		"org/shared/.github/workflows/a.yml@" + sha + "@" + sha,
		"org/shared/.github/workflows/a.yml@" + strings.ToUpper(sha),
		"/shared/.github/workflows/a.yml@" + sha,
		"org/./.github/workflows/a.yml@" + sha,
		"./.github/workflows/a.yml@main",
		"/.github/workflows/a.yml",
		"./.github/workflows/sub/a.yml",
		"org/shared/.github/workflows/sub/a.yml@" + sha,
		"./.github/workflows/a\\b.yml",
	} {
		if c, ok := ParseCall(uses); ok {
			t.Errorf("%q must not be readable: %+v", uses, c)
		}
	}
}

const callerYAML = `
on: push
env: {G: "${{ secrets.CALLER_GLOBAL }}"}
jobs:
  inherit:
    uses: ./.github/workflows/deploy.yml
    secrets: inherit
  explicit:
    uses: ./.github/workflows/deploy.yml
    permissions: {id-token: write}
    secrets: {TOKEN: "${{ secrets.NPM_TOKEN }}"}
`

const calleeYAML = `
on: workflow_call
env: {C: "${{ secrets.CALLEE_GLOBAL }}"}
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions: {id-token: write}
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with: {role-to-assume: "arn:aws:iam::1:role/deploy"}
      - run: npm ci
        env: {T: "${{ secrets.TOKEN }}", D: "${{ secrets.DEPLOY_KEY }}"}
`

func TestThrough(t *testing.T) {
	w, err := Parse([]byte(callerYAML))
	if err != nil {
		t.Fatal(err)
	}
	cw, err := Parse([]byte(calleeYAML))
	if err != nil {
		t.Fatal(err)
	}
	if w.Jobs["inherit"].Call != "./.github/workflows/deploy.yml" {
		t.Fatalf("Call: %q", w.Jobs["inherit"].Call)
	}
	c := cw.Jobs["deploy"]

	ew, ej := w.Through(w.Jobs["inherit"], cw, c)
	e := ew.Exposure(ej)
	if !e.InheritAll || !e.IDTokenWrite || len(e.CloudRoles) != 1 || e.CloudRoles[0].Role != "arn:aws:iam::1:role/deploy" ||
		!slices.Equal(e.Secrets, []string{"CALLEE_GLOBAL", "CALLER_GLOBAL", "DEPLOY_KEY", "TOKEN"}) {
		t.Fatalf("inherit: %+v", e)
	}
	if !ej.InstallsNPM() || slices.Contains(ej.Uses, "./.github/workflows/deploy.yml") {
		t.Fatalf("uses/runs must come from the callee: %+v", ej)
	}

	ew, ej = w.Through(w.Jobs["explicit"], cw, c)
	e = ew.Exposure(ej)
	// callee names (TOKEN, DEPLOY_KEY) are mapping keys or unset here, not the caller's secrets
	if e.InheritAll || !e.IDTokenWrite || !slices.Equal(e.Secrets, []string{"CALLER_GLOBAL", "NPM_TOKEN"}) {
		t.Fatalf("explicit: %+v", e)
	}
	// callee id-token: write is not lost to an empty callee permissions block either way
	cw2, _ := Parse([]byte("on: workflow_call\njobs:\n  d: {permissions: {}, runs-on: x}\n"))
	if _, ej2 := w.Through(w.Jobs["explicit"], cw2, cw2.Jobs["d"]); !ej2.IDTokenWrite {
		t.Fatal("caller id-token: write must carry through")
	}

	// callee job with environment: reads that environment's secrets even when the caller passes explicitly
	cw3, _ := Parse([]byte("on: workflow_call\nenv: {C: \"${{ secrets.CALLEE_GLOBAL }}\"}\njobs:\n  d:\n    runs-on: x\n    environment: prod\n    steps: [{run: x, env: {K: \"${{ secrets.PROD_AWS_KEY }}\"}}]\n"))
	ew, ej = w.Through(w.Jobs["explicit"], cw3, cw3.Jobs["d"])
	if e = ew.Exposure(ej); e.InheritAll || !slices.Contains(e.Secrets, "PROD_AWS_KEY") || !slices.Contains(e.Secrets, "NPM_TOKEN") {
		t.Fatalf("environment: %+v", e)
	}
	if !slices.Equal(c.Secrets, []string{"DEPLOY_KEY", "TOKEN"}) || len(w.Jobs["explicit"].Secrets) != 1 {
		t.Fatal("Through must not modify its inputs")
	}
}

func TestUnionIsDeterministic(t *testing.T) {
	w, _ := Parse([]byte("on: push\njobs:\n" +
		"  b: {runs-on: x, steps: [{uses: 'azure/login@v2', with: {client-id: b}}]}\n" +
		"  a: {runs-on: x, steps: [{uses: 'azure/login@v2', with: {client-id: a}}]}\n"))
	for i := 0; i < 20; i++ {
		if r := w.ExposureAll().CloudRoles; len(r) != 2 || r[0].Role != "a" {
			t.Fatalf("%v", r)
		}
	}
}

func TestRunInstalls(t *testing.T) {
	for script, want := range map[string][]string{
		"npx cowsay hi":                            {"npx cowsay hi", "cowsay", "hi"},
		"npx -y @scope/pkg@1.2.3 --flag":           {"npx -y @scope/pkg@1.2.3 --flag", "@scope/pkg"},
		"npx --yes axios@latest":                   {"npx --yes axios@latest", "axios"},
		"npx -p axios cmd":                         {"npx -p axios cmd", "axios", "cmd"},
		"npx --package=axios cmd":                  {"npx --package=axios cmd", "axios", "cmd"},
		"cd x && npm i -g axios left-pad; ls":      {"npm i -g axios left-pad", "axios", "left-pad"},
		"npm install axios@1.14.1":                 {"npm install axios@1.14.1", "axios"},
		"npm add foo@npm:axios@1":                  {"npm add foo@npm:axios@1", "foo", "axios"},
		"pnpm add @tanstack/query":                 {"pnpm add @tanstack/query", "@tanstack/query"},
		"pnpm dlx create-x app":                    {"pnpm dlx create-x app", "create-x", "app"},
		"yarn add -D axios":                        {"yarn add -D axios", "axios"},
		"yarn dlx axios":                           {"yarn dlx axios", "axios"},
		"bunx axios":                               {"bunx axios", "axios"},
		"execSync('npx axios --x')":                {"npx axios --x", "axios"},
		`npm i "axios" 'left-pad',`:                {"npm i axios left-pad", "axios", "left-pad"},
		"npm exec -- axios":                        {"npm exec -- axios", "axios"},
		"npm x axios@1 foo":                        {"npm x axios@1 foo", "axios", "foo"},
		"pnpx axios":                               {"pnpx axios", "axios"},
		"npx --foo bar axios":                      {"npx --foo bar axios", "bar", "axios"},
		"bun add axios":                            {"bun add axios", "axios"},
		"bun x axios":                              {"bun x axios", "axios"},
		"yarn global add axios":                    {"yarn global add axios", "axios"},
		"npm -g install axios":                     {"npm -g install axios", "axios"},
		"pnpm --filter web add axios":              {"pnpm --filter web add axios", "axios"},
		"npm i --registry https://r.example axios": {"npm i --registry https://r.example axios", "https://r.example", "axios"},
		"npm install --prefix /tmp/x axios":        {"npm install --prefix /tmp/x axios", "/tmp/x", "axios"},
		"npm run build":                            nil,
		"bun install":                              nil,
		"yarn global bin":                          nil,
		"npm ci `npm i axios`":                     {"npm i axios", "axios"},
		"npm ci $(npm i axios)":                    {"npm i axios", "axios"},
		"yarn --version `npx axios`":               {"npx axios", "axios"},
		"npm i \\\n  axios":                        {"npm i axios", "axios"},
		"npm i `\r\n  axios":                       {"npm i axios", "axios"},
		"npm i $PKG":                               {"npm i $PKG", "DYN"},
		"npm i %PKG%":                              {"npm i %PKG%", "DYN"},
		"npx ${{inputs.tool}}":                     {"npx ${{inputs.tool}}", "DYN"},
		"npm i `cat pkgs`":                         {"npm i cat pkgs", "pkgs", "DYN"},
		"npm i axios@$VER":                         {"npm i axios@$VER", "axios"},
		"bun i axios":                              {"bun i axios", "axios"},
		"bun install axios":                        {"bun install axios", "axios"},
		"yarn workspace web add axios":             {"yarn workspace web add axios", "axios"},
		"npm in axios":                             {"npm in axios", "axios"},
		"npm ins axios":                            {"npm ins axios", "axios"},
		"npm isntall axios":                        {"npm isntall axios", "axios"},
		"npm it axios":                             {"npm it axios", "axios"},
		"npm install-test axios":                   {"npm install-test axios", "axios"},
		"npm i -w web axios":                       {"npm i -w web axios", "web", "axios"},
		"npm i --workspace web axios":              {"npm i --workspace web axios", "web", "axios"},
		"pnpm add -w axios":                        {"pnpm add -w axios", "axios"},
		"pnpm add --workspace axios":               {"pnpm add --workspace axios", "axios"},
		"yarn add -C axios":                        {"yarn add -C axios", "axios"},
		"yarn add -F axios":                        {"yarn add -F axios", "axios"},
		"npm ci":                                   nil,
		"npm install":                              nil,
		"npm init -y":                              nil,
		"echo npxfoo":                              nil,
		"./node_modules/.bin/npx-like axios":       nil,
		"yarn install --frozen-lockfile":           nil,
		"pnpm install":                             nil,
	} {
		var got []string
		for _, in := range runInstalls(script) {
			got = append(append(got, in.Cmd), in.Pkgs...)
			if in.Dynamic {
				got = append(got, "DYN")
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%q: got %q, want %q", script, got, want)
		}
	}
}

func TestGithubScriptInstalls(t *testing.T) {
	w, err := Parse([]byte("on: push\njobs:\n  a:\n    runs-on: x\n    steps:\n" +
		"      - uses: actions/github-script@v7\n        with:\n          script: |\n            require('child_process').execSync('npx -y axios')\n"))
	if err != nil {
		t.Fatal(err)
	}
	j := w.Jobs["a"]
	if in := j.RunInstalls(); len(in) != 1 || in[0].Pkgs[0] != "axios" || !j.MayInstallNPM() {
		t.Fatalf("%+v", in)
	}
	if in := w.Union().RunInstalls(); len(in) != 1 {
		t.Fatalf("union must keep scripts: %+v", in)
	}
	if _, ej := w.Through(&Job{ID: "c"}, w, j); len(ej.RunInstalls()) != 1 {
		t.Fatal("Through must keep scripts")
	}
}

func TestParseTokenPermsSetupOnly(t *testing.T) {
	log := "2026-10-01T10:00:00.0000000Z ##[group]Run echo hi\n" +
		"2026-10-01T10:00:00.0000000Z ##[group]GITHUB_TOKEN Permissions\n" +
		"2026-10-01T10:00:00.0000000Z Contents: write\n" +
		"2026-10-01T10:00:00.0000000Z ##[endgroup]\n"
	if p := ParseTokenPerms(log); len(p) != 0 {
		t.Fatalf("job output after the first Run group is untrusted: %v", p)
	}
}

func TestMentions(t *testing.T) {
	w, err := Parse([]byte(`on: push
defaults: {run: {working-directory: site}}
jobs:
  a:
    runs-on: x
    defaults: {run: {working-directory: apps/web}}
    steps:
      - run: make
        working-directory: tools/cli
      - uses: some/action@v1
        with: {path: examples/x, flag: true}
      - run: cd docs && npm ci
  b:
    runs-on: x
    steps: [{run: echo}]
`))
	if err != nil {
		t.Fatal(err)
	}
	a, b := w.Jobs["a"], w.Jobs["b"]
	for _, d := range []string{"apps/web", "tools/cli", "examples/x", "docs", "site"} {
		if !a.Mentions(d) {
			t.Errorf("a: %s", d)
		}
	}
	if !b.Mentions("site") || b.Mentions("examples/x") || a.Mentions("packages/z") {
		t.Errorf("b or negative: %+v %+v", a, b)
	}
	if !w.Union().Mentions("tools/cli") {
		t.Error("union")
	}
}

func TestInstallsNPMStrict(t *testing.T) {
	for run, want := range map[string]bool{
		"npm ci":                             true,
		"npm --prefix web ci":                true,
		"cd web && pnpm i --frozen-lockfile": true,
		"yarn":                               true,
		"yarn --frozen-lockfile; yarn build": true,
		"bun install":                        true,
		"npm update axios":                   true,
		"npm test":                           false,
		"npm run build":                      false,
		"npx eslint .":                       false,
		"yarn build":                         false,
		"echo npm":                           false,
	} {
		if got := (&Job{Runs: []string{run}}).InstallsNPMStrict(); got != want {
			t.Errorf("%q: %v", run, got)
		}
	}
	if !(&Job{Uses: []string{"pnpm/action-setup@v4"}}).InstallsNPMStrict() {
		t.Error("install action")
	}
}

// A templated name that may equal another job's ID or name leaves the job unidentified.
func TestFindJobTemplatedNameShadowsExactHit(t *testing.T) {
	for name, y := range map[string]string{
		"expression-only vs unnamed id": "jobs:\n  build:\n    runs-on: x\n    steps: [{run: a}]\n  deploy:\n    name: ${{ matrix.task }}\n    runs-on: x\n    steps: [{run: b}]\n",
		"expression-only vs name":       "jobs:\n  lint:\n    name: Lint\n    runs-on: x\n    steps: [{run: a}]\n  deploy:\n    name: ${{ matrix.task }}\n    runs-on: x\n    steps: [{run: b}]\n",
		"literal template vs name":      "jobs:\n  a:\n    name: Build x\n    runs-on: x\n    steps: [{run: a}]\n  b:\n    name: Build ${{ matrix.x }}\n    runs-on: x\n    steps: [{run: b}]\n",
	} {
		w, err := Parse([]byte("on: push\n" + y))
		if err != nil {
			t.Fatal(err)
		}
		api := map[string]string{"expression-only vs unnamed id": "build", "expression-only vs name": "Lint", "literal template vs name": "Build x"}[name]
		if j, ok := w.FindJob(api); ok {
			t.Errorf("%s: identified %s", name, j.ID)
		}
	}
	w, _ := Parse([]byte("on: push\njobs:\n  build:\n    runs-on: x\n    steps: [{run: a}]\n"))
	if j, ok := w.FindJob("build"); !ok || j.ID != "build" {
		t.Error("an unambiguous unnamed job is identified by its ID")
	}
}

// A 1 MiB line of package manager names must be read in linear time (it took days).
func TestRunInstallsLinear(t *testing.T) {
	script := strings.Repeat("npx ", 256*1024)
	start := time.Now()
	j := &Job{Runs: []string{script}}
	ins := j.RunInstalls()
	j.InstallsNPM()
	j.InstallsNPMStrict()
	j.MayInstallNPM()
	if d := time.Since(start); d > time.Second {
		t.Errorf("took %v", d)
	}
	if len(ins) == 0 || !slices.ContainsFunc(ins, func(in RunInstall) bool { return in.Dynamic }) {
		t.Error("a script cut short must be marked as naming packages at run time")
	}
}

func TestRunInstallsMoreForms(t *testing.T) {
	for script, want := range map[string][]string{
		"pnpm i axios@latest":        {"pnpm i axios@latest", "axios"},
		"pnpm install axios":         {"pnpm install axios", "axios"},
		"npm update axios":           {"npm update axios", "axios"},
		"npm up axios":               {"npm up axios", "axios"},
		"pnpm up --latest axios":     {"pnpm up --latest axios", "axios"},
		"yarn upgrade axios":         {"yarn upgrade axios", "axios"},
		"yarn up axios":              {"yarn up axios", "axios"},
		"bun update axios":           {"bun update axios", "axios"},
		"npm update":                 {"npm update", "DYN"},
		"pnpm up":                    {"pnpm up", "DYN"},
		"yarn upgrade":               {"yarn upgrade", "DYN"},
		"npm create vite":            {"npm create vite", "vite", "create-vite"},
		"npm init @scope/app":        {"npm init @scope/app", "@scope/app", "@scope/create-app"},
		"pnpm create vite":           {"pnpm create vite", "vite", "create-vite"},
		"yarn create vite":           {"yarn create vite", "vite", "create-vite"},
		"bun create vite":            {"bun create vite", "vite", "create-vite"},
		"npm.cmd i axios":            {"npm.cmd i axios", "axios"},
		"npx.cmd axios":              {"npx.cmd axios", "axios"},
		"bun upgrade":                nil,
		"npm init -y":                nil,
		"npm npm npm npm":            nil,
		"npm install $PKG && npm ci": {"npm install $PKG", "DYN"},
	} {
		var got []string
		for _, in := range runInstalls(script) {
			got = append(append(got, in.Cmd), in.Pkgs...)
			if in.Dynamic {
				got = append(got, "DYN")
			}
		}
		if !slices.Equal(got, want) {
			t.Errorf("%q: got %q, want %q", script, got, want)
		}
	}
}

func TestInstallsNPMStrictForms(t *testing.T) {
	for run, want := range map[string]bool{
		"npm.cmd ci --silent":              true,
		`C:\node\npm.cmd ci`:               true,
		"pnpm i axios":                     true,
		"npm update":                       true,
		"sudo -E npm ci":                   true,
		"corepack yarn install":            true,
		"cd web\nnpm ci":                   true,
		"x=`npm ci`":                       true,
		"npm i -g left-pad":                false,
		"npm install --global left-pad":    false,
		"yarn global add left-pad":         false,
		"which yarn":                       false,
		"corepack enable yarn":             false,
		`echo "run npm ci"`:                false,
		"echo run npm ci":                  false,
		"yarn --version":                   false,
		"npm run ci":                       false,
		"$PM ci":                           false,
		"command -v pnpm || npm i -g pnpm": false,
		"command -v yarn":                  false,
	} {
		if got := (&Job{Runs: []string{run}}).InstallsNPMStrict(); got != want {
			t.Errorf("%q: got %v", run, got)
		}
	}
	// a github-script runs the command from a string literal
	if !(&Job{Scripts: []string{"execSync('npm ci')"}}).InstallsNPMStrict() {
		t.Error("execSync('npm ci')")
	}
	if (&Job{Scripts: []string{"console.log('run npm ci')"}}).InstallsNPMStrict() {
		t.Error("a mention in a script")
	}
}

// A package manager named by a variable, a substitution or eval may install: opaque, never CLEAN.
func TestPackageManagerBehindShellIndirection(t *testing.T) {
	for run, want := range map[string]bool{
		"$PM ci --silent":       true,
		"${PM} ci":              true,
		`"$PM" ci`:              true,
		"${{ env.PM }} ci":      true,
		"cd web && $PM ci":      true,
		"if x; then $PM ci; fi": true,
		`eval "npm ci"`:         true,
		"$(which npm) ci":       true,
		"echo $PM":              false,
		"export PM=npm":         false,
		"echo done":             false,
	} {
		j := &Job{Runs: []string{run}}
		if got := j.RunsOpaque(); got != want {
			t.Errorf("%q: RunsOpaque %v", run, got)
		}
		if j.MayInstallNPM() != (want || CallsPackageManager(run)) {
			t.Errorf("%q: MayInstallNPM %v", run, j.MayInstallNPM())
		}
	}
	if !CallsPackageManager("PM: npm.cmd") || !(&Job{Runs: []string{"npm.exe ci"}}).InstallsNPM() {
		t.Error("npm.cmd and npm.exe are npm")
	}
}
