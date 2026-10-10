// Package workflow extracts secrets, permissions and cloud roles from a GitHub Actions workflow.
package workflow

import (
	"bufio"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/runsweep/runsweep/internal/model"
	"go.yaml.in/yaml/v3"
)

// Job is a parsed workflow job.
type Job struct {
	ID             string
	Name           string
	Uses           []string // step-level `uses:` plus reusable-workflow `uses:`
	Environment    bool     // job declares `environment:`, so it reads that environment's secrets directly
	Call           string   // job-level `uses:`: the reusable workflow this job calls
	Runs           []string // `run:` scripts
	Scripts        []string // actions/github-script `script:` inputs
	Inputs         []string // working-directory (step, job and workflow defaults) and step `with:` values
	Secrets        []string
	InheritSecrets bool
	IDTokenWrite   bool
	CloudRoles     []model.CloudRole
}

// namePattern is a templated job name ("Build ${{ matrix.node }}") compiled once. re is nil
// when the name is not templated, is expression-only, or is unusable (bad: too long, or the
// regexp engine rejects it).
type namePattern struct {
	re  *regexp.Regexp
	lit int // length of the literal text: the longer, the more specific the match
	bad bool
}

// pattern returns j's name pattern, compiled on first use and kept in the workflow (which scan
// caches), so FindJob does not recompile it for every run.
func (w *Workflow) pattern(j *Job) namePattern {
	if v, ok := w.pats.Load(j); ok {
		return v.(namePattern)
	}
	var p namePattern
	defer func() { w.pats.Store(j, p) }() // a concurrent first use may compile twice: harmless
	if !strings.Contains(j.Name, "${{") {
		return p
	}
	if len(j.Name) > maxTemplateName { // would build a huge regexp
		p.bad = true
		return p
	}
	lit := tplRe.ReplaceAllString(j.Name, "")
	if strings.TrimSpace(lit) == "" {
		return p // expression-only name matches anything; only ID/exact stage may match it
	}
	pat := "^"
	for i, part := range tplRe.Split(j.Name, -1) {
		if i > 0 {
			pat += ".+"
		}
		pat += regexp.QuoteMeta(part)
	}
	re, err := regexp.Compile(pat + "$") // fails on e.g. invalid UTF-8
	p.re, p.lit, p.bad = re, len(lit), err != nil
	return p
}

// Workflow is a parsed workflow file.
type Workflow struct {
	Jobs          map[string]*Job
	globalSecrets []string
	globalDynamic bool
	pats          sync.Map // *Job -> namePattern
}

var (
	secretRe  = regexp.MustCompile(`(?i)secrets\.([A-Za-z_][A-Za-z0-9_]*)|secrets\[\s*['"]([^'"]+)['"]\s*\]`)
	exprRe    = regexp.MustCompile(`(?s)\$\{\{(.*?)\}\}`)
	secretsID = regexp.MustCompile(`(?i)\bsecrets\b`)
	namedRe   = regexp.MustCompile(`^(\.[A-Za-z_]|\[\s*['"])`)
	// package-manager binary as a word anywhere in a script; over-reports (e.g. `echo npm`) by design
	installRe = regexp.MustCompile(`(?:^|[^\w./-])(npm|npx|yarn|pnpm|pnpx|bun|bunx)(?:$|[^\w.-])`)
	// opaque runners and scripts that may install npm packages without naming npm in the workflow
	opaqueRe = regexp.MustCompile(`(?:^|[^\w./-])(?:(?:make|task|just|mise|nx|turbo|lerna|rush|corepack|python3?|node|docker(?:-compose)?|podman|buildah|mvnw?|gradlew?|sbt|bazel|dotnet|composer)(?:$|[^\w.-])|(?:ba|z)?sh\s+\S)|(?:^|[\s;&|(])\./[\w-]|\.sh\b`)
	// a package manager command, up to a newline or shell separator; runInstalls reads its arguments
	runtimeRe = regexp.MustCompile(`(?:^|[^\w./-])(npx|pnpx|bunx|npm|pnpm|yarn|bun)(?:$|[ \t]+([^\n;&|)]*))`)
	// a github-script that runs a process, which may be a package manager named in a variable
	scriptExecRe = regexp.MustCompile("exec\\.exec|execSync|execFileSync|spawn|spawnSync|child_process|\\$`")
	tplRe        = regexp.MustCompile(`\$\{\{.*?\}\}`)
	matrixRe     = regexp.MustCompile(` \([^)]*\)$`)
)

// Parse parses a workflow YAML file.
func Parse(b []byte) (*Workflow, error) {
	// Decode into a plain value first: yaml.v3 expands aliases and merge keys with its own
	// cycle/size limits; re-encoding gives an alias-free node tree that is safe to walk.
	var v any
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("workflow yaml: %w", err)
	}
	var root yaml.Node
	if err := root.Encode(v); err != nil {
		return nil, fmt.Errorf("workflow yaml: %w", err)
	}
	doc := &root
	if doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("workflow yaml: not a mapping")
	}
	w := &Workflow{Jobs: map[string]*Job{}}
	w.globalSecrets, w.globalDynamic = secretsIn(get(doc, "env"))
	wfIDToken := idToken(get(doc, "permissions"))
	wfDir := scalar(get(get(get(doc, "defaults"), "run"), "working-directory"))
	jobs := get(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("workflow yaml: no jobs")
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		id, jn := jobs.Content[i].Value, jobs.Content[i+1]
		j := &Job{ID: id, Name: scalar(get(jn, "name"))}
		var dyn bool
		j.Secrets, dyn = secretsIn(jn)
		if perms := get(jn, "permissions"); perms != nil {
			j.IDTokenWrite = idToken(perms)
		} else {
			j.IDTokenWrite = wfIDToken
		}
		if u := scalar(get(jn, "uses")); u != "" {
			j.Uses = append(j.Uses, u)
			j.Call = u
		}
		if env := get(jn, "environment"); env != nil {
			j.Environment = env.Value != "" || len(env.Content) > 0
		}
		j.InheritSecrets = dyn || scalar(get(jn, "secrets")) == "inherit"
		for _, d := range []string{wfDir, scalar(get(get(get(jn, "defaults"), "run"), "working-directory"))} {
			if d != "" {
				j.Inputs = append(j.Inputs, d)
			}
		}
		if steps := get(jn, "steps"); steps != nil {
			for _, st := range steps.Content {
				if u := scalar(get(st, "uses")); u != "" {
					j.Uses = append(j.Uses, u)
					j.CloudRoles = append(j.CloudRoles, cloudRoles(u, get(st, "with"))...)
					if name, _, _ := strings.Cut(strings.ToLower(u), "@"); name == "actions/github-script" {
						if sc := scalar(get(get(st, "with"), "script")); sc != "" {
							j.Scripts = append(j.Scripts, sc)
						}
					}
				}
				if r := scalar(get(st, "run")); r != "" {
					j.Runs = append(j.Runs, r)
				}
				if d := scalar(get(st, "working-directory")); d != "" {
					j.Inputs = append(j.Inputs, d)
				}
				if with := get(st, "with"); with != nil && with.Kind == yaml.MappingNode {
					for i := 1; i < len(with.Content); i += 2 {
						if v := scalar(with.Content[i]); v != "" {
							j.Inputs = append(j.Inputs, v)
						}
					}
				}
			}
		}
		w.Jobs[id] = j
	}
	return w, nil
}

// FindJob maps an API job name (matrix suffix, expressions, "caller / callee") to a workflow job.
// Ambiguous matches return false so callers fall back to ExposureAll.
func (w *Workflow) FindJob(apiName string) (*Job, bool) {
	if j, found := w.findStaged(apiName); found {
		return j, j != nil
	}
	if caller, _, ok := strings.Cut(apiName, " / "); ok {
		if j, found := w.findStaged(caller); found {
			return j, j != nil
		}
	}
	return nil, false
}

// maxTemplateName caps the length of a templated job name matched as a pattern.
const maxTemplateName = 1024

// findStaged: exact, then templated names. found=true with nil job means ambiguous.
func (w *Workflow) findStaged(name string) (*Job, bool) {
	names := []string{name}
	if s := matrixRe.ReplaceAllString(name, ""); s != name {
		names = append(names, s)
	}
	ids := make([]string, 0, len(w.Jobs))
	for id := range w.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, n := range names {
		var hit []*Job
		for _, id := range ids {
			if j := w.Jobs[id]; j.ID == n || j.Name == n {
				hit = append(hit, j)
			}
		}
		if len(hit) == 1 {
			return hit[0], true
		} else if len(hit) > 1 {
			return nil, true
		}
	}
	// templated names: the most specific (longest literal text) match wins; a tie is ambiguous,
	// and so is any name that could not be compared (it might be the more specific match).
	var best *Job
	bestLen, tie := -1, false
	for _, id := range ids {
		j := w.Jobs[id]
		p := w.pattern(j)
		if p.bad {
			return nil, true
		}
		if p.re == nil {
			continue
		}
		for _, n := range names {
			if p.re.MatchString(n) {
				if p.lit > bestLen {
					best, bestLen, tie = j, p.lit, false
				} else if p.lit == bestLen && best != j {
					tie = true
				}
				break
			}
		}
	}
	if best == nil {
		return nil, false
	}
	if tie {
		return nil, true
	}
	return best, true
}

// InstallsNPM reports whether the job installs npm dependencies.
func (j *Job) InstallsNPM() bool {
	for _, u := range j.Uses {
		name, _, _ := strings.Cut(strings.ToLower(u), "@")
		switch name {
		case "bahmutov/npm-install", "cypress-io/github-action", "pnpm/action-setup":
			return true
		}
	}
	if slices.ContainsFunc(slices.Concat(j.Runs, j.Scripts), installRe.MatchString) {
		return true
	}
	return len(j.RunInstalls()) > 0
}

// Mentions reports whether the job's `run:` scripts, working directories or `with:` inputs name dir.
func (j *Job) Mentions(dir string) bool {
	return slices.ContainsFunc(slices.Concat(j.Runs, j.Inputs), func(s string) bool { return strings.Contains(s, dir) })
}

// CallsPackageManager reports whether s calls npm, npx, yarn, pnpm, pnpx, bun or bunx as a command
// word; NPM_TOKEN or npm_config_* names do not count.
func CallsPackageManager(s string) bool { return installRe.MatchString(s) }

// RunInstall is a command that installs or runs npm packages named in the workflow itself.
type RunInstall struct {
	Cmd  string
	Pkgs []string // package names, version stripped; an npm: alias gives both names
	// Dynamic: a positional argument is known only at run time ($VAR, $(…), `…`, ${{ … }})
	Dynamic bool
}

// RunInstalls returns the run-time package installs in the job's `run:` and github-script scripts.
func (j *Job) RunInstalls() []RunInstall {
	var out []RunInstall
	for _, s := range slices.Concat(j.Runs, j.Scripts) {
		out = append(out, runInstalls(s)...)
	}
	return out
}

// installSubs are the "tool subcommand" pairs that install or run named packages. Every positional
// argument is read as a package, also for runners (npx, dlx) whose later arguments belong to the
// command: an unknown value flag must not hide the name, and over-matching is only noise.
var installSubs = map[string]bool{
	"npm i": true, "npm in": true, "npm ins": true, "npm inst": true, "npm insta": true, "npm instal": true,
	"npm install": true, "npm isnt": true, "npm isnta": true, "npm isntal": true, "npm isntall": true,
	"npm add": true, "npm it": true, "npm install-test": true,
	"pnpm add": true, "yarn add": true, "bun add": true, "bun i": true, "bun install": true,
	"npm exec": true, "npm x": true, "pnpm dlx": true, "yarn dlx": true, "bun x": true,
	"npx": true, "pnpx": true, "bunx": true,
}

// valueFlags take the next argument as their value, so it is neither a subcommand nor a package.
var valueFlags = map[string]bool{"--registry": true, "--prefix": true, "--filter": true, "-F": true, "-C": true,
	"--dir": true, "--cwd": true, "--workspace": true, "--cache": true, "--userconfig": true, "--loglevel": true,
	"-c": true, "--call": true}

func valueFlag(tool, a string) bool {
	return valueFlags[a] || tool == "npm" && a == "-w" // pnpm -w is the boolean --workspace-root
}

// continuation joins shell (\) and PowerShell (`) continued lines.
var continuation = strings.NewReplacer("\\\r\n", " ", "\\\n", " ", "`\r\n", " ", "`\n", " ")

// runInstalls finds the package manager commands in script that install or run named packages.
func runInstalls(script string) []RunInstall {
	script = continuation.Replace(script)
	var out []RunInstall
	for pos := 0; pos < len(script); {
		m := runtimeRe.FindStringSubmatchIndex(script[pos:])
		if m == nil {
			break
		}
		tool := script[pos+m[2] : pos+m[3]]
		var args []string
		if m[4] >= 0 {
			for _, f := range strings.Fields(script[pos+m[4] : pos+m[5]]) {
				// a leading backtick stays: it marks a command substitution
				if f = strings.TrimRight(strings.TrimLeft(f, `'",`), "'\"`,"); f != "" {
					args = append(args, f)
				}
			}
		}
		pos += m[3] // resume after the tool name: `…` and $(…) in its arguments are commands too
		cmd := tool
		for _, a := range args {
			cmd += " " + strings.Trim(a, "`")
		}
		key := tool
		if tool == "npm" || tool == "pnpm" || tool == "yarn" || tool == "bun" {
			var sub string
			sub, args = subcommand(tool, args)
			if tool == "yarn" && sub == "global" {
				sub, args = subcommand(tool, args)
			}
			if tool == "yarn" && sub == "workspace" && len(args) > 0 { // yarn workspace <name> add …
				sub, args = subcommand(tool, args[1:])
			}
			key += " " + sub
		}
		if !installSubs[key] {
			continue
		}
		var pkgs []string
		dynamic := false
		for i := 0; i < len(args); i++ {
			a := args[i]
			switch v, isPkg := strings.CutPrefix(a, "--package="); {
			case (a == "-p" || a == "--package") && i+1 < len(args):
				i++
				a = args[i]
			case isPkg:
				a = v
			case strings.HasPrefix(a, "-"): // a value flag's value is read as a name: noise, never a miss
				continue
			}
			for _, n := range pkgNames(a) {
				if strings.ContainsAny(n, "$`%") { // $VAR, $(…), `…`, ${{ … }}, %VAR%: named at run time
					dynamic = true
				} else {
					pkgs = append(pkgs, n)
				}
			}
		}
		if len(pkgs) > 0 || dynamic {
			out = append(out, RunInstall{Cmd: cmd, Pkgs: pkgs, Dynamic: dynamic})
		}
	}
	return out
}

// subcommand returns the first positional argument and the arguments after it.
func subcommand(tool string, args []string) (string, []string) {
	for i := 0; i < len(args); i++ {
		switch {
		case valueFlag(tool, args[i]):
			i++
		case !strings.HasPrefix(args[i], "-"):
			return args[i], args[i+1:]
		}
	}
	return "", nil
}

// pkgNames strips the version from a package spec ("@s/p@1" -> "@s/p"); "x@npm:real@1" gives x and real.
func pkgNames(spec string) []string {
	at := strings.Index(spec[1:], "@")
	if at < 0 {
		return []string{spec}
	}
	name, ver := spec[:at+1], spec[at+2:]
	if target, ok := strings.CutPrefix(ver, "npm:"); ok && target != "" {
		return append([]string{name}, pkgNames(target)...)
	}
	return []string{name}
}

// MayInstallNPM is false only on positive evidence that the job cannot install npm packages:
// every `uses:` is a known non-installing action and no `run:` calls a package manager or an opaque
// script/runner, and no github-script runs a process. Local and third-party actions and reusable workflows may install.
func (j *Job) MayInstallNPM() bool {
	if j.InstallsNPM() {
		return true
	}
	for _, u := range j.Uses {
		name, _, _ := strings.Cut(strings.ToLower(u), "@")
		switch {
		case strings.HasPrefix(name, "actions/setup-"):
		case slices.Contains([]string{"actions/checkout", "actions/cache", "actions/upload-artifact",
			"actions/download-artifact", "actions/github-script"}, name):
		default:
			return true
		}
	}
	return j.RunsOpaque()
}

// RunsOpaque reports whether a `run:` calls an opaque script or runner, or a github-script runs a
// process: either may install packages without output in the log.
func (j *Job) RunsOpaque() bool {
	return slices.ContainsFunc(j.Runs, opaqueRe.MatchString) || slices.ContainsFunc(j.Scripts, scriptExecRe.MatchString)
}

// Exposure returns everything job j could read. Workflow-level env secrets are included.
func (w *Workflow) Exposure(j *Job) model.Exposure {
	return model.Exposure{
		Secrets:      uniq(append(append([]string{}, w.globalSecrets...), j.Secrets...)),
		InheritAll:   j.InheritSecrets || w.globalDynamic,
		IDTokenWrite: j.IDTokenWrite,
		CloudRoles:   append([]model.CloudRole(nil), j.CloudRoles...),
		JobMatched:   true,
	}
}

// ExposureAll is the conservative union over all jobs, used when the job cannot be identified.
func (w *Workflow) ExposureAll() model.Exposure {
	e := w.Exposure(w.Union())
	e.JobMatched = false
	return e
}

// Union merges every job of w into one, for when the job cannot be identified.
func (w *Workflow) Union() *Job {
	ids := make([]string, 0, len(w.Jobs))
	for id := range w.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	u := &Job{}
	for _, id := range ids {
		j := w.Jobs[id]
		u.Uses = append(u.Uses, j.Uses...)
		u.Runs = append(u.Runs, j.Runs...)
		u.Scripts = append(u.Scripts, j.Scripts...)
		u.Inputs = append(u.Inputs, j.Inputs...)
		u.Secrets = append(u.Secrets, j.Secrets...)
		u.InheritSecrets = u.InheritSecrets || j.InheritSecrets
		u.Environment = u.Environment || j.Environment
		u.IDTokenWrite = u.IDTokenWrite || j.IDTokenWrite
		for _, r := range j.CloudRoles {
			if !slices.Contains(u.CloudRoles, r) {
				u.CloudRoles = append(u.CloudRoles, r)
			}
		}
	}
	return u
}

// Call is a reusable workflow named by a job-level `uses:`.
type Call struct {
	Repo string // "owner/name"; empty for a local call (same repository and commit as the caller)
	Path string // ".github/workflows/x.yml"
	SHA  string // commit of a remote call
}

var (
	nameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	// GitHub supports no subdirectories under .github/workflows
	workflowPathRe = regexp.MustCompile(`^\.github/workflows/[^/\\]+\.ya?ml$`)
)

// ParseCall parses a job-level `uses:`. ok is false unless it is a local call
// (./.github/workflows/x.yml) or a remote call pinned to a commit SHA
// (owner/repo/.github/workflows/x.yml@<40 hex>).
func ParseCall(uses string) (c Call, ok bool) {
	if p, local := strings.CutPrefix(uses, "./"); local {
		return Call{Path: p}, workflowPath(p)
	}
	ref, sha, _ := strings.Cut(uses, "@")
	parts := strings.SplitN(ref, "/", 3)
	if len(parts) != 3 || !model.CommitSHA.MatchString(sha) || !workflowPath(parts[2]) {
		return Call{}, false
	}
	for _, n := range parts[:2] {
		if !nameRe.MatchString(n) || n == "." || n == ".." {
			return Call{}, false
		}
	}
	return Call{Repo: parts[0] + "/" + parts[1], Path: parts[2], SHA: sha}, true
}

func workflowPath(p string) bool {
	return workflowPathRe.MatchString(p)
}

// Through returns the job that ran when job j of w called workflow cw and the API job is cw's
// job c, plus a one-job workflow for its Exposure. Uses, Runs, CloudRoles and Call come from c;
// IDTokenWrite is j's or c's; secrets are those j passes, plus the names cw and c reference
// when j uses `secrets: inherit` or c declares `environment:` (only then are those the caller's secret names).
func (w *Workflow) Through(j *Job, cw *Workflow, c *Job) (*Workflow, *Job) {
	e := &Job{ID: j.ID, Name: j.Name, Uses: slices.Clone(c.Uses), Runs: slices.Clone(c.Runs), Scripts: slices.Clone(c.Scripts), Call: c.Call,
		Secrets: slices.Clone(j.Secrets), InheritSecrets: j.InheritSecrets,
		IDTokenWrite: j.IDTokenWrite || c.IDTokenWrite, CloudRoles: slices.Clone(j.CloudRoles)}
	for _, r := range c.CloudRoles {
		if !slices.Contains(e.CloudRoles, r) {
			e.CloudRoles = append(e.CloudRoles, r)
		}
	}
	// a callee job with `environment:` reads that environment's secrets directly
	if j.InheritSecrets || c.Environment {
		e.Secrets = append(append(e.Secrets, cw.globalSecrets...), c.Secrets...)
	}
	return &Workflow{Jobs: map[string]*Job{e.ID: e}, globalSecrets: w.globalSecrets, globalDynamic: w.globalDynamic}, e
}

// SetupSection is the part of a job log the runner writes before the first step ("##[group]Run ");
// from there on the log is the job's own output, which can print anything.
func SetupSection(log string) string {
	setup, _, _ := strings.Cut(log, "##[group]Run ")
	return setup
}

// ParseTokenPerms reads the "GITHUB_TOKEN Permissions" group from a job log. Only the "Set up job"
// section is read: from the first step ("##[group]Run ") on, the log is the job's own output.
func ParseTokenPerms(log string) map[string]string {
	out := map[string]string{}
	in := false
	sc := bufio.NewScanner(strings.NewReader(SetupSection(log)))
	sc.Buffer(make([]byte, 1024*1024), 64*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if _, rest, ok := strings.Cut(line, "Z "); ok && len(line) > 20 && line[4] == '-' {
			line = rest // strip timestamp
		}
		switch {
		case strings.Contains(line, "##[group]GITHUB_TOKEN Permissions"):
			in = true
		case in && strings.Contains(line, "##[endgroup]"):
			return out
		case in:
			if k, v, ok := strings.Cut(line, ":"); ok {
				out[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
			}
		}
	}
	return out
}

func cloudRoles(uses string, with *yaml.Node) []model.CloudRole {
	var roles []model.CloudRole
	add := func(provider, key string) {
		if r := scalar(get(with, key)); r != "" {
			roles = append(roles, model.CloudRole{Provider: provider, Role: r})
		}
	}
	name, _, _ := strings.Cut(strings.ToLower(uses), "@")
	switch name {
	case "aws-actions/configure-aws-credentials":
		add("aws", "role-to-assume")
	case "google-github-actions/auth":
		add("gcp", "service_account")
		add("gcp", "workload_identity_provider")
	case "azure/login":
		add("azure", "client-id")
	}
	return roles
}

func idToken(perms *yaml.Node) bool {
	if perms == nil {
		return false
	}
	if perms.Kind == yaml.ScalarNode {
		return perms.Value == "write-all"
	}
	return scalar(get(perms, "id-token")) == "write"
}

// secretsIn collects referenced secret names (upper-cased); dynamic is true when
// the whole secret set may be read (toJSON(secrets), secrets[<expression>]).
func secretsIn(n *yaml.Node) (out []string, dynamic bool) {
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			dynamic = dynamic || usesWholeSecrets(n.Value)
			for _, m := range secretRe.FindAllStringSubmatch(n.Value, -1) {
				if name := strings.ToUpper(m[1] + m[2]); name != "GITHUB_TOKEN" {
					out = append(out, name)
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(n)
	return uniq(out), dynamic
}

func get(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// usesWholeSecrets: inside ${{ }}, `secrets` not followed by .name or ['name'] reads the whole context.
func usesWholeSecrets(s string) bool {
	for _, e := range exprRe.FindAllStringSubmatch(s, -1) {
		for _, loc := range secretsID.FindAllStringIndex(e[1], -1) {
			if !namedRe.MatchString(e[1][loc[1]:]) {
				return true
			}
		}
	}
	return false
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func uniq(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}
