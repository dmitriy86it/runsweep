// Package workflow extracts secrets, permissions and cloud roles from a GitHub Actions workflow.
package workflow

import (
	"bufio"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/dmitriy86it/runsweep/internal/model"
	"go.yaml.in/yaml/v3"
)

type Job struct {
	ID             string
	Name           string
	Uses           []string // step-level `uses:` plus reusable-workflow `uses:`
	Runs           []string // `run:` scripts
	Secrets        []string
	InheritSecrets bool
	IDTokenWrite   bool
	CloudRoles     []model.CloudRole
}

type Workflow struct {
	Jobs          map[string]*Job
	globalSecrets []string
}

var (
	secretRe  = regexp.MustCompile(`secrets\.([A-Za-z_][A-Za-z0-9_]*)|secrets\[\s*['"]([^'"]+)['"]\s*\]`)
	installRe = regexp.MustCompile(`\b(npm\s+(ci|install|i)|pnpm\s+(install|i)|yarn(\s+install)?|bun\s+install)\b`)
	matrixRe  = regexp.MustCompile(` \([^)]*\)$`)
)

func Parse(b []byte) (*Workflow, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("workflow yaml: %w", err)
	}
	if len(root.Content) == 0 {
		return nil, fmt.Errorf("workflow yaml: empty document")
	}
	doc := root.Content[0]
	w := &Workflow{Jobs: map[string]*Job{}, globalSecrets: secretsIn(get(doc, "env"))}
	wfIDToken := idToken(get(doc, "permissions"))
	jobs := get(doc, "jobs")
	if jobs == nil || jobs.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("workflow yaml: no jobs")
	}
	for i := 0; i+1 < len(jobs.Content); i += 2 {
		id, jn := jobs.Content[i].Value, jobs.Content[i+1]
		j := &Job{ID: id, Name: scalar(get(jn, "name")), Secrets: secretsIn(jn)}
		if perms := get(jn, "permissions"); perms != nil {
			j.IDTokenWrite = idToken(perms)
		} else {
			j.IDTokenWrite = wfIDToken
		}
		if u := scalar(get(jn, "uses")); u != "" {
			j.Uses = append(j.Uses, u)
		}
		j.InheritSecrets = scalar(get(jn, "secrets")) == "inherit"
		if steps := get(jn, "steps"); steps != nil {
			for _, st := range steps.Content {
				if u := scalar(get(st, "uses")); u != "" {
					j.Uses = append(j.Uses, u)
					if role, ok := cloudRole(u, get(st, "with")); ok {
						j.CloudRoles = append(j.CloudRoles, role)
					}
				}
				if r := scalar(get(st, "run")); r != "" {
					j.Runs = append(j.Runs, r)
				}
			}
		}
		w.Jobs[id] = j
	}
	return w, nil
}

// FindJob maps an API job name (matrix suffix, expressions, "caller / callee") to a workflow job.
func (w *Workflow) FindJob(apiName string) (*Job, bool) {
	n := matrixRe.ReplaceAllString(apiName, "")
	if caller, _, ok := strings.Cut(n, " / "); ok {
		n = caller
	}
	for _, j := range w.Jobs {
		if j.ID == n || j.Name == n || j.Name == apiName {
			return j, true
		}
	}
	for _, j := range w.Jobs { // name: "Build ${{ matrix.node }}" vs API "Build 18"
		if i := strings.Index(j.Name, "${{"); i > 0 && strings.HasPrefix(n, strings.TrimSpace(j.Name[:i])) {
			return j, true
		}
	}
	return nil, false
}

func (j *Job) InstallsNPM() bool {
	for _, r := range j.Runs {
		if installRe.MatchString(r) {
			return true
		}
	}
	return false
}

// Exposure: everything job j could read. Workflow-level env secrets are included.
func (w *Workflow) Exposure(j *Job) model.Exposure {
	return model.Exposure{
		Secrets:      uniq(append(append([]string{}, w.globalSecrets...), j.Secrets...)),
		InheritAll:   j.InheritSecrets,
		IDTokenWrite: j.IDTokenWrite,
		CloudRoles:   j.CloudRoles,
		JobMatched:   true,
	}
}

// ExposureAll is the conservative union over all jobs, used when the job cannot be identified.
func (w *Workflow) ExposureAll() model.Exposure {
	e := model.Exposure{Secrets: append([]string{}, w.globalSecrets...)}
	for _, j := range w.Jobs {
		e.Secrets = append(e.Secrets, j.Secrets...)
		e.InheritAll = e.InheritAll || j.InheritSecrets
		e.IDTokenWrite = e.IDTokenWrite || j.IDTokenWrite
		e.CloudRoles = append(e.CloudRoles, j.CloudRoles...)
	}
	e.Secrets = uniq(e.Secrets)
	return e
}

// ParseTokenPerms reads the "GITHUB_TOKEN Permissions" group from a job log.
func ParseTokenPerms(log string) map[string]string {
	out := map[string]string{}
	in := false
	sc := bufio.NewScanner(strings.NewReader(log))
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

func cloudRole(uses string, with *yaml.Node) (model.CloudRole, bool) {
	name, _, _ := strings.Cut(strings.ToLower(uses), "@")
	switch name {
	case "aws-actions/configure-aws-credentials":
		if r := scalar(get(with, "role-to-assume")); r != "" {
			return model.CloudRole{Provider: "aws", Role: r}, true
		}
	case "google-github-actions/auth":
		if r := scalar(get(with, "service_account")); r != "" {
			return model.CloudRole{Provider: "gcp", Role: r}, true
		}
		if r := scalar(get(with, "workload_identity_provider")); r != "" {
			return model.CloudRole{Provider: "gcp", Role: r}, true
		}
	case "azure/login":
		if r := scalar(get(with, "client-id")); r != "" {
			return model.CloudRole{Provider: "azure", Role: r}, true
		}
	}
	return model.CloudRole{}, false
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

func secretsIn(n *yaml.Node) []string {
	var out []string
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			for _, m := range secretRe.FindAllStringSubmatch(n.Value, -1) {
				name := m[1] + m[2]
				if name != "GITHUB_TOKEN" {
					out = append(out, name)
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(n)
	return uniq(out)
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
