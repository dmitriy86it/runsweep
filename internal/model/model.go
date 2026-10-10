// Package model holds the types shared by scan, rotate and report.
package model

import (
	"encoding/json"
	"regexp"
	"time"
)

// CommitSHA matches a full commit SHA: 40 lowercase hex digits.
var CommitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// Status of a job with respect to an incident, ordered by severity.
type Status int

// Status values, from least to most severe.
const (
	Clean Status = iota
	Unchecked
	Possible
	Affected
)

var statusNames = [...]string{"CLEAN", "UNCHECKED", "POSSIBLE", "AFFECTED"}

func (s Status) String() string { return statusNames[s] }

// MarshalJSON encodes the status as its name.
func (s Status) MarshalJSON() ([]byte, error) { return json.Marshal(s.String()) }

// Worse returns the more severe of two statuses.
func Worse(a, b Status) Status {
	if a > b {
		return a
	}
	return b
}

// Evidence explains why a status was assigned. Kind is "npm", "action" or "note".
type Evidence struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

// RunRef identifies one job of one workflow run.
type RunRef struct {
	Repo      string    `json:"repo"`
	RunID     int64     `json:"run_id"`
	Workflow  string    `json:"workflow"`
	HeadSHA   string    `json:"head_sha"`
	RunURL    string    `json:"run_url"`
	CreatedAt time.Time `json:"created_at"`
	JobID     int64     `json:"job_id,omitempty"`
	Job       string    `json:"job,omitempty"`
	JobURL    string    `json:"job_url,omitempty"`
	Attempt   int       `json:"attempt,omitempty"` // run attempt; reports show it when > 1
}

// CloudRole is a cloud role a job can assume.
type CloudRole struct {
	Provider string `json:"provider"`
	Role     string `json:"role"`
}

// Exposure is what an affected job could read.
type Exposure struct {
	Secrets      []string          `json:"secrets"`
	InheritAll   bool              `json:"inherit_all,omitempty"`
	IDTokenWrite bool              `json:"id_token_write,omitempty"`
	CloudRoles   []CloudRole       `json:"cloud_roles,omitempty"`
	TokenPerms   map[string]string `json:"github_token_permissions,omitempty"`
	JobMatched   bool              `json:"job_matched"`
}

// Finding is the verdict for one job.
type Finding struct {
	Run      RunRef     `json:"run"`
	Status   Status     `json:"status"`
	Evidence []Evidence `json:"evidence"`
	Exposure *Exposure  `json:"exposure,omitempty"`
}

// RotationItem is one secret or role to rotate/review. Tier 1 is most urgent.
type RotationItem struct {
	Name   string   `json:"name"`
	Tier   int      `json:"tier"`
	Reason string   `json:"reason"`
	Runs   []RunRef `json:"runs"`
}

// Skip records a repository that could not be scanned and why.
type Skip struct {
	Repo   string `json:"repo"`
	Reason string `json:"reason"`
}

// Result is the outcome of a scan.
type Result struct {
	IncidentID    string         `json:"incident_id"`
	Start         time.Time      `json:"window_start"`
	End           time.Time      `json:"window_end"`
	ReposTargeted int            `json:"repos_targeted"`
	RunsScanned   int            `json:"runs_scanned"`
	JobsScanned   int            `json:"jobs_scanned"`
	Findings      []Finding      `json:"findings"`
	Rotation      []RotationItem `json:"rotation"`
	// Unverified: what UNCHECKED jobs could read, not in Rotation; exposure could not be ruled out.
	Unverified []RotationItem `json:"unverified_rotation"`
	Skipped    []Skip         `json:"skipped"`
	// RetentionWarning: the window started more than 90 days ago, so missing runs prove nothing.
	RetentionWarning bool `json:"retention_warning,omitempty"`
	// Lookback is how long before the window runs were listed to catch re-runs (text report only).
	Lookback time.Duration `json:"-"`
}

// Count returns how many findings have the given status.
func (r *Result) Count(s Status) int {
	n := 0
	for _, f := range r.Findings {
		if f.Status == s {
			n++
		}
	}
	return n
}
