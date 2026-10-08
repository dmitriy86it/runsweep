// Package scan finds jobs affected by an incident.
package scan

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/match/actions"
	"github.com/dmitriy86it/runsweep/internal/match/npm"
	"github.com/dmitriy86it/runsweep/internal/model"
	"github.com/dmitriy86it/runsweep/internal/rotate"
	"github.com/dmitriy86it/runsweep/internal/source"
	"github.com/dmitriy86it/runsweep/internal/workflow"
)

var installLogRe = regexp.MustCompile(`npm (ci|install)|added \d+ packages|yarn install|pnpm install|Lockfile is up to date|bun install`)

// Options configures a scan.
type Options struct {
	Repos       []string
	Org         string
	Concurrency int
	// Lookback widens run listing to runs created this long before the window, so re-runs
	// started inside the window are found.
	Lookback time.Duration
	Logf     func(format string, args ...any)
}

type scanner struct {
	src source.Source
	inc *incident.Incident
	wf  sync.Map // repo@sha:path -> *workflow.Workflow (nil if unavailable)
}

// soft errors mean "could not check", never "clean".
func soft(err error) bool {
	return errors.Is(err, source.ErrGone) || errors.Is(err, source.ErrNoAccess) || errors.Is(err, source.ErrIncomplete)
}

// Run scans the source for jobs affected by the incident.
func Run(ctx context.Context, src source.Source, inc *incident.Incident, opt Options) (*model.Result, error) {
	logf := opt.Logf
	if logf == nil {
		logf = func(string, ...any) {}
	}
	conc := opt.Concurrency
	if conc <= 0 {
		conc = 10
	}
	repos := append([]string{}, opt.Repos...)
	if opt.Org != "" {
		r, err := src.ListRepos(ctx, opt.Org)
		if err != nil {
			return nil, fmt.Errorf("list repositories of %s: %w", opt.Org, err)
		}
		repos = append(repos, r...)
	}
	sort.Strings(repos)
	repos = slices.Compact(repos)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	res := &model.Result{ReposTargeted: len(repos), IncidentID: inc.ID, Start: inc.Window.Start, End: inc.Window.End,
		Lookback: opt.Lookback}
	s := &scanner{src: src, inc: inc}
	for _, repo := range repos {
		runs, err := src.ListRuns(ctx, repo, inc.Window.Start.Add(-opt.Lookback), inc.Window.End)
		if soft(err) {
			res.Skipped = append(res.Skipped, model.Skip{Repo: repo, Reason: err.Error()})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", repo, err)
		}
		logf("%s: %d runs to check", repo, len(runs))
		var (
			wg       sync.WaitGroup
			mu       sync.Mutex
			firstErr error
			sem      = make(chan struct{}, conc)
		)
		for _, run := range runs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				fs, jobs, err := s.scanRun(ctx, repo, run)
				mu.Lock()
				defer mu.Unlock()
				if err != nil && firstErr == nil {
					firstErr = fmt.Errorf("%s run %d: %w", repo, run.ID, err)
					cancel() // stop the other goroutines from issuing API calls
				}
				res.Findings = append(res.Findings, fs...)
				res.JobsScanned += jobs
				if jobs > 0 || len(fs) > 0 {
					res.RunsScanned++
				}
			}()
		}
		wg.Wait()
		if firstErr != nil {
			return nil, firstErr
		}
	}
	sort.SliceStable(res.Findings, func(a, b int) bool {
		x, y := res.Findings[a], res.Findings[b]
		if x.Status != y.Status {
			return x.Status > y.Status
		}
		if x.Run.Repo != y.Run.Repo {
			return x.Run.Repo < y.Run.Repo
		}
		if x.Run.RunID != y.Run.RunID {
			return x.Run.RunID < y.Run.RunID
		}
		if x.Run.Job != y.Run.Job {
			return x.Run.Job < y.Run.Job
		}
		return x.Run.JobID < y.Run.JobID
	})
	res.Rotation = rotate.Plan(res.Findings)
	return res, nil
}

func ref(repo string, r source.Run, j source.Job) model.RunRef {
	attempt := j.Attempt
	if attempt == 0 { // run-level finding: no job
		attempt = r.Attempt
	}
	return model.RunRef{Repo: repo, RunID: r.ID, Workflow: r.Path, HeadSHA: r.HeadSHA, RunURL: r.URL,
		CreatedAt: r.CreatedAt, JobID: j.ID, Job: j.Name, JobURL: j.URL, Attempt: attempt}
}

// before reports a known time earlier than the window start; a zero time is never before.
func before(t, start time.Time) bool { return !t.IsZero() && t.Before(start) }

// workflow returns the parsed workflow file at repo@sha:path, or nil if it is unavailable (soft
// error, missing, unparsable). Hard errors are returned and not cached.
func (s *scanner) workflow(ctx context.Context, repo, sha, path string) (*workflow.Workflow, error) {
	key := repo + "@" + sha + ":" + path
	if v, ok := s.wf.Load(key); ok {
		return v.(*workflow.Workflow), nil
	}
	var wf *workflow.Workflow
	entries, _, err := s.src.Tree(ctx, repo, sha)
	if err != nil && !soft(err) {
		return nil, err
	}
	for _, e := range entries {
		if e.Path != path {
			continue
		}
		b, err := s.src.Blob(ctx, repo, e.SHA)
		if err != nil && !soft(err) {
			return nil, err
		}
		if err == nil {
			wf, _ = workflow.Parse(b)
		}
	}
	s.wf.Store(key, wf)
	return wf, nil
}

func note(format string, args ...any) model.Evidence {
	return model.Evidence{Kind: "note", Detail: fmt.Sprintf(format, args...)}
}

func (s *scanner) scanRun(ctx context.Context, repo string, run source.Run) ([]model.Finding, int, error) {
	start := s.inc.Window.Start
	// Listed through the lookback and finished before the window: nothing ran in it.
	if run.Status == "completed" && before(run.StartedAt, start) && before(run.UpdatedAt, start) {
		return nil, 0, nil
	}
	jobs, err := s.src.ListJobs(ctx, repo, run.ID)
	if soft(err) {
		return []model.Finding{{Run: ref(repo, run, source.Job{}), Status: model.Unchecked,
			Evidence: []model.Evidence{note("jobs unavailable: %v", err)}}}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	// Jobs that started and ended before the window did not run in it; a zero CompletedAt
	// (still running or unknown) keeps the job.
	jobs = slices.DeleteFunc(jobs, func(j source.Job) bool { return before(j.StartedAt, start) && before(j.CompletedAt, start) })
	if len(jobs) == 0 {
		return nil, 0, nil
	}
	wf, err := s.workflow(ctx, repo, run.HeadSHA, run.Path)
	if err != nil {
		return nil, 0, err
	}

	var npmRes npm.Result
	if len(s.inc.NPM) > 0 {
		npmRes, err = npm.Match(ctx, s.src, repo, run.HeadSHA, s.inc.NPM)
		if soft(err) { // keep evidence found before the error
			npmRes.Status = model.Worse(npmRes.Status, model.Unchecked)
			npmRes.Evidence = append(npmRes.Evidence, note("commit tree or file unavailable: %v", err))
		} else if err != nil {
			return nil, 0, err
		}
	}

	var out []model.Finding
	for _, job := range jobs {
		if job.Conclusion == "skipped" {
			continue // never ran: no runner, no install, no log
		}
		f := model.Finding{Run: ref(repo, run, job)}
		var wj *workflow.Job
		if wf != nil {
			wj, _ = wf.FindJob(job.Name) // nil when not found or ambiguous
		}
		call := callee{wf: wf, job: wj, matched: true}
		if wj != nil && wj.Call != "" {
			if call, err = s.resolveCall(ctx, repo, run.HeadSHA, wf, wj, job.Name); err != nil {
				return nil, 0, err
			}
			wj = call.job
		}
		var log string
		var logErr = source.ErrGone
		if len(s.inc.Actions) > 0 || npmRes.Status > model.Clean {
			log, logErr = s.src.JobLog(ctx, repo, job.ID)
			if logErr != nil && !soft(logErr) {
				return nil, 0, logErr
			}
		}
		// Drop npm evidence only on positive evidence the job cannot install packages.
		if npmRes.Status > model.Clean && (wj == nil || wj.MayInstallNPM() || logErr == nil && installLogRe.MatchString(log)) {
			f.Status = model.Worse(f.Status, npmRes.Status)
			f.Evidence = append(f.Evidence, npmRes.Evidence...)
		}
		if len(s.inc.Actions) > 0 {
			var st model.Status
			var ev []model.Evidence
			switch {
			case logErr == nil:
				st, ev = actions.MatchLog(log, s.inc.Actions)
				// A log without download records (truncated, unexpected format) proves nothing about remote uses.
				uses := allUses(wf)
				if wj != nil {
					uses = wj.Uses
				}
				noDownloads := len(actions.ParseDownloads(log)) == 0
				if noDownloads && wf == nil {
					st = model.Worse(st, model.Unchecked)
					ev = append(ev, note("job log has no action download records and the workflow file is unavailable"))
				} else if noDownloads && slices.ContainsFunc(uses, remote) {
					ust, uev := actions.MatchUses(uses, s.inc.Actions)
					st = model.Worse(model.Worse(st, ust), model.Unchecked)
					ev = append(append(ev, uev...), note("job log has no action download records"))
				}
			case wj != nil:
				st, ev = actions.MatchUses(wj.Uses, s.inc.Actions)
			case wf != nil: // job not identified: judge by every job's uses
				st, ev = actions.MatchUses(allUses(wf), s.inc.Actions)
			default:
				ev = []model.Evidence{note("workflow file unavailable")}
			}
			if logErr != nil {
				// Without the log `uses:` can raise the status but never prove the job clean.
				st = model.Worse(st, model.Unchecked)
				ev = append(ev, note("job log unavailable (%v); composite actions and reusable workflows not checked", logErr))
			}
			f.Status = model.Worse(f.Status, st)
			f.Evidence = append(f.Evidence, ev...)
		}

		f.Status = model.Worse(f.Status, call.status)
		f.Evidence = append(f.Evidence, call.notes...)

		if f.Status >= model.Possible {
			var e model.Exposure
			switch {
			case wj != nil:
				e = call.wf.Exposure(wj)
				e.JobMatched = call.matched
			case wf != nil:
				e = wf.ExposureAll()
			default:
				f.Evidence = append(f.Evidence, note("workflow file unavailable: secrets unknown"))
			}
			if logErr == nil {
				e.TokenPerms = workflow.ParseTokenPerms(log)
			}
			f.Exposure = &e
		}
		if f.Status != model.Clean {
			out = append(out, f)
		}
	}
	return out, len(jobs), nil
}

// maxCallDepth caps how many nested reusable-workflow calls are followed (GitHub allows four
// levels of workflows); it also stops a workflow that calls itself.
const maxCallDepth = 4

// callee is what a job that calls a reusable workflow resolved to.
type callee struct {
	wf      *workflow.Workflow // workflow whose Exposure(job) is the job's exposure
	job     *workflow.Job
	status  model.Status // UNCHECKED when a called workflow could not be read
	notes   []model.Evidence
	matched bool // false when a called job was not identified and the union of its workflow was used
}

// resolveCall follows job wj of wf through the reusable workflows it calls. Each further
// " / " segment of the API job name is matched against the called file. It stops at a call it
// cannot read and keeps what was resolved so far (the caller job, as before reusable workflows
// were read).
func (s *scanner) resolveCall(ctx context.Context, repo, sha string, wf *workflow.Workflow, wj *workflow.Job, apiName string) (callee, error) {
	c := callee{wf: wf, job: wj, matched: true}
	segs := strings.Split(apiName, " / ")[1:]
	for depth := 0; c.job.Call != ""; depth++ {
		uses := c.job.Call
		if depth == maxCallDepth {
			c.notes = append(c.notes, note("called workflow %s is nested more than %d levels deep — not read", uses, maxCallDepth))
			return c, nil
		}
		call, ok := workflow.ParseCall(uses)
		if !ok {
			c.notes = append(c.notes, note("called workflow %s is not pinned to a SHA — not read", uses))
			return c, nil
		}
		if call.Repo == "" { // local: same repository and commit as the calling file
			call.Repo, call.SHA = repo, sha
		}
		cw, err := s.workflow(ctx, call.Repo, call.SHA, call.Path)
		if err != nil {
			return c, err
		}
		if cw == nil {
			c.status = model.Unchecked
			c.notes = append(c.notes, note("called workflow %s unavailable — exposure judged from the caller job", uses))
			return c, nil
		}
		name := strings.Join(segs, " / ")
		var cj *workflow.Job
		if name != "" {
			cj, _ = cw.FindJob(name)
		}
		if cj == nil {
			cj, c.matched = cw.Union(), false
			c.notes = append(c.notes, note("job %q not identified in called workflow %s — exposure covers all its jobs", name, uses))
		}
		c.wf, c.job = c.wf.Through(c.job, cw, cj)
		repo, sha = call.Repo, call.SHA
		if len(segs) > 0 {
			segs = segs[1:]
		}
	}
	return c, nil
}

// remote reports whether a `uses:` is downloaded by the runner (not a local path or docker image).
func remote(u string) bool {
	return !strings.HasPrefix(u, "./") && !strings.HasPrefix(u, "docker://")
}

func allUses(wf *workflow.Workflow) []string {
	if wf == nil {
		return nil
	}
	ids := make([]string, 0, len(wf.Jobs))
	for id := range wf.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var uses []string
	for _, id := range ids {
		uses = append(uses, wf.Jobs[id].Uses...)
	}
	return uses
}
