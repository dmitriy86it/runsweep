// Package scan finds jobs affected by an incident.
package scan

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/match/actions"
	"github.com/dmitriy86it/runsweep/internal/match/npm"
	"github.com/dmitriy86it/runsweep/internal/model"
	"github.com/dmitriy86it/runsweep/internal/rotate"
	"github.com/dmitriy86it/runsweep/internal/source"
	"github.com/dmitriy86it/runsweep/internal/workflow"
)

type Options struct {
	Repos       []string
	Org         string
	Concurrency int
	Logf        func(format string, args ...any)
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
	res := &model.Result{IncidentID: inc.ID, Start: inc.Window.Start, End: inc.Window.End}
	s := &scanner{src: src, inc: inc}
	for _, repo := range repos {
		runs, err := src.ListRuns(ctx, repo, inc.Window.Start, inc.Window.End)
		if soft(err) {
			res.Skipped = append(res.Skipped, model.Skip{Repo: repo, Reason: err.Error()})
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", repo, err)
		}
		logf("%s: %d runs in window", repo, len(runs))
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
				}
				res.Findings = append(res.Findings, fs...)
				res.JobsScanned += jobs
			}()
		}
		wg.Wait()
		if firstErr != nil {
			return nil, firstErr
		}
		res.RunsScanned += len(runs)
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
		return x.Run.Job < y.Run.Job
	})
	res.Rotation = rotate.Plan(res.Findings)
	return res, nil
}

func ref(repo string, r source.Run, j source.Job) model.RunRef {
	return model.RunRef{Repo: repo, RunID: r.ID, Workflow: r.Path, HeadSHA: r.HeadSHA, RunURL: r.URL,
		CreatedAt: r.CreatedAt, JobID: j.ID, Job: j.Name, JobURL: j.URL}
}

// workflow returns the parsed workflow file of a run, or nil if it is unavailable or unparsable.
func (s *scanner) workflow(ctx context.Context, repo string, run source.Run) *workflow.Workflow {
	key := repo + "@" + run.HeadSHA + ":" + run.Path
	if v, ok := s.wf.Load(key); ok {
		return v.(*workflow.Workflow)
	}
	var wf *workflow.Workflow
	if entries, _, err := s.src.Tree(ctx, repo, run.HeadSHA); err == nil {
		for _, e := range entries {
			if e.Path == run.Path {
				if b, err := s.src.Blob(ctx, repo, e.SHA); err == nil {
					wf, _ = workflow.Parse(b)
				}
			}
		}
	}
	s.wf.Store(key, wf)
	return wf
}

func note(format string, args ...any) model.Evidence {
	return model.Evidence{Kind: "note", Detail: fmt.Sprintf(format, args...)}
}

func (s *scanner) scanRun(ctx context.Context, repo string, run source.Run) ([]model.Finding, int, error) {
	jobs, err := s.src.ListJobs(ctx, repo, run.ID)
	if soft(err) {
		return []model.Finding{{Run: ref(repo, run, source.Job{}), Status: model.Unchecked,
			Evidence: []model.Evidence{note("jobs unavailable: %v", err)}}}, 0, nil
	}
	if err != nil {
		return nil, 0, err
	}
	wf := s.workflow(ctx, repo, run)

	var npmRes npm.Result
	if len(s.inc.NPM) > 0 {
		npmRes, err = npm.Match(ctx, s.src, repo, run.HeadSHA, s.inc.NPM)
		if soft(err) {
			npmRes = npm.Result{Status: model.Unchecked, Evidence: []model.Evidence{note("commit tree unavailable: %v", err)}}
		} else if err != nil {
			return nil, 0, err
		}
	}

	var out []model.Finding
	for _, job := range jobs {
		f := model.Finding{Run: ref(repo, run, job)}
		var wj *workflow.Job
		if wf != nil {
			wj, _ = wf.FindJob(job.Name) // nil when not found or ambiguous
		}
		if npmRes.Status > model.Clean && (wj == nil || wj.InstallsNPM()) {
			f.Status = model.Worse(f.Status, npmRes.Status)
			f.Evidence = append(f.Evidence, npmRes.Evidence...)
		}

		var log string
		var logErr error = source.ErrGone
		if len(s.inc.Actions) > 0 || f.Status >= model.Possible {
			log, logErr = s.src.JobLog(ctx, repo, job.ID)
			if logErr != nil && !soft(logErr) {
				return nil, 0, logErr
			}
		}
		if len(s.inc.Actions) > 0 {
			var st model.Status
			var ev []model.Evidence
			switch {
			case logErr == nil:
				st, ev = actions.MatchLog(log, s.inc.Actions)
			case wj != nil:
				st, ev = actions.MatchUses(wj.Uses, s.inc.Actions)
			case wf != nil:
				// Job not identified: judge by every job's uses, but never call it clean.
				st, ev = actions.MatchUses(allUses(wf), s.inc.Actions)
				st = model.Worse(st, model.Unchecked)
			default:
				st = model.Unchecked
				ev = []model.Evidence{note("workflow file unavailable")}
			}
			if logErr != nil {
				if errors.Is(logErr, source.ErrIncomplete) {
					st = model.Worse(st, model.Unchecked) // partial log: absence of evidence proves nothing
				}
				ev = append(ev, note("job log unavailable: %v", logErr))
			}
			f.Status = model.Worse(f.Status, st)
			f.Evidence = append(f.Evidence, ev...)
		}

		if f.Status >= model.Possible {
			var e model.Exposure
			switch {
			case wj != nil:
				e = wf.Exposure(wj)
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

func allUses(wf *workflow.Workflow) []string {
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
