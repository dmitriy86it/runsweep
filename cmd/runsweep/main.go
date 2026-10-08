// Command runsweep finds GitHub Actions jobs hit by a supply-chain incident.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/dmitriy86it/runsweep/internal/gh"
	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
	"github.com/dmitriy86it/runsweep/internal/report"
	"github.com/dmitriy86it/runsweep/internal/scan"
	"github.com/dmitriy86it/runsweep/internal/source"
	"github.com/spf13/cobra"
)

var version, commit, date = "dev", "none", "unknown"

var errFindings = errors.New("affected or possibly affected jobs found")

type deps struct {
	newSource func(token string) (source.Source, error)
	token     func() (string, error)
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, deps{newSource: newGitHub, token: githubToken}))
}

func newGitHub(token string) (source.Source, error) {
	c, err := gh.New(nil, token, "")
	if err != nil {
		return nil, err
	}
	c.Logf = func(f string, a ...any) { fmt.Fprintln(os.Stderr, report.Clean(fmt.Sprintf(f, a...))) }
	return c, nil
}

var (
	repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	orgRe  = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

const maxLookback = 30 * 24 * time.Hour // GitHub allows re-running a run for 30 days

// parseLookback accepts a Go duration ("36h") or whole days ("7d"), from 0 to 30 days.
func parseLookback(s string) (time.Duration, error) {
	bad := fmt.Errorf("--lookback must be a duration from 0 to 30d (e.g. 7d, 36h), got %q", s)
	if n, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(n)
		if err != nil || days < 0 || days > 30 {
			return 0, bad
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 || d > maxLookback {
		return 0, bad
	}
	return d, nil
}

func validateTargets(repos []string, org string) error {
	for _, r := range repos {
		owner, name, _ := strings.Cut(r, "/")
		if !repoRe.MatchString(r) || owner == "." || owner == ".." || name == "." || name == ".." {
			return fmt.Errorf("invalid --repo %q: want owner/name", r)
		}
	}
	if org != "" && !orgRe.MatchString(org) {
		return fmt.Errorf("invalid --org %q", org)
	}
	return nil
}

func githubToken() (string, error) {
	if t := strings.TrimSpace(os.Getenv("GITHUB_TOKEN")); t != "" {
		return t, nil
	}
	out, err := exec.Command("gh", "auth", "token").Output()
	if t := strings.TrimSpace(string(out)); err == nil && t != "" {
		return t, nil
	}
	return "", errors.New("no GitHub token: set GITHUB_TOKEN or run `gh auth login` (read-only access to Actions, Contents and Metadata is enough)")
}

func run(args []string, stdout, stderr io.Writer, d deps) int {
	root := &cobra.Command{Use: "runsweep", Short: "Find GitHub Actions jobs hit by a supply-chain incident and what to rotate",
		SilenceUsage: true, SilenceErrors: true}
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(&cobra.Command{Use: "version", Short: "Print version", Run: func(c *cobra.Command, _ []string) {
		_, _ = fmt.Fprintf(c.OutOrStdout(), "runsweep %s (%s, %s)\n", version, commit, date)
	}})
	root.AddCommand(&cobra.Command{Use: "incidents", Short: "List built-in incident presets", RunE: func(c *cobra.Command, _ []string) error {
		ps, err := incident.Presets()
		if err != nil {
			return err
		}
		for _, p := range ps {
			_, _ = fmt.Fprintf(c.OutOrStdout(), "%-24s %s\n", p.ID, p.Title)
		}
		return nil
	}})
	root.AddCommand(scanCmd(d))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	err := root.ExecuteContext(ctx)
	switch {
	case err == nil:
		return 0
	case errors.Is(err, errFindings):
		return 1
	case errors.Is(err, context.Canceled):
		_, _ = fmt.Fprintln(stderr, "error: interrupted")
		return 2
	default:
		_, _ = fmt.Fprintln(stderr, "error:", report.Clean(err.Error()))
		return 2
	}
}

func scanCmd(d deps) *cobra.Command {
	var incRef, org, format, since, until, lookback string
	var repos []string
	c := &cobra.Command{
		Use:   "scan",
		Short: "Scan workflow runs in the incident window",
		Example: `  runsweep scan --incident axios-2026-03 --repo owner/name
  runsweep scan --incident ./incident.yaml --org my-org --format json`,
		RunE: func(c *cobra.Command, _ []string) error {
			if len(repos) == 0 && org == "" {
				return errors.New("pass --repo owner/name (repeatable) or --org name")
			}
			if format != "md" && format != "json" {
				return fmt.Errorf("--format must be md or json, got %q", format)
			}
			if err := validateTargets(repos, org); err != nil {
				return err
			}
			back, err := parseLookback(lookback)
			if err != nil {
				return err
			}
			inc, err := incident.Load(incRef)
			if err != nil {
				return err
			}
			for _, o := range []struct {
				val string
				dst *time.Time
			}{{since, &inc.Window.Start}, {until, &inc.Window.End}} {
				if o.val == "" {
					continue
				}
				t, err := time.Parse(time.RFC3339, o.val)
				if err != nil {
					return fmt.Errorf("--since/--until must be RFC3339 (2026-03-31T00:00:00Z): %w", err)
				}
				*o.dst = t
			}
			if err := inc.Validate(); err != nil {
				return err
			}
			token, err := d.token()
			if err != nil {
				return err
			}
			src, err := d.newSource(token)
			if err != nil {
				return err
			}
			logf := func(f string, a ...any) { _, _ = fmt.Fprintln(c.ErrOrStderr(), report.Clean(fmt.Sprintf(f, a...))) }
			res, err := scan.Run(c.Context(), src, inc, scan.Options{Repos: repos, Org: org, Lookback: back, Logf: logf})
			if err != nil {
				return err
			}
			res.RetentionWarning = inc.Window.Start.Before(time.Now().Add(-90 * 24 * time.Hour))
			if format == "json" {
				err = report.JSON(c.OutOrStdout(), inc, res)
			} else {
				err = report.Markdown(c.OutOrStdout(), inc, res)
			}
			if err != nil {
				return err
			}
			warn := func(f string, a ...any) { _, _ = fmt.Fprintf(c.ErrOrStderr(), "warning: "+f+"\n", a...) }
			if n := res.Count(model.Unchecked); n > 0 {
				warn("%d jobs could not be checked (UNCHECKED)", n)
			}
			if res.RunsScanned == 0 {
				warn("no workflow runs in the window")
			}
			if res.RetentionWarning {
				warn("%s", report.RetentionNote)
			}
			if res.ReposTargeted == 0 {
				return errors.New("no repositories to scan (does the token have access to the organization?)")
			}
			if n := len(res.Skipped); n > 0 {
				noun := "repositories"
				if n == 1 {
					noun = "repository"
				}
				warn("%d %s skipped (see report)", n, noun)
				if n == res.ReposTargeted {
					return errors.New("no repository could be scanned (missing access?)")
				}
			}
			if res.Count(model.Affected)+res.Count(model.Possible) > 0 {
				return errFindings
			}
			return nil
		},
	}
	c.Flags().StringVar(&incRef, "incident", "", "built-in incident id (see `runsweep incidents`) or path to a YAML file")
	c.Flags().StringSliceVar(&repos, "repo", nil, "repository owner/name (repeatable)")
	c.Flags().StringVar(&org, "org", "", "scan every repository of an organization")
	c.Flags().StringVar(&format, "format", "md", "output format: md or json")
	c.Flags().StringVar(&since, "since", "", "override window start (RFC3339)")
	c.Flags().StringVar(&until, "until", "", "override window end (RFC3339)")
	c.Flags().StringVar(&lookback, "lookback", "7d", "also check re-runs of runs created this long before the window (max 30d)")
	_ = c.MarkFlagRequired("incident")
	return c
}
