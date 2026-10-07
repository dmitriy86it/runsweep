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
	"slices"
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
	c.Logf = func(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...) }
	return c, nil
}

var (
	repoRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	orgRe  = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

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

// counting records how many repositories the scan will cover.
type counting struct {
	source.Source
	orgRepos int
}

func (c *counting) ListRepos(ctx context.Context, org string) ([]string, error) {
	r, err := c.Source.ListRepos(ctx, org)
	c.orgRepos = len(r)
	return r, err
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
		fmt.Fprintf(c.OutOrStdout(), "runsweep %s (%s, %s)\n", version, commit, date)
	}})
	root.AddCommand(&cobra.Command{Use: "incidents", Short: "List built-in incident presets", RunE: func(c *cobra.Command, _ []string) error {
		ps, err := incident.Presets()
		if err != nil {
			return err
		}
		for _, p := range ps {
			fmt.Fprintf(c.OutOrStdout(), "%-24s %s\n", p.ID, p.Title)
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
		fmt.Fprintln(stderr, "error: interrupted")
		return 2
	default:
		fmt.Fprintln(stderr, "error:", err)
		return 2
	}
}

func scanCmd(d deps) *cobra.Command {
	var incRef, org, format, since, until string
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
			base, err := d.newSource(token)
			if err != nil {
				return err
			}
			src := &counting{Source: base}
			logf := func(f string, a ...any) { fmt.Fprintf(c.ErrOrStderr(), f+"\n", a...) }
			res, err := scan.Run(c.Context(), src, inc, scan.Options{Repos: repos, Org: org, Logf: logf})
			if err != nil {
				return err
			}
			if format == "json" {
				err = report.JSON(c.OutOrStdout(), inc, res)
			} else {
				err = report.Markdown(c.OutOrStdout(), inc, res)
			}
			if err != nil {
				return err
			}
			if n := len(res.Skipped); n > 0 {
				fmt.Fprintf(c.ErrOrStderr(), "warning: %d repositories skipped (see report)\n", n)
				total := len(slices.Compact(slices.Sorted(slices.Values(repos)))) + src.orgRepos
				if res.RunsScanned == 0 && n >= total {
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
	_ = c.MarkFlagRequired("incident")
	return c
}
