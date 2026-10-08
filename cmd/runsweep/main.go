// Command runsweep finds GitHub Actions jobs hit by a supply-chain incident.
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/dmitriy86it/runsweep/internal/gh"
	"github.com/dmitriy86it/runsweep/internal/importer"
	"github.com/dmitriy86it/runsweep/internal/incident"
	"github.com/dmitriy86it/runsweep/internal/model"
	"github.com/dmitriy86it/runsweep/internal/report"
	"github.com/dmitriy86it/runsweep/internal/scan"
	"github.com/dmitriy86it/runsweep/internal/source"
	"github.com/spf13/cobra"
)

var version, commit, date = "dev", "none", "unknown" // set by the release build

// versionString is "VERSION (COMMIT, DATE)". A build without release values (go install, go build)
// falls back to what the Go toolchain recorded: the module version and the VCS revision and time.
func versionString(v, c, d string, info *debug.BuildInfo) string {
	if v == "dev" && info != nil {
		if m := info.Main.Version; m != "" && m != "(devel)" {
			v = m
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				c = s.Value
			case "vcs.time":
				d = s.Value
			}
		}
	}
	return fmt.Sprintf("%s (%s, %s)", v, c, d)
}

// exitCode ends the command with that code; its message has already been printed.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit %d", int(e)) }

const (
	exitFindings   exitCode = 1 // AFFECTED or POSSIBLE jobs
	exitIncomplete exitCode = 3 // UNCHECKED jobs, skipped repositories or an interrupted scan
)

type deps struct {
	newSource   func(token string) (source.Source, error)
	token       func(ctx context.Context) (string, error)
	isTerminal  func(w io.Writer) bool // nil: never a terminal
	stdin       io.Reader              // nil: empty
	newImporter func() *importer.Client
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, deps{newSource: newGitHub, token: githubToken, isTerminal: isTerminal,
		stdin: os.Stdin, newImporter: importer.New}))
}

// isTerminal reports whether w is a character device (a terminal), not a pipe or a file.
func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	return err == nil && st.Mode()&os.ModeCharDevice != 0
}

func newGitHub(token string) (source.Source, error) {
	c, err := gh.New(&http.Client{Timeout: 5 * time.Minute}, token, "") // bounds a stalled request, log downloads included
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

func githubToken(ctx context.Context) (string, error) {
	for _, v := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if t := strings.TrimSpace(os.Getenv(v)); t != "" {
			return t, nil
		}
	}
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if t := strings.TrimSpace(string(out)); err == nil && t != "" {
		return t, nil
	}
	return "", errors.New("no GitHub token: set GITHUB_TOKEN or GH_TOKEN, or run `gh auth login` (read-only access to Actions, Contents and Metadata is enough)")
}

func run(args []string, stdout, stderr io.Writer, d deps) int {
	root := &cobra.Command{Use: "runsweep", Short: "Find GitHub Actions jobs hit by a supply-chain incident and what to rotate",
		SilenceUsage: true, SilenceErrors: true}
	info, _ := debug.ReadBuildInfo()
	root.Version = versionString(version, commit, date, info)
	root.SetVersionTemplate("runsweep {{.Version}}\n")
	root.SetArgs(args)
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.AddCommand(&cobra.Command{Use: "version", Short: "Print version", Run: func(c *cobra.Command, _ []string) {
		_, _ = fmt.Fprintf(c.OutOrStdout(), "runsweep %s\n", root.Version)
	}})
	incidents := &cobra.Command{Use: "incidents", Short: "List built-in incident presets", Args: func(_ *cobra.Command, args []string) error {
		if len(args) > 0 {
			return fmt.Errorf("unknown subcommand %q", args[0])
		}
		return nil
	}, RunE: func(c *cobra.Command, _ []string) error {
		ps, err := incident.Presets()
		if err != nil {
			return err
		}
		for _, p := range ps {
			_, _ = fmt.Fprintf(c.OutOrStdout(), "%-24s %s\n", p.ID, p.Title)
		}
		return nil
	}}
	incidents.AddCommand(importCmd(d))
	root.AddCommand(incidents)
	root.AddCommand(scanCmd(d))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	go func() {
		<-ctx.Done()
		stop() // a second Ctrl-C kills the process instead of waiting for the partial report
	}()
	err := root.ExecuteContext(ctx)
	var code exitCode
	switch {
	case err == nil:
		return 0
	case errors.As(err, &code):
		return int(code)
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
		Long: `Scan workflow runs in the incident window.

Exit codes:
  0  every job checked, nothing AFFECTED or POSSIBLE
  1  at least one job AFFECTED or POSSIBLE
  2  error (bad flags or incident, no token, token rejected, organization not listed,
     nothing could be scanned)
  3  nothing AFFECTED or POSSIBLE, but not everything was checked: UNCHECKED jobs,
     skipped repositories, or the scan was interrupted (Ctrl-C, API error)
1 wins over 2 and 3: findings are reported even if the scan then stops on an error.`,
		Example: `  runsweep scan --incident axios-2026-03 --repo owner/name
  runsweep scan --incident ./incident.yaml --org my-org --format json`,
		RunE: func(c *cobra.Command, _ []string) error {
			if len(repos) == 0 && org == "" {
				return errors.New("pass --repo owner/name (repeatable) or --org name")
			}
			tty := d.isTerminal != nil && d.isTerminal(c.OutOrStdout())
			if format == "" {
				format = "md" // pipes and files: CI pipelines read the Markdown report
				if tty {
					format = "text"
				}
			}
			if format != "text" && format != "md" && format != "json" {
				return fmt.Errorf("--format must be text, md or json, got %q", format)
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
			token, err := d.token(c.Context())
			if err != nil {
				return err
			}
			src, err := d.newSource(token)
			if err != nil {
				return err
			}
			logf := func(f string, a ...any) { _, _ = fmt.Fprintln(c.ErrOrStderr(), report.Clean(fmt.Sprintf(f, a...))) }
			res, scanErr := scan.Run(c.Context(), src, inc, scan.Options{Repos: repos, Org: org, Lookback: back, Logf: logf})
			if res == nil { // listing the organization failed: nothing scanned, so an error (2) unless interrupted
				if errors.Is(scanErr, context.Canceled) {
					return stopped(c.ErrOrStderr(), scanErr, false)
				}
				return scanErr
			}
			res.RetentionWarning = inc.Window.Start.Before(time.Now().Add(-90 * 24 * time.Hour))
			switch format {
			case "json":
				err = report.JSON(c.OutOrStdout(), inc, res)
			case "text":
				color := tty && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
				err = report.Text(c.OutOrStdout(), inc, res, color)
			default:
				err = report.Markdown(c.OutOrStdout(), inc, res)
			}
			if err != nil {
				return err
			}
			warn := func(f string, a ...any) { _, _ = fmt.Fprintf(c.ErrOrStderr(), "warning: "+f+"\n", a...) }
			if n := res.Count(model.Unchecked); n > 0 {
				noun := "jobs"
				if n == 1 {
					noun = "job"
				}
				warn("%d %s could not be checked (UNCHECKED)", n, noun)
			}
			if res.RunsScanned == 0 && scanErr == nil {
				warn("no workflow runs in the window")
			}
			if res.RetentionWarning {
				warn("%s", report.RetentionNote)
			}
			findings := res.Count(model.Affected)+res.Count(model.Possible) > 0
			if scanErr != nil {
				return stopped(c.ErrOrStderr(), scanErr, findings)
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
			if findings {
				return exitFindings
			}
			if res.Count(model.Unchecked) > 0 || len(res.Skipped) > 0 {
				return exitIncomplete
			}
			return nil
		},
	}
	c.Flags().StringVar(&incRef, "incident", "", "built-in incident id (see runsweep incidents) or path to a YAML file")
	c.Flags().StringSliceVar(&repos, "repo", nil, "repository owner/name (repeatable)")
	c.Flags().StringVar(&org, "org", "", "scan every repository of an organization")
	c.Flags().StringVar(&format, "format", "", "output format: text, md or json (default text on a terminal, md otherwise)")
	c.Flags().StringVar(&since, "since", "", "override window start (RFC3339)")
	c.Flags().StringVar(&until, "until", "", "override window end (RFC3339)")
	c.Flags().StringVar(&lookback, "lookback", "7d", "also check re-runs of runs created this long before the window (max 30d)")
	_ = c.MarkFlagRequired("incident")
	return c
}

// stopped reports the error that ended a scan early, after its partial report. Findings still
// exit 1; a rejected token exits 2 (the error is returned for run to print); otherwise 3.
func stopped(stderr io.Writer, err error, findings bool) error {
	if errors.Is(err, source.ErrAuth) && !findings {
		return err
	}
	msg := "interrupted"
	if !errors.Is(err, context.Canceled) {
		msg = report.Clean(err.Error())
	}
	_, _ = fmt.Fprintln(stderr, "error:", msg)
	if findings {
		return exitFindings
	}
	return exitIncomplete
}

func importCmd(d deps) *cobra.Command {
	var o importer.Options
	var packages []string
	var since, until, out string
	c := &cobra.Command{
		Use:   "import [OSV-ID...]",
		Short: "Build an incident file from OSV advisories and npm registry publish times",
		Example: `  runsweep incidents import MAL-2026-2307 -o axios.yaml
  runsweep incidents import --package npm:axios
  grep -o 'MAL-[0-9-]*' advisory.txt | runsweep incidents import -o incident.yaml
  runsweep incidents import --action owner/repo@<sha> --since 2026-03-19T17:43:00Z --until 2026-03-20T06:00:00Z`,
		RunE: func(c *cobra.Command, args []string) error {
			o.IDs = args
			if len(args) == 0 && len(packages) == 0 && len(o.Actions) == 0 && d.stdin != nil {
				f, isFile := d.stdin.(*os.File)
				if !isFile || !isTerminal(f) {
					ids, err := readIDs(d.stdin)
					if err != nil {
						return err
					}
					o.IDs = ids
				}
			}
			for _, p := range packages {
				name, ok := strings.CutPrefix(p, "npm:")
				if !ok {
					return fmt.Errorf("--package %q: want npm:NAME", p)
				}
				o.Packages = append(o.Packages, name)
			}
			if len(o.IDs) == 0 && len(o.Packages) == 0 && len(o.Actions) == 0 {
				return errors.New("nothing to import: pass OSV ids (as arguments or on stdin), --package npm:NAME or --action owner/repo@SHA")
			}
			for _, f := range []struct {
				val string
				dst *time.Time
			}{{since, &o.Since}, {until, &o.Until}} {
				if f.val == "" {
					continue
				}
				t, err := time.Parse(time.RFC3339, f.val)
				if err != nil {
					return fmt.Errorf("--since/--until must be RFC3339 (2026-03-31T00:00:00Z): %w", err)
				}
				*f.dst = t
			}
			stderr := c.ErrOrStderr()
			o.Now = time.Now().UTC()
			o.Warnf = func(f string, a ...any) { _, _ = fmt.Fprintln(stderr, "warning:", report.Clean(fmt.Sprintf(f, a...))) }
			o.Logf = func(f string, a ...any) { _, _ = fmt.Fprintln(stderr, report.Clean(fmt.Sprintf(f, a...))) }
			cl := d.newImporter()
			cl.Logf = o.Logf
			b, err := cl.Import(c.Context(), o)
			if err != nil {
				return err
			}
			if out == "" {
				_, err = c.OutOrStdout().Write(b)
				return err
			}
			return writeAtomic(out, b)
		},
	}
	c.Flags().StringArrayVar(&packages, "package", nil, "npm:NAME — import every MAL-* record OSV has for the package (repeatable)")
	c.Flags().StringArrayVar(&o.Actions, "action", nil, "compromised action commit owner/repo@<40-hex sha> (repeatable)")
	c.Flags().StringVar(&o.ID, "id", "", "incident id (default import-<window start date>)")
	c.Flags().StringVar(&o.Title, "title", "", "incident title (default: the first OSV ids)")
	c.Flags().BoolVar(&o.KeepAll, "keep-all", false, "keep packages published more than 7 days before the wave")
	c.Flags().StringVar(&since, "since", "", "window start (RFC3339); overrides the computed start")
	c.Flags().StringVar(&until, "until", "", "window end (RFC3339); overrides the computed end")
	c.Flags().StringVarP(&out, "output", "o", "", "write to FILE atomically instead of stdout")
	return c
}

const maxIDs = 10000

// readIDs reads one OSV id per line ('#' starts a comment), deduplicated.
func readIDs(r io.Reader) ([]string, error) {
	var ids []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	sc.Buffer(nil, 1<<20)
	n := 0
	for sc.Scan() {
		n++
		text := sc.Text()
		if n == 1 {
			text = strings.TrimPrefix(text, "\ufeff")
		}
		line, _, _ := strings.Cut(text, "#")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !importer.ValidID(line) {
			return nil, fmt.Errorf("stdin line %d: %q is not an OSV id", n, line)
		}
		if seen[line] {
			continue
		}
		if len(ids) == maxIDs {
			return nil, fmt.Errorf("stdin line %d: more than %d ids", n, maxIDs)
		}
		seen[line] = true
		ids = append(ids, line)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("stdin line %d: %w", n+1, err)
	}
	return ids, nil
}

// writeAtomic writes b to a temp file next to path and renames it over path.
// The file keeps the mode of an existing path, else 0644.
func writeAtomic(path string, b []byte) error {
	mode := os.FileMode(0o644)
	if st, err := os.Stat(path); err == nil {
		mode = st.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runsweep-import-*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }() // no-op after a successful rename
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
