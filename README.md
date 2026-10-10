# runsweep

[![ci](https://github.com/runsweep/runsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/runsweep/runsweep/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/runsweep/runsweep/badge)](https://scorecard.dev/viewer/?uri=github.com/runsweep/runsweep)

Did the worm touch my CI? Retroactive blast radius for GitHub Actions — which runs pulled the bad package or action, what secrets they could see, what to rotate first.

![runsweep scanning the demo repository](docs/demo.gif)

The recording scans [runsweep-demo](https://github.com/runsweep/runsweep-demo) with [`examples/drill.yaml`](examples/drill.yaml), a fire drill that pretends `is-number@7.0.0` and a pinned `actions/setup-node` SHA were compromised.

## Install

Download the latest release from [Releases](https://github.com/runsweep/runsweep/releases) and verify it before running it: the archive's checksum (required), the signature of the checksum file (needs [cosign](https://github.com/sigstore/cosign), optional: `brew install cosign`), and its build provenance. Run it in an empty directory, so the globs match only the downloaded files. The commands below are for linux on amd64; on an Apple Silicon Mac use `darwin_arm64` in place of `linux_amd64`.

```bash
gh release download -R runsweep/runsweep -p '*_linux_amd64.tar.gz' -p checksums.txt -p checksums.txt.sigstore.json
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/runsweep/runsweep/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt     # macOS: shasum -a 256 --ignore-missing -c checksums.txt
gh attestation verify runsweep_*_linux_amd64.tar.gz -R runsweep/runsweep
tar xzf runsweep_*_linux_amd64.tar.gz runsweep
```

Archives are named `runsweep_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) for linux, darwin and windows on amd64 and arm64.

Or build from source (Go 1.27+):

```bash
go install github.com/runsweep/runsweep/cmd/runsweep@latest
```

## Usage

```bash
runsweep scan --incident chaindrop-2026-08 --repo owner/name   # one or more repos (--repo is repeatable)
runsweep scan --incident ./incident.yaml --org my-org          # every repository of an organization
runsweep scan --incident chaindrop-2026-08 --repo owner/name --format json
runsweep scan --incident chaindrop-2026-08 --repo owner/name --lookback 30d   # also re-runs of month-old runs
runsweep incidents                                             # built-in incident presets
runsweep incidents import MAL-2026-2307 -o incident.yaml       # build an incident file from OSV and npm
```

The `axios-2026-03` and `tj-actions-2025-03` presets are past the 90-day log retention for most repositories: their runs and logs are gone, so expect UNCHECKED or no runs.

`--incident` takes a built-in preset id or a file: a value with a `/` or ending in `.yaml`/`.yml` is read as a file (write `./name`), anything else is only a preset id. `--since` / `--until` (RFC3339) override the incident window. On a terminal the report is a short colored summary (`--format text`); piped or redirected — for example in CI — it is Markdown (`--format md`), and `--format json` gives machine-readable output. Colors are off when `NO_COLOR` is set or `TERM=dumb`. Progress and warnings go to stderr.

`--lookback` (default `7d`, up to `30d`, the period GitHub allows re-runs) also lists runs created that long before the window, so a re-run started inside the window is scanned. Jobs that started and finished before the window are skipped.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | every job checked, nothing AFFECTED or POSSIBLE |
| `1` | at least one job AFFECTED or POSSIBLE |
| `2` | error: bad flags or incident file, no token, token rejected (HTTP 401), a GitHub Enterprise host, organization could not be listed, nothing could be scanned |
| `3` | nothing AFFECTED or POSSIBLE, but not everything was checked: UNCHECKED jobs, skipped repositories, the scan stopped early (Ctrl-C, an API or network error), or no runs were found in a window that starts more than 90 days ago (GitHub may have deleted them) |

`1` wins over `2` and `3`: findings are reported even if the scan then stops on an error, such as a rejected token. A scan that stops early (an error or Ctrl-C) still prints the report of what it checked, starting with `Scan incomplete: <reason>` (the JSON has `incomplete` and `error`); what it did not reach is listed as `interrupted: not scanned`. A second Ctrl-C exits at once.

**Token.** runsweep uses `GITHUB_TOKEN`, then `GH_TOKEN`, or else `gh auth token`. It only reads, and it talks only to api.github.com: if `GITHUB_API_URL` or `GH_HOST` name another host (GitHub Enterprise Server or GHE.com), it exits with `2` and the token is not sent. A fine-grained token needs read-only **Actions**, **Contents** and **Metadata** on the repositories you scan; a classic token needs `repo` for private repositories and no scope for public ones.

## Incident file format

```yaml
id: axios-2026-03
title: "axios 1.14.1 / 0.30.4 malicious release"
# when the bad artifact could be downloaded; jobs that ran in this window are scanned
window: {start: 2026-03-31T00:21:58Z, end: 2026-03-31T03:15:30Z}
npm:                       # compromised package versions
  - {name: axios, versions: ["1.14.1", "0.30.4"]}  # ["*"] alone: every version is malicious
actions:                   # compromised action commits (40-char SHAs)
  - {uses: tj-actions/changed-files, shas: ["0e58ed8671d6b60d0890c21b07f8835ace038e67"]}
iocs:                      # informational, not matched
  domains: [sfrclak.com]
  ips: [142.11.206.73]
refs:
  - https://osv.dev/vulnerability/MAL-2026-2307
```

`id`, `window` and at least one of `npm` / `actions` are required. Unknown fields are errors.

## Built-in incidents

| Preset | Incident |
|---|---|
| `axios-2026-03` | axios 1.14.1 / 0.30.4 malicious release |
| `chaindrop-2026-08` | Shai-Hulud wave: keyv / cacheable and 400+ npm packages |
| `tanstack-2026-05` | Mini Shai-Hulud wave: TanStack and 128 other npm packages, 170 packages / 432 versions (CVE-2026-45321) |
| `tj-actions-2025-03` | tj-actions/changed-files compromised (CVE-2025-30066) |
| `trivy-action-2026-03` | aquasecurity/trivy-action and setup-trivy tags hijacked (CVE-2026-33634) |

## Importing a new incident

`runsweep incidents import` turns OSV records into an incident file, so a new incident can be scanned minutes after it is published:

```bash
runsweep incidents import MAL-2026-2307 GHSA-g7cv-rxg3-hmpx -o incident.yaml   # OSV ids (MAL-, GHSA-, CVE-)
runsweep incidents import --package npm:axios                                   # every MAL-* record for a package
grep -o 'MAL-[0-9]*-[0-9]*' advisory.txt | runsweep incidents import            # ids on stdin, one per line
runsweep incidents import --action owner/repo@<40-hex sha> --since 2026-03-19T17:43:00Z --until 2026-03-20T06:00:00Z
```

It takes the npm versions OSV lists (an OSV range — with no versions listed, or with no fix — is expanded to the registry versions inside it; if none are, the package gets `["*"]`, every version), looks up their publish times in the npm registry and derives the window: the start is the earliest publish, the end is when the registry shows the versions removed, or now if any is still published. Packages are grouped by when their bad versions were first published; groups separated by more than 7 days are treated as separate waves. The largest group (the latest on a tie) and everything after it are kept, earlier groups are dropped as unrelated and listed in a comment (`--keep-all` keeps everything). A package is never split. Every assumption is written as a comment in the file; check them, and override the window with `--since` / `--until` when a source gives better times.

Ids on stdin are read only when no ids, `--package` or `--action` are given (at most 10 000). An import that has only `--action` needs `--since` and `--until`. GitHub Actions advisories are reported on stderr: OSV has no commit SHAs, so pass them with `--action`. The output is validated before it is written; `-o` replaces the file atomically. Only `api.osv.dev` and `registry.npmjs.org` are contacted. Any error, including an unknown subcommand, exits with `2`.

## How it decides

For each job that ran inside the window (including re-runs of runs created up to `--lookback` earlier), runsweep reads the job, its log, the workflow file — and the called workflow when the job runs a reusable workflow that is local or pinned to a commit SHA — and the lockfiles at the run's commit, and gives every job one status:

| Status | Meaning |
|---|---|
| **AFFECTED** | Strong evidence the job used the bad artifact: it installed from a lockfile that pins a bad version (package manager output or `[command]` lines in the log, or an explicit install step in the workflow), or its log shows the bad action commit was downloaded or, with the log gone, the workflow pins it (steps with `if:` are assumed to run). |
| **POSSIBLE** | It could have, but this is not confirmed: an opaque script, third-party or local actions that may install silently, only a package manager call, a lockfile not linked to the job, a `package.json` that declares the package without a covering lockfile entry, a mutable action ref (tag/branch) with no log, or a `pull_request_target` / `workflow_run` run whose lockfile or `uses:` points at the bad version. |
| **UNCHECKED** | Cannot be judged: the run, log, commit tree or a file is unavailable or unparseable, the lockfile is stale or `package-lock=false` is set (the report adds a note), package names are only known at run time, a `pull_request_target` / `workflow_run` run with no other evidence, or a limit was hit. Never reported as clean. |
| **CLEAN** | Checked and nothing found. |

For AFFECTED and POSSIBLE jobs the report lists what the job could read — secrets referenced by the job, `id-token: write`, cloud roles it could assume, `GITHUB_TOKEN` permissions — and merges them into a **Rotate first** list ordered by priority (cloud roles, then publish/deploy credentials, then third-party services). The secrets of UNCHECKED jobs are listed apart, under **Not verified — could not rule out exposure** (`unverified_rotation` in JSON): rotate them if you cannot verify otherwise. With nothing confirmed the report says `Nothing confirmed to rotate; N secrets…` instead of `Nothing to rotate.` Jobs whose secrets are unknown (workflow file or job list unavailable) are listed as `Secrets unknown for N jobs…` (`secrets_unknown_jobs` in JSON); the report then never says `Nothing to rotate.`

`pull_request_target` and `workflow_run` run the workflow from the base branch, but runsweep reads files at the run's `head_sha`: secrets and lockfile may differ from what ran, and a fork can control them. These runs are marked and at least UNCHECKED; lockfile and `uses:` evidence is capped at POSSIBLE; a bad action download in the log is still AFFECTED.

## Limits

- GitHub deletes workflow runs, logs and checks after the repository's retention period (90 days by default). Older runs cannot be checked and show as UNCHECKED or are absent.
- Which secrets a job could read is derived from the workflow file at the run's commit; GitHub's API does not expose it directly.
- Priority by secret name is a name-based heuristic. Review the list; do not treat it as complete.
- A job whose log was unavailable is reported UNCHECKED: actions used via composite actions (and reusable workflows that are neither local nor pinned to a SHA) can only be seen in the log. Job logs over 64 MB count as unavailable.
- Lockfiles are assumed to be written by npm, pnpm or yarn; hand-edited or hand-crafted lockfiles may be misread or may not match what was installed. `bun.lock`, `bun.lockb`, `deno.lock` and Yarn PnP (`.pnp.cjs`) are not read: their directory is at least UNCHECKED, also when an npm, pnpm or yarn lockfile next to them is read (it may be stale).
- A missing, unread, unsupported or stale lockfile does not mark a job whose log shows no package install (npm, pnpm, yarn or bun output) and whose workflow installs none. A lockfile that pins a bad version does not mark an identified job whose log was read and shows no package install or package manager call, whose workflow installs nothing and runs no opaque script, and whose only actions are actions/checkout, actions/setup-*, actions/cache, actions/upload-artifact, actions/download-artifact and actions/github-script; this never applies to pull_request_target or workflow_run runs. A dependency on a package of the same repository (a workspace) is not reported as missing from the lockfile.
- An install whose output is fully suppressed inside a JS action or a called script is not seen.
- A lockfile in a directory that declares workspaces covers only its members. A `package.json` that no lockfile covers, below the root, is POSSIBLE only for a job whose steps or log name its directory; otherwise UNCHECKED.
- Packages named on the command line (`npm i axios`) are found only in the workflow's own `run:` steps, not in scripts it calls or in local composite actions.
- Only repositories the token can see are scanned; with `--org`, repositories it cannot see are not listed at all.
- Pull request runs are checked at the head commit of the pull request, not at the merge commit GitHub actually built.
- Jobs that check out another ref (e.g. actions/checkout with: ref:, issue_comment) are judged by the run's commit.
- Container images (`container:`, `services:`, `docker://` actions) are not checked.
- Re-runs of runs created more than the lookback period (default 7 days) before the window are not scanned; use --lookback 30d for full coverage.
- Called workflows are read when local or pinned to a commit SHA, and in the scanned repository's owner or a public repository; others are judged from the caller job. A call into another owner's private repository is not read; the job is at least UNCHECKED.
- Workflow files over 1 MiB, lockfiles or `package.json` over 32 MB, and lockfiles and `package.json` files past the first 500 of a commit are not read; the job is at least UNCHECKED.
- Lateral movement is not traced: malicious code can spread through caches, artifacts and `needs` outputs, `repository_dispatch` / `workflow_run` chains, and self-hosted runners (`runs-on` is not read). `node_modules` restored from a cache or artifact is not seen either, so a job that only runs tests can still have run bad code.
- Runs that start after the window end are not scanned.
- GitHub Enterprise (GHES, GHE.com) is not supported.
- A large organization takes hours under the 5000 requests/hour rate limit: scan with `--repo`, or narrow the window with `--since` / `--until`.
- OIDC `id-token` access in nested reusable workflows is not resolved; cloud roles reached only that way may be missing from the list.
- A job name made only of an expression (`${{ matrix.os }}`), or equal to another job's id, leaves the job unidentified; its exposure is taken from the whole workflow, which gives more POSSIBLE and UNCHECKED jobs.
- npm and GitHub Actions only; no PyPI yet.

## FAQ

**Is my project exposed to a vulnerable dependency right now?** Use [osv-scanner](https://github.com/google/osv-scanner) for the current exposure of your dependencies. runsweep answers what ran during the incident window.

## Contributing incidents

See [CONTRIBUTING.md](CONTRIBUTING.md): start with `runsweep incidents import`, confirm every version or SHA with two independent sources, and explain the window in comments. If you cannot open a pull request, use the [new incident](https://github.com/runsweep/runsweep/issues/new?template=new-incident.yml) issue form.

## License

[Apache-2.0](LICENSE)
