# runsweep

[![ci](https://github.com/dmitriy86it/runsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/dmitriy86it/runsweep/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dmitriy86it/runsweep/badge)](https://scorecard.dev/viewer/?uri=github.com/dmitriy86it/runsweep)

Did the worm touch my CI? Retroactive blast radius for GitHub Actions — which runs pulled the bad package or action, what secrets they could see, what to rotate first.

![runsweep scanning the demo repository](docs/demo.gif)

The recording scans [runsweep-demo](https://github.com/dmitriy86it/runsweep-demo) with [`examples/drill.yaml`](examples/drill.yaml), a fire drill that pretends `is-number@7.0.0` and a pinned `actions/setup-node` SHA were compromised.

## Install

Download an archive from [Releases](https://github.com/dmitriy86it/runsweep/releases) and verify its build provenance before running it:

```bash
gh release download v0.1.0 -R dmitriy86it/runsweep -p 'runsweep_*_linux_amd64.tar.gz'
gh attestation verify runsweep_0.1.0_linux_amd64.tar.gz -R dmitriy86it/runsweep
tar xzf runsweep_0.1.0_linux_amd64.tar.gz runsweep
```

Archives are named `runsweep_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) for linux, darwin and windows on amd64 and arm64.

Or build from source (Go 1.27+):

```bash
go install github.com/dmitriy86it/runsweep/cmd/runsweep@latest
```

## Usage

```bash
runsweep incidents                                          # built-in incident presets
runsweep scan --incident axios-2026-03 --repo owner/name    # one or more repos (--repo is repeatable)
runsweep scan --incident ./incident.yaml --org my-org       # every repository of an organization
runsweep scan --incident tj-actions-2025-03 --repo owner/name --format json
runsweep scan --incident axios-2026-03 --repo owner/name --lookback 30d   # also re-runs of month-old runs
```

`--since` / `--until` (RFC3339) override the incident window. On a terminal the report is a short colored summary (`--format text`); piped or redirected — for example in CI — it is Markdown (`--format md`), and `--format json` gives machine-readable output. Colors are off when `NO_COLOR` is set or `TERM=dumb`. Progress and warnings go to stderr.

`--lookback` (default `7d`, up to `30d`, the period GitHub allows re-runs) also lists runs created that long before the window, so a re-run started inside the window is scanned. Jobs that started and finished before the window are skipped.

Exit codes:

| Code | Meaning |
|---|---|
| `0` | nothing AFFECTED or POSSIBLE |
| `1` | at least one job AFFECTED or POSSIBLE |
| `2` | error |

**Token.** runsweep uses `GITHUB_TOKEN`, or else `gh auth token`. It only reads. A fine-grained token needs read-only **Actions**, **Contents** and **Metadata** on the repositories you scan; a classic token needs `repo` for private repositories and no scope for public ones.

## Incident file format

```yaml
id: axios-2026-03
title: "axios 1.14.1 / 0.30.4 malicious release"
# when the bad artifact could be downloaded; jobs that ran in this window are scanned
window: {start: 2026-03-31T00:21:58Z, end: 2026-03-31T03:15:30Z}
npm:                       # compromised package versions
  - {name: axios, versions: ["1.14.1", "0.30.4"]}
actions:                   # compromised action commits (40-char SHAs)
  - {uses: tj-actions/changed-files, shas: ["0e58ed8671d6b60d0890c21b07f8835ace038e67"]}
iocs:                      # informational, not matched
  domains: [sfrclak.com]
  ips: [142.11.206.73]
refs:
  - https://osv.dev/vulnerability/MAL-2026-2307
```

`id`, `window` and at least one of `npm` / `actions` are required. Unknown fields are errors.

## How it decides

For each job that ran inside the window (including re-runs of runs created up to `--lookback` earlier), runsweep reads the job, its log, the workflow file — and the called workflow when the job runs a reusable workflow that is local or pinned to a commit SHA — and the lockfiles at the run's commit, and gives every job one status:

| Status | Meaning |
|---|---|
| **AFFECTED** | Proof the job used the bad artifact: a lockfile at the run's commit pins a bad version (dropped only when the job provably installs no packages), or the job log shows the bad action SHA was downloaded (or the workflow pins it). |
| **POSSIBLE** | It could have: a `package.json` declares the package without a lockfile entry covering it, or the workflow uses the action by a mutable ref (tag/branch) and the log is gone, so the resolved SHA is unknown. |
| **UNCHECKED** | Could not be checked: the run, log, commit tree or a file is unavailable or unparseable. Never reported as clean. |
| **CLEAN** | Checked and nothing found. |

For AFFECTED and POSSIBLE jobs the report lists what the job could read — secrets referenced by the job, `id-token: write`, cloud roles it could assume, `GITHUB_TOKEN` permissions — and merges them into a **Rotate first** list ordered by priority (cloud roles, then publish/deploy credentials, then third-party services).

## Limits

- GitHub deletes workflow runs, logs and checks after the repository's retention period (90 days by default). Older runs cannot be checked and show as UNCHECKED or are absent.
- Which secrets a job could read is derived from the workflow file at the run's commit; GitHub's API does not expose it directly.
- Priority by secret name is a name-based heuristic. Review the list; do not treat it as complete.
- A job whose log was unavailable is reported UNCHECKED: actions used via composite actions (and reusable workflows that are neither local nor pinned to a SHA) can only be seen in the log.
- Lockfiles are assumed to be written by npm, pnpm or yarn; hand-edited lockfiles may be misread.
- Re-runs of runs created more than the lookback period (default 7 days) before the window are not scanned; use --lookback 30d for full coverage.
- Called workflows are read when local or pinned to a commit SHA; others are judged from the caller job.
- npm and GitHub Actions only; no PyPI yet.

## Contributing incidents

Open a pull request adding a YAML file to [`internal/incident/presets/`](internal/incident/presets/) in the format above. Include `refs` to primary sources (advisory, registry metadata, vendor write-up) and note in comments how the window start and end were derived.

## License

[Apache-2.0](LICENSE)
