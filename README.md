# runsweep

[![ci](https://github.com/dmitriy86it/runsweep/actions/workflows/ci.yml/badge.svg)](https://github.com/dmitriy86it/runsweep/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/dmitriy86it/runsweep/badge)](https://scorecard.dev/viewer/?uri=github.com/dmitriy86it/runsweep)

Did the worm touch my CI? Retroactive blast radius for GitHub Actions — which runs pulled the bad package or action, what secrets they could see, what to rotate first.

![runsweep scanning the demo repository](docs/demo.gif)

The recording scans [runsweep-demo](https://github.com/dmitriy86it/runsweep-demo) with [`examples/drill.yaml`](examples/drill.yaml), a fire drill that pretends `is-number@7.0.0` and a pinned `actions/setup-node` SHA were compromised.

## Install

Download an archive from [Releases](https://github.com/dmitriy86it/runsweep/releases) and verify its build provenance before running it:

```bash
gh attestation verify runsweep_*.tar.gz -R dmitriy86it/runsweep
tar xzf runsweep_*.tar.gz runsweep
```

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
```

`--since` / `--until` (RFC3339) override the incident window. The report (Markdown or JSON) goes to stdout, progress and warnings to stderr.

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
# when the bad artifact could be downloaded; runs created in this window are scanned
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

For each workflow run created inside the window, runsweep reads the jobs, their logs, the workflow file and the lockfiles at the run's commit, and gives every job one status:

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
- A job whose log was unavailable is reported UNCHECKED: actions used via composite actions or reusable workflows can only be seen in the log.
- Lockfiles are assumed to be written by npm, pnpm or yarn; hand-edited lockfiles may be misread.
- Runs are selected by creation time: re-runs of older runs and runs queued before the window are not scanned.
- Reusable workflows are judged from the caller job: OIDC roles and permissions inside the called workflow are not shown.
- npm and GitHub Actions only; no PyPI yet.

## Contributing incidents

Open a pull request adding a YAML file to [`internal/incident/presets/`](internal/incident/presets/) in the format above. Include `refs` to primary sources (advisory, registry metadata, vendor write-up) and note in comments how the window start and end were derived.

## License

[Apache-2.0](LICENSE)
