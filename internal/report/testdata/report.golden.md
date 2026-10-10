# runsweep: `axios malicious release` (`axios-2026-03`)

Window: 2026-03-31 00:21:00 → 2026-03-31 03:21:00 UTC · repositories scanned: 2 · runs scanned: 3 · jobs scanned: 5

**AFFECTED: 1 · POSSIBLE: 0 · UNCHECKED: 1**

## Rotate first

Secrets unknown for 1 job (workflow or job list unavailable); review them manually: `o/old#9`.

| # | Secret / role | Priority | Why | Seen in |
|---|---|---|---|---|
| 1 | `OIDC token (id-token: write)` | 1 · cloud | review cloud roles | `o/app#42 build attempt 2` |
| 2 | `NPM_TOKEN` | 2 · publish/deploy | rotate | `o/app#42 build attempt 2` |

## Not verified — could not rule out exposure

| # | Secret / role | Priority | Why | Seen in |
|---|---|---|---|---|
| 1 | `DEPLOY_KEY` | 2 · publish/deploy | rotate | `o/app#43 publish` |

## Findings

| Status | Repo | Workflow / job | Run | Evidence |
|---|---|---|---|---|
| AFFECTED | `o/app` | `.github/workflows/ci.yml / build` | [42](https://github.com/o/app/actions/runs/42) attempt 2 | `axios@1.14.1 in package-lock.json at abcdef1` |
| UNCHECKED | `o/old` | `.github/workflows/ci.yml` | 9 | `jobs unavailable: deleted by GitHub retention (HTTP 410)` |

## Skipped repositories

- `o/private` — `no access (HTTP 403/404)`

The token needs read access to Actions, Contents and Metadata for these repositories.

## Incident sources

- `https://osv.dev/vulnerability/MAL-2026-2307`

Malicious code can spread through caches, artifacts, self-hosted runners and workflow chains; see Limits

## Limits

- GitHub deletes workflow runs, checks and logs after the repository's retention period (default 90 days). Older runs cannot be checked and show as UNCHECKED or are absent.
- Which secrets a job could read is derived from the workflow file at the run's commit; GitHub's API does not expose it directly.
- Priority by secret name is a name-based heuristic. Review the list; do not treat it as complete.
- A job whose log was unavailable is reported UNCHECKED: actions used via composite actions (and reusable workflows that are neither local nor pinned to a SHA) can only be seen in the log. Job logs over 64 MB count as unavailable.
- Lockfiles are assumed to be written by npm, pnpm or yarn; hand-edited lockfiles may be misread. bun.lock, bun.lockb, deno.lock and .pnp.cjs are not read: their directory is at least UNCHECKED, even next to a lockfile that is read (it may be stale).
- A missing, unread, unsupported or stale lockfile does not mark a job whose log shows no package install and whose workflow installs none. A lockfile that pins a bad version does not mark an identified job whose log was read and shows no package install or package manager call, whose workflow installs nothing and runs no opaque script, and whose only actions are actions/checkout, actions/setup-*, actions/cache, actions/upload-artifact, actions/download-artifact and actions/github-script; this never applies to pull_request_target or workflow_run runs. A pin is AFFECTED only for a job that installed from that lockfile (the root one or one in a directory its steps or log name); a job that may have installed it is POSSIBLE. A dependency on a package of the same repository (a workspace) is not reported as missing from the lockfile.
- An install whose output is fully suppressed inside a JS action or a called script is not seen.
- A lockfile in a directory that declares workspaces covers only its members. A package.json that no lockfile covers, below the root, is POSSIBLE only for a job whose steps or log name its directory; otherwise UNCHECKED.
- Packages named on the command line (npm i axios) are found only in the workflow's own run: steps, not in scripts it calls or in local composite actions.
- Only repositories the token can see are scanned.
- Pull request runs are checked at the pull request's head commit, not the merge commit.
- Jobs that check out another ref (e.g. actions/checkout with: ref:, issue_comment) are judged by the run's commit.
- Container images are not checked.
- Re-runs of runs created more than the lookback period (default 7 days) before the window are not scanned; use --lookback 30d for full coverage.
- Called workflows are read when local or pinned to a commit SHA, and in the scanned repository's owner or a public repository; others are judged from the caller job, at least UNCHECKED for another owner's private repository.
- Workflow files over 1 MiB, lockfiles or package.json over 32 MB, and those past the first 500 of a commit are not read; the job is at least UNCHECKED.
- Lateral movement is not traced: caches, artifacts and needs outputs, dispatch and workflow_run chains, and self-hosted runners (runs-on is not read) can carry malicious code beyond the job that ran it. node_modules restored from a cache or artifact is not seen.
- pull_request_target and workflow_run run the base-branch workflow, but files are read at head_sha: secrets and lockfile may differ from what ran, and a fork can control them. Such runs are at least UNCHECKED; lockfile and uses: evidence is capped at POSSIBLE; a bad action download in the log is still AFFECTED.
- A job name made only of an expression, or equal to another job's id, leaves the job unidentified; its exposure is taken from the whole workflow, so more jobs are POSSIBLE or UNCHECKED.
- Runs that start after the window end are not scanned.
- GitHub Enterprise is not supported; OIDC trust in nested reusable workflows is not resolved.
- npm and GitHub Actions only.
