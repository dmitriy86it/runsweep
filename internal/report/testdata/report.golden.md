# runsweep: `axios malicious release` (`axios-2026-03`)

Window: 2026-03-31 00:21:00 → 2026-03-31 03:21:00 UTC · runs scanned: 3 · jobs scanned: 5

**AFFECTED: 1 · POSSIBLE: 0 · UNCHECKED: 1**

## Rotate first

| # | Secret / role | Priority | Why | Seen in |
|---|---|---|---|---|
| 1 | `OIDC token (id-token: write)` | 1 · cloud | review cloud roles | `o/app#42 build` |
| 2 | `NPM_TOKEN` | 2 · publish/deploy | rotate | `o/app#42 build` |

## Findings

| Status | Repo | Workflow / job | Run | Evidence |
|---|---|---|---|---|
| AFFECTED | `o/app` | `.github/workflows/ci.yml / build` | [42](https://github.com/o/app/actions/runs/42) | `axios@1.14.1 in package-lock.json at abcdef1` |
| UNCHECKED | `o/old` | `.github/workflows/ci.yml` | 9 | `jobs unavailable: deleted by GitHub retention (HTTP 410)` |

## Skipped repositories

- `o/private` — `no access (HTTP 403/404)`

The token needs read access to Actions, Contents and Metadata for these repositories.

## Incident sources

- `https://osv.dev/vulnerability/MAL-2026-2307`

## Limits

- GitHub deletes workflow runs, checks and logs after the repository's retention period (default 90 days). Older runs cannot be checked and show as UNCHECKED or are absent.
- Which secrets a job could read is derived from the workflow file at the run's commit; GitHub's API does not expose it directly.
- Priority by secret name is a name-based heuristic. Review the list; do not treat it as complete.
- A job whose log was unavailable is reported UNCHECKED: actions used via composite actions or reusable workflows can only be seen in the log.
- Lockfiles are assumed to be written by npm, pnpm or yarn; hand-edited lockfiles may be misread.
- Runs are selected by creation time: re-runs of older runs and runs queued before the window are not scanned.
- Reusable workflows are judged from the caller job: OIDC roles and permissions inside the called workflow are not shown.
