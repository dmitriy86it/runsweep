# Contributing

Bug reports, fixes and new incident presets are welcome. For anything larger than a preset or a small fix, open an issue first.

## Adding an incident preset

A preset is one YAML file in [`internal/incident/presets/`](internal/incident/presets/), named `<id>.yaml`, in the format described in the [README](README.md#incident-file-format).

1. Start from OSV. `runsweep incidents import` builds the file from OSV records and npm registry publish times:

   ```bash
   runsweep incidents import MAL-2026-2307 GHSA-g7cv-rxg3-hmpx -o internal/incident/presets/<id>.yaml
   runsweep incidents import --package npm:axios                       # every MAL-* record OSV has for a package
   runsweep incidents import --action owner/repo@<40-hex sha> \
     --since 2026-03-19T17:43:00Z --until 2026-03-20T06:00:00Z           # compromised action commits
   ```

   Read the warnings and the comments in the output. Packages are grouped by when their bad versions were first published; groups more than 7 days before the main wave are dropped and listed in a comment (`--keep-all` keeps them). GitHub Actions advisories carry no commit SHAs and need `--action`, which also needs `--since` and `--until`. `versions: ["*"]` (only element) means every version is malicious; `import` writes it when an OSV range cannot be filled from the registry (package gone, or no registry version in the range).
2. Check every package version and every commit SHA against at least two independent sources (OSV or a GitHub advisory, plus a vendor or maintainer write-up). Leave out what only one source lists, and say so in a comment.
3. Check the window. `import` takes the start from npm publish times and the end from the registry, which often only gives an upper bound (`time.modified`). Replace it with `--since` / `--until` when a source gives better times, and widen rather than narrow: a missed job is worse than an extra one.
4. Comment how the start and the end were derived, with the sources.
5. `refs` must list at least two `https` URLs on different hosts.
6. Run `go test ./...`. A test checks every preset: valid, `id` equal to the file name, two independent `refs`.

Rules:

- Only public indicators: package versions, commit SHAs, domains and IPs that a public advisory or write-up already lists.
- No links to attacker infrastructure, payload downloads or lookalike domains. Write domains as plain text under `iocs`.
- No private data from your own incident response.

If you cannot open a pull request, use the [new incident](https://github.com/dmitriy86it/runsweep/issues/new?template=new-incident.yml) issue form.

## Code

- `gofmt`, `go vet ./...`, `go test -race ./...` and `golangci-lint run` (v2.14.0) must be clean.
- New behaviour comes with a test. A job must never become CLEAN because of missing data: when in doubt, report it UNCHECKED.
- No new dependencies without discussion.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).
