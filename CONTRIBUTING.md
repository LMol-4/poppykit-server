# Contributing

This package targets Personal Agent Protocol draft 0.2. Check the current
[specification](https://personalagentprotocol.org/docs/0.2/spec) and
[guides](https://personalagentprotocol.org/docs/0.2/guides); retained snapshots and
tests are supporting evidence. Distinguish MUST requirements, SHOULD recommendations
and product choices. Individual extensions and demo/business workflows are excluded.

Use Node 24.12.0, TypeScript 5.9.3 and @types/node 24.10.0.
Install with the pinned pnpm version in package.json and `pnpm install --frozen-lockfile`.
Run `npm run typecheck`, `npm run build`, `npm test` and `npm run check:docs`.
CI partitions tests without omitting any test file; full `npm test` remains useful
locally. Read [RELEASING.md](RELEASING.md) before changing workflow/release behavior.

Keep changes small and complete: include callers, declarations, regression checks
and documentation. Do not log credentials, weaken destination validation or silently
reset persisted data. Pull requests must explain checks actually run and limitations.
Use the repository's Issues for non-sensitive defects and feature discussions.
Code is licensed under [MIT](LICENSE). No separate contribution agreement is
configured; confirm permission for third-party contributions and obtain owner
authorization before publishing.

## TypeScript test harness and coverage

First-party tests, executable fixtures, process workers and packaged verification
scripts are canonical `.mts` files. Run `npm run typecheck:tests` for the complete
strict program and `npm run build:tests` before individual
`node scripts/run-checks.mjs GROUP` commands (unit, contracts, integration or
validation). `npm test` performs that checked harness build and runs all groups.
Build production first with `npm run build`; tests import compiled `dist/*.js`,
not TypeScript source. No loader or native type stripping replaces the compiler.

The existing TypeScript compiler emits ignored adjacent `.mjs` files only after
all strict diagnostics pass. Failed builds remove stale canonical outputs.
`scripts/build-tests.mjs` is compiler/bootstrap tooling, not an unchecked test
runner. Canonical test sources use LF, enforced by `.gitattributes`, so Linux and
Windows validate the same exact source bytes. Test output stays outside the npm
package allowlist. Retained JavaScript release/build tools and packaged examples
are genuine production tooling/examples; retained protocol captures are references.

Run `npm run coverage` for a production build, checked harness and native Node
24.12.0 line/branch/function report. `coverage/summary.txt`, `coverage/lcov.info`,
`coverage/report.json` and `coverage/raw/` are generated local reports. Metrics
refer to first-party compiled `dist` JavaScript; production emits no source maps
and no TypeScript remapping is claimed. Third-party `node_modules` is excluded;
unloaded modules are listed explicitly. Raw child-process reports are retained,
but arbitrary subprocess execution is not guaranteed to be merged into the native
runner summary, and killed/crashed workers may not flush counters. Actual installed
package/OS checks remain separate evidence. No percentage threshold substitutes
for protocol, negative/security, process and platform assertions.
