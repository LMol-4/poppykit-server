# Contributing

Follow the pinned draft 0.3 [specification](https://personalagentprotocol.org/docs/0.3/spec)
and [guides](https://personalagentprotocol.org/docs/0.3/guides). Tests/snapshots are
supporting evidence. This unreleased checkout has completed only the discovery
stage of migration; auth, wire/storage and integrations still need their stages.
Demo/business workflows and individual extensions are excluded.
Code is [MIT](LICENSE); confirm rights for third-party contributions.

Use Node 24.21.0, TypeScript 5.9.3 and @types/node 24.10.0.
Install the packageManager-pinned pnpm and run pnpm install --frozen-lockfile --ignore-scripts.

```sh
npm run typecheck
npm run build
npm run typecheck:tests
npm test
npm run check:docs
```

First-party tests/workers/verification helpers are canonical `.mts`. The existing
compiler checks the whole strict program before emitting ignored adjacent `.mjs`.
Failed builds remove stale outputs; no loader/type stripping substitutes for checking.
Run `npm run build:tests` before `node scripts/run-checks.mjs GROUP` (unit, contracts,
integration, validation). Groups are exhaustive/disjoint. LF source bytes are enforced
by Git attributes. Generated test code is outside the npm allowlist; production tests
import built/installed JavaScript. Release/build tools and examples may remain JS.

`npm run coverage` builds production and checked tests, then writes native Node
line/branch/function reports under `coverage/` (summary.txt, lcov.info, report.json,
raw/). Metrics cover loaded first-party dist JS: no production source maps or TS
remapping; node_modules excluded, unloaded modules listed. Raw subprocess reports
are retained, but arbitrary children may not merge and killed workers may not flush.
Installed/OS/host checks are separate evidence; no percentage proves conformance.

Include callers, meaningful regression evidence and docs with behavior changes.
Preserve credential/destination validation, private errors and persisted data.
Report checks actually run and limits. Use Issues for non-sensitive defects and
[SECURITY.md](SECURITY.md) for vulnerabilities. Follow [RELEASING.md](RELEASING.md)
before tagging/publishing; obtain explicit owner authorization.

Required CI also runs scripts/postgres-ci.mjs in a dedicated disposable PostgreSQL17
cluster with POPPY_DISPOSABLE_POSTGRES=1, D1_LOCAL=1 and explicit loopback PGHOST,
PGPORT, PGUSER, PGPASSWORD, PGDATABASE. Build production/tests first; use a fresh
database without SDK schemas. Never point it at shared/cloud data. It migrates
only this package's schemas, runs all named durable suites, rejects skips/missing
discovery and leaves cluster destruction to its owner. Default source-suite skips
do not replace this gate. See the workflow for the pinned image and setup.
