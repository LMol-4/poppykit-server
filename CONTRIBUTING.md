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
No public contribution license/CLA has been selected; ask the owner before accepting
third-party rights or publishing code.
