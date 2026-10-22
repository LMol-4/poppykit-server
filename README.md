# PoppyKit server

J1 supplies targeted storage contracts and an optional SQLite company database.
See [STORAGE.md](STORAGE.md) for Node requirements, adapter setup, atomic
authorization/revocation ordering, recovery guarantees and reset instructions.

Designed to be integrated into an existing company's backend. The SDK implements
Poppy protocol handling through adapters; the company owns its account system,
authorization policy, persistence, agent runtime and business tools. No hosted
PoppyKit service or particular model provider is required.

The embedding company supplies login pages, account data, and its agent runtime.
Demo applications are deferred and are not dependencies of this SDK. Poppy authorization
semantics are available as an optional experimental reference module; conversation
serving also supports a compatible external issuer and does not require that
module's storage, an agent handler or a worker queue. Application services publish
through SDK-validated operations; storage adapters supply atomic persistence.

Company-side TypeScript SDK for authentication verification and agent conversations.

Status (2026-10-22): unpublished implementation of request authentication,
an optional Direct/Device/Mediated reference issuer, and JSON conversation lifecycle and
publication. Known correctness issues remain; durable production adapters and
complete protocol conformance have not been established.

Targets the current [Personal Agent Protocol draft 0.2 specification](https://personalagentprotocol.org/docs/0.2/spec)
and [guides](https://personalagentprotocol.org/docs/0.2/guides).

The October 19 source pin is historical evidence, not overriding authority.
See [AUTH.md](AUTH.md) for method configuration, trusted hooks, scope/attempt
policy and account-isolated revocation fences. The reviewed programme also adds
streaming, API/browser integration, and feedback. These are planned capabilities,
not features available in this checkout. The personal-agent hosted identity
reference belongs with the client SDK and remains separate from this company's
reference issuer, even when one operator hosts both.

Accepted work may outlive its original Session Token. Hosts explicitly choose
whether account work already in progress stops after revocation; new requests
still require current access. Account-bound conversations remain open but reject
signed-out access. Official schemas and the partial upstream validator supplement,
but do not replace, normative prose and behavioral conformance tests.

This is an independent implementation with behavioral tests and a partial review;
complete protocol conformance and clean-package/platform verification remain open.

Creating this repository does not reserve a name on npm, PyPI, or crates.io.


## Package names

- npm: @poppykit/server
- Future PyPI distribution: poppykit-server (Python import: poppykit_server)
- Future crates.io package: poppykit-server (Rust library name: poppykit_server, if applicable)

These are intended names, not reserved registry packages. Python and Rust implementations are not yet present.

