# PoppyKit server

Designed to be integrated into an existing company's backend. The SDK implements
Poppy protocol handling through adapters; the company owns its account system,
authorization policy, persistence, agent runtime and business tools. No hosted
PoppyKit service or particular model provider is required.

The reference login pages, account data and OpenAI-powered agent belong in
[poppykit-demo](https://github.com/LMol-4/poppykit-demo). Poppy authorization
semantics will be available as an optional experimental module; conversation
serving also supports a compatible external issuer and does not require that
module's storage, an agent handler or a worker queue. Application services publish
through SDK-validated operations; storage adapters supply atomic persistence.

Company-side TypeScript SDK for authentication verification and agent conversations.

Status: initial project scaffold. No SDK or CLI implementation is published yet.

Targets the Personal Agent Protocol (Poppy): https://personalagentprotocol.org/docs/spec

Current design target (reviewed 2026-10-19): draft **0.2, in progress**, pinned to
`30c476455c20c23c13b050c74c47d9b3269413c7`. Each company needs its own full issuer,
including on shared hosting. ES256 support is required; advertising issuer DPoP
algorithms is optional. Client and session assertions have a five-minute maximum
lifetime and per-client replay protection through expiry. Both sides need safe
HTTPS/address/redirect handling. These are requirements, not implemented behavior.

Accepted work may outlive its original Session Token. Hosts explicitly choose
whether account work already in progress stops after revocation; new requests
still require current access. Account-bound conversations remain open but reject
signed-out access. Official schemas and the partial upstream validator supplement,
but do not replace, normative prose and behavioral conformance tests.

This is an independent implementation. Protocol conformance has not yet been tested.

Creating this repository does not reserve a name on npm, PyPI, or crates.io.


## Package names

- npm: @poppykit/server
- Future PyPI distribution: poppykit-server (Python import: poppykit_server)
- Future crates.io package: poppykit-server (Rust library name: poppykit_server, if applicable)

These are intended names, not reserved registry packages. Python and Rust implementations are not yet present.

