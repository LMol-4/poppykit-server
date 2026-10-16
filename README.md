# PoppyKit server

Designed to be integrated into an existing company's backend. The SDK implements
Poppy protocol handling through adapters; the company owns its account system,
authorization policy, persistence, agent runtime and business tools. No hosted
PoppyKit service or particular model provider is required.

The reference login service and OpenAI-powered agent belong in
[poppykit-demo](https://github.com/LMol-4/poppykit-demo), not the core SDK.

Company-side TypeScript SDK for authentication verification and agent conversations.

Status: initial project scaffold. No SDK or CLI implementation is published yet.

Targets the Personal Agent Protocol (Poppy): https://personalagentprotocol.org/docs/spec

This is an independent implementation. Protocol conformance has not yet been tested.

Creating this repository does not reserve a name on npm, PyPI, or crates.io.


## Package names

- npm: @poppykit/server
- Future PyPI distribution: poppykit-server (Python import: poppykit_server)
- Future crates.io package: poppykit-server (Rust library name: poppykit_server, if applicable)

These are intended names, not reserved registry packages. Python and Rust implementations are not yet present.

