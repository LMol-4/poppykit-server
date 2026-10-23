# PoppyKit server

TypeScript SDK for companies exposing services through [Personal Agent Protocol
draft 0.2](https://personalagentprotocol.org/docs/0.2/spec). Verify requests, serve
JSON/SSE conversations, enforce current permissions, support browser-session joining
and accept feedback. Your company owns accounts, consent UI, agent and business tools.

## Installation

Requires Node **24.12.0 or later** and ESM. CI certifies Node 24.12.0; later majors
have no separate certification. Optional SQLite uses experimental `node:sqlite`
and requires local filesystem locking.

The package is **private and unpublished, version 0.0.0**. Install a verified tarball:

```sh
npm install ./poppykit-server-0.0.0.tgz
```

The only production dependency is `jose@6.2.12`. Neither client SDK nor CLI is required.
First-publication preparation is in [RELEASING.md](RELEASING.md).

## Quickstart

The complete [quickstart](examples/quickstart.mjs) creates an optional reference
issuer, verified request authenticator and conversation service, then checks that
an unauthenticated request is rejected. It starts no network listener:

```sh
node examples/quickstart.mjs
```

Its essential service configuration is:

```js
import { createRequestAuthenticator, createConversationService } from '@poppykit/server';
const conversations = createConversationService({
  endpoint, store: database.conversations(issuer), policy: auth.authority.policy,
  authenticator: createRequestAuthenticator({ authority: auth.authority,
    endpoints: [{ origin: 'https://company.example', pathPrefix: '/conversations', resource: endpoint }],
    now: Date.now }), clock: { now: Date.now },
});
```

`database`, `auth`, `issuer` and `endpoint` are created in the runnable example.
Use a private database file for persistence and your HTTPS framework to route
trusted public Requests to `conversations.handle(request)`. Configure company
account/consent hooks before advertising sign-in methods.

## Configuration and authentication

Existing issuers integrate through `ExternalAuthorityAdapter`: provide token
introspection, an explicit revocation-visibility guarantee and `AuthorityPolicy`
that orders checks with protected writes. `createRequestAuthenticator` verifies
the actual public method/URL and DPoP/resource binding. Resolve public URLs at
your trusted proxy boundary; do not trust arbitrary forwarded headers. Core
imports do not load or run the optional reference issuer.

The separate `/reference-auth` implements Direct, Device and Mediated flows.
Configure endpoints/trusted hooks, publish discovery/authorization metadata and
route token/revocation and method handlers. Your company authenticates humans,
protects consent with browser sessions/CSRF, delivers/verifies codes and chooses
scopes. Opening a consent link never approves it. See [AUTH.md](AUTH.md).

## Examples and common operations

Route protocol requests to `conversations.handle(request)`. Workers use `claim`,
`reply`, `finish` and lifecycle methods rather than writing rows directly. Use
`requireAccount(work, scopes)` or protected-operation hooks before accessing
account data. Model text cannot grant permission. Your application owns tool
execution, validation and effect idempotency; receipt/publication deduplication
does not make external writes exactly-once.

`createBrowserSessions` integrates your cookie store with current session authority.
`createFeedbackHandler` accepts validated reports, including signed-out sessions.
`mcpResourceMetadata` and `mcpAuthorizationError` integrate an existing MCP server
and issuer. See [INTEGRATIONS.md](INTEGRATIONS.md), [DELIVERY.md](DELIVERY.md) and
the independent generic request fixtures in `tests/independent-peer.test.mjs`.

## Errors, cancellation, retries and limits

`AuthorityError` contains a safe code, HTTP status and authentication headers.
Conversation handlers return protocol responses for known errors; your framework
must handle unexpected host failures without exposing private diagnostics. Bound
ingress bodies/rates before authentication. Propagate cancellation; a disconnected
client cannot undo accepted application work.

JSON pages and SSE events obey UTF-8 budgets. Notifications are hints; durable
targeted reads reconcile lost notifications. [DELIVERY.md](DELIVERY.md) documents
cursor/history gaps, waiting and record-specific retention. Choose
`stop-account-work` or `allow-accepted-work-to-finish` deliberately; new requests
always need current access. Immediate reference-issuer revocation visibility is
an implementation policy, not a universal protocol requirement.

## Storage and production responsibilities

Use one `SqliteCompanyDatabase` for reference issuer, conversations and coordinator
so authorization, revocation and protected writes share a transaction. SQLite
serializes writers and requires local filesystem locking. Supply your own
`ConversationStore`, `IssuerStore` and `AuthorityCoordinator` for other databases;
adapters enforce cross-process atomicity. [STORAGE.md](STORAGE.md) specifies
contracts, retention and explicit reset.

Company credentials and signing infrastructure remain your responsibility. The
personal-agent identity provider is a distinct trust role in the client package.
No model, database service, deployment vendor or demo is required.

## Reference and support

[API.md](API.md) maps public entry points and declarations to deeper guides.
This independent draft implementation has generic integration and packaged tests;
deployed issuer, proxy, database and browser policies need operator validation.
Individual extensions and business workflows are excluded. See
[CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md),
[CHANGELOG.md](CHANGELOG.md) and [RELEASING.md](RELEASING.md). No public license
grant has been selected; licensing remains an owner decision before publication.
