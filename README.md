# PoppyKit server

Draft 0.3 migration (2026-10-28), pinned to the public source captured that day.
Client/CLI 0.5.0 and server 0.4.0 break the earlier protocol contracts. Stop old
writers and follow the documented storage/reset procedure before compatible
writers resume. Registry, deployment and live acceptance have separate receipts.

The Node 24.21.0 minimum is an owner-accepted compatibility baseline. Use a current patched Node 24 runtime where available; this minimum does not establish that older runtimes contain later security fixes. Build and release CI read `.node-version`.

TypeScript SDK for companies implementing [Personal Agent Protocol draft 0.3](https://personalagentprotocol.org/docs/0.3/spec).
Verify requests, serve conversations and enforce current authority. Your company
supplies accounts, consent UI, agent, business tools and HTTPS routing. [MIT](LICENSE).

## Install

Use the exact version verified by its protected release workflow; check registry publication before installation.

Requires Node **24.x, at least 24.21.0**, and ESM. CI tests Node 24.21.0 on Linux, macOS and Windows;
other Node majors are unsupported. SQLite is optional/experimental and
requires local filesystem locking.

```sh
npm install @poppykit/server
```

## Configure a service

This runnable example starts no listener and rejects an unauthenticated request.
`:memory:` is non-durable; use a private file and configured company sign-in hooks
in production. The reference issuer is optional; [existing issuers](AUTH.md) use
an ExternalAuthorityAdapter instead.

```js
import { createRequestAuthenticator, createConversationService } from '@poppykit/server';
import { createMetadataResolver, createNodeTransport, createReferenceIssuer } from '@poppykit/server/reference-auth';
import { SqliteCompanyDatabase } from '@poppykit/server/sqlite';

const database = new SqliteCompanyDatabase(':memory:');
const transport = createNodeTransport();
try {
  const issuer = 'https://company.example/issuer';
  const endpoint = 'https://company.example/conversations';
  const auth = createReferenceIssuer({
    issuer, tokenEndpoint: issuer + '/token', revocationEndpoint: issuer + '/revoke',
    protectedResources: ['https://company.example'], supportedScopes: [], resources: [endpoint],
    metadata: createMetadataResolver(transport), store: database.issuer(issuer),
    coordinator: database, now: Date.now,
  });
  const service = createConversationService({
    historyScopes: ['orders:read'],
    endpoint, store: database.conversations(issuer), policy: auth.authority.policy,
    authenticator: createRequestAuthenticator({ authority: auth.authority,
      endpoints: [{ origin: 'https://company.example', pathPrefix: '/conversations', resource: endpoint }],
      now: Date.now }), clock: { now: Date.now },
  });
  console.log((await service.handle(new Request(endpoint, { method: 'POST',
    headers: { 'content-type': 'application/json' }, body: '{}' }))).status); // 401
} finally {
  transport.close?.();
  database.close();
}
```

## Guides

- [Authentication](AUTH.md): external/reference issuers, consent and revocation.
- [Storage](STORAGE.md): shared authority coordinator, cross-process transactions and reset.
- [Delivery](DELIVERY.md): workers, streaming, cursors, retention and effect idempotency.
- [Integrations](INTEGRATIONS.md): MCP, browser cookies and feedback.
- [API exports](API.md), [contributing](CONTRIBUTING.md), [security](SECURITY.md),
  [changelog](CHANGELOG.md) and [releasing](RELEASING.md).

Your ingress must bound bodies/rates before authentication, supply the trusted
public URL and propagate cancellation. Never trust arbitrary forwarding headers.
Use current policy before protected work; model text cannot grant permission.
Receipt/publication deduplication does not make external effects exactly-once.
Validate deployed database, issuer and browser policies; no model/service vendor
or demo application is required.
