import assert from 'node:assert/strict';
import { createRequestAuthenticator, createConversationService } from '@poppykit/server';
import { createMetadataResolver, createNodeTransport, createReferenceIssuer } from '@poppykit/server/reference-auth';
import { SqliteCompanyDatabase } from '@poppykit/server/sqlite';

const database = new SqliteCompanyDatabase(':memory:'); // Non-durable example; use a private file in production.
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
  const conversations = createConversationService({
    historyScopes: ['orders:read'],
    endpoint, store: database.conversations(issuer), policy: auth.authority.policy,
    authenticator: createRequestAuthenticator({ authority: auth.authority,
      endpoints: [{ origin: 'https://company.example', pathPrefix: '/conversations', resource: endpoint }],
      now: Date.now }), clock: { now: Date.now },
  });
  // Your HTTPS framework routes trusted public Requests to this handler.
  assert.equal((await conversations.handle(new Request(endpoint, {method:'POST', headers:{'content-type':'application/json'}, body:'{}'}))).status, 401);
  console.log('Reference issuer and conversation service configured; anonymous request rejected.');
} finally {
  transport.close?.();
  database.close();
}
