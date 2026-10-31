import assert from 'node:assert/strict';
import { createRequestAuthenticator, createConversationService, createSessionAuthority } from '@poppykit/server';
import { createMetadataResolver, createNodeTransport, createReferenceIssuer } from '@poppykit/server/reference-auth';
import { SqliteCompanyDatabase } from '@poppykit/server/sqlite';

const database = new SqliteCompanyDatabase(':memory:'); // Non-durable example; use a private file in production.
const transport = createNodeTransport();
try {
  const issuer = 'https://company.example/issuer';
  const endpoint = 'https://company.example/conversations';
  const metadata = createMetadataResolver(transport);
  const auth = createReferenceIssuer({
    issuer, tokenEndpoint: issuer + '/token', revocationEndpoint: issuer + '/revoke',
    protectedResources: ['https://company.example'], supportedScopes: [], resources: [endpoint],
    metadata, store: database.issuer(issuer),
    coordinator: database, now: Date.now,
  });
  const sessions = createSessionAuthority({companyId:issuer,metadata,store:database.sessions(issuer),
    coordinator:database,accountPolicy:auth.authority.policy,now:Date.now});
  const conversations = createConversationService({
    historyScopes: ['orders:read'],
    endpoint, store: database.conversations(issuer), policy: sessions.policy,
    authenticator: createRequestAuthenticator({ sessions, authority: auth.authority,
      endpoints: [{ origin: 'https://company.example', pathPrefix: '/conversations', resource: endpoint }],
      now: Date.now }), clock: { now: Date.now },
  });
  // Your HTTPS framework routes trusted public Requests to this handler.
  assert.equal((await conversations.handle(new Request(endpoint, {method:'POST', headers:{'content-type':'application/json'}, body:'{}'}))).status, 400);
  console.log('Reference issuer and conversation service configured; anonymous request rejected.');
} finally {
  transport.close?.();
  database.close();
}
