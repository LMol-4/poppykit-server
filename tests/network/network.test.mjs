import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import dns from 'node:dns';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import { createNodeTransport, isPublicAddress } from '../../dist/network/transport.js';
import { createMetadataResolver, parsePoppyDocument, parseAuthorizationMetadata, validateClientId, authorizationMetadataUrl } from '../../dist/network/discovery.js';
import * as wire from '../../dist/protocol/wire.js';

const state = { conversation_id: 'c1', status: 'idle', responder: 'agent' };
const event = { id: 'e1', type: 'future', created_at: '2026-10-19T00:00:00Z', opaque: { preserved: true } };
test('wire validates every known event while preserving unknown events and message fields', () => {
  assert.equal(wire.parseEvent(event), event);
  const variants = [{ type: 'message', message: { id: 'm', sender: 'human', role: 'user', text: '' } }, { type: 'state', status: 'working', responder: 'human' }, { type: 'authorization', error: 'sign_in_required' }, { type: 'authorization', error: 'insufficient_scope', scope: 'poppy:read' }, { type: 'user_requested', reason: '' }, { type: 'direct_opened', conversation_id: 'child' }, { type: 'direct_closed', conversation_id: 'child' }];
  for (const variant of variants) wire.parseEvent({ ...event, ...variant });
  assert.throws(() => wire.parseEvent({ ...event, type: 'message' }));
  assert.throws(() => wire.parseEvent({ ...event, type: 'authorization', error: 'insufficient_scope' }));
  const source = { id: 'm', sender: 'human', role: 'company', context: { locale: 'en-US', time_zone: 'Europe/Dublin', user_available: false }, unknown: 1 };
  assert.equal(wire.parseMessage(source).role, undefined); assert.equal(source.role, 'company'); assert.equal(wire.parseMessage(source).unknown, 1);
  for (const invalid of [{ id: 'm', sender: 'agent' }, { id: 'bad/id', sender: 'human', text: 'x' }, { id: 'm', sender: 'human', context: { time_zone: '+01:00' } }]) assert.throws(() => wire.parseMessage(invalid));
  assert.throws(() => wire.parseMessage({ id: 'm', sender: 'agent', context: {} }, { company: true }));
  assert.throws(() => wire.parseEvent({ ...event, created_at: '2026-02-31T00:00:00Z' }));
  let nested = {}; for (let i = 0; i < 70; i++) nested = { nested };
  assert.throws(() => wire.parseMessage({ id: 'm', sender: 'human', data: nested }));
});
test('six-field pages and narrow null cursor preserve replay position', () => {
  const page = { ...state, events: [event], cursor: 'e1', has_more: false }; assert.deepEqual(wire.parseEventPage(page), page);
  for (const key of Object.keys(page)) { const bad = { ...page }; delete bad[key]; assert.throws(() => wire.parseEventPage(bad), key); }
  wire.parseEventPage({ ...state, events: [], cursor: null, has_more: false });
  assert.throws(() => wire.parseEventPage({ ...page, cursor: null }));
  assert.throws(() => wire.parseEventPage({ ...page, events: [], cursor: null }, 'before'));
  assert.throws(() => wire.parseEventPage({ ...page, cursor: 'wrong' }));
  assert.deepEqual(wire.parseReadOptions(new URL('https://example.test/?wait=9999999999999999999999&cursor=opaque'), 30), { cursor: 'opaque', waitSeconds: 30 });
  for (const query of ['wait=-1', 'wait=1.1', 'wait=2&wait=3']) assert.throws(() => wire.parseReadOptions(new URL(`https://example.test/?${query}`), 30));
});
test('token/error/retry codecs enforce semantic minimums without logging secret payload', () => {
  const token = { access_token: 'secret', token_type: 'DPoP', expires_in: 30, scope: '', session_id: 'session', signed_in: false };
  assert.deepEqual(wire.parseTokenResponse(token), token);
  assert.throws(() => wire.parseTokenResponse({ ...token, expires_in: 0 }), error => !error.message.includes('secret'));
  assert.throws(() => wire.parseProtocolError({ error: 'extension_required' }));
  wire.parseProtocolError({ error: 'extension_required', extension: 'future' });
  assert.equal(wire.retryAfterMilliseconds('12', 0), 12000); assert.equal(wire.retryAfterMilliseconds('Mon, 19 Oct 2026 00:00:00 GMT', Date.parse('2026-10-18T23:59:59Z')), 1000); assert.equal(wire.retryAfterMilliseconds('-1', 0), undefined);
});
const document = { protocol_version: '0.2', organization: { name: 'Shop', domain: 'shop.example' }, auth: { issuer: 'https://auth.example/tenant', direct: { scopes: ['poppy:read'] } }, agent: { protocols: [{ type: 'future', endpoint: 'https://shop.example/conversations' }] } };
const authorization = { issuer: 'https://auth.example/tenant', token_endpoint: 'https://auth.example/token', revocation_endpoint: 'https://auth.example/revoke', authorization_endpoint: 'https://auth.example/authorize', poppy_domains: ['shop.example'], client_id_metadata_document_supported: true };
test('discovery enforces version, reciprocal issuer, algorithms, capability and client URL rules', () => {
  parsePoppyDocument(document, 'https://shop.example/.well-known/poppy.json');
  parsePoppyDocument({ protocol_version: '0.2', organization: document.organization, web: {} }, 'https://shop.example/x');
  parseAuthorizationMetadata(authorization, document);
  assert.equal(authorizationMetadataUrl('https://auth.example/tenant'), 'https://auth.example/.well-known/oauth-authorization-server/tenant');
  for (const bad of [{ ...document, protocol_version: '0.3' }, { ...document, organization: { name: 'Shop', domain: 'other.example' } }, { protocol_version: '0.2', organization: document.organization, feedback: { endpoint: 'https://shop.example/feedback' } }]) assert.throws(() => parsePoppyDocument(bad, 'https://shop.example/x'));
  for (const bad of [{ ...authorization, issuer: 'https://auth.example/other' }, { ...authorization, poppy_domains: ['other.example'] }, { ...authorization, dpop_signing_alg_values_supported: ['RS256'] }]) assert.throws(() => parseAuthorizationMetadata(bad, document));
  for (const bad of ['https://client.example', 'https://client.example/a/../client', 'https://client.example/%2e/client', 'https://user@client.example/client', 'http://client.example/client']) assert.throws(() => validateClientId(bad));
  validateClientId('https://client.example/');
});
test('metadata client no redirects, invalid uncached, JWKS refresh bounded, domains not conflated', async () => {
  const calls = []; let clientStatus = 302;
  const client = { client_id: 'https://agent.example/client', client_name: 'Agent', jwks_uri: 'https://agent.example/keys', redirect_uris: ['https://agent.example/callback'], token_endpoint_auth_method: 'private_key_jwt' };
  const resolver = createMetadataResolver({ async fetch(request, options) {
    calls.push([request.url, options.mode]);
    if (request.url.endsWith('/client')) return Response.json(client, { status: clientStatus, headers: { 'cache-control': 'max-age=300' } });
    if (request.url.endsWith('/keys')) return Response.json({ keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }] });
    if (request.url.includes('oauth-authorization-server')) return Response.json(authorization);
    return Response.json(document);
  } });
  await assert.rejects(resolver.resolveClient(client.client_id)); clientStatus = 200; assert.equal((await resolver.resolveClient(client.client_id)).client_id, client.client_id);
  assert.deepEqual(calls.slice(0, 2).map(item => item[1]), ['endpoint', 'endpoint']);
  await resolver.resolveClient(client.client_id); assert.equal(calls.length, 2);
  await resolver.resolveJwks(client.jwks_uri, { refresh: true }); await assert.rejects(resolver.resolveJwks(client.jwks_uri, { refresh: true }));
  assert.equal((await resolver.resolveCompany('shop.example')).authorization.issuer, authorization.issuer);
});
test('issuer auth consistency is checked across cached domains and errors never enter cache', async () => {
  let bad = true; let requests = 0;
  const resolver = createMetadataResolver({ async fetch(request) {
    requests++;
    if (request.url.includes('oauth-authorization-server')) return Response.json({ ...authorization, poppy_domains: ['shop.example', 'other.example'] }, { headers: { 'cache-control': 'max-age=300' } });
    const other = request.url.includes('other.example');
    return Response.json({ ...document, protocol_version: bad ? 'wrong' : '0.2', organization: { name: 'Shop', domain: other ? 'other.example' : 'shop.example' }, auth: other ? { ...document.auth, unknown: 'changed' } : document.auth }, { headers: { 'cache-control': 'max-age=300' } });
  } });
  await assert.rejects(resolver.resolveCompany('shop.example')); bad = false; await resolver.resolveCompany('shop.example'); assert.equal(requests, 3);
  await assert.rejects(resolver.resolveCompany('other.example'), /auth.consistency/);
});
test('address policy rejects private, mapped, transition and alternate numeric URLs', async () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '172.31.0.1', '192.168.1.1', '169.254.1.1', '100.64.0.1', '::1', '::ffff:127.0.0.1', 'fc00::1', 'fe80::1', '2001:db8::1', '2002:7f00:1::']) assert.equal(isPublicAddress(address), false, address);
  assert.equal(isPublicAddress('8.8.8.8'), true); assert.equal(isPublicAddress('2606:4700:4700::1111'), true);
  await assert.rejects(createNodeTransport().fetch(new Request('https://2130706433/')), { code: 'blocked_address' });
});
test('real TLS enforces trust, bounded bodies/time, safe redirects and exact address exceptions', async t => {
  const key = await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url));
  const cert = await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url));
  let requests = 0; let port;
  const server = createServer({ key, cert }, (request, response) => {
    requests++;
    if (request.url === '/redirect') { response.writeHead(302, { location: `https://localhost:${port}/ok` }); response.end(); }
    else if (request.url === '/loop') { response.writeHead(302, { location: '/loop' }); response.end(); }
    else if (request.url === '/large') response.end('x'.repeat(2048));
    else if (request.url === '/slow') { response.writeHead(200); response.flushHeaders(); }
    else { response.writeHead(429, { 'Retry-After': '2', 'DPoP-Nonce': 'n', 'WWW-Authenticate': ['DPoP error="use_dpop_nonce"', 'Bearer realm="example"'] }); response.end('{"error":"rate_limited"}'); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve)); port = server.address().port;
  t.after(() => { server.closeAllConnections(); server.close(); });
  const target = path => new Request(`https://localhost:${port}${path}`);
  const options = { ca: cert.toString(), localExceptions: [{ hostname: 'localhost', addresses: ['127.0.0.1'] }] };
  await assert.rejects(createNodeTransport({ ...options, ca: undefined }).fetch(target('/ok')));
  assert.equal(requests, 0, 'untrusted TLS must not transmit HTTP');
  await assert.rejects(createNodeTransport({ ...options, localExceptions: [{ hostname: 'localhost', addresses: ['127.0.0.2'] }] }).fetch(target('/ok')));
  const transport = createNodeTransport(options);
  const response = await transport.fetch(target('/ok')); assert.equal(response.status, 429); assert.equal(response.headers.get('retry-after'), '2'); assert.equal(response.headers.get('dpop-nonce'), 'n'); assert.match(response.headers.get('www-authenticate'), /Bearer/); assert.equal((await response.json()).error, 'rate_limited');
  const before = requests;
  const redirected = await transport.fetch(new Request(`https://localhost:${port}/redirect`, { headers: { authorization: 'DPoP secret', DPoP: 'proof' } })); assert.equal(redirected.status, 302); assert.equal(requests, before + 1);
  const discovered = await transport.fetch(target('/redirect'), { mode: 'discovery' }); assert.equal(discovered.url, `https://localhost:${port}/ok`);
  await assert.rejects(createNodeTransport({ ...options, maxRedirects: 1 }).fetch(target('/loop'), { mode: 'discovery' }), { code: 'redirect_limit' });
  await assert.rejects(createNodeTransport({ ...options, maxResponseBytes: 100 }).fetch(target('/large')), { code: 'body_limit' });
  await assert.rejects(createNodeTransport({ ...options, timeoutMs: 100 }).fetch(target('/slow')), { code: 'timeout' });
  await assert.rejects(createNodeTransport({ ...options, maxRequestBytes: 2 }).fetch(new Request(`https://localhost:${port}/ok`, { method: 'POST', body: 'large' })), { code: 'body_limit' });
  await assert.rejects(transport.fetch(new Request(`https://localhost:${port}/ok`, { signal: AbortSignal.abort() })));
  const original = dns.lookup; let count = 0;
  dns.lookup = (_host, _options, callback) => { count++; callback(null, [{ address: count === 1 ? '127.0.0.1' : '127.0.0.2', family: 4 }]); };
  syncBuiltinESMExports();
  try { await transport.fetch(target('/ok')); await assert.rejects(transport.fetch(target('/ok'))); assert.equal(count, 2, 'DNS rechecked for next connection'); }
  finally { dns.lookup = original; syncBuiltinESMExports(); }
});
test('actual socket address mismatch aborts before handing socket to HTTP', async () => {
  const original = tls.connect; let destroyed = false;
  tls.connect = () => { const socket = new EventEmitter(); socket.remoteAddress = '127.0.0.1'; socket.destroy = () => { destroyed = true; }; queueMicrotask(() => socket.emit('secureConnect')); return socket; };
  syncBuiltinESMExports();
  try { await assert.rejects(createNodeTransport().fetch(new Request('https://8.8.8.8/')), { code: 'blocked_address' }); assert.equal(destroyed, true); }
  finally { tls.connect = original; syncBuiltinESMExports(); }
});
test('hostile URLs and discovery-mode requests are rejected before any connection', async () => {
  const transport = createNodeTransport();
  for (const url of ['http://example.com/', 'https://example.com/#frag', 'https://0x7f.1/', 'https://[::ffff:7f00:1]/', 'https://localhost/', 'https://127.1/'])
    await assert.rejects(transport.fetch(new Request(url)), { name: 'TransportError' }, url);
  await assert.rejects(transport.fetch(new Request('https://8.8.8.8/', { headers: { authorization: 'x' } }), { mode: 'discovery' }), { code: 'invalid_url' });
  await assert.rejects(transport.fetch(new Request('https://8.8.8.8/', { method: 'POST', body: 'x' }), { mode: 'discovery' }), { code: 'invalid_url' });
  assert.throws(() => createNodeTransport({ timeoutMs: 0 }), TypeError);
  for (const id of ['https://a.example', 'https://a.example/x/../y', 'https://a.example/%2E%2e/y', 'https://a.example/x\\..\\y', 'https://a.example/x#f', 'https://u@a.example/x', 'http://a.example/x']) assert.throws(() => validateClientId(id), /Error/, id);
});
test('assertion and DPoP claim codecs enforce spec shapes and keep unknown claims', () => {
  const claims = { iss: 'https://agent.example/agent.json', sub: 'usr_1', aud: 'https://auth.example.com', iat: 1790900000, exp: 1790900060, jti: 'V6vJGs2ixBAvGdaQgGaTzg', extra: 1 };
  assert.deepEqual(wire.parseAssertionClaims(claims), claims);
  for (const bad of [{ aud: ['https://auth.example.com'] }, { exp: 1790900301 }, { exp: 1790900000 }, { jti: 'short' }, { iat: 1.5 }, { sub: undefined }]) assert.throws(() => wire.parseAssertionClaims({ ...claims, ...bad }), { name: 'ValidationError' });
  const proof = { jti: 'e1j3V_bKic8-LAEB', htm: 'POST', htu: 'https://api.example.com/orders', iat: 1790900000, ath: 'abc', nonce: 'n' };
  assert.deepEqual(wire.parseDpopClaims(proof), proof);
  for (const bad of [{ htu: 'https://api.example.com/o?x=1' }, { htu: 'https://api.example.com/o#f' }, { htu: 'http://api.example.com/' }, { htm: 1 }, { iat: 0 }, { ath: 5 }]) assert.throws(() => wire.parseDpopClaims({ ...proof, ...bad }), { name: 'ValidationError' });
});
