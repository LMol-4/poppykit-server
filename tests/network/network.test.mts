import { expectValue } from '../../test-support/assertions.mjs';
import test,{mock} from 'node:test';
import type {Server} from 'node:net';
type MetadataOptions=NonNullable<Parameters<typeof createMetadataResolver>[1]>;
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import dns from 'node:dns';
import tls from 'node:tls';
import { syncBuiltinESMExports } from 'node:module';
import { EventEmitter } from 'node:events';
import { createNodeTransport, isPublicAddress } from '../../dist/network/transport.js';
import { createMetadataResolver, parsePoppyDocument, parseAuthorizationMetadata, validateClientId, authorizationMetadataUrl, signInMethods } from '../../dist/network/discovery.js';
import * as wire from '../../dist/protocol/wire.js';
import { parseClientMetadata } from '../../dist/network/discovery.js';
import { registeredRedirect } from '../../dist/network/redirect.js';

test('loopback redirect exception allows literal IP ports and preserves every other component', async () => {
  const client = 'https://agent.example/client', registered = ['http://127.0.0.1:8000/cb?route=fixed', 'http://[::1]:8000/cb'];
  const metadata = { client_id: client, client_name: 'Agent', jwks_uri: 'https://agent.example/keys', redirect_uris: registered, token_endpoint_auth_method: 'private_key_jwt' };
  assert.deepEqual(parseClientMetadata(metadata, client).redirect_uris, registered);
  for (const value of ['http://127.0.0.1:49152/cb?route=fixed', 'http://[::1]:49152/cb']) assert.equal(registeredRedirect(value, registered, client), true);
  for (const value of ['http://localhost:8000/cb', 'http://127.1:8000/cb', 'http://2130706433:8000/cb', 'http://127.0.0.1.evil.example/cb', 'http://127.0.0.2/cb', 'http://[::ffff:127.0.0.1]/cb', 'http://127.0.0.1:8000/cb?route=other', 'http://127.0.0.1:8000/other?route=fixed', 'http://user@127.0.0.1:8000/cb', 'http://127.0.0.1:8000/cb#fragment']) {
    assert.equal(registeredRedirect(value, registered, client), false, value);
  }
  for (const value of ['http://localhost:8000/cb', 'http://127.1:8000/cb', 'http://10.0.0.1/cb']) assert.throws(() => parseClientMetadata({ ...metadata, redirect_uris: [value] }, client));
  assert.throws(() => parseClientMetadata({ ...metadata, jwks_uri: registered[0] }, client));
  await assert.rejects(createNodeTransport().fetch(new Request('http://127.0.0.1:49152/cb')), { code: 'invalid_url' });
});


function serverPort(server:Server):number {const address=server.address();assert.ok(address&&typeof address!=='string');return address.port;}

const state = { conversation_id: 'c1', status: 'idle', responder: 'agent' };
const event = { id: 'e1', type: 'future', created_at: '2026-10-19T00:00:00Z', opaque: { preserved: true } };
test('wire validates every known event while preserving unknown events and message fields', () => {
  assert.equal(wire.parseEvent(event), event);
  const variants = [{ type: 'message', message: { id: 'm', sender: 'human', role: 'user', text: '' } }, { type: 'state', status: 'working', responder: 'human' }, { type: 'authorization', error: 'sign_in_required' }, { type: 'authorization', error: 'insufficient_scope', scope: 'orders:read' }, { type: 'user_requested', reason: '' }, { type: 'direct_opened', conversation_id: 'child' }, { type: 'direct_closed', conversation_id: 'child' }];
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
  for (const key of Object.keys(page)) { const bad:Record<string,unknown> = { ...page }; delete bad[key]; assert.throws(() => wire.parseEventPage(bad), key); }
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
  assert.throws(() => wire.parseTokenResponse({ ...token, expires_in: 0 }), error => error instanceof Error && !error.message.includes('secret'));
  assert.throws(() => wire.parseProtocolError({ error: 'extension_required' }));
  wire.parseProtocolError({ error: 'extension_required', extension: 'future' });
  assert.equal(wire.retryAfterMilliseconds('12', 0), 12000); assert.equal(wire.retryAfterMilliseconds('Mon, 19 Oct 2026 00:00:00 GMT', Date.parse('2026-10-18T23:59:59Z')), 1000); assert.equal(wire.retryAfterMilliseconds('-1', 0), undefined);
});
const document = { protocol_version: '0.3', organization: { name: 'Shop', domain: 'shop.example' }, auth: { issuer: 'https://auth.example/tenant', scopes: { 'orders:read': 'Read orders' } }, agent: { protocols: [{ type: 'future', endpoint: 'https://shop.example/conversations' }] } };
const authorization = { issuer: 'https://auth.example/tenant', token_endpoint: 'https://auth.example/token', revocation_endpoint: 'https://auth.example/revoke', authorization_endpoint: 'https://auth.example/authorize', protected_resources: ['https://shop.example'], grant_types_supported: ['urn:ietf:params:oauth:grant-type:jwt-bearer', 'refresh_token', 'authorization_code'], scopes_supported: ['orders:read'], client_id_metadata_document_supported: true };
test('discovery enforces version, reciprocal issuer, algorithms, capability and client URL rules', () => {
  parsePoppyDocument(document, 'https://shop.example/.well-known/poppy.json');
  parsePoppyDocument({ protocol_version: '0.3', organization: document.organization, web: {} }, 'https://shop.example/.well-known/poppy.json');
  parseAuthorizationMetadata(authorization, parsePoppyDocument(document,'https://shop.example/.well-known/poppy.json'));
  assert.equal(authorizationMetadataUrl('https://auth.example/tenant'), 'https://auth.example/.well-known/oauth-authorization-server/tenant');
  for (const bad of [{ ...document, protocol_version: '0.2' }, { ...document, organization: { name: 'Shop', domain: 'other.example' } }, { protocol_version: '0.3', organization: document.organization, feedback: { endpoint: 'https://shop.example/feedback' } }]) assert.throws(() => parsePoppyDocument(bad, 'https://shop.example/.well-known/poppy.json'));
  for (const bad of [{ ...authorization, issuer: 'https://auth.example/other' }, { ...authorization, protected_resources: ['https://other.example'] }, { ...authorization, dpop_signing_alg_values_supported: ['RS256'] }]) assert.throws(() => parseAuthorizationMetadata(bad, parsePoppyDocument(document,'https://shop.example/.well-known/poppy.json')));
  for (const bad of ['https://client.example', 'https://client.example/a/../client', 'https://client.example/%2e/client', 'https://user@client.example/client', 'http://client.example/client']) assert.throws(() => validateClientId(bad));
  validateClientId('https://client.example/');
});
test('metadata client no redirects, invalid uncached, JWKS refresh bounded, domains not conflated', async () => {
  const calls: (string|undefined)[][] = []; let clientStatus = 302;
  const client = { client_id: 'https://agent.example/client', client_name: 'Agent', jwks_uri: 'https://agent.example/keys', redirect_uris: ['https://agent.example/callback'], token_endpoint_auth_method: 'private_key_jwt' };
  const resolver = createMetadataResolver({ async fetch(request, options) {
    calls.push([request.url, expectValue(options).mode]);
    if (request.url.endsWith('/client')) return Response.json(client, { status: clientStatus, headers: { 'cache-control': 'max-age=300' } });
    if (request.url.endsWith('/keys')) return Response.json({ keys: [{ kty: 'EC', crv: 'P-256', x: 'x', y: 'y' }] });
    if (request.url.includes('oauth-authorization-server')) return Response.json(authorization);
    return Response.json(document);
  } });
  await assert.rejects(resolver.resolveClient(client.client_id)); clientStatus = 200; assert.equal((await resolver.resolveClient(client.client_id)).client_id, client.client_id);
  assert.deepEqual(calls.slice(0, 2).map(item => item[1]), ['endpoint', 'endpoint']);
  await resolver.resolveClient(client.client_id); assert.equal(calls.length, 2);
  await resolver.resolveJwks(client.jwks_uri, { refresh: true }); await assert.rejects(resolver.resolveJwks(client.jwks_uri, { refresh: true }));
  assert.equal(expectValue((await resolver.resolveCompany('shop.example')).authorization).issuer, authorization.issuer);
});
test('issuer auth consistency is checked across cached domains and errors never enter cache', async () => {
  let bad = true; let requests = 0;
  const resolver = createMetadataResolver({ async fetch(request) {
    requests++;
    if (request.url.includes('oauth-authorization-server')) return Response.json({ ...authorization, protected_resources: ['https://shop.example', 'https://other.example'] }, { headers: { 'cache-control': 'max-age=300' } });
    const other = request.url.includes('other.example');
    return Response.json({ ...document, protocol_version: bad ? 'wrong' : '0.3', organization: { name: 'Shop', domain: other ? 'other.example' : 'shop.example' }, auth: other ? { ...document.auth, unknown: 'changed' } : document.auth }, { headers: { 'cache-control': 'max-age=300' } });
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
  let requests = 0; let port=0;
  const server = createServer({ key, cert }, (request, response) => {
    requests++;
    if (request.url === '/redirect') { response.writeHead(302, { location: `https://localhost:${port}/ok` }); response.end(); }
    else if (request.url === '/to-http') { response.writeHead(302, { location: `http://localhost:${port}/ok` }); response.end(); }
    else if (request.url === '/to-ip') { response.writeHead(302, { location: `https://127.0.0.1:${port}/ok` }); response.end(); }
    else if (request.url === '/loop') { response.writeHead(302, { location: '/loop' }); response.end(); }
    else if (request.url === '/large') response.end('x'.repeat(2048));
    else if (request.url === '/slow') { response.writeHead(200); response.flushHeaders(); }
    else if (request.url === '/held') setTimeout(() => response.end('held'), 300); // a long poll answered late
    else { response.writeHead(429, { 'Retry-After': '2', 'DPoP-Nonce': 'n', 'WWW-Authenticate': ['DPoP error="use_dpop_nonce"', 'Bearer realm="example"'] }); response.end('{"error":"rate_limited"}'); }
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve)); port = serverPort(server);
  t.after(() => { server.closeAllConnections(); server.close(); });
  const target = (path: string ) => new Request(`https://localhost:${port}${path}`);
  const options = { ca: cert.toString(), localExceptions: [{ hostname: 'localhost', addresses: ['127.0.0.1'] }] };
  await assert.rejects(createNodeTransport({ ...options, ca: undefined }).fetch(target('/ok')));
  assert.equal(requests, 0, 'untrusted TLS must not transmit HTTP');
  await assert.rejects(createNodeTransport({ ...options, localExceptions: [{ hostname: 'localhost', addresses: ['127.0.0.2'] }] }).fetch(target('/ok')));
  const transport = createNodeTransport(options);
  const response = await transport.fetch(target('/ok')); assert.equal(response.status, 429); assert.equal(response.headers.get('retry-after'), '2'); assert.equal(response.headers.get('dpop-nonce'), 'n'); assert.match(expectValue(response.headers.get('www-authenticate')), /Bearer/); assert.equal((await response.json()).error, 'rate_limited');
  const before = requests;
  const redirected = await transport.fetch(new Request(`https://localhost:${port}/redirect`, { headers: { authorization: 'DPoP secret', DPoP: 'proof' } })); assert.equal(redirected.status, 302); assert.equal(requests, before + 1);
  const discovered = await transport.fetch(target('/redirect'), { mode: 'discovery' }); assert.equal(discovered.url, `https://localhost:${port}/ok`);
  for (const [path, code] of [['/to-http', 'invalid_url'], ['/to-ip', 'blocked_address']]) {
    const seen:number = requests;
    await assert.rejects(transport.fetch(target(path), { mode: 'discovery' }), { code }, path);
    assert.equal(requests, seen + 1, `${path}: redirect target never reached the server`);
  }
  await assert.rejects(createNodeTransport({ ...options, maxRedirects: 1 }).fetch(target('/loop'), { mode: 'discovery' }), { code: 'redirect_limit' });
  await assert.rejects(createNodeTransport({ ...options, maxResponseBytes: 100 }).fetch(target('/large')), { code: 'body_limit' });
  await assert.rejects(createNodeTransport({ ...options, timeoutMs: 100 }).fetch(target('/slow')), { code: 'timeout' });
  // A held long poll gets its wait on top of the timeout; without it the same request times out.
  const short = createNodeTransport({ ...options, timeoutMs: 100 });
  assert.equal(await (await short.fetch(target('/held'), { waitMs: 1000 })).text(), 'held');
  await assert.rejects(short.fetch(target('/held')), { code: 'timeout' });
  for (const waitMs of [-1, 1.5, 2 ** 31]) await assert.rejects(short.fetch(target('/held'), { waitMs }), TypeError, String(waitMs));
  await assert.rejects(createNodeTransport({ ...options, maxRequestBytes: 2 }).fetch(new Request(`https://localhost:${port}/ok`, { method: 'POST', body: 'large' })), { code: 'body_limit' });
  await assert.rejects(transport.fetch(new Request(`https://localhost:${port}/ok`, { signal: AbortSignal.abort() })));
  const original = dns.lookup; let count = 0;
  mock.method(dns,'lookup',(_host:string,_options:dns.LookupOptions,callback:(error:NodeJS.ErrnoException|null,addresses:dns.LookupAddress[])=>void) => { count++; callback(null, [{ address: count === 1 ? '127.0.0.1' : '127.0.0.2', family: 4 }]); });
  syncBuiltinESMExports();
  try { await transport.fetch(target('/ok')); await assert.rejects(transport.fetch(target('/ok'))); assert.equal(count, 2, 'DNS rechecked for next connection'); }
  finally { dns.lookup = original; syncBuiltinESMExports(); }
});
test('actual socket address mismatch aborts before handing socket to HTTP', async () => {
  const original = tls.connect; let destroyed = false;
  mock.method(tls,'connect',() => { const socket=Object.assign(new EventEmitter(),{remoteAddress:'127.0.0.1',destroy(){destroyed=true;}}); queueMicrotask(() => socket.emit('secureConnect')); return socket; });
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
  for (const bad of [{ aud: ['https://auth.example.com'] }, { exp: 1790900301 }, { exp: 1790900000 }, { jti: 'x'.repeat(15) }, { jti: 'x'.repeat(257) }, { iat: 1.5 }, { sub: undefined }]) assert.throws(() => wire.parseAssertionClaims({ ...claims, ...bad }), { name: 'ValidationError' });
  const proof = { jti: 'e1j3V_bKic8-LAEB', htm: 'POST', htu: 'https://api.example.com/orders', iat: 1790900000, ath: 'abc', nonce: 'n' };
  assert.deepEqual(wire.parseDpopClaims(proof), proof);
  for (const bad of [{ htu: 'https://api.example.com/o?x=1' }, { htu: 'https://api.example.com/o#f' }, { htu: 'http://api.example.com/' }, { htm: 1 }, { iat: 0 }, { ath: 5 }]) assert.throws(() => wire.parseDpopClaims({ ...proof, ...bad }), { name: 'ValidationError' });
});
test('every blocked range has a denied sample and a public neighbour', () => {
  const table: [string,boolean][] = [
    ['0.1.2.3', false], ['1.0.0.1', true], ['10.255.255.255', false], ['11.0.0.1', true],
    ['100.64.0.1', false], ['100.128.0.1', true], ['127.0.0.2', false], ['128.0.0.1', true],
    ['169.254.169.254', false], ['169.255.0.1', true], ['172.16.0.1', false], ['172.32.0.1', true],
    ['192.0.0.9', false], ['192.0.1.1', true], ['192.0.2.7', false], ['192.88.99.1', false],
    ['192.168.0.1', false], ['192.169.0.1', true], ['198.18.0.1', false], ['198.20.0.1', true],
    ['198.51.100.9', false], ['198.51.101.1', true], ['203.0.113.9', false], ['203.0.114.1', true],
    ['224.0.0.1', false], ['255.255.255.255', false], ['223.255.255.255', true],
    ['2606:4700::1', true], ['2000::1', true], ['1fff::1', false], ['4000::1', false],
    ['2001::1', false], ['2001:1ff::1', false], ['2001:200::1', true], ['2001:db8::1', false],
    ['2002::1', false], ['3fff::1', false], ['3fff:1000::1', true], ['::', false], ['::1', false],
    ['::ffff:8.8.8.8', false], ['fe80::1', false], ['fc00::1', false], ['ff02::1', false],
  ];
  for (const [address, expected] of table) assert.equal(isPublicAddress(address), expected, address);
});
test('assertion jti accepts standard base64 and the length edges only', () => {
  const claims = { iss: 'i', sub: 's', aud: 'a', iat: 1790900000, exp: 1790900060 };
  for (const jti of ['VGhpcyBpcyAxNiBieXRlcw==', 'x'.repeat(16), 'x'.repeat(256)]) assert.equal(wire.parseAssertionClaims({ ...claims, jti }).jti, jti);
});
test('discovery mode rejects a caller-set Host header that would follow redirects', async () => {
  await assert.rejects(createNodeTransport().fetch(new Request('https://8.8.8.8/', { headers: { host: '8.8.8.8' } }), { mode: 'discovery' }), { code: 'invalid_url' });
});
test('zoned IPv6 addresses fail closed instead of throwing', () => {
  assert.equal(isPublicAddress('fe80::1%eth0'), false);
  assert.equal(isPublicAddress('2606:4700:4700::1111%eth0'), false);
});
test('mixed DNS answers never dial a private address; all-private fails closed', async t => {
  const key = await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url));
  const cert = await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url));
  const server = createServer({ key, cert }, (_request, response) => response.end('ok'));
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve)); const port = serverPort(server);
  const original = dns.lookup; let answers: string[] = [];
  t.after(() => { dns.lookup = original; syncBuiltinESMExports(); server.closeAllConnections(); server.close(); });
  mock.method(dns,'lookup',(_host:string,_options:dns.LookupOptions,callback:(error:NodeJS.ErrnoException|null,addresses:dns.LookupAddress[])=>void) => callback(null, answers.map(address => ({ address, family: 4 }))));
  syncBuiltinESMExports();
  const transport = createNodeTransport({ ca: cert.toString(), timeoutMs: 2000, localExceptions: [{ hostname: 'localhost', addresses: ['127.0.0.1'] }] });
  const dialed:(string|undefined)[] = []; const connect = tls.connect;
  mock.method(tls,'connect',(options:tls.ConnectionOptions,...rest:[(()=>void)?]) => { dialed.push(options.host); return connect(options, ...rest); });
  syncBuiltinESMExports();
  try {
    answers = ['10.0.0.1', '127.0.0.1'];
    assert.equal((await transport.fetch(new Request(`https://localhost:${port}/`))).status, 200);
    answers = ['10.0.0.1', '192.168.0.1'];
    await assert.rejects(transport.fetch(new Request(`https://localhost:${port}/`)), { code: 'blocked_address' });
  } finally { tls.connect = connect; syncBuiltinESMExports(); }
  assert.deepEqual(dialed, ['127.0.0.1'], 'all-private answers are rejected before TLS');
});
const bounded = (clock:{t:number},calls:string[],extra:MetadataOptions = {}) => createMetadataResolver({ async fetch(request) {
  calls.push(request.url);
  const id = request.url; return Response.json({ client_id: id, client_name: 'A', jwks_uri: `${new URL(id).origin}/k`, redirect_uris: [], token_endpoint_auth_method: 'private_key_jwt' }, { headers: { 'cache-control': `max-age=${id.includes('short') ? 50 : 100}` } });
} }, { now: () => clock.t, ...extra });
test('metadata cache stays at its cap and evicts expired then oldest entries', async () => {
  const clock = { t: 0 }; const calls:string[] = [];
  const resolver = bounded(clock, calls, { maxEntries: 3 });
  for (const n of [1, 2, 3, 4]) await resolver.resolveClient(`https://c${n}.example/id`);
  assert.equal(calls.length, 4);
  await resolver.resolveClient('https://c4.example/id'); await resolver.resolveClient('https://c2.example/id'); assert.equal(calls.length, 4);
  await resolver.resolveClient('https://c1.example/id'); assert.equal(calls.length, 5); // oldest was evicted
  clock.t = 101000; await resolver.resolveClient('https://c5.example/id'); // all earlier entries expired
  await resolver.resolveClient('https://c5.example/id'); assert.equal(calls.length, 6);
});
test('cold fetches are rate and concurrency limited, deterministically', async () => {
  const clock = { t: 0 }; const calls:string[] = [];
  const resolver = bounded(clock, calls, { maxFetchesPerMinute: 2 });
  await resolver.resolveClient('https://a.example/id'); await resolver.resolveClient('https://b.example/id');
  await assert.rejects(resolver.resolveClient('https://c.example/id'), /metadata.rate_limited/);
  await resolver.resolveClient('https://a.example/id'); assert.equal(calls.length, 2); // cache hits are not limited
  clock.t = 60000; await resolver.resolveClient('https://c.example/id'); assert.equal(calls.length, 3);
  let release!:()=>void; const gate = new Promise<void>(resolve => { release = resolve; });
  const slow = createMetadataResolver({ async fetch(request) { await gate; return Response.json({}, { status: 500 }); } }, { maxConcurrentFetches: 1 });
  const first = slow.resolveClient('https://a.example/id'); const second = slow.resolveClient('https://b.example/id');
  await assert.rejects(second, /metadata.rate_limited/); release(); await assert.rejects(first, /metadata.status/);
});
test('refresh and auth-document maps are bounded', async () => {
  const clock = { t: 0 }; const resolver = createMetadataResolver({ async fetch(request) { return Response.json({ keys: [] }); } }, { now: () => clock.t, maxEntries: 2, maxFetchesPerMinute: 1000 });
  for (let n = 0; n < 10; n++) await resolver.resolveJwks(`https://j${n}.example/k`, { refresh: true });
  await resolver.resolveJwks('https://j9.example/k').catch(() => {});
  await assert.rejects(resolver.resolveJwks('https://j9.example/k', { refresh: true }), /refresh_limited/); // newest still limited
  await resolver.resolveJwks('https://j0.example/k', { refresh: true }); // oldest was evicted
});
test('expired entries are evicted before older live ones', async () => {
  const clock = { t: 0 }; const calls:string[] = [];
  const resolver = bounded(clock, calls, { maxEntries: 2 });
  await resolver.resolveClient('https://live.example/id'); await resolver.resolveClient('https://short.example/id');
  clock.t = 60000; await resolver.resolveClient('https://new.example/id'); assert.equal(calls.length, 3);
  await resolver.resolveClient('https://live.example/id'); assert.equal(calls.length, 3); // oldest live entry kept
  await resolver.resolveClient('https://short.example/id'); assert.equal(calls.length, 4); // expired entry was the one dropped
});
test('cold-fetch slot is released after a failed fetch', async () => {
  let release!:()=>void; const gate = new Promise<void>(resolve => { release = resolve; });
  const slow = createMetadataResolver({ async fetch() { await gate; return Response.json({}, { status: 500 }); } }, { maxConcurrentFetches: 1 });
  const first = slow.resolveClient('https://a.example/id'); await assert.rejects(slow.resolveClient('https://b.example/id'), /rate_limited/);
  release(); await assert.rejects(first, /metadata.status/);
  await assert.rejects(slow.resolveClient('https://c.example/id'), /metadata.status/);
});
test('rate-limited refresh does not burn the refresh slot', async () => {
  let release!:()=>void; const gate = new Promise<void>(resolve => { release = resolve; });
  const resolver = createMetadataResolver({ async fetch() { await gate; return Response.json({ keys: [] }); } }, { now: () => 0, maxConcurrentFetches: 1 });
  const x = resolver.resolveJwks('https://x.example/k');
  await assert.rejects(resolver.resolveJwks('https://y.example/k', { refresh: true }), /metadata.rate_limited/);
  release(); await x;
  await resolver.resolveJwks('https://y.example/k', { refresh: true }); // same clock time: only a burned slot would block this
});
test('authDocuments inner and outer maps are bounded; live entries still conflict', async () => {
  const issuers:Record<string,string> = { 'a1.example': 'i1', 'a2.example': 'i2', 'a3.example': 'i3', 'a4.example': 'i1', 'b1.example': 'j', 'b2.example': 'j', 'b3.example': 'j', 'b4.example': 'j' };
  const scopesFor:Record<string,string[]> = {}; // domain -> direct scopes
  const make = (clock:{t:number},extra:MetadataOptions = {}) => createMetadataResolver({ async fetch(request) {
    const url = new URL(request.url); const headers = { 'cache-control': `max-age=${url.hostname === 'b1.example' ? 300 : 100}` };
    if (url.pathname.includes('oauth-authorization-server')) return Response.json({ ...authorization, issuer: `https://${url.hostname}`, protected_resources: Object.keys(issuers).map(domain => `https://${domain}`), scopes_supported: ['x','y'] }, { headers });
    const domain = url.hostname;
    return Response.json({ ...document, organization: { name: 'S', domain }, auth: { issuer: `https://${issuers[domain]}.example`, scopes: {x:"Permission x",y:"Permission y"}, fixture_policy: scopesFor[domain] } }, { headers });
  } }, { now: () => clock.t, maxFetchesPerMinute: 1000, ...extra });
  Object.assign(scopesFor, { 'a1.example': ['x'], 'a2.example': ['x'], 'a3.example': ['x'], 'a4.example': ['y'] });
  const full = make({ t: 0 }); for (const d of ['a1', 'a2', 'a3']) await full.resolveCompany(`${d}.example`);
  await assert.rejects(full.resolveCompany('a4.example'), /auth.consistency/); // live entry conflicts
  const clock = { t: 0 }; const outer = make(clock, { maxEntries: 2 });
  for (const d of ['a1', 'a2', 'a3']) await outer.resolveCompany(`${d}.example`);
  await outer.resolveCompany('a4.example'); // issuer i1 was evicted from the outer map
  Object.assign(scopesFor, { 'b1.example': ['x'], 'b2.example': ['x'], 'b3.example': ['x'], 'b4.example': ['y'] });
  const inner = make(clock, { maxEntries: 2 }); clock.t = 0;
  for (const d of ['b1', 'b2', 'b3']) await inner.resolveCompany(`${d}.example`); // b1 (300 s) evicted from inner map, b2/b3 live 100 s
  await assert.rejects(inner.resolveCompany('b4.example'), /auth.consistency/);
  clock.t = 150000; await inner.resolveCompany('b4.example'); // b2/b3 expired, evicted b1 no longer conflicts
});

test('parseJson rejects duplicate member names at any depth and accepts look-alikes', () => {
  assert.deepEqual(wire.parseJson('{"a":1,"b":{"a":2},"c":[{"a":1},{"a":2}],"d":"a\\":1,\\"a"}'), { a: 1, b: { a: 2 }, c: [{ a: 1 }, { a: 2 }], d: 'a":1,"a' });
  for (const text of ['{"a":1,"a":2}', '{"x":{"a":1,"a":2}}', '[{"a":1,"\\u0061":2}]', '{"a":{"b":1},"a":1}']) assert.throws(() => wire.parseJson(text), { field: 'json.duplicate_member' }, text);
  assert.throws(() => wire.parseJson('{"a":'), SyntaxError);
});
test('canonical sorts keys but keeps array order', () => {
  assert.equal(wire.canonical({ b: [2, 1], a: { d: 1, c: undefined } }), '{"a":{"d":1},"b":[2,1]}');
});
test('metadata cache floors at 60 s without cache headers and stays uncached for no-store/no-cache', async () => {
  for (const [control, cached] of ([[undefined, true], ['no-store', false], ['no-cache', false]] satisfies [string|undefined,boolean][])) {
    const clock = { t: 0 }; let calls = 0;
    const resolver = createMetadataResolver({ async fetch() { calls++; return Response.json({ keys: [] }, control ? { headers: { 'cache-control': control } } : {}); } }, { now: () => clock.t });
    await resolver.resolveJwks('https://a.example/keys'); clock.t = 59_000; await resolver.resolveJwks('https://a.example/keys');
    assert.equal(calls, cached ? 1 : 2, String(control));
    if (cached) { clock.t = 60_001; await resolver.resolveJwks('https://a.example/keys'); assert.equal(calls, 2, 'expires after the floor'); }
  }
});
test('discovery duplicate member names are rejected', async () => {
  const resolver = createMetadataResolver({ async fetch() { return new Response('{"keys":[],"keys":[]}'); } });
  await assert.rejects(resolver.resolveJwks('https://a.example/keys'), { field: 'metadata.json' });
});
test('discovery fetches are capped at 100 KB while other fetches keep the configured limit', async t => {
  const key = await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url));
  const cert = await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url));
  const server = createServer({ key, cert }, (request, response) => response.end('x'.repeat(150_000)));
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  const transport = createNodeTransport({ ca: cert.toString(), localExceptions: [{ hostname: 'localhost', addresses: ['127.0.0.1'] }] });
  const url = `https://localhost:${serverPort(server)}/`;
  await assert.rejects(transport.fetch(new Request(url), { mode: 'discovery' }), { code: 'body_limit' });
  assert.equal((await (await transport.fetch(new Request(url))).text()).length, 150_000);
});

test('pool reuses TLS, separates discovery and streams, rejects changed policy before bytes, and closes', async t => {
  const key = await readFile(new URL('./fixtures/localhost-key.pem', import.meta.url));
  const cert = await readFile(new URL('./fixtures/localhost-cert.pem', import.meta.url));
  let connections=0, requests=0;
  const server=createServer({key,cert},(_q,r)=>{ requests++; r.end('ok'); });
  server.on('secureConnection',()=>connections++);
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const localExceptions=[{hostname:'localhost',addresses:['127.0.0.1']}];
  const transport=createNodeTransport({ca:cert.toString(),localExceptions,maxPools:3});
  t.after(()=>{expectValue(transport.close).call(transport);server.closeAllConnections();server.close();});
  const make=()=>new Request(`https://localhost:${serverPort(server)}/`);
  for(let i=0;i<8;i++) assert.equal(await (await transport.fetch(make())).text(),'ok');
  assert.equal(connections,1,'8 requests / 1 TLS connection');
  t.diagnostic(JSON.stringify({sequentialRequests:8,tlsConnections:connections}));
  await transport.fetch(make(),{mode:'discovery'}); assert.equal(connections,2);
  assert.equal(await (await expectValue(transport.stream).call(transport, make())).text(),'ok'); assert.equal(connections,3);
  const before=requests; localExceptions[0].addresses=[];
  await assert.rejects(transport.fetch(make()),{code:'blocked_address'}); assert.equal(requests,before);
  expectValue(transport.close).call(transport); await assert.rejects(transport.fetch(make()),{code:'closed'});
});

test('stream body cancellation releases bounded request slots and JSON queue cancellation is harmless',async t=>{
  const key=await readFile(new URL('./fixtures/localhost-key.pem',import.meta.url));
  const cert=await readFile(new URL('./fixtures/localhost-cert.pem',import.meta.url));
  let requests=0;
  const server=createServer({key,cert},(q,r)=>{requests++;if(q.url==='/stream'){r.writeHead(200,{'content-type':'text/event-stream'});r.write('data: {}\n\n');}else if(q.url==='/hold'){r.writeHead(200);r.flushHeaders();}else r.end('ok');});
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const transport=createNodeTransport({ca:cert.toString(),localExceptions:[{hostname:'localhost',addresses:['127.0.0.1']}],maxRequests:2,maxSockets:1,timeoutMs:1000});
  t.after(()=>{expectValue(transport.close).call(transport);server.closeAllConnections();server.close();});
  const url=(p: string) =>`https://localhost:${serverPort(server)}${p}`;
  const response=await expectValue(transport.stream)(new Request(url('/stream'))); await expectValue(response.body).cancel();
  const first=new AbortController(),second=new AbortController();
  const held=transport.fetch(new Request(url('/hold'),{signal:first.signal}));
  while(requests<2) await new Promise(resolve=>setTimeout(resolve,1));
  const queued=transport.fetch(new Request(url('/ok'),{signal:second.signal}));
  second.abort(); await assert.rejects(queued); first.abort(); await assert.rejects(held);
  assert.equal(await(await transport.fetch(new Request(url('/ok')))).text(),'ok');
});

test('aborted pooled requests retire their socket before the next live request connects',async t=>{
  const key=await readFile(new URL('./fixtures/localhost-key.pem',import.meta.url));
  const cert=await readFile(new URL('./fixtures/localhost-cert.pem',import.meta.url));
  let entered!:()=>void;
  const server=createServer({key,cert},(q,r)=>{if(q.url==='/hold'){r.writeHead(200);r.flushHeaders();entered();}else r.end('live');});
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const transport=createNodeTransport({ca:cert.toString(),localExceptions:[{hostname:'localhost',addresses:['127.0.0.1']}],maxSockets:1,timeoutMs:2000});
  t.after(()=>{expectValue(transport.close).call(transport);server.closeAllConnections();server.close();});
  const url=(path: string) =>`https://localhost:${serverPort(server)}${path}`;
  for(let i=0;i<25;i++){
    const controller=new AbortController(),ready=new Promise<void>(resolve=>entered=resolve);
    const held=transport.fetch(new Request(url('/hold'),{signal:controller.signal}));
    const failed=assert.rejects(held,{code:'network_error'});
    await ready;controller.abort();await failed;
    assert.equal(await(await transport.fetch(new Request(url('/next')))).text(),'live');
  }
});

test('JSON body failures and same-pool stream cancellation/limits retire sockets before replacement',async t=>{
  const key=await readFile(new URL('./fixtures/localhost-key.pem',import.meta.url)),cert=await readFile(new URL('./fixtures/localhost-cert.pem',import.meta.url));
  const server=createServer({key,cert},(q,r)=>{
    if(q.url==='/large')r.end('x'.repeat(128));
    else if(q.url==='/reset'){r.write('partial');setImmediate(()=>r.destroy());}
    else if(q.url==='/stream'){r.writeHead(200);r.write('chunk');}
    else r.end('ok');
  });
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const transport=createNodeTransport({ca:cert.toString(),localExceptions:[{hostname:'localhost',addresses:['127.0.0.1']}],maxSockets:1,maxResponseBytes:16,maxStreamBytes:16,timeoutMs:2000});
  t.after(()=>{expectValue(transport.close).call(transport);server.closeAllConnections();server.close();});
  const request=(path: string) =>new Request(`https://localhost:${serverPort(server)}${path}`);
  for(let i=0;i<10;i++){
    await assert.rejects(transport.fetch(request('/large')),{code:'body_limit'});
    assert.equal(await(await transport.fetch(request('/ok'))).text(),'ok');
    await assert.rejects(transport.fetch(request('/reset')),{code:'network_error'});
    assert.equal(await(await transport.fetch(request('/ok'))).text(),'ok');
    const stream=await expectValue(transport.stream)(request('/stream'));await expectValue(stream.body).cancel();
    assert.equal(await(await expectValue(transport.stream).call(transport, request('/ok'))).text(),'ok');
    const oversized=await expectValue(transport.stream)(request('/large'));await assert.rejects(oversized.text(),{code:'body_limit'});
    assert.equal(await(await expectValue(transport.stream).call(transport, request('/ok'))).text(),'ok');
  }
  const completed=await expectValue(transport.stream)(request('/ok')),reader=expectValue(completed.body).getReader();assert.equal(new TextDecoder().decode((await reader.read()).value),'ok');
  await new Promise(resolve=>setImmediate(resolve));
  let timer:ReturnType<typeof setTimeout>|undefined;try{await Promise.race([reader.cancel(),new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('cancel waited for an idle pooled socket')),500);})]);}finally{clearTimeout(timer);}
  assert.equal(await(await expectValue(transport.stream).call(transport, request('/ok'))).text(),'ok');
});

test('cache validators revalidate after expiry; invalidation refetches and never carries credentials',async()=>{
  let now=0,calls=0;const uri='https://agent.example/client';
  const value={client_id:uri,client_name:'Agent',jwks_uri:'https://agent.example/keys',redirect_uris:[],token_endpoint_auth_method:'private_key_jwt'};
  const resolver=createMetadataResolver({async fetch(request){calls++;assert.equal(request.headers.has('authorization'),false);if(request.headers.get('if-none-match'))return new Response(null,{status:304,headers:{'cache-control':'max-age=60'}});return Response.json(value,{headers:{etag:'"v1"','cache-control':'max-age=60'}});}},{now:()=>now});
  await resolver.resolveClient(uri);await resolver.resolveClient(uri);assert.equal(calls,1);
  now=60001;assert.equal((await resolver.resolveClient(uri)).client_name,'Agent');assert.equal(calls,2);
  expectValue(resolver.invalidate).call(resolver, uri);await resolver.resolveClient(uri);assert.equal(calls,3);
});

test('stalled TLS is counted against pool cap and abort destroys the unassigned socket',async t=>{
  const net=await import('node:net');let connections=0,closed=0;const sockets=new Set<import('node:net').Socket>();
  const server=net.createServer(socket=>{connections++;sockets.add(socket);socket.on('data',()=>{});socket.on('close',()=>{closed++;sockets.delete(socket);});});
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  const transport=createNodeTransport({maxSockets:1,timeoutMs:2000,localExceptions:[{hostname:'127.0.0.1',addresses:['127.0.0.1']}]});
  t.after(()=>{expectValue(transport.close).call(transport);for(const socket of sockets)socket.destroy();server.close();});
  const controller=new AbortController(),url=`https://127.0.0.1:${serverPort(server)}/`;
  const first=transport.fetch(new Request(url,{signal:controller.signal}));
  while(connections===0)await new Promise(resolve=>setTimeout(resolve,1));
  await assert.rejects(transport.fetch(new Request(url)),{code:'overloaded'});assert.equal(connections,1);
  controller.abort();await assert.rejects(first);
  const deadline=Date.now()+500;while(!closed&&Date.now()<deadline)await new Promise(resolve=>setTimeout(resolve,1));
  assert.equal(closed,1,'aborted handshake closes before timeout');
});

test('304 inherits no-cache; invalidation fences an in-flight stale fetch',async()=>{
  const uri='https://agent.example/client',value={client_id:uri,client_name:'old',jwks_uri:'https://agent.example/keys',redirect_uris:[],token_endpoint_auth_method:'private_key_jwt'};let calls=0;
  const resolver=createMetadataResolver({async fetch(){return ++calls===1?Response.json(value,{headers:{etag:'"v1"','cache-control':'no-cache'}}):new Response(null,{status:304});}});
  await resolver.resolveClient(uri);await resolver.resolveClient(uri);await resolver.resolveClient(uri);assert.equal(calls,3);
  let release!:()=>void,started!:()=>void;const gate=new Promise<void>(resolve=>release=resolve),entered=new Promise<void>(resolve=>started=resolve);calls=0;
  const racing=createMetadataResolver({async fetch(){if(++calls===1){started();await gate;return Response.json(value);}return Response.json({...value,client_name:'new'});}});
  const old=racing.resolveClient(uri);await entered;expectValue(racing.invalidate).call(racing, uri);assert.equal((await racing.resolveClient(uri)).client_name,'new');release();await old;assert.equal((await racing.resolveClient(uri)).client_name,'new');assert.equal(calls,2);
});

test('invalidating pending metadata preserves the global active-fetch cap',async()=>{
  let release!:()=>void,entered!:()=>void;const gate=new Promise<void>(resolve=>release=resolve),started=new Promise<void>(resolve=>entered=resolve);let calls=0;
  const uri='https://agent.example/client';const value={client_id:uri,client_name:'A',jwks_uri:'https://agent.example/keys',redirect_uris:[],token_endpoint_auth_method:'private_key_jwt'};
  const resolver=createMetadataResolver({async fetch(){calls++;entered();await gate;return Response.json(value);}},{maxConcurrentFetches:1});
  const first=resolver.resolveClient(uri);await started;expectValue(resolver.invalidate).call(resolver, uri);await assert.rejects(resolver.resolveClient(uri),{field:'metadata.rate_limited'});assert.equal(calls,1);release();await first;await resolver.resolveClient(uri);assert.equal(calls,2);
});

test('close during DNS prevents a resumed lookup from opening any connection',async()=>{
  const original=dns.lookup;let release!:()=>void,entered!:()=>void;const ready=new Promise<void>(resolve=>entered=resolve);let connects=0;const connect=tls.connect;
  mock.method(dns,'lookup',(_host:string,_opts:dns.LookupOptions,callback:(error:NodeJS.ErrnoException|null,addresses:dns.LookupAddress[])=>void)=>{release=()=>callback(null,[{address:'8.8.8.8',family:4}]);entered();});mock.method(tls,'connect',(options:tls.ConnectionOptions,listener?:()=>void)=>{connects++;return connect(options,listener);});syncBuiltinESMExports();
  const transport=createNodeTransport();
  try{const pending=transport.fetch(new Request('https://late.example/'));await ready;expectValue(transport.close).call(transport);release();await assert.rejects(pending,{code:'closed'});assert.equal(connects,0);}finally{dns.lookup=original;tls.connect=connect;syncBuiltinESMExports();expectValue(transport.close).call(transport);}
});

// Independent peer literals: no reference issuer or publisher helper supplies this contract.
test('0.3 peer grants select methods and require described company scopes and endpoints', () => {
  const doc = parsePoppyDocument(document, 'https://shop.example/.well-known/poppy.json');
  const grants = ['urn:ietf:params:oauth:grant-type:jwt-bearer', 'refresh_token'];
  const peer = { ...authorization, grant_types_supported: [...grants, 'authorization_code', 'urn:ietf:params:oauth:grant-type:device_code'], device_authorization_endpoint: 'https://auth.example/device' };
  const parsed = parseAuthorizationMetadata(peer, doc);
  assert.deepEqual(signInMethods({ document: doc, authorization: parsed, url: 'https://shop.example/.well-known/poppy.json' }), [{method:'direct',scopes:['orders:read']},{method:'device',scopes:['orders:read']}]);
  assert.deepEqual(signInMethods({ document: doc, authorization: parseAuthorizationMetadata({...peer,grant_types_supported:grants},doc), url:'' }), [], 'endpoints and old auth.direct/device fields alone never select a method');
  for (const changes of [{grant_types_supported:undefined},{grant_types_supported:['refresh_token']},{grant_types_supported:[grants[0]]},{authorization_endpoint:undefined},{device_authorization_endpoint:undefined},{scopes_supported:undefined},{scopes_supported:['poppy:read']},{scopes_supported:['bad scope']}]) assert.throws(()=>parseAuthorizationMetadata({...peer,...changes},doc));
  assert.throws(()=>parseAuthorizationMetadata({...peer,scopes_supported:['unexplained']},doc),{field:'auth.scopes'});
  assert.throws(()=>parsePoppyDocument({...document,auth:{...document.auth,scopes:{'poppy:future':'Reserved'}}},'https://shop.example/.well-known/poppy.json'),{field:'scopes'});
  const mediated = parsePoppyDocument({...document,auth:{...document.auth,mediated:{endpoint:'https://auth.example/sign-in',scopes:['orders:read'],fields:[{name:'password',label:'Password',secret:true}]}}},'https://shop.example/.well-known/poppy.json');
  assert.throws(()=>parseAuthorizationMetadata({...peer,scopes_supported:[]},mediated),{field:'mediated.scopes'});
  assert.equal(signInMethods({document:mediated,authorization:parsed,url:''})[2].method,'mediated');
});

test('reciprocal resources compare host case only and issuer character for character', () => {
  const doc = parsePoppyDocument(document,'https://shop.example/.well-known/poppy.json');
  parseAuthorizationMetadata({...authorization,protected_resources:['https://SHOP.Example','https://mcp.example/mcp']},doc);
  for(const resource of ['https://shop.example/','https://shop.example/path','https://shop.example:443','https://shop.example?','https://shop.example.evil','https://shop.example.','HTTPS://shop.example']) assert.throws(()=>parseAuthorizationMetadata({...authorization,protected_resources:[resource]},doc),{field:'protected_resources'},resource);
  assert.throws(()=>parseAuthorizationMetadata({...authorization,issuer:authorization.issuer+'/'},doc),{field:'issuer'});
});

test('final well-known path is checked before use, cache and 304 revalidation', async () => {
  let now=0,calls=0,finalUrl='https://shop.example/.well-known/poppy.json',status=200;
  const resolver=createMetadataResolver({async fetch(request){
    calls++; if(request.url.includes('oauth-authorization-server')) return Response.json(authorization);
    const response=status===304?new Response(null,{status,headers:{'cache-control':'max-age=1'}}):Response.json(document,{headers:{'cache-control':'max-age=1',etag:'peer-v1'}});
    Object.defineProperty(response,'url',{value:finalUrl}); return response;
  }},{now:()=>now});
  for(const destination of ['https://shop.example/uploads/claim.json','https://shop.example/.well-known/poppy.json?x=1','https://shop.example/.well-known/poppy.json?']) {
    finalUrl=destination;await assert.rejects(resolver.resolveCompany('www.shop.example'),{field:'discovery.url'});
  }
  finalUrl='https://shop.example/.well-known/poppy.json';
  assert.equal((await resolver.resolveCompany('www.shop.example')).url,finalUrl,'cross-host HTTPS well-known redirects work');
  const cachedCalls=calls; await resolver.resolveCompany('www.shop.example');assert.equal(calls,cachedCalls);
  now=1001;status=304;finalUrl='https://shop.example/uploads/claim.json?x=1';
  await assert.rejects(resolver.resolveCompany('www.shop.example'),{field:'discovery.url'});
  finalUrl='https://shop.example/.well-known/poppy.json';assert.equal((await resolver.resolveCompany('www.shop.example')).url,finalUrl);
});
