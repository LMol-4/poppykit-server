# Company authentication

Resources own Poppy Sessions; OAuth issuers supply account grants. An existing
issuer implements `ExternalAuthorityAdapter` (introspection and current/accepted
authority policy) without importing the optional reference issuer. Its introspector
must validate exact resource audience, expiry, client/account identity, scope and
DPoP binding, and document revocation visibility and ordering with protected work.

Create a separate resource Session authority and use its combined policy:

```ts
const sessions = createSessionAuthority({
  companyId, metadata, store: database.sessions(companyId), coordinator: database,
  accountPolicy: externalAuthority?.policy, now: Date.now,
  maxSessionsPerClient: 10000, lifetimeSeconds: 86400,
});
const authenticator = createRequestAuthenticator({
  sessions, authority: externalAuthority, now: Date.now,
  endpoints: [{ origin: 'https://api.company.example', pathPrefix: '/conversations' }],
});
// Pass authenticator and sessions.policy to conversation/browser/feedback handlers.
```

`companyId` is the verified issuer, or the Company's HTTPS domain without a slash
when issuerless. Signed-out Sessions require no authorization server or token.
The authenticator verifies the delegated ES256 Session JWT before using any of its
identity, audience, method/URL, token hash or continuity claims. Delegations accept
ES256 and PS384 root signatures, require a public P-256 delegated key and expire
within 24 hours. A root-signed Session JWT without delegation is rejected.
Client metadata fetches refuse redirects; hosts keep the supplied safe transport's
TLS/address and bounded-fetch checks. Operator signatures never replace these checks.

Sessions are keyed by exact client_id plus sid; User and optional Agent IDs cannot
change. Delegated keys can change on every request. Account grants and proof keys
do not identify Sessions. The resource remembers a previously used account and
returns invalid_session on account change. A request without an access token is
signed out, even when the Session used an account before. One account grant can
serve many Sessions. Introspection alone never establishes a Poppy User or sid.

Session lifetime defaults to one day, admission to 10,000 active Sessions per client.
Bundled stores serialize quota counts and creation across processes; overflow is
429 with Retry-After until the earliest expiry. Ended/expired Sessions do not occupy
admission slots. Call bounded database cleanup for expired Session records; the
Company may forget ended Sessions under core 5.5. Recreated records get a fresh
instanceId, exposed as Principal.sessionInstanceId, so future ownership contracts
can distinguish them. Configure this cap on createSessionAuthority: passing the
old maxSessionsPerClient option to createReferenceIssuer fails with a relocation error.

`withCurrent` checks current Session instance/generation, validity, accepted scopes
and live account policy immediately before protected work. `withAccepted` preserves
the accepted scope ceiling and explicit work-revocation policy while allowing an
admission token to expire. A database coordinator orders authorization with writes;
a process mutex alone is insufficient across replicas. External effects still need
host idempotency and reconciliation. [Operations v2](OPERATIONS.md) provides separate durable business mechanics with explicit host effect contracts.

Authority errors expose response(): invalid_session is JSON/400; missing account
authority is an errorless Bearer/DPoP challenge/401 with scope; insufficient_scope
is 403, invalid_token is 401. Rate limits are JSON/429 with Retry-After. MCP helpers
include resource_metadata in OAuth challenges; see [INTEGRATIONS.md](INTEGRATIONS.md).

## Optional reference issuer

Configure protectedResources with the Company domain identifier (no path, port or
slash) and supportedScopes. The issuer publishes refresh_token plus enabled
Direct/Device/Mediated grants; it does not issue signed-out Session tokens or
advertise token exchange. Scope names, including poppy-prefixed ones, are Company
policy; publish descriptions and optional hints. Resource-specific tokens use normal
sign-in/refresh with resource. Configure exact MCP resources and their DPoP policy.
The reference issuer chooses DPoP for its other account resources; an external issuer
can also supply Bearer grants through the core authenticator.

Direct uses beginAuthorization/completeAuthorization. The host authenticates the
human, protects consent/CSRF and supplies a high-entropy browser binding. Registered
redirects must be HTTPS on the client metadata domain or RFC 8252 loopback IP URLs;
only a loopback port can vary. PKCE and exact issuer response validation remain
required. OAuth dpop_jkt optionally binds the code to a proof key; it is not a Session.
Missing binding fields in legacy pending codes fail closed.

Direct also requires a synchronous authenticated authorizationResultCipher with a
durable protected key. Complete consent and an encrypted callback receipt commit
atomically. An identical decision recovers the same URL through its original validity
window; changed decisions, owners, revocation or expiry fail. Recovery never issues
a replacement code, extends consent or retries an uncertain token exchange.

Device configuration supplies endpoint and verificationUri. Serve deviceAuthorization
at that endpoint. The human page uses beginDeviceAuthorization then an explicit,
authenticated completeDeviceAuthorization decision. Opening a link does not approve.
Polling enforces pending/slowdown/denial/expiry and one-use codes, bound to client_id
rather than a Session or first polling key. Apply RFC 10027 risk controls in the host;
prefer Direct when it fits the device. Keep device codes private.

Mediated configuration supplies fields, scopes, authenticate and verifyCode. Advertise
`mediated-sign-in` version 1 and route the form grant at the normal token endpoint.
The credentials/code never arrive with a Session JWT or account token. Client-bound
continuations preserve the original scopes/resource/expiry. A code challenge is
HTTP400 code_required with sign_in_id, sent_to and expires_in; continuation uses
one_time_code without repeating credentials/scope. Hooks receive {issuer,clientId},
not Session identity, and must enforce backend/account/network throttles. Input
objects are cleared on exit; never log or retain credentials or OTPs.

An interrupted/throwing remote hook remains verifying, is never automatically
repeated and survives expiry/cleanup for host reconciliation. It continues counting
toward pending limits. No expiry timer proves a remote action failed. Defaults are
five credential attempts per client per minute, five code attempts per challenge,
1000 pending requests globally and 100 per client; apply network limits before auth.
Client/account revision fences prevent late consent from undoing disconnect.

Refresh grants have a fixed lifetime; rotation never extends it. Retain every
ancestor hash through that lifetime so replay revokes the lineage. Client assertions
remain mandatory, independently of Sessions and proof-key rotation. Revocation
signs resources out according to live account policy without deleting Sessions.

Issuer record versions 3/4 upgrade to 5 under their writer lock, retaining generation,
Sessions/maps, grants/ancestor hashes, pending consent, uncertain hooks, replay,
nonces and encrypted recovery receipts. Only proven client/account associations
are backfilled. Unknown/conflicting legacy records are not reinterpreted. The retired browserSessions/sessionForKey and separate mediatedSignIn entry points
are removed. Browser joining uses resource Sessions and fixed approval snapshots;
mediated grants use token(). Retained legacy records remain available through
explicit storage reads for reconciliation.
See [STORAGE.md](STORAGE.md). Earlier unsupported versions fail closed.

Authentication lifecycle OperationRecord/operationId values never approve business operations. OAuth access consent, provider enrollment and mediated credential collection cannot supply business consent. [Operations v2](OPERATIONS.md) binds each actual user answer to the exact revision and request, and rechecks current Session/account authority for execution and protected replay.
