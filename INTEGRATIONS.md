# API, browser and feedback integration

Use the same authority policy and coordinator as protected conversation work.
Supply the trusted public request URL; never derive it from arbitrary forwarding
headers. Custom issuers and transports remain responsible for their documented
revocation, address-validation and storage guarantees.

## MCP authentication

```ts
const metadata = mcpResourceMetadata({ resource: mcpUrl, issuer, dpop: true });
const authenticator = createRequestAuthenticator({ authority, now: Date.now,
  endpoints: [{ origin: 'https://company.example', pathPrefix: '/mcp', resource: mcpUrl,
    mcp: { dpop: true, metadataUrl: 'https://company.example/.well-known/oauth-protected-resource/mcp' } }],
});
// Serve metadata publicly without credentials. In the existing MCP handler:
try {
  const principal = await authenticator.authenticate(request);
  return await authority.policy.withCurrent(principal, ['tools:read'], () => handleMcp(request));
} catch (error) {
  if (error instanceof AuthorityError) return mcpAuthorizationError(error, metadataUrl, true);
  throw error;
}
```

MCP metadata identifies the exact resource URL, issuer and ES256 support when
enabled. Challenges include Bearer and, if supported, DPoP with `resource_metadata`.
The exact endpoint accepts no child paths or added query. All other APIs retain
DPoP-only authentication. Configure the reference issuer `mcpResources` with the
same `{url,dpop}` list. Non-DPoP MCP targets require Token Exchange of a current
DPoP Session Token, a matching client assertion and the Session Key proof. Other
grants reject those targets with invalid_target; exchange rejects DPoP MCP targets.
Exchange preserves the Session and narrows subject scopes without rotating an
Account Token. Metadata advertises exchange when a Bearer-only MCP resource exists.
DPoP MCP continues using normal DPoP token grants. Bearer tokens are
resource-bound; DPoP-bound tokens cannot be presented as Bearer.

An existing issuer can accept ordinary MCP OAuth clients through its own flow.
Its introspector returns `dpopJkt: null` only for truly unbound Bearer credentials;
ordinary MCP principals have empty `userId` and an account-bound session owned by
the MCP client. Such sessions end on sign-in revocation/expiry and must not
continue signed out. The external issuer must enforce this on every introspection
and policy check and document its revocation visibility. The reference issuer
implements personal-agent grants; it does not add a general OAuth login product.

## Browser sessions

```ts
const browser = createBrowserSessions({ endpoint: browserEndpoint, domain: companyDomain,
  authority: referenceIssuer.browserSessions,
  policy: referenceIssuer.authority.policy, cookies: cookieStore, now: Date.now,
});
// Mount browser.join on browserEndpoint; no request-body logging at this route.
const result = await browser.withSession(request, ['records:read'], principal => readRecords(principal));
```

`BrowserCookieStore.put/get` stores SHA256 cookie-value hashes, session bindings and
expiry. Supply durable storage with targeted operations and expire old rows. Never
store plaintext cookie values. The same store must implement `putJoin(codeHash,
{cookieHash, expiresAt})` and atomic `consumeJoin(codeHash)`, which removes and
returns the entry even if expired. Expire abandoned joins and rate-limit the public
route in the host. Cookie/code hashes may be shared durably across handler replicas.
`BrowserSessionAuthority.join(sessionKey)` resolves an existing active key; it never
creates a Session. `current` reads current permissions. The reference issuer uses
targeted key/Session selectors on its existing memory/SQLite/PostgreSQL stores.

Mount both GET and POST. GET sets only a 60-second Strict __Host-poppy_join cookie
and emits a random 256-bit hidden code, no-store, frame-ancestors none and same-origin
opener isolation. POST consumes the submitted code first, including failed cookie,
origin and proof checks. It requires that browser's cookie and a valid Session Key
DPoP proof whose nonce is the code and which has no ath. Invalid requests return 400
with no cookie; success clears the join cookie, sets the Session cookie and returns
303 to the endpoint's website root. No provider signing/JWKS assertion is involved. Defaults are `__Host-poppy-session`, Path=/, Secure,
HttpOnly, SameSite=Lax and max 3600 seconds capped by the current session lifetime.
SameSite=None is supported; Strict is refused. `authenticate` resolves current
authority on every request. Use `withSession` for scoped mutations so permission
checks and work are ordered by the same policy/coordinator. Sign-in, scope changes
and revocation are reflected immediately; no permissions are cached in cookies.
Host adapters must isolate the agent browser from the user's consent browser.

## Feedback

`createFeedbackHandler({endpoint, authenticator, policy, accept, allow?})` validates
a Session Token, including a signed-out token with no account scope. It checks the
JSON/UTF8 byte budget and nonempty task/description limits (200/2000 Unicode
codepoints), accepts unknown kinds and passes only a frozen inert-data report to
`accept`. Do not interpret its text as instructions, including in later model use.
The optional host `allow` hook supplies rate limiting; false returns 429. Malformed
reports return 400, auth errors use the shared challenge, success is empty 202.
There is no protocol deduplication identifier and no exactly-once promise. Hosts
own report retention, privacy filtering and downstream side-effect handling.

`tests/integrations.test.mts` exercises browser replay/current authority in memory
and SQLite, MCP schemes/resources/ordinary-client integration and feedback.
