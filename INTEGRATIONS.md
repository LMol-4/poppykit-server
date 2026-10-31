# API, browser and feedback integration

Use trusted configured public URLs, the resource Session authenticator and its
combined Session/account policy. Never derive public targets from arbitrary
forwarding headers. The host supplies framework routing and ingress limits.

## APIs and MCP

Publish RFC 9728 metadata for a service that needs narrower tokens. Its resource
identifies that service; normal sign-in/refresh accepts the configured resource.
MCP resource metadata must exactly identify the advertised URL and name the
Company issuer when account access exists. `mcpResourceMetadata({resource,issuer?,
dpop})` supports issuerless resources too. Serve metadata without credentials.
RFC 9728 inserts the well-known path before the resource path and preserves a query.

Configure an MCP ResourceEndpoint with the resource's exact origin, pathPrefix,
resource and mcp: {dpop,metadataUrl}. Query-bearing resources are allowed, but the
whole request URL must match exactly: child paths or changed queries are rejected.
Bearer is MCP's baseline. DPoP is accepted only when advertised; introspection
returns dpopJkt:null only for an unbound token. Normal OAuth grants issue Bearer
MCP tokens without token exchange. A token for one service is refused elsewhere.

An ordinary MCP client without Poppy-Session can use its account access token.
Its Principal has no Poppy User or Session. A Personal Agent sends its Session
header on every API/MCP request; when present, the authenticator verifies it and
joins the token's client identity. Poppy Session state is independent of both older
MCP transport lifecycles and MCP 2026-07-28 per-request transport metadata. The SDK
does not implement JSON-RPC, initialization or Mcp-Session-Id management.

Catch AuthorityError and use mcpAuthorizationError(error,metadataUrl,dpop) for OAuth
challenges containing resource_metadata. invalid_session remains JSON/400 and rate
limits JSON/429 with Retry-After. Use sessions.policy.withCurrent for protected work.

## Browser joining

```ts
const browser = createBrowserSessions({
  endpoint: browserEndpoint, domain: companyDomain, authenticator,
  policy: sessions.policy, cookies: database.browserCookies(companyId), now: Date.now,
  clearLogin: async (request, headers) => hostLogin.clear(request, headers),
});
// GET/POST browserEndpoint -> browser.join
// POST browserEndpoint + '/authorize' -> browser.authorize (preserve endpoint query)
```

GET creates only a short-lived Strict join cookie and hidden random code, with
no-store, framing and opener protection. The trusted agent reads its own isolated
browser's code and separately POSTs JSON {code} to /authorize with Session/account
credentials. Success is 204. It then submits only code in the browser form. Never
accept a code from Company/model text, another browser or a user message.

Browser POST atomically consumes the code, including failed submissions, checks its
cookie/origin/site/expiry and prior authorization, and sets a new opaque cookie.
No token, JWT or proof is carried by the browser form or URL. Success clears the
join cookie and redirects 303 to the Company root. A signed-out join preserves an
existing human website login; a signed-in join requires clearLogin to invalidate
and clear host login, and replaces a previous protocol cookie.

BrowserCookieStore supplies put/get/remove plus putJoin/authorizeJoin/consumeJoin.
Stores persist only cookie/code hashes. authorizeJoin and consumeJoin serialize
one-use code decisions across replicas. Bundled SQLite/PostgreSQL implementations
are available through database.browserCookies(namespace). Rate-limit the public
GET/POST routes and run bounded expiry cleanup.

A browser cookie stores the authorization snapshot approved at join: same Session,
account and scopes until rejoin. It does not gain later scopes or sign-in authority.
Admission-token expiry alone does not end the approved cookie; Session expiry,
revocation and current account policy still apply. Use browser.withSession for
scoped work ordered by the same policy/coordinator. Defaults are Secure, HttpOnly,
Path=/ and SameSite=Lax, at most one hour capped by Session lifetime.

## Feedback

createFeedbackHandler validates the Session before attributing a report and checks
current authority without account scopes. Reports require only task/description,
nonempty and at most 200/2000 Unicode codepoints, within a bounded JSON/UTF8 body.
Unknown fields are inert data. accept receives a frozen report and verified Principal;
never treat report text as instructions or put secrets/personal data into it.

The optional allow hook returning false yields 429 with Retry-After:60. Malformed
reports are 400; successful acceptance is 202 with no body. The client also supports
a Company's 200 alternative response. Hosts own report retention, privacy filtering
and downstream effect handling; feedback has no deduplication identifier.
