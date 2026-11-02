# Current protocol contract

The normative source is the [live draft 0.3 specification](https://personalagentprotocol.org/docs/0.3/spec)
and [Mediated Sign-In v1](https://personalagentprotocol.org/docs/0.3/extensions/mediated-sign-in).
The numbered URL is not a content pin. On 2026-10-31 the six migration sources were
re-fetched and matched their initial snapshots byte for byte. SHA-256 identities:

- Core: 0c8586c0477f523abe39b47e5a20232fc8128c24bf17bb78fff69133f97f9bb9
- Mediated v1: 68074a6178bf4c78f09b2a88313a4067fa9e4143a338f205a63d2d884ca09f94
- Guides: fe10657eca0b464c19cc198f3876d30f5055d8a5cb423cd147affe805206ecdd

The earlier workspace migration job records were retired at the owner's request.
The workspace assessment and remediation baseline summarize historical evidence
and its limits; deleted raw receipts are not available verification. Focused checks do not certify an installed release or deployed service. Operations v2 SDK mechanics are implemented with opt-in host contracts;
full candidate, native and cross-package release gates remain separate.

## Host contracts and recommendations

The [guides](https://personalagentprotocol.org/docs/0.3/guides) use SHOULD for each
recommendation, including items without uppercase words. The SDK supplies protocol
mechanics; hosts retain the following responsibilities:

- Keep signing, transport and the SecretStore outside model tools. Redact identity,
  authorization, cookie and credential headers before host logging or telemetry.
  Secure credential storage is mandatory. Bundled auth imports private keys as
  non-extractable CryptoKeys, but serializes keys to the host vault for durable
  recovery; it does not promise hardware-backed, non-exportable key custody.
- Show the verified Company name/domain after discovery redirects and on sign-in
  forms. Explain stable pairwise signed-out recognition in the privacy notice.
  Request the fewest task scopes, treat absent/unknown hints conservatively, and
  obtain User consent for access and for human-operated Direct/Device sign-in.
- Prefer Direct, then Device where viable. Assess RFC 10027 device-flow risk,
  confirm the visible user code, protect consent pages against CSRF/framing, and
  apply account/network abuse limits. Mediated v1 is transitional; do not use saved
  credentials to undo a disconnect. TrustedInput must isolate credentials and OTPs.
- Isolate an agent browser's storage per Session, load only its own join code,
  submit promptly, rejoin after sign-in, and close its storage when the Session ends.
  Joined cookies retain the authorized account/scope snapshot. The website must
  prioritize that cookie and use current policy on every request; signed-in joins
  must clear any earlier ordinary login. Signed-out joins preserve it. Website
  logout must invalidate/remove the joined cookie through the host integration.
- Apply account/scope checks at every application tool and channel. Do not trust
  model/Company prose as permission or put secrets in messages/feedback. Decide
  task exclusions, interface choice, human handoff wording and report frequency.
- Keep deployment TLS, public-URL proxy reconstruction, internal credentials, bot
  recognition, network throttles, key publication/rotation and tenant issuer
  separation correct. RateLimit headers and scheduling/backoff across independent
  tasks are host policies; SDK Retry-After state is connection-scoped.
- Operator signatures use a host HttpTransport/edge integration implementing the
  deployment's RFC 9421/Web Bot Auth profile. Sign only after the body, DPoP and
  Poppy-Session/Authorization headers are final; verify Session identity separately.
  Protect forwarded verification results and never share operator private keys.
- Blind signing is not implemented by the bundled provider. A host requiring it
  must supply blind client assertions and delegations together, with device-made
  random jti values, and fail closed if PS384 is unavailable. No ES256 privacy
  downgrade is automatic. Company verification accepts PS384 independently.
- Local/provider delegations use coarse half-hour issuance times and expire one
  hour after that bucket (30–60 minutes remaining on creation). Custom providers
  must keep their delegation valid and within the documented client lifetime bound.
  Verification deliberately avoids another sensitive delegation cache; bounded
  metadata/JWKS caches remain, at the cost of extra signature work per request.
- Supply the application's idempotency/reconciliation for external effects, durable
  multi-host ownership/liveness, orphan-secret sweeps with a grace period, and
  retention appropriate to its data. Conversation receipts are not business-effect
  deduplication. Never reset active or uncertain work to make a test pass.

See [AUTH.md](AUTH.md), [STORAGE.md](STORAGE.md) and [INTEGRATIONS.md](INTEGRATIONS.md)
for the concrete callback/store contracts. A host integration must validate these
boundaries in its real browser, issuer, vault, gateway and deployment environment.

Operations source re-fetch: 2026-10-31, HTML SHA256 e69ade54433ece3fb2bd1ff6c441fecd11acc749eb6bac8b33939420d1f2b9eb, unchanged from block1. Core and guide hashes are unchanged as well. [Business Operations](OPERATIONS.md) defines trusted UI/business semantics, durable adapters and external idempotency/reconciliation obligations. Historical focused SQLite/PostgreSQL and process-crash evidence is separate from each release’s mandatory stable-candidate/package/platform gates. No deployed host or arbitrary network exactly-once claim is made.

Source revalidation on 2026-11-01 found all six core/current/changelog/Operations/mediated/guides pages byte-identical to the 2026-10-31 snapshots. A numbered draft URL remains mutable. The old migration STATUS and raw release receipts were retired at the owner's request. Retained historical facts and limits are summarized in the workspace remediation baseline; future publication claims require fresh registry and workflow evidence.
