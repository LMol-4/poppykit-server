# Company authentication

Integrating an existing issuer uses the core `ExternalAuthorityAdapter` and
`createRequestAuthenticator`. It does not import, run, or persist the optional
reference issuer. The host must describe its issuer's revocation visibility and
order authorization checks with protected work. The reference issuer is a
separate `/reference-auth` import and uses the shared company database coordinator
for immediate revocation visibility.

For draft 0.3 discovery configure `protectedResources`, including
`https://company.example` (host only, no port/path/trailing slash), and
`supportedScopes`, the company-defined account scopes. This replaces
`poppyDomains` and `directScopes` in reference issuer options. Direct and Device
use that same supported list; Device configuration no longer has a `scopes` field.
Mediated retains its own subset. Publish descriptions in company `auth.scopes` or
a listed OpenAPI document. Names starting with `poppy:` are reserved. Issuer
metadata emits the mandatory session/refresh grants and enabled sign-in grants.
Token exchange for Bearer-only MCP remains a later migration stage.

Reference Direct sign-in uses `beginAuthorization` / `completeAuthorization`.
The host authenticates the human and protects consent with its own browser
session/CSRF controls; pass a high-entropy browser binding. Registered callback
URLs must be HTTPS on the client metadata domain and exactly match registration.

Direct hosts must configure `authorizationResultCipher: { seal, open }` with
synchronous authenticated encryption and a durable protected key before calling
`beginAuthorization`. Hosts already using the optional client provider can reuse
its `createResultCipher` instance. Other hosts supply the same structural contract;
no client package or database driver is loaded by the reference issuer.

`completeAuthorization(id, browserBinding, decision)` commits one decision and
an encrypted callback receipt atomically. Repeating the same decision returns
the same URL after restart; changed browser/account/scopes/decision and stale
account revocation/reset fail. Approval recovery expires at the earlier of the
original authorization deadline and code expiry; denial uses the original deadline.
Recovery never mints a replacement code or extends consent. The host must retain
its authenticated owner/installation/session binding and chosen decision durably,
then reconcile delivery outside transactions. Never retry an uncertain code exchange.

`withCurrent` checks token, Session and grant expiry immediately before protected
actions, including after body reads and long-poll waits. Streams close at token
expiry and recheck current authority for each emitted frame; reconnect with fresh
authentication. `withAccepted` intentionally ignores admission-token expiry while
preserving the accepted scope ceiling, reset generation and configured revocation policy.

Account Token rotation retains all issued hashes through the fixed grant lifetime.
Replaying any ancestor revokes its entire lineage and signs its Sessions out;
rotation never extends the grant. Client authentication remains mandatory, while
Session Tokens can move to a new DPoP key as the protocol permits. Shared provider
signing does not bind a copied refresh token to one provider enrollment. Keep
tokens secret and serialize rotation; never retry a lost token response blindly.
Bounded database cleanup removes hashes only after their lineage is expired,
revoked or absent. No plaintext callback code is persisted.

Upgrade prerequisite: older issuers discarded ancestors beyond the previous hash.
Those missing hashes cannot be reconstructed by this update. Before public
enablement, revoke every pre-upgrade live lineage through the issuer's normal
revocation/disconnect flow and require fresh consent, or prove it has expired.
Until then, the full-ancestor guarantee applies only to newly created lineages.
This update does not reset stored data or silently revoke legacy grants.

Enable reference Device sign-in with `device: { endpoint, verificationUri,
}`. Route the configured device endpoint to `deviceAuthorization`.
On the human page call `beginDeviceAuthorization(userCode, browserBinding)` and
show the client identity and requested scopes. After an authenticated explicit
approve/decline action call `completeDeviceAuthorization`. Opening a link must
never approve it. The token endpoint handles durable polling intervals, slowdown,
denial, expiry, partial consent, one-use codes and the Session's sticky account.

Enable Mediated sign-in with `mediated: { endpoint, scopes, fields,
authenticate, verifyCode }` and route that endpoint and its sign-in-ID children
to `mediatedSignIn`. The SDK authenticates the Session Token and DPoP proof,
validates declared fields, counts attempts before calling the host backend,
and binds challenges to the initiating client, UserID and Session. The host
verifies credentials in `authenticate` and may return an account plus a narrower
scope list. It may instead return a challenge handle and safe delivery hint,
then verify codes using `verifyCode`. Host hooks must not log or retain credentials
and must enforce their own backend security and OTP delivery/verification.

Credentials and codes exist only during the trusted handler call; the SDK clears
input objects on exit, stores no passwords/codes and never includes them in
responses. Backend errors return a safe unavailable code. Pending remote hooks
are not automatically repeated after interruption. An operation left verifying
expires; the user can explicitly start another sign-in subject to attempt limits.

Defaults are five credential attempts per Session per minute, 100 per client per
minute, five code attempts per challenge, and ten-minute sign-in expiry. Configure
limits for your service and apply network-level limits before authentication.
SQLite persists attempt windows and bounded tombstones; `cleanup` removes sign-in
records only after their original expiry plus 30 seconds. A failed/expired code
continues returning the same terminal status through that retained window.

Each pending request captures a client revision. Account disconnect increments
the revision and records that account's fence; later credential/consent results
for that account cannot undo disconnect. Requests for other accounts sharing the
same personal-agent client continue. A fresh explicit sign-in captures the new
revision. Revision and per-account fence records remain until explicit issuer
reset and never count as pending requests. Terminal method tombstones also do
not consume pending quota.

Issuer state is version 3. Older development state is refused without mutation;
there is no automatic migration. Follow the explicit stop/backup/reset procedure
in [STORAGE.md](STORAGE.md) only for state you choose to discard.

Advertise only configured methods in your `poppy.json`; `authorizationMetadata()`
adds the device endpoint only when enabled. There is no login/consent UI, identity
provider, CLI or application workflow in this package.
