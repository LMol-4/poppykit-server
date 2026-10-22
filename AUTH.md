# Company authentication

Integrating an existing issuer uses the core `ExternalAuthorityAdapter` and
`createRequestAuthenticator`. It does not import, run, or persist the optional
reference issuer. The host must describe its issuer's revocation visibility and
order authorization checks with protected work. The reference issuer is a
separate `/reference-auth` import and uses the shared company database coordinator
for immediate revocation visibility.

Reference Direct sign-in uses `beginAuthorization` / `completeAuthorization`.
The host authenticates the human and protects consent with its own browser
session/CSRF controls; pass a high-entropy browser binding. Registered callback
URLs must be HTTPS on the client metadata domain and exactly match registration.

Enable reference Device sign-in with `device: { endpoint, verificationUri,
scopes }`. Route the configured device endpoint to `deviceAuthorization`.
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
