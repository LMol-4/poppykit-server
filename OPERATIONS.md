# Business operations (Operations v2)

Enable `extensions.operations: operationsV2` in Company discovery only after
installing these mechanics on every interface offering approval-gated actions.
There is no v1 operations endpoint. The SDK does not auto-advertise support.
`createBusinessOperations({companyId,metadata,policy,store,now?,retentionMs?,
maxRevisions?,effectTimeoutMs?})` verifies the client's exact v2 metadata before returning an
operation. Use the same verified Session/account policy and database coordinator
as request authentication. OAuth-only MCP identity cannot approve Poppy work.

The host chooses a stable URL-safe `operationId` for one business action, from
its own records. It must never derive another action identity from the submitted
approval, allocate a fresh action on retry, or reuse an ID for different work.
The service stores every issued, unexpired revision with its exact request.
A newer revision does not invalidate an older one. Summary/terms/expiry changes
always receive a fresh opaque revision. Default admission is 1000 live revisions
per action; overflow is 429/Retry-After, preserving issued revisions.

## Propose and execute

`OperationInput` contains `operationId`, authenticated `principal`, required
`scopes`, `request`, optional parsed `approval`, and `proposal()`. The proposal
callback supplies the current `summary`, optional `terms`, and `expires_at`.
Describe every action condition, amount, recipient and date in the summary and
terms. Give the User at least 15 minutes where business conditions permit. Use
request/resource field names in structured terms, and document `approval_required`
in your OpenAPI responses. These business-semantic choices belong to the host.

Call `propose(input)` to publish terms without an effect, or route every action
through `local`/`external`: without a valid approval they return
`{kind:'approval_required',operation}` and execute nothing. Current authorization,
scopes and ownership precede receipt replay. Signed-out ownership includes the
exact Session instance/generation, not just a reused sid. Signed-in ownership
includes Company, client, User and account; another Session of that same identity
can approve. Signed-out access to account work receives an OAuth account challenge.
Foreign identities see the same `operation_not_found` error. Recheck current
policy before exposing protected results. Model text and Company conversation
text cannot create the approval field.

Bind requests with `captureApiOperationRequest(request)` (complete method/URL,
base64 exact body bytes), `{channel:'mcp',url,name,arguments}`, or
`{channel:'conversation',endpoint,conversationId}`. Use `parseApprovalHeader`,
`mcpApproval(params)` or the accepted conversation message's `approval`.
A mismatched/expired/unknown revision or wrong request performs nothing and
returns freshly generated terms, never the rejected approval's revision.
Execution is serialized by business action ID across all revisions and workers.

`OperationOutcome` is `approval_required`, `pending` or `completed` (result and
replay flag). `operationApiResponse(outcome,success?)` maps proposal to403 JSON and
pending to503/Retry-After. The default success is JSON200; pass a stable response
builder for your API's status/headers. Replay returns the first committed result
or an equivalent response. No approval goes in WWW-Authenticate.
`operationMcpResponse` produces the structured tool error or successful tool
result, and HTTP503/Retry-After for unresolved work. Pass a caught
`BusinessOperationError('extension_required')` to it for an ordinary tool error;
only refusing the entire MCP client uses the OAuth extension_required challenge.

## Local and external effect contracts

`local(input,async approvedRevision => result)` executes only same-database
mutations. Use `database.withTransaction` inside the callback, on the SAME
`SqliteCompanyDatabase`/`PostgresCompanyDatabase` instance as the operation store
and authorization coordinator. The host mutation and operation receipt commit or
roll back together, including process death. Never put a network call, another
database or nontransactional filesystem effect in `local`. It receives the actual
approved revision: execute those exact terms, not a freshly recomputed quote.
SQLite supplies scoped `run/get`; PostgreSQL supplies a scoped query connection.
Handles reject use after their transaction ends.

`external(input,adapter)` commits an uncertain execution claim BEFORE invoking
`adapter.execute({key,operation})`. The key is derived from Company/action ID,
not revision or message ID. The host MUST guarantee durable idempotency for that
key in the external system, including concurrent calls and old paused workers.
It must preserve the approved terms and authenticate/authorize the action at its
submission boundary. Already accepted effects may finish during subsequent
revocation; revocation cannot retroactively undo an external system's commit.
Arbitrary network effects are not exactly-once, and a local receipt alone cannot
make them so. Do not use this API with a downstream lacking this contract.

Execution/reconciliation has a default30s deadline (`effectTimeoutMs`). It returns pending on a deadline, without cancelling or freeing a possibly running effect. A timeout/throw/process death leaves the claim uncertain indefinitely. Retrying
returns pending and never calls execute again automatically. Lease expiration,
new terms, process restart and receipt cleanup cannot release the claim.
`reconcile(input,adapter)` asks the host's durable system by the same key:

- `pending`: remain fenced, answer503 with Retry-After.
- `completed,result`: record the actual outcome and replay it.
- `absent`: assert the old worker cannot later commit outside that idempotency
  fence; the SDK may submit the same key and original approved revision again.

Reconciliation itself must be safe concurrently with execute and other
reconcilers. The first committed result is immutable. Preserve a meaningful
business failure as an equivalent terminal outcome when definitively known;
never describe unknown effect state as failure. Hosts enforce ingress quotas,
worker deadlines and external reconciliation scheduling. A deadline must return
pending without deleting the durable claim, even if its worker is still alive.

## Conversations

Configure `createConversationService({operations:metadata,...})` only on an
endpoint with complete v2 execution. It refuses unsupported clients with the
extension challenge. It accepts approval-only user-side messages and operation-only
Company messages, gated by current client metadata on requests/publication.
`operationContext(work)` provides the accepted principal, conversation binding
and only the actual message approval. Use that context with the business service,
then `reply` with `operation` when proposing or the actual business outcome after
execution. A conversation's lease/message receipts do not deduplicate effects.
Repeated approval in a new message adds no event or work; same message-ID retries
retain the ordinary original receipt. Cross-conversation approval fails binding.

## Store contract, retention and migration

`database.businessOperations(companyNamespace)` implements
`BusinessOperationStore`: an asynchronous, serializable transaction on one action
slot, including absent-row serialization across processes. Local host effects
and policy checks must enlist in the same coordinator. Exceptions roll back the
slot and effects even inside an enclosing transaction. Snapshots/results detach;
unknown record versions and changed IDs are refused. Run
`runBusinessOperationAdapterContract` from the adapter-contract subpath for a
custom store, plus your engine's process-death/effect-enlistment tests.

Business record version1 uses the existing SQLite/PostgreSQL `records` table,
kind `business_operations`. No applied SQL migration is rewritten, no old writer
can overwrite this kind through existing targeted auth/conversation selectors,
and no credentials or user rows are removed. Authentication lifecycle records
remain separate. Stop incompatible future writers before any version transition.

Each execution retains its first protected result at least through the approved
revision's expiry (default also24h after claim). `prune(operationId)` only drops a
completed result and terms strictly AFTER retention. It keeps a minimal owner/
action tombstone permanently; later attempts can get fresh terms but cannot
execute that business action again. Uncertain claims/terms never prune. If you
need to retire tombstones, an authoritative permanent business fence must still
prevent re-execution; deleting the namespace is not retention. Protect stored
terms/results with your database access/encryption policy. Approval attribution
records the owner, approved revision and claim time; this states what the agent
asserted, not proof of what a human saw.

`node examples/operations.mjs --self-check` uses only synthetic identities and a
private temporary SQLite file. Real hosts use the request authenticator and
combined Session/account policy, not the example's test policy. Process-crash,
concurrent-process, independent wire and PostgreSQL acceptance is in
`tests/operations.test.mts`.
