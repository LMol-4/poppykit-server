# Company persistence and authorization

Request paths use targeted domain selections, not whole-state rewrites. Node 24.12.0 or later is required.
The optional `@poppykit/server/sqlite` entry point exports `SqliteCompanyDatabase`.
The core and reference issuer entry points do not import SQLite. Consumers can
implement `ConversationStore`, `IssuerStore` and `AuthorityCoordinator` themselves.
The tested Node 24.12.0 runtime marks `node:sqlite` experimental.

```ts
import { SqliteCompanyDatabase } from '@poppykit/server/sqlite';
const database = new SqliteCompanyDatabase('/private/path/company.db');
const issuer = 'https://company.example/issuer';
const issuerStore = database.issuer(issuer);
const conversationStore = database.conversations(issuer);
// Reference issuer options: store: issuerStore, coordinator: database.
// Conversation options: store: conversationStore, policy: referenceIssuer.authority.policy.
// Close database only after all in-flight requests/work have ended.
```

Use the same database instance for the reference issuer, its coordinator, and its
conversation storage. A policy check and the protected conversation mutation join
one SQLite transaction. Revocation/rotation/acceptance cannot interleave between
authorization and commit. External issuers still supply their own policy and must
state revocation latency and how their checks are ordered with protected writes.
Never replace the coordinator with a process-local mutex for a multi-process service.

SQLite uses WAL and FULL synchronous commits. A database serializes writers; this
reference adapter does not promise parallel SQLite writers. The short per-instance
queue protects its single connection, and SQLite coordinates separate processes.
There is no application-wide static lock: separate databases are independent. The
coordinator is a database transaction boundary, not a lock held during external
model, vault, or HTTP calls. SQL busy retries are bounded. Use a local filesystem
with correct SQLite locks; network-mounted multi-host SQLite is unsupported.

## Domain records and guarantees

Every primary key includes a namespace (use the exact full issuer). Sessions,
grants, current/previous token hashes, authorization requests, codes, access-token
hashes, replay keys, conversation metadata, shared account bindings, message
receipts and work intent are separate records. Ordered events are a separate table
keyed by namespace/conversation/sequence. Indexes cover client, account, grant,
conversation, binding, phase and expiry. User identity and authorization checks
still apply inside the SDK; a namespace name alone is not authentication.

Conversation selections resolve an ID, message receipt, work ID, or next eligible
claim. Reads include the related parent/Direct Conversation binding group, not
unrelated conversations. A worker query selects the oldest eligible message for a
conversation; publication rechecks lease and fence. Cursor-relative event selectors bound delivery reads without loading work/history
aggregates. `ConversationNotifications` defines subscribe/unsubscribe/publish:
subscribe before reading, treat wakes as hints, and always reconcile durable state
after a wake or bounded timeout. Publishing after commit is best-effort, not an outbox.

Issuer selections address metadata, token admission, a principal, a token hash, an
authorization, or a client/account disconnect. Session and authorization limits
use indexed counts rather than loading other clients' records. Related grant
sessions are loaded when revocation must sign them out atomically.

All mutations run synchronous callbacks over detached domain records. Async
callbacks and non-JSON values are rejected. Exceptions roll back; domain savepoints
also roll back if an enclosing policy caller catches an error. Returned values and
retained callback objects cannot mutate persisted state after commit. Only changed
rows and newly appended events are written. Conversation deletion, event rewriting,
and generation reset are not silently accepted through a targeted transaction.

Acceptance, event append, message deduplication receipt and pending work commit in
one transaction. There is no second outbox. The same message ID with different
content/target conflicts. Claim recovery can execute application work again after
a lease expires: the fence prevents stale SDK publication, but cannot undo or
deduplicate arbitrary external effects. The application's downstream system needs
its own idempotency key (such as the stable work ID), or the application must retain
an uncertain result for reconciliation. Never claim universal exactly-once execution.

`cleanup(namespace, now, limit)` bounds deletion to at most 1000 expired short-lived
codes, authorizations, access tokens or replay entries. It does not delete grants,
work intent, message receipts or conversation events. Receipt identity remains
through retention for the conversation lifetime. Finished work pruning is
per selected conversation binding group; unrelated conversation growth cannot
force another conversation's receipts out of storage.

## Non-durable use and resets

`new SqliteCompanyDatabase(':memory:')` is an explicit non-durable adapter for tests
and development. Each instance is separate, is lost at close/process death, and
offers no cross-process persistence. The test fixture's object store is also
non-durable and is not evidence of database atomicity.

No old whole-state files are migrated or deleted automatically. For a disposable
development reset, stop all processes, resolve uncertain external effects, and
explicitly move aside the database and WAL/SHM files. Reopen a fresh database to
obtain new generations. Never reset a live database behind active processes.

Contract tests cover real process contention/death, publication fences, rotation/
revocation, rollback, isolation and targeted read counts; see [contributing](CONTRIBUTING.md).

## Bounded conversation delivery and retention

`ConversationSelection.events` loads a cursor-relative, count/byte-bounded event
window without work/history aggregates; it is read-only inside transactions.
`append` loads operational records without historical event payloads. `cursorCheck`
checks retained cursor identities for waited POSTs. These selectors preserve the
shared authority coordinator. Custom adapters must implement equivalent targeted
reads before claiming the same operation-count guarantees.

SQLite `pruneEvents(conversationId, beforeUnixMilliseconds, limit=100)` deletes at
most 1000 old payloads per call and refuses active held/pending/claimed work.
Message receipts, event cursor identities and the latest user message/context stay
with the conversation for its lifetime. Closure is not deletion. Retention uses
one database transaction; concurrent writers/readers see a coherent before/after
state. Default payload retention is indefinite; operators should retain at least
30 days and explicitly choose any shorter policy. See [DELIVERY.md](DELIVERY.md)
for distinct lifetimes and client recovery behavior. No automatic destructive
reset or history deletion was added.
