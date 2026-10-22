# Conversation delivery and transport

The SDK targets Personal Agent Protocol draft 0.2. Company content, messages,
unknown events and partial text remain untrusted data for the host application.

## Client

Bind `createConversationClient` to the existing auth lifecycle:

```ts
const target = await auth.target(connectionId);
const conversations = createConversationClient({
  ...target, connectionId, store, clock: { now: Date.now },
  authorizedRequest: request => auth.authorizedFetch(connectionId, request, target),
  authorization: (id, scopes) => auth.authorization(id, scopes),
});
for await (const item of conversations.watch(conversationId, { consumer: 'ui', signal })) {
  await processEvent(item.event);
  await item.ack();
}
```

`authorization(eventOrError)` returns the single auth lifecycle's verified
required/granted/missing scopes and eligible methods. The UI requests consent and
chooses an advertised method; Device or Mediated does not require Direct support.

`read` returns one page; `drain` follows `has_more` immediately. Named consumers
advance only on explicit acknowledgement. `watch` accepts SSE or JSON fallback,
skips unknown event types, deduplicates up to 10,000 event IDs per invocation, and
never rewinds its cursor on a duplicate. JSON pagination has its separate
`maxPages` bound (default 1000), without consuming reconnect attempts. Reconnects
are bounded (default 4); exhaustion is explicit `reconnect_exhausted`.

`lastEventId` takes precedence over the starting cursor. On reconnect the watcher
sends `Last-Event-ID`. `onPartial` is display-only: a null value clears unfinished
text on completion/disconnect; never execute or reason from an incomplete delta.
Messages are actionable only after a complete `message` event. SSE frames and
JSON fallback are limited to 1 MiB, streams to 16 MiB, and partial text per stream
to 1 MiB. UTF-8 fragmentation and CR/LF/CRLF are supported.

`cursor_expired` is an explicit history gap. Inform the user, then reset a named
consumer and reread retained history, or supply `onHistoryGap` returning true.
Automatic recovery is limited to one reset per watch; it does not recover missing
events. Checkpoints and pending sends survive process restart with durable stores.
Send retries keep their original connection, issuer, endpoint, ID, body and read
parameters. Abort signals are invocation-local and are never persisted. Canceling
delivery does not cancel an accepted company action or prove a lost send failed.

## Node transport

`createNodeTransport` uses Node HTTPS agents, with separate discovery, JSON and
stream pools. Defaults: 8 pools total, 2 connections per pool (including pending
TLS), 32 active operations, 15-second JSON timeout, and 5-second discovery timeout.
There is no hidden request queue: excess pool capacity fails `overloaded`, so a
later attempt performs fresh DNS and policy checks. Hosts decide scheduling.
Streams use `transport.stream` with a 5-minute/16-MiB lifetime budget. Call
`transport.close()` to cancel outstanding reads, DNS waiters, connects and streams.

Every request rechecks DNS and current address policy before pool assignment.
Changed approved addresses retire incompatible pools; actual TLS peers and reused
sockets are checked before HTTP bytes. TLS certificates remain verified. Only
explicit hostname/address exceptions permit private peers. Discovery never carries
credentials and follows only HTTPS redirects; credential-bearing requests never
follow redirects. Pool retirement may interrupt an active stream; reconnect uses
the durable cursor and fresh authorization.

Metadata caching remains bounded and honors freshness, Age, validators, no-cache
and no-store, with a 300-second upper bound. Expired entries revalidate; 304s retain
prior caching directives. `resolver.invalidate(target?)` fences old pending cache
writes without bypassing fetch concurrency/rate limits. J2 rejects changed saved
issuer/endpoint/resource bindings rather than rerouting persisted work.

## Company service and retention

The server accepts `supportedScopes`, the union offered by its actual sign-in
methods. `directScopes` remains a compatibility alias. One coordinator must still
cover authority checks and durable conversation reads/mutations.

Default JSON/request/frame budget is 1 MiB; the maximum encoded event is
1 MiB minus 1025 bytes. Page sizing reserves 1024 bytes for worst-case IDs, cursors
and envelopes and counts UTF-8 bytes. Company events and client messages that
cannot fit are rejected before commit; no receipt/work survives a rejected write.
Do not reduce configured budgets below those used for retained accepted events.

Notifications are post-commit hints. Subscribe before reading; reconcile durable
state on wake or every 1000 ms by default. `createConversationNotifications` is
local acceleration only. Multiple processes work without a broker through targeted
SQLite reconciliation; deployments can implement the same notification contract
with their own distributed adapter. Lost/duplicate hints cannot erase a commit.
SQLite event windows and append operations do not reload complete event histories.

Server streams default to 30 seconds and apply pull backpressure, rechecking
current authority before further pages. This bounded-connection policy omits
periodic idle comments; proxies may close an idle stream sooner, and the client
reconnects. Longer-lived deployments should supply heartbeat handling at their
HTTP adapter. Hosts must propagate disconnect/AbortSignal and body cancellation.

| Record | Lifetime / deletion rule |
| --- | --- |
| Conversation and message receipts | Entire conversation lifetime, including after closure and payload pruning; no automatic deletion |
| Event payloads | Retained indefinitely by default; host may call SQLite `pruneEvents(id, before, limit)` in bounded batches; recommend at least 30 days |
| Event cursor identities | Conversation lifetime; distinguish expired payloads (410) from foreign cursors (400) |
| Active work | Never pruned while held/pending/claimed; event pruning protects these conversations |
| Completed work | Bounded inspection retention; stale fences cannot publish |
| Latest user message, context and account binding | Operational conversation record, retained for its lifetime, including handoff after payload pruning |
| Client outbound/checkpoints | Retained until explicit local store deletion/reset; preserve pending/uncertain sends until reconciled |
| Pending auth and replay records | Separate auth validity/owner rules in AUTH.md and STORAGE.md; not the event TTL |
| CLI transcripts/retries | CLI ownership; local deletion never deletes company history or revokes authorization |

Pruning is explicit operator policy, never automatic data loss. It preserves old
message receipts and cursor identity. Concurrent reads see a coherent snapshot or
`cursor_expired`. Invalid/expired waited-POST cursors are rejected before accepting
the new write; an existing message ID still returns its original receipt.
