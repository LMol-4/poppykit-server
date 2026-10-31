# Explicit retirement of legacy issuer rows

This is an operator-run record migration, separate from the automatic v3/v4 → v5
record enrichment. It is not called by constructors, requests, cleanup(), or SQL
schema installation. No existing SQL migration is rewritten. No live data has
been migrated or deleted by preparing this plan.

Stop every old and new writer, back up the database and its matching protected
cipher/vault keys, and rehearse on a disposable copy. Select one exact namespace.
Complete the v5 enrichment first: it backfills access-token client/account identity
only from proven associations. Unknown/conflicting associations require manual
reconciliation. Do not guess them from a key, User ID, or a shared host.

Take an exclusive write transaction: BEGIN IMMEDIATE for SQLite; BEGIN followed
by LOCK TABLE poppy_server.records IN EXCLUSIVE MODE for PostgreSQL. Keep the
transaction through selection, validation and deletion. Confirm the selected
issuer_meta record is version 5. Abort on another version or unresolved work.

## Prepare the deletion list

Use the existing bounded cleanup for expired access tokens, codes, authorizations,
browser cookies/join codes and replay records first. Preserve mediated verifying
records, active refresh-token ancestry, encrypted callback delivery references,
grants, conversations, work, receipts and events. A timeout is not proof of failure.

Then inspect legacy sessions/sessionKeys with these rules, in this order:

1. A key mapping must be a JSON string pointing to an absent or expired legacy
   Session. Retain it if any record in the namespace refers to its key through
   sessionKey or jkt, or to its target through sessionId, principal.sessionId or
   authority.principal.sessionId. This includes pending/uncertain sign-ins,
   authorization/code records, browser snapshots and accepted conversation/work
   authority. Retain malformed or conflicting mappings for reconciliation.
2. After deleting only approved, unreferenced mappings, consider an expired legacy
   Session. Retain it while any mapping points to it or any record has one of the
   Session references above. An active Session is never a candidate. Current
   resource_sessions are a different record kind and are excluded.
3. Do not delete grants or live refreshTokens as part of Session retirement. The
   ordinary refresh-token expiry/revocation cleanup has its own lineage checks.

The cross-reference scan is deliberately conservative: even completed history can
retain a reference. Its removal requires a separate, explicit retention decision.
Never remove a reference merely to make its target eligible for deletion.

For SQLite, read references with json_extract(body,'$.sessionKey'), '$.jkt',
'$.sessionId', '$.principal.sessionId' and '$.authority.principal.sessionId'.
Read mapping targets with json_extract(body,'$'), checking json_type(body)='text'.
For PostgreSQL use body::jsonb->>'sessionKey', body::jsonb->>'jkt',
body::jsonb->>'sessionId', body::jsonb#>>'{principal,sessionId}' and
body::jsonb#>>'{authority,principal,sessionId}'; mapping targets use
body::jsonb#>>'{}' with jsonb_typeof(body::jsonb)='string'. Every lookup includes ns.

## Apply only the reviewed list

Record the approved kind, id and exact original body privately. Recheck all
references under the same write lock immediately before each removal. Use bound
parameters and compare the original body, for example:

```sql
-- SQLite, inside the exclusive transaction and only after the checks above:
DELETE FROM records WHERE ns=?1 AND kind=?2 AND id=?3 AND body=?4;
-- PostgreSQL, inside the locked transaction:
DELETE FROM poppy_server.records WHERE ns=$1 AND kind=$2 AND id=$3 AND body=$4;
```

Allow only kind=sessionKeys first, then kind=sessions; require exactly one affected
row for each approved removal. Abort and roll back if a body, reference, version
or count differs. Work in bounded batches of at most 1000 records. Verify that
credential, pending/uncertain, recovery and conversation records are unchanged
before committing. Restart only compatible writers. Keep the backup until the
production migration has independent acceptance; do not downgrade old writers
onto the enriched records.

The SDK's existing migration tests prove record preservation across SQLite and
PostgreSQL. Execution of this optional retirement plan, and deployment-specific
retention choices, need the operator's disposable rehearsal and later production
authorization. Automatic legacy-row deletion was intentionally not added.
