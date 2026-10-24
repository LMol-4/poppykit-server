import type { Pool } from 'pg';
import { initialConversationState } from './conversation/service.js';
import type { ConversationStoreState, ConversationRecord } from './conversation/service.js';
import type { ConversationStore, ConversationSelection } from './conversation/store.js';
import { initialIssuerState } from './reference-auth/index.js';
import { clientRevisionKey, accountRevisionKey } from './reference-auth/store.js';
import type { IssuerState } from './reference-auth/index.js';
import type { IssuerStore, IssuerSelection } from './reference-auth/store.js';
import { PostgresRuntime, json } from './postgres-runtime.js';
import type { PostgresConnection } from './postgres-runtime.js';
export { createPostgresPool, migratePostgres, postgresMigration, postgresSchemaVersion } from './postgres-runtime.js';
export type { PostgresConnection } from './postgres-runtime.js';

type Row = { id: string; body: string };
/** Share this coordinator between the issuer, conversation service and host business mutations. */
export class PostgresCompanyDatabase {
  private readonly db: PostgresRuntime;
  constructor(pool: Pool) { this.db = new PostgresRuntime(pool, 'poppy_server'); }
  get metrics() { return this.db.metrics; }
  close(): Promise<void> { return this.db.close(); }
  run<T>(action: () => Promise<T>): Promise<T> { return this.db.run(action); }
  withTransaction<T>(action: (connection: PostgresConnection) => Promise<T>): Promise<T> { return this.run(() => action(this.db.connection())); }
  private atomic<T>(action: () => Promise<T>): Promise<T> { return this.db.run(action); }
  private sqlAll(sql: string, values: unknown[] = []): Promise<Record<string, any>[]> { return this.db.query(sql, values); }
  private async sqlGet(sql: string, values: unknown[] = []): Promise<Record<string, any> | undefined> { return (await this.sqlAll(sql, values))[0]; }
  private async sqlRun(sql: string, values: unknown[] = []): Promise<{ changes: number }> { const result = await this.db.connection().query(sql, values); return { changes: result.rowCount ?? 0 }; }
  private async rows(ns: string, kind: string, where = '', params: (string | number)[] = []): Promise<Row[]> { return this.db.query<Row>(`SELECT id,body FROM poppy_server.records WHERE ns=$1 AND kind=$2 ${where}`, [ns, kind, ...params]); }
  private async one<T>(ns: string, kind: string, id: string): Promise<T | undefined> { const row = (await this.rows(ns, kind, 'AND id=$3', [id]))[0]; return row ? JSON.parse(row.body) as T : undefined; }
  private async put(ns: string, kind: string, id: string, value: unknown): Promise<void> { await this.sqlRun('INSERT INTO poppy_server.records(ns,kind,id,body) VALUES($1,$2,$3,$4) ON CONFLICT(ns,kind,id) DO UPDATE SET body=excluded.body', [ns, kind, id, json(value)]); this.metrics.rowsWritten++; }
  private async save(ns: string, kind: string, before: Record<string, unknown>, after: Record<string, unknown>): Promise<void> {
    for (const id of Object.keys(before)) if (!Object.hasOwn(after, id)) { await this.sqlRun('DELETE FROM poppy_server.records WHERE ns=$1 AND kind=$2 AND id=$3', [ns, kind, id]); this.metrics.rowsWritten++; }
    for (const [id, value] of Object.entries(after)) if (!Object.hasOwn(before, id) || json(before[id]) !== json(value)) await this.put(ns, kind, id, value);
  }
  private async meta<T>(ns: string, kind: string, initial: () => T): Promise<T> {
    const found = await this.one<T>(ns, kind, 'meta'); if (found) return found;
    await this.db.lock(JSON.stringify([ns, kind, 'meta']));
    const raced = await this.one<T>(ns, kind, 'meta'); if (raced) return raced;
    const value = initial(); await this.put(ns, kind, 'meta', value); return value;
  }
    conversations(namespace: string): ConversationStore {
        const load = async (selection: ConversationSelection): Promise<ConversationStoreState> => {
            const state: ConversationStoreState = { ...await this.meta(namespace, 'conversation_meta', () => { const { version, generation } = initialConversationState(); return { version, generation }; }), conversations: {}, bindings: {}, messages: {}, work: [] };
            if (selection.messageKey) await this.db.lock(JSON.stringify([namespace, 'message', selection.messageKey]));
            let id = selection.conversationId;
            if (selection.messageKey) {
                const message = await this.one<ConversationStoreState['messages'][string]>(namespace, 'messages', selection.messageKey);
                if (message) {
                    state.messages[selection.messageKey] = message;
                    id = message.conversationId;
                }
            }
            if (selection.workId)
                id = (await this.one<ConversationStoreState['work'][number]>(namespace, 'work', selection.workId))?.conversationId;
            if (selection.claimAt !== undefined) {
                const row = await this.sqlGet(`SELECT w.body FROM poppy_server.records w JOIN poppy_server.records c ON c.ns=w.ns AND c.kind='conversations' AND c.id=(w.body::jsonb#>>'{conversationId}')
          WHERE w.ns=$1 AND w.kind='work' AND (w.body::jsonb#>>'{phase}') IN ('pending','claimed','held')
          AND (c.body::jsonb#>>'{childId}') IS NULL AND (
            ((c.body::jsonb#>>'{responder}')='human' AND coalesce(((c.body::jsonb#>>'{humanUntil}')::double precision),0)<=$2) OR
            ((c.body::jsonb#>>'{responder}')!='human' AND (c.body::jsonb#>>'{status}')!='queued' AND (w.body::jsonb#>>'{phase}') IN ('pending','claimed')
              AND ((w.body::jsonb#>>'{phase}')='pending' OR coalesce(((w.body::jsonb#>>'{leaseUntil}')::double precision),0)<=$3)
              AND NOT EXISTS (SELECT 1 FROM poppy_server.records earlier WHERE earlier.ns=w.ns AND earlier.kind='work' AND earlier.ordinal<w.ordinal
                AND (earlier.body::jsonb#>>'{conversationId}')=(w.body::jsonb#>>'{conversationId}') AND (earlier.body::jsonb#>>'{phase}') IN ('pending','claimed'))))
          ORDER BY w.ordinal LIMIT 1`, [namespace, selection.claimAt, selection.claimAt]);
                if (row) {
                    this.metrics.rowsRead++;
                    id = JSON.parse(row.body as string).conversationId;
                }
            }
            let target = id ? await this.one<ConversationRecord>(namespace, 'conversations', id) : undefined;
            if (target) { await this.db.lock(JSON.stringify([namespace, 'binding', target.bindingId])); target = await this.one<ConversationRecord>(namespace, 'conversations', target.id); }
            if (!target)
                return state;
            if (selection.cursorCheck !== undefined) {
                const found = await this.sqlGet("SELECT seq FROM poppy_server.event_cursors WHERE ns=$1 AND conversation=$2 AND id=$3", [namespace, target.id, selection.cursorCheck]);
                if (!found)
                    state.cursorStatus = 'invalid';
                else if (!await this.sqlGet("SELECT 1 FROM poppy_server.events WHERE ns=$1 AND conversation=$2 AND seq=$3", [namespace, target.id, Number(found.seq)]))
                    state.cursorStatus = 'expired';
            }
            for (const row of await this.rows(namespace, 'conversations', selection.events ? 'AND id=$3' : "AND (body::jsonb->>'bindingId')=$3", [selection.events ? target.id : target.bindingId])) {
                const conversation: ConversationRecord = JSON.parse(row.body);
                let from = -1;
                if (selection.events?.cursor !== undefined) {
                    const found = await this.sqlGet("SELECT seq FROM poppy_server.event_cursors WHERE ns=$1 AND conversation=$2 AND id=$3", [namespace, row.id, selection.events.cursor]);
                    if (!found)
                        conversation.eventWindow = { invalid: true, hasMore: false };
                    else {
                        from = Number(found.seq);
                        if (!await this.sqlGet("SELECT 1 FROM poppy_server.events WHERE ns=$1 AND conversation=$2 AND seq=$3", [namespace, row.id, from]))
                            conversation.eventWindow = { expired: true, hasMore: false };
                    }
                }
                const events: Record<string, unknown>[] = [];
                let hasMore = false;
                if (selection.events) {
                    let bytes = 0;
                    for (const event of await this.sqlAll("SELECT body FROM poppy_server.events WHERE ns=$1 AND conversation=$2 AND seq>$3 ORDER BY seq LIMIT $4", [namespace, row.id, from, selection.events.limit + 1])) {
                        this.metrics.rowsRead++;
                        const size = Buffer.byteLength(event.body as string) + 1;
                        if (events.length >= selection.events.limit || bytes + size > (selection.events.maxBytes ?? 1048576)) {
                            hasMore = true;
                            break;
                        }
                        events.push(event);
                        bytes += size;
                    }
                    conversation.eventWindow = { ...conversation.eventWindow, hasMore };
                }
                else if (!selection.append)
                    events.push(...await this.sqlAll("SELECT body FROM poppy_server.events WHERE ns=$1 AND conversation=$2 ORDER BY seq", [namespace, row.id]));
                if (!selection.events)
                    this.metrics.rowsRead += events.length;
                if (selection.append && !conversation.lastUserMessage) {
                    const last = await this.sqlGet("SELECT body FROM poppy_server.events WHERE ns=$1 AND conversation=$2 AND (body::jsonb#>>'{type}')='message' AND (body::jsonb#>>'{message,role}')='user' ORDER BY seq DESC LIMIT 1", [namespace, row.id]);
                    if (last) {
                        this.metrics.rowsRead++;
                        conversation.lastUserMessage = JSON.parse(last.body as string).message;
                    }
                }
                conversation.events = events.map(event => JSON.parse(event.body as string));
                state.conversations[row.id] = conversation;
                if (!selection.events)
                    state.work.push(...(await this.rows(namespace, 'work', "AND (body::jsonb#>>'{conversationId}')=$3 ORDER BY ordinal", [row.id])).map(work => JSON.parse(work.body)));
            }
            const binding = await this.one<ConversationStoreState['bindings'][string]>(namespace, 'bindings', target.bindingId);
            if (binding)
                state.bindings[target.bindingId] = binding;
            return state;
        };
        return {
            pruneEvents: (conversationId, before, limit = 100) => {
                if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000 || !Number.isFinite(before))
                    throw new TypeError('retention limit');
                return this.run(async () => {
                    const target = await this.one<ConversationRecord>(namespace,'conversations',conversationId);
                    if (target) await this.db.lock(JSON.stringify([namespace, 'binding', target.bindingId]));
                    const active = await this.sqlGet("SELECT 1 FROM poppy_server.records WHERE ns=$1 AND kind='work' AND (body::jsonb#>>'{conversationId}')=$2 AND (body::jsonb#>>'{phase}') IN ('held','pending','claimed') LIMIT 1", [namespace, conversationId]);
                    if (active)
                        return 0;
                    const removed = await this.sqlRun("DELETE FROM poppy_server.events WHERE ns=$1 AND conversation=$2 AND seq IN (SELECT seq FROM poppy_server.events WHERE ns=$3 AND conversation=$4 AND (body::jsonb#>>'{created_at}')<$5 ORDER BY seq LIMIT $6)", [namespace, conversationId, namespace, conversationId, new Date(before).toISOString(), limit]);
                    return Number(removed.changes);
                });
            },
            read: selection => this.run(async () => await load(selection)),
            transaction: (selection, change) => this.run(async () => this.atomic(async () => {
                const state = await load(selection), before = structuredClone(state);
                const result = change(state);
                if (result && typeof (result as {
                    then?: unknown;
                }).then === 'function')
                    throw new TypeError('async conversation transaction');
                if (selection.events) {
                    if (json(state) !== json(before))
                        throw new TypeError('event windows are read-only');
                    return structuredClone(result);
                }
                if (state.version !== before.version || state.generation !== before.generation || Object.keys(before.conversations).some(id => !Object.hasOwn(state.conversations, id)))
                    throw new TypeError('use an explicit offline reset');
                for (const [id, conversation] of Object.entries(state.conversations)) {
                    const oldEvents = before.conversations[id]?.events ?? [];
                    if (conversation.events.length < oldEvents.length || oldEvents.some((event, i) => json(event) !== json(conversation.events[i])))
                        throw new TypeError('events must be append-only');
                    const last = Number((await this.sqlGet("SELECT coalesce(max(seq),-1) AS seq FROM poppy_server.event_cursors WHERE ns=$1 AND conversation=$2", [namespace, id]))!.seq);
                    for (let i = oldEvents.length; i < conversation.events.length; i++) {
                        const seq = last + i - oldEvents.length + 1, event = conversation.events[i];
                        await this.sqlRun("INSERT INTO poppy_server.events VALUES ($1,$2,$3,$4)", [namespace, id, seq, json(event)]);
                        await this.sqlRun("INSERT INTO poppy_server.event_cursors VALUES ($1,$2,$3,$4)", [namespace, id, event.id, seq]);
                        this.metrics.rowsWritten += 2;
                    }
                    const { events: _events, ...record } = conversation;
                    const { events: _oldEvents, ...old } = before.conversations[id] ?? {};
                    if (json(record) !== json(old))
                        await this.put(namespace, 'conversations', id, record);
                }
                await this.save(namespace, 'bindings', before.bindings, state.bindings);
                await this.save(namespace, 'messages', before.messages, state.messages);
                await this.save(namespace, 'work', Object.fromEntries(before.work.map(row => [row.id, row])), Object.fromEntries(state.work.map(row => [row.id, row])));
                return structuredClone(result);
            })),
        };
    }
    issuer(namespace: string): IssuerStore {
        const kinds = ['sessions', 'grants', 'refreshTokens', 'authorizations', 'codes', 'signIns', 'accessTokens', 'replay'] as const;
        const load = async (selection: IssuerSelection): Promise<IssuerState> => {
            await this.db.lock(JSON.stringify([namespace, 'issuer']));
            const state: IssuerState = { ...await this.meta(namespace, 'issuer_meta', () => { const { version, generation, nonces } = initialIssuerState(); return { version, generation, nonces }; }), sessions: {}, grants: {}, refreshTokens: {}, authorizations: {}, codes: {}, signIns: {}, accessTokens: {}, replay: {} };
            const get = async (kind: typeof kinds[number], id: string | undefined) => {
                if (!id)
                    return;
                const value = await this.one(namespace, kind, id);
                if (value !== undefined)
                    (state[kind] as Record<string, unknown>)[id] = value;
            };
            const find = async (kind: typeof kinds[number], where: string, ...params: (string | number)[]) => {
                for (const row of await this.rows(namespace, kind, where, params))
                    (state[kind] as Record<string, unknown>)[row.id] = JSON.parse(row.body);
            };
            if (selection.kind === 'access')
                await get('accessTokens', selection.hash);
            if (selection.kind === 'sign_in') {
                for (const id of selection.ids)
                    await get('signIns', id);
                await get('sessions', selection.sessionId);
                await get('accessTokens', selection.accessHash);
                for (const key of selection.replayKeys)
                    await get('replay', key);
                const counts = (await this.sqlGet("SELECT count(*) AS n, sum(CASE WHEN (body::jsonb#>>'{clientId}')=$1 THEN 1 ELSE 0 END) AS client FROM poppy_server.records WHERE ns=$2 AND kind='signIns' AND (body::jsonb#>>'{status}') IN ('pending','approved','verifying') AND ((body::jsonb#>>'{expiresAt}')::double precision)>$3", [selection.clientId ?? '', namespace, selection.at]))!;
                state.limits = { sessions: 0, earliestSessionExpiry: 0, pending: Number(counts.n), pendingForClient: Number(counts.client ?? 0) };
            }
            if (selection.kind === 'principal') {
                await get('sessions', selection.sessionId);
                await get('grants', selection.grantId);
            }
            if (selection.kind === 'browser') {
                await get('sessions', selection.sessionId);
                await get('replay', selection.replayKey);
            }
            if (selection.kind === 'authorization') {
                await get('authorizations', selection.id);
                await get('signIns', selection.revocationKey);
            }
            if (selection.kind === 'token') {
                await get('sessions', selection.sessionId);
                await get('codes', selection.codeHash);
                await get('refreshTokens', selection.refreshHash);
                for (const key of selection.replayKeys)
                    await get('replay', key);
                const counts = (await this.sqlGet("SELECT count(*) AS n, min(((body::jsonb#>>'{expiresAt}')::double precision)) AS expiry FROM poppy_server.records WHERE ns=$1 AND kind='sessions' AND (body::jsonb#>>'{clientId}')=$2 AND ((body::jsonb#>>'{expiresAt}')::double precision)>$3", [namespace, selection.clientId, selection.at]))!;
                state.limits = { sessions: Number(counts.n), earliestSessionExpiry: Number(counts.expiry ?? selection.at), pending: 0, pendingForClient: 0 };
            }
            if (selection.kind === 'revoke') {
                await get('refreshTokens', selection.refreshHash);
                await get('replay', selection.replayKey);
            }
            if (selection.kind === 'authorize') {
                await get('signIns', clientRevisionKey(selection.clientId));
                const pending = (await this.sqlGet("SELECT count(*) AS n FROM poppy_server.records WHERE ns=$1 AND kind='authorizations' AND body::jsonb->'completion' IS NULL AND ((body::jsonb#>>'{expiresAt}')::double precision)>$2", [namespace, selection.at]))!;
                const client = (await this.sqlGet("SELECT count(*) AS n FROM poppy_server.records WHERE ns=$1 AND kind='authorizations' AND body::jsonb->'completion' IS NULL AND (body::jsonb#>>'{clientId}')=$2 AND ((body::jsonb#>>'{expiresAt}')::double precision)>$3", [namespace, selection.clientId, selection.at]))!;
                state.limits = { sessions: 0, earliestSessionExpiry: 0, pending: Number(pending.n), pendingForClient: Number(client.n) };
            }
            if (selection.kind === 'disconnect') {
                for (const kind of ['grants', 'codes'] as const)
                    await find(kind, "AND (body::jsonb->>'clientId')=$3 AND (body::jsonb->>'accountId')=$4", selection.clientId, selection.accountId);
                await find('signIns', "AND (body::jsonb->>'clientId')=$3 AND (body::jsonb->>'accountId')=$4", selection.clientId, selection.accountId);
                await get('signIns', clientRevisionKey(selection.clientId));
                await get('signIns', accountRevisionKey(selection.clientId, selection.accountId));
            }
            for (const record of Object.values(state.accessTokens)) {
                await get('sessions', record.sessionId);
                if (record.grantId)
                    await get('grants', record.grantId);
            }
            for (const record of [...Object.values(state.sessions), ...Object.values(state.codes)])
                if (record.grantId)
                    await get('grants', record.grantId);
            for (const record of Object.values(state.codes))
                await get('signIns', accountRevisionKey(record.clientId, record.accountId));
            for (const id of Object.values(state.refreshTokens))
                await get('grants', id);
            for (const [id, grant] of Object.entries(state.grants)) {
                await get('refreshTokens', grant.refreshHash);
                await get('refreshTokens', grant.previousHash);
                if (['token', 'revoke', 'disconnect'].includes(selection.kind))
                    await find('sessions', "AND (body::jsonb->>'grantId')=$3", id);
            }
            return state;
        };
        return {
            read: selection => this.run(async () => await load(selection)),
            transaction: (selection, change) => this.run(async () => this.atomic(async () => {
                const state = await load(selection), before = structuredClone(state);
                const result = change(state);
                if (result && typeof (result as {
                    then?: unknown;
                }).then === 'function')
                    throw new TypeError('async issuer transaction');
                for (const kind of kinds)
                    await this.save(namespace, kind, before[kind], state[kind]);
                const { version, generation, nonces } = state;
                if (json({ version, generation, nonces }) !== json({ version: before.version, generation: before.generation, nonces: before.nonces }))
                    await this.put(namespace, 'issuer_meta', 'meta', { version, generation, nonces });
                return structuredClone(result);
            })),
        };
    }
    /** Bounded maintenance; never deletes message receipts, events, grants or work intent. */
    cleanup(namespace: string, now: number, limit = 100): Promise<number> {
        if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000)
            throw new TypeError('cleanup limit');
        return this.run(async () => {
            await this.db.lock(JSON.stringify([namespace, 'issuer']));
            const rows = await this.sqlAll(`SELECT kind,id FROM poppy_server.records AS retained WHERE ns=$1 AND
        ((kind IN ('authorizations','codes','accessTokens') AND ((body::jsonb#>>'{expiresAt}')::double precision)<=$2) OR (kind='signIns' AND ((body::jsonb#>>'{expiresAt}')::double precision)+30000<$3) OR (kind='replay' AND (body::jsonb#>>'{}')::double precision<$4)
        OR (kind='refreshTokens' AND NOT EXISTS (SELECT 1 FROM poppy_server.records AS lineage WHERE lineage.ns=retained.ns AND lineage.kind='grants' AND lineage.id=retained.body::jsonb#>>'{}' AND (lineage.body::jsonb->>'expiresAt')::double precision>$5 AND lineage.body::jsonb->>'revoked'='false'))) LIMIT $6`, [namespace, now, now, now, now, limit]);
            for (const row of rows)
                await this.sqlRun("DELETE FROM poppy_server.records WHERE ns=$1 AND kind=$2 AND id=$3", [namespace, row.kind, row.id]);
            return rows.length;
        });
    }
}
