import { DatabaseSync } from 'node:sqlite';
import { initializeSqlite } from './sqlite-init.js';
import { AsyncLocalStorage } from 'node:async_hooks';
import { setTimeout as sleep } from 'node:timers/promises';
import { initialConversationState } from './conversation/service.js';
import type { ConversationStoreState, ConversationRecord } from './conversation/service.js';
import type { ConversationStore, ConversationSelection } from './conversation/store.js';
import { initialIssuerState } from './reference-auth/index.js';
import type { IssuerState } from './reference-auth/index.js';
import type { IssuerStore, IssuerSelection } from './reference-auth/store.js';

type Row = { id: string; body: string };
function json(value: unknown): string {
  return JSON.stringify(value, (_key, item) => {
    if (item === undefined || typeof item === 'function' || typeof item === 'bigint' || (typeof item === 'number' && !Number.isFinite(item))) throw new TypeError('non-JSON record');
    return item;
  });
}

/** Share this instance between issuer and conversations so authorization and mutation commit together. */
export class SqliteCompanyDatabase {
  private readonly db: DatabaseSync;
  private readonly inside = new AsyncLocalStorage<{ active: boolean }>();
  private queue: Promise<unknown> = Promise.resolve();
  private savepoint = 0;
  readonly metrics = { rowsRead: 0, rowsWritten: 0 };
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    initializeSqlite(this.db, () => this.db.exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
      CREATE TABLE IF NOT EXISTS records (ns TEXT NOT NULL, kind TEXT NOT NULL, id TEXT NOT NULL, body TEXT NOT NULL, PRIMARY KEY(ns,kind,id));
      CREATE INDEX IF NOT EXISTS by_conversation ON records(ns,kind,json_extract(body,'$.conversationId'));
      CREATE INDEX IF NOT EXISTS by_binding ON records(ns,kind,json_extract(body,'$.bindingId'));
      CREATE INDEX IF NOT EXISTS by_client ON records(ns,kind,json_extract(body,'$.clientId'),json_extract(body,'$.expiresAt'));
      CREATE INDEX IF NOT EXISTS by_account ON records(ns,kind,json_extract(body,'$.clientId'),json_extract(body,'$.accountId'));
      CREATE INDEX IF NOT EXISTS by_grant ON records(ns,kind,json_extract(body,'$.grantId'));
      CREATE INDEX IF NOT EXISTS by_phase ON records(ns,kind,json_extract(body,'$.phase'));
      CREATE INDEX IF NOT EXISTS by_expiry ON records(ns,kind,json_extract(body,'$.expiresAt'));
      CREATE INDEX IF NOT EXISTS replay_expiry ON records(ns,kind,CAST(body AS REAL));
      CREATE TABLE IF NOT EXISTS events (ns TEXT NOT NULL, conversation TEXT NOT NULL, seq INTEGER NOT NULL, body TEXT NOT NULL, PRIMARY KEY(ns,conversation,seq));
      PRAGMA busy_timeout=0;`));
  }
  close(): void { this.db.close(); }
  /** Required SQLite writer serialization, not an application-wide lock or network-call boundary. */
  run<T>(action: () => Promise<T>): Promise<T> {
    if (this.inside.getStore()?.active) return action();
    const run = this.queue.then(async () => {
      const deadline = Date.now() + 5000;
      for (;;) {
        try { this.db.exec('BEGIN IMMEDIATE'); break; }
        catch (error) {
          if (!(error instanceof Error && /locked|busy/i.test(error.message)) || Date.now() >= deadline) throw error;
          await sleep(10);
        }
      }
      const context = { active: true };
      try {
        const result = await this.inside.run(context, action);
        this.db.exec('COMMIT'); return result;
      } catch (error) { this.db.exec('ROLLBACK'); throw error; }
      finally { context.active = false; }
    });
    this.queue = run.catch(() => {});
    return run;
  }
  private atomic<T>(action: () => T): T {
    const name = `nested_${++this.savepoint}`;
    this.db.exec(`SAVEPOINT ${name}`);
    try { const result = action(); this.db.exec(`RELEASE ${name}`); return result; }
    catch (error) { this.db.exec(`ROLLBACK TO ${name}; RELEASE ${name}`); throw error; }
  }
  private rows(ns: string, kind: string, where = '', params: (string | number)[] = []): Row[] {
    const rows = this.db.prepare(`SELECT id,body FROM records WHERE ns=? AND kind=? ${where}`).all(ns, kind, ...params) as unknown as Row[];
    this.metrics.rowsRead += rows.length;
    return rows;
  }
  private one<T>(ns: string, kind: string, id: string): T | undefined {
    const row = this.rows(ns, kind, 'AND id=?', [id])[0];
    return row ? JSON.parse(row.body) as T : undefined;
  }
  private put(ns: string, kind: string, id: string, value: unknown): void {
    this.db.prepare('INSERT INTO records VALUES (?,?,?,?) ON CONFLICT(ns,kind,id) DO UPDATE SET body=excluded.body').run(ns, kind, id, json(value));
    this.metrics.rowsWritten++;
  }
  private save(ns: string, kind: string, before: Record<string, unknown>, after: Record<string, unknown>): void {
    for (const id of Object.keys(before)) if (!Object.hasOwn(after, id)) {
      this.db.prepare('DELETE FROM records WHERE ns=? AND kind=? AND id=?').run(ns, kind, id); this.metrics.rowsWritten++;
    }
    for (const [id, value] of Object.entries(after)) if (!Object.hasOwn(before, id) || json(before[id]) !== json(value)) this.put(ns, kind, id, value);
  }
  private meta<T>(ns: string, kind: string, initial: () => T): T {
    const found = this.one<T>(ns, kind, 'meta');
    if (found) return found;
    const value = initial(); this.put(ns, kind, 'meta', value); return value;
  }
  conversations(namespace: string): ConversationStore {
    const load = (selection: ConversationSelection): ConversationStoreState => {
      const state: ConversationStoreState = { ...this.meta(namespace, 'conversation_meta', () => { const { version, generation } = initialConversationState(); return { version, generation }; }), conversations: {}, bindings: {}, messages: {}, work: [] };
      let id = selection.conversationId;
      if (selection.messageKey) {
        const message = this.one<ConversationStoreState['messages'][string]>(namespace, 'messages', selection.messageKey);
        if (message) { state.messages[selection.messageKey] = message; id = message.conversationId; }
      }
      if (selection.workId) id = this.one<ConversationStoreState['work'][number]>(namespace, 'work', selection.workId)?.conversationId;
      if (selection.claimAt !== undefined) {
        const row = this.db.prepare(`SELECT w.body FROM records w JOIN records c ON c.ns=w.ns AND c.kind='conversations' AND c.id=json_extract(w.body,'$.conversationId')
          WHERE w.ns=? AND w.kind='work' AND json_extract(w.body,'$.phase') IN ('pending','claimed','held')
          AND json_extract(c.body,'$.childId') IS NULL AND (
            (json_extract(c.body,'$.responder')='human' AND coalesce(json_extract(c.body,'$.humanUntil'),0)<=?) OR
            (json_extract(c.body,'$.responder')!='human' AND json_extract(c.body,'$.status')!='queued' AND json_extract(w.body,'$.phase') IN ('pending','claimed')
              AND (json_extract(w.body,'$.phase')='pending' OR coalesce(json_extract(w.body,'$.leaseUntil'),0)<=?)
              AND NOT EXISTS (SELECT 1 FROM records earlier WHERE earlier.ns=w.ns AND earlier.kind='work' AND earlier.rowid<w.rowid
                AND json_extract(earlier.body,'$.conversationId')=json_extract(w.body,'$.conversationId') AND json_extract(earlier.body,'$.phase') IN ('pending','claimed'))))
          ORDER BY w.rowid LIMIT 1`).get(namespace, selection.claimAt, selection.claimAt);
        if (row) { this.metrics.rowsRead++; id = JSON.parse(row.body as string).conversationId; }
      }
      const target = id ? this.one<ConversationRecord>(namespace, 'conversations', id) : undefined;
      if (!target) return state;
      for (const row of this.rows(namespace, 'conversations', "AND json_extract(body,'$.bindingId')=?", [target.bindingId])) {
        const conversation: ConversationRecord = JSON.parse(row.body);
        const events = this.db.prepare('SELECT body FROM events WHERE ns=? AND conversation=? ORDER BY seq').all(namespace, row.id);
        this.metrics.rowsRead += events.length;
        conversation.events = events.map(event => JSON.parse(event.body as string));
        state.conversations[row.id] = conversation;
        state.work.push(...this.rows(namespace, 'work', "AND json_extract(body,'$.conversationId')=? ORDER BY rowid", [row.id]).map(work => JSON.parse(work.body)));
      }
      const binding = this.one<ConversationStoreState['bindings'][string]>(namespace, 'bindings', target.bindingId);
      if (binding) state.bindings[target.bindingId] = binding;
      return state;
    };
    return {
      read: selection => this.run(async () => load(selection)),
      transaction: (selection, change) => this.run(async () => this.atomic(() => {
        const state = load(selection), before = structuredClone(state);
        const result = change(state);
        if (result && typeof (result as { then?: unknown }).then === 'function') throw new TypeError('async conversation transaction');
        if (state.version !== before.version || state.generation !== before.generation || Object.keys(before.conversations).some(id => !Object.hasOwn(state.conversations, id))) throw new TypeError('use an explicit offline reset');
        for (const [id, conversation] of Object.entries(state.conversations)) {
          const oldEvents = before.conversations[id]?.events ?? [];
          if (conversation.events.length < oldEvents.length || oldEvents.some((event, i) => json(event) !== json(conversation.events[i]))) throw new TypeError('events must be append-only');
          for (let seq = oldEvents.length; seq < conversation.events.length; seq++) {
            this.db.prepare('INSERT INTO events VALUES (?,?,?,?)').run(namespace, id, seq, json(conversation.events[seq])); this.metrics.rowsWritten++;
          }
          const { events: _events, ...record } = conversation;
          const { events: _oldEvents, ...old } = before.conversations[id] ?? {};
          if (json(record) !== json(old)) this.put(namespace, 'conversations', id, record);
        }
        this.save(namespace, 'bindings', before.bindings, state.bindings);
        this.save(namespace, 'messages', before.messages, state.messages);
        this.save(namespace, 'work', Object.fromEntries(before.work.map(row => [row.id, row])), Object.fromEntries(state.work.map(row => [row.id, row])));
        return structuredClone(result);
      })),
    };
  }
  issuer(namespace: string): IssuerStore {
    const kinds = ['sessions', 'grants', 'refreshTokens', 'authorizations', 'codes', 'accessTokens', 'replay'] as const;
    const load = (selection: IssuerSelection): IssuerState => {
      const state: IssuerState = { ...this.meta(namespace, 'issuer_meta', () => { const { version, generation, nonces } = initialIssuerState(); return { version, generation, nonces }; }), sessions: {}, grants: {}, refreshTokens: {}, authorizations: {}, codes: {}, accessTokens: {}, replay: {} };
      const get = (kind: typeof kinds[number], id: string | undefined) => {
        if (!id) return;
        const value = this.one(namespace, kind, id);
        if (value !== undefined) (state[kind] as Record<string, unknown>)[id] = value;
      };
      const find = (kind: typeof kinds[number], where: string, ...params: (string | number)[]) => {
        for (const row of this.rows(namespace, kind, where, params)) (state[kind] as Record<string, unknown>)[row.id] = JSON.parse(row.body);
      };
      if (selection.kind === 'access') get('accessTokens', selection.hash);
      if (selection.kind === 'principal') { get('sessions', selection.sessionId); get('grants', selection.grantId); }
      if (selection.kind === 'authorization') get('authorizations', selection.id);
      if (selection.kind === 'token') {
        get('sessions', selection.sessionId); get('codes', selection.codeHash); get('refreshTokens', selection.refreshHash);
        for (const key of selection.replayKeys) get('replay', key);
        const counts = this.db.prepare("SELECT count(*) AS n, min(json_extract(body,'$.expiresAt')) AS expiry FROM records WHERE ns=? AND kind='sessions' AND json_extract(body,'$.clientId')=? AND json_extract(body,'$.expiresAt')>?").get(namespace, selection.clientId, selection.at)!;
        state.limits = { sessions: Number(counts.n), earliestSessionExpiry: Number(counts.expiry ?? selection.at), pending: 0, pendingForClient: 0 };
      }
      if (selection.kind === 'revoke') { get('refreshTokens', selection.refreshHash); get('replay', selection.replayKey); }
      if (selection.kind === 'authorize') {
        const pending = this.db.prepare("SELECT count(*) AS n FROM records WHERE ns=? AND kind='authorizations' AND json_extract(body,'$.expiresAt')>?").get(namespace, selection.at)!;
        const client = this.db.prepare("SELECT count(*) AS n FROM records WHERE ns=? AND kind='authorizations' AND json_extract(body,'$.clientId')=? AND json_extract(body,'$.expiresAt')>?").get(namespace, selection.clientId, selection.at)!;
        state.limits = { sessions: 0, earliestSessionExpiry: 0, pending: Number(pending.n), pendingForClient: Number(client.n) };
      }
      if (selection.kind === 'disconnect') for (const kind of ['grants', 'codes'] as const) find(kind, "AND json_extract(body,'$.clientId')=? AND json_extract(body,'$.accountId')=?", selection.clientId, selection.accountId);
      for (const record of Object.values(state.accessTokens)) { get('sessions', record.sessionId); if (record.grantId) get('grants', record.grantId); }
      for (const record of [...Object.values(state.sessions), ...Object.values(state.codes)]) if (record.grantId) get('grants', record.grantId);
      for (const id of Object.values(state.refreshTokens)) get('grants', id);
      for (const [id, grant] of Object.entries(state.grants)) {
        get('refreshTokens', grant.refreshHash); get('refreshTokens', grant.previousHash);
        if (['token', 'revoke', 'disconnect'].includes(selection.kind)) find('sessions', "AND json_extract(body,'$.grantId')=?", id);
      }
      return state;
    };
    return {
      read: selection => this.run(async () => load(selection)),
      transaction: (selection, change) => this.run(async () => this.atomic(() => {
        const state = load(selection), before = structuredClone(state);
        const result = change(state);
        if (result && typeof (result as { then?: unknown }).then === 'function') throw new TypeError('async issuer transaction');
        for (const kind of kinds) this.save(namespace, kind, before[kind], state[kind]);
        const { version, generation, nonces } = state;
        if (json({ version, generation, nonces }) !== json({ version: before.version, generation: before.generation, nonces: before.nonces })) this.put(namespace, 'issuer_meta', 'meta', { version, generation, nonces });
        return structuredClone(result);
      })),
    };
  }
  /** Bounded maintenance; never deletes message receipts, events, grants or work intent. */
  cleanup(namespace: string, now: number, limit = 100): Promise<number> {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 1000) throw new TypeError('cleanup limit');
    return this.run(async () => {
      const rows = this.db.prepare(`SELECT kind,id FROM records WHERE ns=? AND
        ((kind IN ('authorizations','codes','accessTokens') AND json_extract(body,'$.expiresAt')<=?) OR (kind='replay' AND CAST(body AS REAL)<?)) LIMIT ?`).all(namespace, now, now, limit);
      for (const row of rows) this.db.prepare('DELETE FROM records WHERE ns=? AND kind=? AND id=?').run(namespace, row.kind, row.id);
      return rows.length;
    });
  }
}
