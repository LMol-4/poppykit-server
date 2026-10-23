import { AsyncLocalStorage } from 'node:async_hooks';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import type { Pool, PoolClient, PoolConfig, QueryResult, QueryResultRow } from 'pg';

export type PostgresSchema = 'poppy_client' | 'poppy_provider' | 'poppy_server';
export type PostgresConnection = { query<R extends QueryResultRow = QueryResultRow>(sql: string, values?: unknown[]): Promise<QueryResult<R>> };
export function json(value: unknown): string {
  return JSON.stringify(value, (_key, item) => {
    if (item === undefined || typeof item === 'function' || typeof item === 'bigint' || (typeof item === 'number' && !Number.isFinite(item))) throw new TypeError('non-JSON record');
    return item;
  });
}
export function synchronous<T>(value: T): T {
  if (value && typeof (value as { then?: unknown }).then === 'function') throw new TypeError('transaction callback must be synchronous');
  return structuredClone(value);
}
/** Remote defaults verify TLS; plaintext must be explicitly selected for a trusted local test server. */
export function createPostgresPool(config: PoolConfig): Pool {
  if (config.ssl && typeof config.ssl === 'object' && config.ssl.rejectUnauthorized === false) throw new TypeError('Postgres TLS verification is required');
  if (config.connectionString && [...new URL(config.connectionString).searchParams.keys()].some(key => key.toLowerCase().startsWith('ssl') || key === 'uselibpqcompat')) throw new TypeError('configure verified TLS through ssl, not connection-string overrides');
  return new pg.Pool({ max: 2, connectionTimeoutMillis: 3000, idleTimeoutMillis: 10000, ...config, ssl: config.ssl ?? { rejectUnauthorized: true } });
}
export const postgresSchemaVersion = 1;
function schemaName(schema: PostgresSchema): PostgresSchema {
  if (!['poppy_client','poppy_provider','poppy_server'].includes(schema)) throw new TypeError('unsupported Postgres schema');
  return schema;
}
export async function postgresMigration(schema: PostgresSchema): Promise<string> {
  schemaName(schema);
  return readFile(new URL(`../migrations/postgres/0001_${schema}.sql`, import.meta.url), 'utf8');
}
/** Explicit administration only. Constructors never execute DDL. */
export async function migratePostgres(pool: Pool, schema: PostgresSchema): Promise<void> {
  schemaName(schema);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL statement_timeout='5s'");
    await client.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`poppykit:migrate:${schema}`]);
    const exists = (await client.query('SELECT to_regclass($1) AS name', [`${schema}.schema_version`])).rows[0].name;
    if (exists) {
      const rows = (await client.query(`SELECT version FROM ${schema}.schema_version`)).rows;
      if (rows.length !== 1 || rows[0].version !== postgresSchemaVersion) throw new Error('unsupported Postgres schema version');
    } else await client.query(await postgresMigration(schema));
    await client.query('COMMIT');
  } catch (error) { await client.query('ROLLBACK'); throw error; }
  finally { client.release(); }
}

type Context = { client: PoolClient; active: boolean; locks: Set<string>; state: { serial: number }; childActive: boolean };
export class PostgresRuntime {
  private readonly context = new AsyncLocalStorage<Context>();
  private closed = false;
  readonly metrics = { rowsRead: 0, rowsWritten: 0 };
  constructor(readonly pool: Pool, readonly schema: PostgresSchema, private readonly ownsPool = false) {}
  async close(): Promise<void> { this.closed = true; if (this.ownsPool) await this.pool.end(); }
  async run<T>(action: () => Promise<T>): Promise<T> {
    if (this.closed) throw new Error('Postgres adapter is closed');
    const parent = this.context.getStore();
    if (parent) {
      if (!parent.active) throw new Error('expired Postgres transaction');
      if (parent.childActive) throw new Error('concurrent nested Postgres transactions are unsupported; await each mutation');
      parent.childActive = true;
      const savepoint = `nested_${++parent.state.serial}`;
      const child: Context = { ...parent, active: true, childActive: false, locks: new Set(parent.locks) };
      let started = false;
      try {
        await parent.client.query(`SAVEPOINT ${savepoint}`); started = true;
        const result = await this.context.run(child, action);
        await parent.client.query(`RELEASE SAVEPOINT ${savepoint}`); parent.locks = child.locks; return result;
      } catch (error) {
        if (started) { await parent.client.query(`ROLLBACK TO SAVEPOINT ${savepoint}`); await parent.client.query(`RELEASE SAVEPOINT ${savepoint}`); }
        throw error;
      } finally { child.active = false; parent.childActive = false; }
    }
    const client = await this.pool.connect(), context: Context = { client, active: true, locks: new Set(), state: { serial: 0 }, childActive: false };
    try {
      await client.query('BEGIN');
      await client.query("SET LOCAL statement_timeout='5s'");
      await client.query("SET LOCAL lock_timeout='2s'");
      await client.query("SET LOCAL idle_in_transaction_session_timeout='5s'");
      await client.query("SET LOCAL transaction_timeout='5s'");
      const versions = (await client.query(`SELECT version FROM ${this.schema}.schema_version`)).rows;
      if (versions.length !== 1 || versions[0].version !== postgresSchemaVersion) throw new Error('unsupported Postgres schema version');
      const result = await this.context.run(context, action);
      await client.query('COMMIT'); return result;
    } catch (error) { await client.query('ROLLBACK').catch(() => {}); throw error; }
    finally { context.active = false; client.release(); }
  }
  connection(): PostgresConnection {
    const context = this.context.getStore();
    if (!context?.active) throw new Error('no active Postgres transaction');
    return { query: async (sql, values) => {
      if (!context.active || this.context.getStore() !== context) throw new Error('expired Postgres transaction');
      if (context.childActive) throw new Error('concurrent Postgres transaction use is unsupported; await each mutation');
      return context.client.query(sql, values);
    } };
  }
  async query<R extends QueryResultRow = QueryResultRow>(sql: string, values: unknown[] = []): Promise<R[]> {
    const result = await this.connection().query<R>(sql, values); this.metrics.rowsRead += result.rows.length; return result.rows;
  }
  async lock(key: string): Promise<void> {
    const context = this.context.getStore();
    if (!context?.active) throw new Error('no active Postgres transaction');
    if (!context.locks.has(key)) { await this.query('SELECT pg_advisory_xact_lock(hashtextextended($1,0))', [`${this.schema}:${key}`]); context.locks.add(key); }
  }
}
