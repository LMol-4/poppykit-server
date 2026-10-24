import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';

export function checkPostgresTap(output: string, minimum: number, required: readonly string[]): number {
  const count = (name: string) => { const matches = [...output.matchAll(new RegExp(`^# ${name} (\\d+)$`, 'gm'))]; assert.equal(matches.length, 1, `missing/duplicate TAP ${name}`); return Number(matches[0][1]); };
  const total = count('tests'); assert.ok(total >= minimum, 'Postgres test discovery shrank');
  assert.equal(count('pass'), total); for (const name of ['fail', 'cancelled', 'skipped', 'todo']) assert.equal(count(name), 0, `Postgres ${name}`);
  for (const name of required) assert.ok(output.includes(` ${name}\n`) || output.includes(` ${name}\r\n`), `missing Postgres contract: ${name}`);
  return total;
}

async function main() {
  const { createPostgresPool, migratePostgres } = await import('../dist/postgres.js');
  assert.equal(process.env.POPPY_DISPOSABLE_POSTGRES, '1', 'a dedicated disposable cluster is required');
  assert.equal(process.env.PGHOST, '127.0.0.1', 'CI must not use a cloud/shared database');
  const pkg = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const client = pkg.name === '@poppykit/client'; assert.ok(client || pkg.name === '@poppykit/server');
  const schemas = client ? ['poppy_client', 'poppy_provider'] as const : ['poppy_server'] as const;
  const pool = createPostgresPool({ host: process.env.PGHOST, port: Number(process.env.PGPORT), user: process.env.PGUSER, password: process.env.PGPASSWORD, database: process.env.PGDATABASE, ssl: false, max: 2 });
  try {
    const version = String((await pool.query('SHOW server_version_num')).rows[0].server_version_num);
    assert.match(version, /^17\d{4}$/, 'Postgres 17 required');
    assert.equal((await pool.query('SELECT nspname FROM pg_namespace WHERE nspname=ANY($1)', [schemas])).rowCount, 0, 'refuse an existing SDK database');
    for (const schema of schemas) await migratePostgres(pool, schema);
    const files = client ? ['tests/provider.test.mjs', 'tests/postgres.test.mjs', 'tests/adapter-contract.test.mjs', 'tests/auth/client-auth.test.mjs']
      : ['tests/postgres-storage.test.mjs', 'tests/postgres-lifecycle.test.mjs', 'tests/issuer-contract.test.mjs', 'tests/conversation/postgres-adapter-contract.test.mjs'];
    const result = spawnSync(process.execPath, ['--no-experimental-strip-types', '--test', '--test-reporter=tap', '--test-concurrency=1', ...files], {
      env: { ...process.env, D1_POSTGRES: '1', D1_NAMESPACE: `postgres-ci-${randomUUID()}` }, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024, windowsHide: true,
    });
    process.stdout.write(result.stdout ?? ''); process.stderr.write(result.stderr ?? '');
    if (result.error) throw result.error; assert.equal(result.status, 0, 'Postgres contracts failed');
    const required = client ? ['global auth history pruning uses bounded durable selectors (Postgres)', 'callback results encrypted, correlated, atomic, one time; restart, replay, cancel and expiry']
      : ['Direct completion survives lost commit responses, independent handles and restart without minting a new callback', 'adapter contract: reserved output IDs persist atomic reply and prompt receipts across handles'];
    console.log(JSON.stringify({ postgresVersion: version, tests: checkPostgresTap(result.stdout, client ? 160 : 22, required), skipped: 0 }));
  } finally { await pool.end(); }
  // The caller owns and destroys the entire isolated cluster, including roles/resources.
}
if (process.argv[1] && new URL(import.meta.url).href === pathToFileURL(process.argv[1]).href) await main();
