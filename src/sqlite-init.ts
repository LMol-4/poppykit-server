import type { DatabaseSync } from 'node:sqlite';

// SQLite may return BUSY immediately when two processes first enable WAL, despite busy_timeout.
export function initializeSqlite(db: DatabaseSync, initialize: () => void): void {
  const deadline = Date.now() + 5000;
  for (;;) {
    try { initialize(); return; }
    catch (error) {
      if (![5, 6].includes((error as { errcode?: number }).errcode ?? 0) || Date.now() >= deadline) { db.close(); throw error; }
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 10);
    }
  }
}
