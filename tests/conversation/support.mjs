import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';

// Strict JSON in-memory store: detached values, rollback on throw, rejects undefined fields and async callbacks.
export function memoryStore(initial) {
  let state = structuredClone(initial);
  let queue = Promise.resolve();
  const store = {
    transactions: 0,
    afterRead: null, // test hook: runs once between a read and the next transaction
    async read() { const copy = structuredClone(state); const hook = store.afterRead; store.afterRead = null; await hook?.(state); return copy; },
    transaction(change) {
      const run = queue.then(() => {
        const draft = structuredClone(state);
        const result = change(draft);
        if (result && typeof result.then === 'function') throw new Error('async transaction callback');
        assert.deepStrictEqual(JSON.parse(JSON.stringify(draft)), draft, 'state must be strict JSON');
        state = draft; store.transactions++;
        return result === undefined ? undefined : structuredClone(result);
      });
      queue = run.catch(() => {});
      return run;
    },
    set(mutate) { mutate(state); },
  };
  return store;
}

// Same contract as the demo SQLite coordinator, in one process: one holder at a time, released on throw, no nesting.
export function memoryCoordinator() {
  const inside = new AsyncLocalStorage();
  let queue = Promise.resolve();
  const coordinator = {
    held: false, runs: 0,
    run(action) {
      if (inside.getStore()) return Promise.reject(new Error('nested coordinator run'));
      const run = queue.then(() => { coordinator.held = true; coordinator.runs++; return inside.run(true, action); }).finally(() => { coordinator.held = false; });
      queue = run.catch(() => {});
      return run;
    },
  };
  return coordinator;
}
