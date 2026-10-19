import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { AuthorityError, createConversationService, initialConversationState } from '../../dist/index.js';

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

export const endpoint = 'https://api.example.test/poppy/conversations';
const base = { issuer: 'https://auth.example.test', clientId: 'https://agent.example.test/client', sessionId: 's1', scopes: [], tokenExpiresAt: 9e12, sessionVersion: 1 };
export const principals = {
  alice: { ...base, userId: 'u_alice' },
  aliceSignedIn: { ...base, userId: 'u_alice', accountId: 'acct_1', scopes: ['poppy:read'] },
  aliceNoScopes: { ...base, userId: 'u_alice', accountId: 'acct_1', scopes: [] },
  aliceOtherAccount: { ...base, userId: 'u_alice', accountId: 'acct_2', scopes: ['poppy:read'] },
  bob: { ...base, userId: 'u_bob' },
  bobOtherAccount: { ...base, userId: 'u_bob', accountId: 'acct_2', scopes: ['poppy:read'] },
  carolSameAccount: { ...base, userId: 'u_carol', accountId: 'acct_1', scopes: ['poppy:read'] },
  otherClientSameAccount: { ...base, clientId: 'https://evil.example.test/client', userId: 'u_alice', accountId: 'acct_1', scopes: ['poppy:read'] },
  otherClientNoScopes: { ...base, clientId: 'https://evil.example.test/client', userId: 'u_alice', accountId: 'acct_1', scopes: [] },
  otherClient: { ...base, clientId: 'https://evil.example.test/client', userId: 'u_alice' },
};

export function setup(options = {}) {
  let now = Date.UTC(2026, 9, 19, 12);
  const clock = { now: () => now, advance(ms) { now += ms; } };
  const store = memoryStore(initialConversationState());
  const calls = [];
  const authenticator = {
    async authenticate(request) {
      const token = /^DPoP (\w+)$/.exec(request.headers.get('authorization') ?? '')?.[1];
      if (!token || !principals[token]) throw new AuthorityError('invalid_token');
      return principals[token];
    },
  };
  const policy = {
    deny: null, denyCurrent: null,
    async withCurrent(principal, scopes, action) {
      calls.push({ kind: 'current', userId: principal.userId, scopes: [...scopes] });
      if (policy.deny ?? policy.denyCurrent) throw policy.deny ?? policy.denyCurrent;
      if (!scopes.every(scope => principal.scopes.includes(scope))) throw new AuthorityError('insufficient_scope', { scope: scopes.join(' ') });
      return action();
    },
    async withAccepted(authority, scopes, action) {
      calls.push({ kind: 'accepted', userId: authority.principal.userId, scopes: [...scopes] });
      if (policy.deny) throw policy.deny;
      if (!scopes.every(scope => authority.principal.scopes.includes(scope))) throw new AuthorityError('insufficient_scope', { scope: scopes.join(' ') });
      return action();
    },
  };
  const service = createConversationService({ endpoint, store, authenticator, policy, clock, ...options });
  async function call(method, path, { as = 'alice', body, query = '', signal } = {}) {
    const response = await service.handle(new Request(`${endpoint}${path}${query}`, {
      method, signal, headers: { authorization: `DPoP ${as}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    }));
    return { status: response.status, headers: response.headers, body: await response.json() };
  }
  const start = (message, opts) => call('POST', '', { ...opts, body: { message } });
  const send = (id, message, opts) => call('POST', `/${id}/messages`, { ...opts, body: { message } });
  const read = (id, opts) => call('GET', `/${id}/events`, opts);
  const direct = (parentId, message, opts) => call('POST', '', { ...opts, body: { parent_conversation_id: parentId, message } });
  const handoff = (id, opts) => call('POST', `/${id}/handoff`, { body: {}, ...opts });
  const close = (id, opts) => call('POST', `/${id}/close`, { body: {}, ...opts });
  return { service, store, clock, calls, policy, call, start, send, read, direct, handoff, close };
}

export const hello = { id: 'msg_1', sender: 'agent', text: 'Where is order 1042?', data: { b: 1, a: [1, 2] }, x_extension: { keep: true } };
