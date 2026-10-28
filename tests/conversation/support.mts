import type {ConversationOptions,ConversationStoreState} from '../../dist/conversation/service.js';
import type {ConversationSelection} from '../../dist/conversation/store.js';
import type {IssuerSelection} from '../../dist/reference-auth/store.js';
import type {Principal,AuthorityPolicy,RequestAuthenticator} from '../../dist/auth/authority.js';
import type {ConversationState,ConversationEvent,Status,AuthorType,Message} from '../../dist/protocol/wire.js';
import assert from 'node:assert/strict';
import { AsyncLocalStorage } from 'node:async_hooks';
import { AuthorityError, createConversationService, initialConversationState } from '../../dist/index.js';

// Strict JSON in-memory store: detached values, rollback on throw, rejects undefined fields and async callbacks.
export function memoryStore<S>(initial:S) {
  let state = structuredClone(initial);
  let queue:Promise<unknown> = Promise.resolve();
  const store = {
    transactions: 0,
    afterRead: null as ((state:S)=>unknown|Promise<unknown>)|null, // test hook: runs once between a read and the next transaction
    reads: 0, readWaiters: [] as {count:number;resolve:()=>void}[],
    async read(_selection?:ConversationSelection|IssuerSelection) {
      const copy = structuredClone(state);
      store.reads++;
      store.readWaiters = store.readWaiters.filter(waiter => store.reads < waiter.count || void waiter.resolve());
      const hook = store.afterRead; store.afterRead = null; await hook?.(state); return copy;
    },
    // Resolves once the store has served `count` reads in total: lets a test act exactly when a long poll is holding.
    untilReads(count:number) { return new Promise<void>(resolve => { if (store.reads >= count) resolve(); else store.readWaiters.push({ count, resolve }); }); },
    transaction<T>(selection:ConversationSelection|IssuerSelection|((draft:S)=>T),change?: (draft:S)=>T) {
      const mutate=typeof selection==='function'?selection:change;assert.ok(mutate);
      const run = queue.then(() => {
        const draft = structuredClone(state);
        const result = mutate(draft);
        if(result&&typeof result==='object'&&'then' in result&&typeof result.then==='function') throw new Error('async transaction callback');
        assert.deepStrictEqual(JSON.parse(JSON.stringify(draft)), draft, 'state must be strict JSON');
        state = structuredClone(draft); store.transactions++;
        return structuredClone(result);
      });
      queue = run.catch(() => {});
      return run;
    },
    set(mutate:(state:S)=>void) { mutate(state); },
  };
  return store;
}

// Same contract as the demo SQLite coordinator, in one process: one holder at a time, released on throw, no nesting.
export function memoryCoordinator() {
  const inside = new AsyncLocalStorage<boolean>();
  let queue:Promise<unknown> = Promise.resolve();
  const coordinator = {
    held: false, runs: 0,
    run<T>(action:()=>Promise<T>) {
      if (inside.getStore()) return Promise.reject(new Error('nested coordinator run'));
      const run = queue.then(() => { coordinator.held = true; coordinator.runs++; return inside.run(true, action); }).finally(() => { coordinator.held = false; });
      queue = run.catch(() => {});
      return run;
    },
  };
  return coordinator;
}

interface CallOptions {as?:string;body?:unknown;query?:string;signal?:AbortSignal}
export const endpoint = 'https://api.example.test/poppy/conversations';
const base = { issuer: 'https://auth.example.test', clientId: 'https://agent.example.test/client', sessionId: 's1', scopes: [], tokenExpiresAt: 9e12, sessionVersion: 1 };
export const principals:Record<string,Principal> = {
  alice: { ...base, userId: 'u_alice' },
  aliceSignedIn: { ...base, userId: 'u_alice', accountId: 'acct_1', scopes: ['orders:read'] },
  aliceCustomScope: { ...base, userId: 'u_alice', accountId: 'acct_1', scopes: ['shop:history'] },
  aliceNoScopes: { ...base, userId: 'u_alice', accountId: 'acct_1', scopes: [] },
  aliceOtherAccount: { ...base, userId: 'u_alice', accountId: 'acct_2', scopes: ['orders:read'] },
  bob: { ...base, userId: 'u_bob' },
  bobOtherAccount: { ...base, userId: 'u_bob', accountId: 'acct_2', scopes: ['orders:read'] },
  carolSameAccount: { ...base, userId: 'u_carol', accountId: 'acct_1', scopes: ['orders:read'] },
  otherClientSameAccount: { ...base, clientId: 'https://evil.example.test/client', userId: 'u_alice', accountId: 'acct_1', scopes: ['orders:read'] },
  otherClientNoScopes: { ...base, clientId: 'https://evil.example.test/client', userId: 'u_alice', accountId: 'acct_1', scopes: [] },
  otherClient: { ...base, clientId: 'https://evil.example.test/client', userId: 'u_alice' },
};

export function setup(options:Partial<ConversationOptions> = {}) {
  let now = Date.UTC(2026, 9, 19, 12);
  const clock = { now: () => now, advance(ms:number) { now += ms; } };
  const store = memoryStore(initialConversationState());
  const calls:{kind:string;userId:string;scopes:string[]}[] = [];
  const authenticator:RequestAuthenticator = {
    async authenticate(request) {
      const token = /^DPoP (\w+)$/.exec(request.headers.get('authorization') ?? '')?.[1];
      if (!token || !principals[token]) throw new AuthorityError('invalid_token');
      return principals[token];
    },
  };
  const policy:AuthorityPolicy & {deny:Error|null;denyCurrent:Error|null} = {
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
  const service = createConversationService({ historyScopes: ['orders:read'], endpoint, store, authenticator, policy, clock, ...options });
  async function call(method:string,path:string, { as = 'alice', body, query = '', signal }:CallOptions = {}) {
    const response = await service.handle(new Request(`${endpoint}${path}${query}`, {
      method, signal, headers: { authorization: `DPoP ${as}`, 'content-type': 'application/json' },
      body: body === undefined ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
    }));
    return { status: response.status, headers: response.headers, body: await response.json() };
  }
  const start = (message:unknown,opts?:CallOptions) => call('POST', '', { ...opts, body: { message } });
  const send = (id:string,message:unknown,opts?:CallOptions) => call('POST', `/${id}/messages`, { ...opts, body: { message } });
  const read = (id:string,opts?:CallOptions) => call('GET', `/${id}/events`, opts);
  const direct = (parentId:string,message:unknown,opts?:CallOptions) => call('POST', '', { ...opts, body: { parent_conversation_id: parentId, message } });
  const handoff = (id:string,opts?:CallOptions) => call('POST', `/${id}/handoff`, { body: {}, ...opts });
  const close = (id:string,opts?:CallOptions) => call('POST', `/${id}/close`, { body: {}, ...opts });
  return { service, store, clock, calls, policy, call, start, send, read, direct, handoff, close };
}

export const hello = { id: 'msg_1', author: { type: 'agent' }, text: 'Where is order 1042?', data: { b: 1, a: [1, 2] }, x_extension: { keep: true } } satisfies Message;
