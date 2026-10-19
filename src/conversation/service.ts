import { randomBytes } from 'node:crypto';
import { setTimeout as sleep } from 'node:timers/promises';
import { ValidationError, object, parseConversationRequest, parseMessage, parseReadOptions } from '../protocol/wire.js';
import type { ConversationEvent, ConversationRequest, JsonObject, Message, RecordedMessage, Sender, Status } from '../protocol/wire.js';
import { secureUrl } from '../network/transport.js';
import { AuthorityError } from '../auth/authority.js';
import type { AcceptedAuthority, AuthorityPolicy, Principal, RequestAuthenticator, WorkRevocationPolicy } from '../auth/authority.js';

interface StateStore<State> {
  read(): Promise<State>;
  transaction<T>(change: (draft: State) => T): Promise<T>;
}
export interface ConversationRecord {
  id: string; issuer: string; clientId: string; userId: string; bindingId: string;
  status: Status; responder: Sender; context: JsonObject; events: ConversationEvent[];
  authority: AcceptedAuthority; // of the latest accepted message; staff operations act under it
  parentId?: string; // set on a Direct Conversation
  childId?: string; // the parent's open Direct Conversation
}
export interface WorkRecord {
  id: string; conversationId: string; message: Message; authority: AcceptedAuthority;
  phase: 'pending' | 'claimed' | 'completed' | 'suspended' | 'failed' | 'cancelled';
  fence?: string; leaseUntil?: number;
  human?: true; // a staff attempt: no lease, never claimed by automation
  outputs: Record<string, string>; // outputId -> canonical payload
}
export interface MessageRecord { conversationId: string; fingerprint: string; receipt: { status: number; body: JsonObject } }
export interface ConversationStoreState {
  version: 1; generation: string;
  conversations: Record<string, ConversationRecord>;
  bindings: Record<string, { accountId?: string }>;
  messages: Record<string, MessageRecord>; // keyed by JSON [issuer, clientId, userId, messageId]
  work: WorkRecord[];
}
export interface ConversationOptions {
  endpoint: string;
  store: StateStore<ConversationStoreState>;
  authenticator: RequestAuthenticator;
  policy: AuthorityPolicy;
  clock: { now(): number };
  revocationPolicy?: WorkRevocationPolicy;
  pageSize?: number;
  leaseMs?: number;
  pollIntervalMs?: number; // long-poll store checks, outside all locks
  /** Mandatory for staff methods: authenticate and authorize this company operator for the conversation, or throw. */
  authorizeOperator?: (operator: unknown, conversationId: string) => Promise<void>;
}
export interface WorkRef { workId: string; fence: string }
export interface WorkClaim extends WorkRef { conversationId: string; message: Message; context: JsonObject }
export interface ConversationService {
  /** Protocol errors become responses; anything else is re-thrown, so hosts must catch it and answer 500. */
  handle(request: Request): Promise<Response>;
  claim(): Promise<WorkClaim | null>;
  renew(work: WorkRef): Promise<void>;
  /** Conversation history for a model or handler; account-bound history needs the bound account and poppy:read. */
  history(work: WorkRef): Promise<ConversationEvent[]>;
  /** Account-use gate: call before any account read or tool. Checks accepted authority, then binds the shared ownership once. */
  requireAccount(work: WorkRef, scopes: readonly string[]): Promise<{ accountId: string }>;
  reply(work: WorkRef, outputId: string, message: Message): Promise<void>;
  finish(work: WorkRef, outcome: 'completed' | 'suspended' | 'failed'): Promise<void>;
  /** The company asks for a person on its own: this attempt ends and the conversation is queued. */
  handoff(work: WorkRef): Promise<void>;
  /** The company closes the conversation (and its open Direct Conversation); idempotent. */
  close(work: WorkRef): Promise<void>;
  /** A person joins: automated work is fenced and the returned claim publishes with sender human. */
  joinHuman(operator: unknown, conversationId: string): Promise<WorkClaim>;
  /** Nobody can join a queued conversation: the agent says why and the conversation leaves the queue. No-op unless queued. */
  noHumanAvailable(operator: unknown, conversationId: string, reason: string): Promise<void>;
  /** The person hands back to automation; their claim stops working. No-op unless a person is responding. */
  returnToAgent(operator: unknown, conversationId: string): Promise<void>;
}
export class PublicationError extends Error {
  constructor(readonly code: 'stale_work' | 'output_conflict') { super(`Publication rejected: ${code}`); this.name = 'PublicationError'; }
}

const maxBodyBytes = 1048576;
const maxWaitSeconds = 30;
const randomId = (prefix: string) => prefix + randomBytes(16).toString('base64url');
const own = <T>(record: Record<string, T>, key: string): T | undefined => Object.hasOwn(record, key) ? record[key] : undefined;

export function initialConversationState(): ConversationStoreState {
  return { version: 1, generation: randomId(''), conversations: {}, bindings: {}, messages: {}, work: [] };
}
/** For the host's reset transaction: a fresh state with a new generation, so every old fence is stale. */
export function resetConversationState(draft: ConversationStoreState): void {
  Object.assign(draft, initialConversationState());
}

class HttpError extends Error {
  constructor(readonly status: number, readonly body: JsonObject, readonly headers: HeadersInit = {}) { super(String(body.error)); }
}
class Rescope extends Error {}
const notFound = () => new HttpError(404, { error: 'conversation_not_found' });
const closed = () => new HttpError(409, { error: 'conversation_closed' });
const directOpen = (childId: string) => new HttpError(409, { error: 'direct_conversation_open', conversation_id: childId });
const unfinished = (work: WorkRecord) => work.phase === 'pending' || work.phase === 'claimed';

function json(status: number, body: unknown, headers: HeadersInit = {}): Response {
  const response = Response.json(body, { status, headers });
  response.headers.set('Cache-Control', 'no-store');
  return response;
}

// Key order independent; arrays, strings and unknown members compared exactly.
function canonical(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    const entries = value as Record<string, unknown>;
    return `{${Object.keys(entries).sort().map(key => `${JSON.stringify(key)}:${canonical(entries[key])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

async function readJson(request: Request): Promise<unknown> {
  const chunks: Uint8Array[] = [];
  let size = 0;
  const reader = request.body?.getReader();
  for (let part = await reader?.read(); part && !part.done; part = await reader!.read()) {
    size += part.value.byteLength;
    if (size > maxBodyBytes) { await reader!.cancel(); throw new ValidationError('body'); }
    chunks.push(part.value);
  }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { throw new ValidationError('body'); }
}

export function createConversationService(options: ConversationOptions): ConversationService {
  const { store, authenticator, policy, clock } = options;
  const pageSize = options.pageSize ?? 100;
  const leaseMs = options.leaseMs ?? 60000;
  const pollIntervalMs = options.pollIntervalMs ?? 25;
  const revocationPolicy = options.revocationPolicy ?? 'stop-account-work';
  for (const value of [pageSize, leaseMs, pollIntervalMs]) if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError('Invalid conversation option');
  const endpoint = secureUrl(options.endpoint);
  const basePath = endpoint.pathname.replace(/\/$/, '');

  const timestamp = () => new Date(clock.now()).toISOString();
  function addEvent(conversation: ConversationRecord, event: JsonObject): void {
    conversation.events.push({ id: randomId('evt_'), created_at: timestamp(), ...event } as ConversationEvent);
  }
  function setState(conversation: ConversationRecord, status: Status, responder = conversation.responder): void {
    if (conversation.status === status && conversation.responder === responder) return;
    conversation.status = status;
    conversation.responder = responder;
    addEvent(conversation, { type: 'state', status, responder });
  }
  const newFence = (draft: ConversationStoreState) => `${draft.generation}.${randomId('')}`;
  const idleOrWorking = (draft: ConversationStoreState, id: string): Status =>
    draft.work.some(work => work.conversationId === id && unfinished(work)) ? 'working' : 'idle';
  // Invalidates every current claim on a conversation: automated work returns to pending, or all of it is cancelled.
  // Staff attempts are always cancelled; a person rejoins explicitly.
  function fence(draft: ConversationStoreState, id: string, outcome: 'pending' | 'cancelled'): void {
    for (const work of draft.work) {
      if (work.conversationId !== id || !unfinished(work)) continue;
      work.phase = outcome === 'cancelled' || work.human ? 'cancelled' : 'pending';
      delete work.fence;
      delete work.leaseUntil;
    }
  }
  function requestHandoff(draft: ConversationStoreState, conversation: ConversationRecord): void {
    if (conversation.status === 'queued' || conversation.responder === 'human') return;
    // The handed-off request is for a person now, so automation drops it rather than retrying it.
    fence(draft, conversation.id, 'cancelled');
    setState(conversation, 'queued');
  }
  // User messages after event index `after` that nobody answered become automated work, under the latest authority.
  function requeueUnanswered(draft: ConversationStoreState, conversation: ConversationRecord, after: number): void {
    for (const event of conversation.events.slice(after + 1)) {
      if (event.type !== 'message') continue;
      const { role, ...message } = event.message as RecordedMessage;
      if (role === 'user' && ('text' in message || 'data' in message)) {
        draft.work.push({ id: randomId('wrk_'), conversationId: conversation.id, message, authority: conversation.authority, phase: 'pending', outputs: {} });
      }
    }
  }
  // Closing a parent closes its open Direct Conversation first; closing a child reopens its parent for messages.
  function closeConversation(draft: ConversationStoreState, conversation: ConversationRecord): void {
    if (conversation.status === 'closed') return;
    if (conversation.childId !== undefined) closeConversation(draft, draft.conversations[conversation.childId]);
    fence(draft, conversation.id, 'cancelled');
    setState(conversation, 'closed');
    const parent = conversation.parentId === undefined ? undefined : draft.conversations[conversation.parentId];
    if (parent?.childId === conversation.id) {
      delete parent.childId;
      addEvent(parent, { type: 'direct_closed', conversation_id: conversation.id });
    }
  }
  // Each Direct Conversation ran while its parent was suspended, so its events belong right after direct_opened.
  function linkedHistory(draft: ConversationStoreState, conversation: ConversationRecord): ConversationEvent[] {
    const root = conversation.parentId === undefined ? conversation : draft.conversations[conversation.parentId];
    return root.events.flatMap(event => event.type === 'direct_opened' ? [event, ...draft.conversations[event.conversation_id as string].events] : [event]);
  }
  function page(conversation: ConversationRecord, cursor?: string): JsonObject {
    let start = 0;
    if (cursor !== undefined) {
      const index = conversation.events.findIndex(event => event.id === cursor);
      // shortcut: no retention, so cursor_expired never occurs; add expired-cursor markers with a retention job.
      if (index < 0) throw new HttpError(400, { error: 'invalid_cursor' });
      start = index + 1;
    }
    const events = conversation.events.slice(start, start + pageSize);
    return {
      conversation_id: conversation.id, events: events as unknown as JsonObject[], cursor: events.at(-1)?.id ?? cursor ?? null,
      has_more: start + events.length < conversation.events.length, status: conversation.status, responder: conversation.responder,
    };
  }
  function ack(conversation: ConversationRecord): JsonObject {
    return { conversation_id: conversation.id, status: conversation.status, responder: conversation.responder };
  }
  // Account-bound history needs poppy:read; sending alone does not read history. Other readers fail ownership first.
  const scopesFor = (state: ConversationStoreState, principal: Principal, conversation: ConversationRecord | undefined, history: boolean) =>
    // Only an owner may see a scope error; for anyone else ownership fails first with 404, so existence never leaks.
    conversation && history && conversation.issuer === principal.issuer && conversation.clientId === principal.clientId && principal.accountId !== undefined
      && own(state.bindings, conversation.bindingId)?.accountId === principal.accountId ? ['poppy:read'] : [];

  // Spec 7.2: owned by client_id + User ID until account use, then by client_id + account instead.
  function owned(state: ConversationStoreState, principal: Principal, id: string): ConversationRecord {
    const conversation = own(state.conversations, id);
    if (!conversation || conversation.issuer !== principal.issuer || conversation.clientId !== principal.clientId) throw notFound();
    const accountId = own(state.bindings, conversation.bindingId)?.accountId;
    if (accountId === undefined ? conversation.userId === principal.userId : principal.accountId === accountId) return conversation;
    // Spec 7.11: the same User not signed in to the bound account (signed out or another account) is told to sign in; anyone else learns nothing.
    if (accountId !== undefined && conversation.userId === principal.userId) throw new AuthorityError('sign_in_required');
    throw notFound();
  }

  // Runs change under withCurrent; target() and history() decide the scopes from the state being checked.
  async function current<T>(principal: Principal, target: (state: ConversationStoreState) => string | undefined, history: (state: ConversationStoreState) => boolean,
    change: (draft: ConversationStoreState) => T): Promise<T> {
    for (;;) {
      const before = await store.read();
      const id = target(before);
      const scopes = scopesFor(before, principal, id === undefined ? undefined : own(before.conversations, id), history(before));
      const result = await policy.withCurrent(principal, scopes, () => store.transaction(draft => {
        const now = target(draft);
        // Binding only ever gains an account, so a rerun with the wider scopes settles it.
        if (scopesFor(draft, principal, now === undefined ? undefined : own(draft.conversations, now), history(draft)).length > scopes.length) return { rescope: true } as const;
        return { value: change(draft) };
      }));
      if (!('rescope' in result)) return result.value;
    }
  }

  async function accept(request: Request, principal: Principal, url: URL, conversationId?: string): Promise<Response> {
    const read = parseReadOptions(url, maxWaitSeconds);
    const waiting = url.searchParams.has('wait');
    const body: ConversationRequest = parseConversationRequest(await readJson(request));
    const parentId = conversationId === undefined ? body.parent_conversation_id : undefined;
    // A Direct Conversation carries the User's own words (7.10).
    if (parentId !== undefined && body.message.sender !== 'human') throw new ValidationError('message.sender');
    const key = JSON.stringify([principal.issuer, principal.clientId, principal.userId, body.message.id]);
    const fingerprint = canonical({ target: conversationId ?? null, request: body });
    const authority = JSON.parse(JSON.stringify({ principal, acceptedAt: clock.now(), revocationPolicy })) as AcceptedAuthority;
    // A new Direct Conversation shares its parent's binding, so the parent decides the scopes.
    const target = (state: ConversationStoreState) => conversationId ?? own(state.messages, key)?.conversationId ?? parentId;
    // A retry returns the saved receipt, which is a history page if the original request waited.
    const history = (state: ConversationStoreState) => waiting || 'events' in (own(state.messages, key)?.receipt.body ?? {});

    const receipt = await current(principal, target, history, draft => {
      if (conversationId !== undefined) owned(draft, principal, conversationId);
      const existing = own(draft.messages, key);
      if (existing) {
        // Ownership first, so a foreign account learns nothing from a conflict.
        owned(draft, principal, existing.conversationId);
        if (existing.fingerprint !== fingerprint) throw new HttpError(409, { error: 'message_id_conflict' });
        return existing.receipt;
      }
      let conversation: ConversationRecord;
      if (conversationId === undefined) {
        if (read.cursor !== undefined) throw new HttpError(400, { error: 'invalid_cursor' });
        const id = randomId('cnv_');
        let bindingId = id;
        if (parentId === undefined) draft.bindings[id] = {};
        else {
          // Same serialized transition as account binding: the child joins whatever binding the parent has now.
          const parent = owned(draft, principal, parentId);
          if (parent.parentId !== undefined) throw notFound();
          if (parent.status === 'closed') throw closed();
          if (parent.childId !== undefined) throw directOpen(parent.childId);
          // Parent automation pauses while the Direct Conversation is open; its current attempt can no longer publish.
          // A person handling the parent loses their claim but stays responder: staff hosts rejoin or returnToAgent after the child closes.
          fence(draft, parent.id, 'pending');
          parent.childId = id;
          bindingId = parent.bindingId;
          addEvent(parent, { type: 'direct_opened', conversation_id: id });
        }
        conversation = {
          id, issuer: principal.issuer, clientId: principal.clientId, userId: principal.userId, bindingId,
          status: 'idle', responder: 'agent', context: {}, events: [], authority, ...(parentId === undefined ? {} : { parentId }),
        };
        draft.conversations[id] = conversation;
      } else {
        conversation = owned(draft, principal, conversationId);
        if (conversation.status === 'closed') throw closed();
        if (conversation.childId !== undefined) throw directOpen(conversation.childId);
        if (conversation.parentId !== undefined && body.message.sender !== 'human') throw new ValidationError('message.sender');
        if (read.cursor !== undefined) page(conversation, read.cursor);
        conversation.authority = authority;
      }
      const message = body.message;
      if (message.context) conversation.context = { ...conversation.context, ...message.context };
      addEvent(conversation, { type: 'message', message: { ...message, role: 'user' } as JsonObject });
      // A context-only message asks nothing; while queued for or answered by a person, messages are for that person.
      if (('text' in message || 'data' in message) && conversation.responder === 'agent' && conversation.status !== 'queued') {
        draft.work.push({ id: randomId('wrk_'), conversationId: conversation.id, message, authority, phase: 'pending', outputs: {} });
        if (conversation.status === 'idle') setState(conversation, 'working');
      }
      // A read from the cursor always finds the message just accepted, so 7.5 returns at once and the receipt
      // commits with the acceptance: there is no accepted-but-unanswered state for a crash to leave behind.
      const result = { status: conversationId === undefined ? 201 : 202, body: waiting ? page(conversation, read.cursor) : ack(conversation) };
      draft.messages[key] = { conversationId: conversation.id, fingerprint, receipt: result };
      return result;
    });
    return json(receipt.status, receipt.body);
  }

  async function events(request: Request, principal: Principal, url: URL, conversationId: string): Promise<Response> {
    const read = parseReadOptions(url, maxWaitSeconds);
    const deadline = clock.now() + read.waitSeconds * 1000;
    const deliver = () => current(principal, () => conversationId, () => true, draft => page(owned(draft, principal, conversationId), read.cursor));
    const first = await deliver();
    if ((first.events as unknown[]).length || read.waitSeconds === 0) return json(200, first);
    // Wait outside all locks without releasing anything; events are append-only, so a new last event means news.
    // shortcut: every waiting reader re-reads the whole state each pollIntervalMs; add change notification for many readers.
    const arrived = async () => (own((await store.read()).conversations, conversationId)?.events.at(-1)?.id ?? null) !== first.cursor;
    while (clock.now() < deadline && !request.signal.aborted && !await arrived()) await sleep(pollIntervalMs);
    // Delivery rechecks the reader now: a revocation during the hold returns no data.
    return json(200, await deliver());
  }

  async function lifecycle(request: Request, principal: Principal, conversationId: string, action: 'handoff' | 'close'): Promise<Response> {
    object(await readJson(request));
    const body = await current(principal, () => conversationId, () => false, draft => {
      const conversation = owned(draft, principal, conversationId);
      if (action === 'close') closeConversation(draft, conversation);
      else {
        if (conversation.status === 'closed') throw closed();
        if (conversation.childId !== undefined) throw directOpen(conversation.childId);
        requestHandoff(draft, conversation);
      }
      return ack(conversation);
    });
    return json(action === 'close' ? 200 : 202, body);
  }

  async function route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== endpoint.origin || !(url.pathname === basePath || url.pathname.startsWith(basePath + '/'))) throw new HttpError(404, { error: 'not_found' });
    const rest = url.pathname.slice(basePath.length);
    const match = /^\/([A-Za-z0-9_-]{1,256})\/(messages|events|handoff|close)$/.exec(rest);
    if (rest !== '' && !match) throw new HttpError(404, { error: 'not_found' });
    const method = match?.[2] === 'events' ? 'GET' : 'POST';
    if (request.method !== method) throw new HttpError(405, { error: 'method_not_allowed' }, { Allow: method });
    const principal = await authenticator.authenticate(request);
    if (!match) return accept(request, principal, url);
    const [, id, action] = match;
    if (action === 'messages') return accept(request, principal, url, id);
    return action === 'events' ? events(request, principal, url, id) : lifecycle(request, principal, id, action as 'handoff' | 'close');
  }

  // Resolves the durable authority, then revalidates fence, lease and phase inside the transaction.
  // scopes() is evaluated on the read and again on the draft; a binding gained in between reruns with wider scopes.
  async function publish<T>(ref: WorkRef, scopes: (state: ConversationStoreState, work: WorkRecord) => string[],
    change: (draft: ConversationStoreState, work: WorkRecord, conversation: ConversationRecord) => T, ending = false): Promise<T> {
    for (;;) {
      const before = await store.read();
      const stored = before.work.find(work => work.id === ref.workId);
      if (!stored) throw new PublicationError('stale_work');
      const granted = scopes(before, stored);
      // Failing or suspending uses no account and must stay possible after revocation, or the work is reclaimed forever.
      const authority: AcceptedAuthority = ending ? { ...stored.authority, revocationPolicy: 'allow-accepted-work-to-finish' } : stored.authority;
      try {
        return await policy.withAccepted(authority, granted, () => store.transaction(draft => {
          const work = draft.work.find(item => item.id === ref.workId);
          if (!work || work.phase !== 'claimed' || work.fence !== ref.fence || (!work.human && (work.leaseUntil ?? 0) <= clock.now())) throw new PublicationError('stale_work');
          if (scopes(draft, work).length > granted.length) throw new Rescope(); // nothing changed yet, so the rollback is free
          return change(draft, work, draft.conversations[work.conversationId]);
        }));
      } catch (error) {
        if (!(error instanceof Rescope)) throw error;
      }
    }
  }
  const noScopes = () => [];

  // Staff operations: the host authorizes the operator, then the conversation's stored customer authority applies.
  async function staff<T>(operator: unknown, conversationId: string, ending: boolean,
    change: (draft: ConversationStoreState, conversation: ConversationRecord, authority: AcceptedAuthority) => T): Promise<T> {
    if (!options.authorizeOperator) throw new TypeError('authorizeOperator is not configured');
    await options.authorizeOperator(operator, conversationId);
    for (;;) {
      const stored = own((await store.read()).conversations, conversationId);
      if (!stored) throw new PublicationError('stale_work');
      // Leaving the queue or handing back uses no account, so it stays possible after revocation.
      const authority: AcceptedAuthority = ending ? { ...stored.authority, revocationPolicy: 'allow-accepted-work-to-finish' } : stored.authority;
      try {
        return await policy.withAccepted(authority, [], () => store.transaction(draft => {
          const conversation = own(draft.conversations, conversationId);
          if (!conversation) throw new PublicationError('stale_work');
          // A message accepted in between replaced the authority that was checked.
          if (canonical(conversation.authority) !== canonical(stored.authority)) throw new Rescope();
          return change(draft, conversation, stored.authority);
        }));
      } catch (error) {
        if (!(error instanceof Rescope)) throw error;
      }
    }
  }
  const boundAccount = (state: ConversationStoreState, work: WorkRecord) => own(state.bindings, state.conversations[work.conversationId].bindingId)?.accountId;

  return {
    async handle(request) {
      try {
        return await route(request);
      } catch (error) {
        if (error instanceof HttpError) return json(error.status, error.body, error.headers);
        if (error instanceof ValidationError) return json(400, { error: 'invalid_request' });
        // Status/code/headers only, never the raw message.
        if (error instanceof AuthorityError) return json(error.status, { error: error.code }, error.headers);
        throw error;
      }
    },

    claim() {
      return store.transaction(draft => {
        const now = clock.now();
        const seen = new Set<string>();
        for (const work of draft.work) {
          if (!unfinished(work)) continue;
          // Serial per conversation: only the oldest unfinished work item is eligible.
          if (seen.has(work.conversationId)) continue;
          seen.add(work.conversationId);
          const conversation = draft.conversations[work.conversationId];
          // Automation pauses while queued for or handled by a person, and while a Direct Conversation is open.
          if (conversation.status === 'queued' || conversation.responder === 'human' || conversation.childId !== undefined) continue;
          if (work.phase === 'claimed' && (work.leaseUntil ?? 0) > now) continue;
          work.phase = 'claimed';
          work.fence = newFence(draft);
          work.leaseUntil = now + leaseMs;
          return { workId: work.id, fence: work.fence, conversationId: work.conversationId, message: work.message, context: conversation.context };
        }
        return null;
      });
    },

    renew(ref) {
      return publish(ref, noScopes, (_draft, work) => { work.leaseUntil = clock.now() + leaseMs; });
    },

    history(ref) {
      return publish(ref, (state, work) => boundAccount(state, work) === undefined ? [] : ['poppy:read'], (draft, work, conversation) => {
        const accountId = boundAccount(draft, work);
        if (accountId !== undefined && work.authority.principal.accountId !== accountId) throw new AuthorityError('sign_in_required');
        return linkedHistory(draft, conversation);
      });
    },

    requireAccount(ref, scopes) {
      return publish(ref, () => [...scopes], (draft, work, conversation) => {
        const accountId = work.authority.principal.accountId;
        const binding = draft.bindings[conversation.bindingId];
        // Parent and child share this record, so the first account use wins for both and no other account can.
        if (accountId === undefined || (binding.accountId ?? accountId) !== accountId) throw new AuthorityError('sign_in_required');
        binding.accountId = accountId;
        return { accountId };
      });
    },

    async reply(ref, outputId, message) {
      const parsed = parseMessage(message, { company: true });
      const payload = canonical({ reply: parsed });
      await publish(ref, noScopes, (_draft, work, conversation) => {
        if (parsed.sender !== conversation.responder) throw new ValidationError('message.sender');
        const previous = own(work.outputs, outputId);
        if (previous !== undefined) {
          if (previous !== payload) throw new PublicationError('output_conflict');
          return;
        }
        work.outputs[outputId] = payload;
        addEvent(conversation, { type: 'message', message: { ...parsed, role: 'company' } as JsonObject });
      });
    },

    finish(ref, outcome) {
      return publish(ref, noScopes, (draft, work, conversation) => {
        work.phase = outcome;
        delete work.fence;
        delete work.leaseUntil;
        if (outcome === 'failed') {
          addEvent(conversation, { type: 'message', message: { id: randomId('msg_'), role: 'company', sender: 'agent', text: 'Sorry, something went wrong and this request could not be completed.' } });
        }
        if (conversation.status === 'working') setState(conversation, idleOrWorking(draft, conversation.id));
      }, outcome !== 'completed');
    },

    handoff(ref) {
      return publish(ref, noScopes, (draft, work, conversation) => {
        work.phase = 'completed';
        delete work.fence;
        delete work.leaseUntil;
        requestHandoff(draft, conversation);
      }, true);
    },

    close(ref) {
      return publish(ref, noScopes, (draft, _work, conversation) => closeConversation(draft, conversation), true);
    },

    joinHuman(operator, conversationId) {
      return staff(operator, conversationId, false, (draft, conversation, authority) => {
        if (conversation.status === 'closed' || conversation.childId !== undefined) throw new PublicationError('stale_work');
        fence(draft, conversationId, 'cancelled');
        const last = conversation.events.findLast(event => event.type === 'message' && (event.message as Message).role === 'user');
        const { role: _role, ...message } = last!.message as Message;
        const work: WorkRecord = { id: randomId('wrk_'), conversationId, message, authority, phase: 'claimed', fence: newFence(draft), human: true, outputs: {} };
        draft.work.push(work);
        setState(conversation, 'idle', 'human');
        return { workId: work.id, fence: work.fence!, conversationId, message, context: conversation.context };
      });
    },

    noHumanAvailable(operator, conversationId, reason) {
      if (typeof reason !== 'string' || reason === '') return Promise.reject(new TypeError('reason'));
      return staff(operator, conversationId, true, (draft, conversation) => {
        if (conversation.status !== 'queued') return;
        // Parent publication waits until its Direct Conversation closes.
        if (conversation.childId !== undefined) throw new PublicationError('stale_work');
        // Messages sent while queued were meant for a person; the agent answers them now.
        requeueUnanswered(draft, conversation, conversation.events.findLastIndex(event => event.type === 'state' && event.status === 'queued'));
        addEvent(conversation, { type: 'message', message: { id: randomId('msg_'), role: 'company', sender: 'agent', text: reason } });
        setState(conversation, idleOrWorking(draft, conversationId), 'agent');
      });
    },

    returnToAgent(operator, conversationId) {
      return staff(operator, conversationId, true, (draft, conversation) => {
        if (conversation.responder !== 'human' || conversation.status === 'closed') return;
        fence(draft, conversationId, 'cancelled');
        requeueUnanswered(draft, conversation, conversation.events.findLastIndex(event => event.type === 'message' && (event.message as RecordedMessage).role === 'company'));
        setState(conversation, idleOrWorking(draft, conversationId), 'agent');
      });
    },
  };
}
