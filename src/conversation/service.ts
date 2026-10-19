import { randomBytes } from 'node:crypto';
import { ValidationError, parseConversationRequest, parseMessage, parseReadOptions } from '../protocol/wire.js';
import type { ConversationEvent, ConversationRequest, JsonObject, Message, Sender, Status } from '../protocol/wire.js';
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
}
export interface WorkRecord {
  id: string; conversationId: string; message: Message; authority: AcceptedAuthority;
  phase: 'pending' | 'claimed' | 'completed' | 'suspended' | 'failed';
  fence?: string; leaseUntil?: number;
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
}
export interface WorkRef { workId: string; fence: string }
export interface WorkClaim extends WorkRef { conversationId: string; message: Message; context: JsonObject }
export interface ConversationService {
  /** Protocol errors become responses; anything else is re-thrown, so hosts must catch it and answer 500. */
  handle(request: Request): Promise<Response>;
  claim(): Promise<WorkClaim | null>;
  renew(work: WorkRef): Promise<void>;
  reply(work: WorkRef, outputId: string, message: Message): Promise<void>;
  finish(work: WorkRef, outcome: 'completed' | 'suspended' | 'failed'): Promise<void>;
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

class HttpError extends Error {
  constructor(readonly status: number, readonly body: JsonObject, readonly headers: HeadersInit = {}) { super(String(body.error)); }
}
const notFound = () => new HttpError(404, { error: 'conversation_not_found' });

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
  const revocationPolicy = options.revocationPolicy ?? 'stop-account-work';
  for (const value of [pageSize, leaseMs]) if (!Number.isSafeInteger(value) || value <= 0) throw new TypeError('Invalid conversation option');
  const endpoint = secureUrl(options.endpoint);
  const basePath = endpoint.pathname.replace(/\/$/, '');

  const timestamp = () => new Date(clock.now()).toISOString();
  function addEvent(conversation: ConversationRecord, event: JsonObject): void {
    conversation.events.push({ id: randomId('evt_'), created_at: timestamp(), ...event } as ConversationEvent);
  }
  function setState(conversation: ConversationRecord, status: Status): void {
    if (conversation.status === status) return;
    conversation.status = status;
    addEvent(conversation, { type: 'state', status, responder: conversation.responder });
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
    conversation && history && principal.accountId !== undefined && own(state.bindings, conversation.bindingId)?.accountId === principal.accountId ? ['poppy:read'] : [];

  function owned(state: ConversationStoreState, principal: Principal, id: string): ConversationRecord {
    const conversation = own(state.conversations, id);
    if (!conversation || conversation.issuer !== principal.issuer || conversation.clientId !== principal.clientId || conversation.userId !== principal.userId) throw notFound();
    const accountId = own(state.bindings, conversation.bindingId)?.accountId;
    if (accountId !== undefined && principal.accountId !== accountId) {
      if (principal.accountId === undefined) throw new HttpError(403, { error: 'sign_in_required' }, { 'WWW-Authenticate': 'DPoP error="sign_in_required"' });
      throw notFound();
    }
    return conversation;
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
    // shortcut: Direct Conversations are not served yet; J15 adds parent linkage.
    if (conversationId === undefined && 'parent_conversation_id' in body) throw new ValidationError('parent_conversation_id');
    const key = JSON.stringify([principal.issuer, principal.clientId, principal.userId, body.message.id]);
    const fingerprint = canonical({ target: conversationId ?? null, request: body });
    const authority = JSON.parse(JSON.stringify({ principal, acceptedAt: clock.now(), revocationPolicy })) as AcceptedAuthority;
    const target = (state: ConversationStoreState) => conversationId ?? own(state.messages, key)?.conversationId;
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
        conversation = { id, issuer: principal.issuer, clientId: principal.clientId, userId: principal.userId, bindingId: id, status: 'idle', responder: 'agent', context: {}, events: [] };
        draft.conversations[id] = conversation;
        draft.bindings[id] = {};
      } else {
        conversation = owned(draft, principal, conversationId);
        if (conversation.status === 'closed') throw new HttpError(409, { error: 'conversation_closed' });
        if (read.cursor !== undefined) page(conversation, read.cursor);
      }
      const message = body.message;
      if (message.context) conversation.context = { ...conversation.context, ...message.context };
      addEvent(conversation, { type: 'message', message: { ...message, role: 'user' } as JsonObject });
      // A context-only message updates context without asking the company to do anything.
      if ('text' in message || 'data' in message) {
        draft.work.push({ id: randomId('wrk_'), conversationId: conversation.id, message, authority, phase: 'pending', outputs: {} });
        if (conversation.status === 'idle') setState(conversation, 'working');
      }
      // shortcut: a waited POST is answered at once from the cursor; J15 adds holding and receipt recovery.
      const result = { status: conversationId === undefined ? 201 : 202, body: waiting ? page(conversation, read.cursor) : ack(conversation) };
      draft.messages[key] = { conversationId: conversation.id, fingerprint, receipt: result };
      return result;
    });
    return json(receipt.status, receipt.body);
  }

  async function events(principal: Principal, url: URL, conversationId: string): Promise<Response> {
    const read = parseReadOptions(url, maxWaitSeconds);
    // shortcut: GET returns at once instead of holding for wait; J15 adds capped long polls.
    const body = await current(principal, () => conversationId, () => true, draft => page(owned(draft, principal, conversationId), read.cursor));
    return json(200, body);
  }

  async function route(request: Request): Promise<Response> {
    const url = new URL(request.url);
    if (url.origin !== endpoint.origin || !(url.pathname === basePath || url.pathname.startsWith(basePath + '/'))) throw new HttpError(404, { error: 'not_found' });
    const rest = url.pathname.slice(basePath.length);
    // shortcut: handoff and close routes arrive with J15.
    const match = /^\/([A-Za-z0-9_-]{1,256})\/(messages|events)$/.exec(rest);
    if (rest !== '' && !match) throw new HttpError(404, { error: 'not_found' });
    const method = match?.[2] === 'events' ? 'GET' : 'POST';
    if (request.method !== method) throw new HttpError(405, { error: 'method_not_allowed' }, { Allow: method });
    const principal = await authenticator.authenticate(request);
    if (!match) return accept(request, principal, url);
    return match[2] === 'messages' ? accept(request, principal, url, match[1]) : events(principal, url, match[1]);
  }

  // Resolves the durable authority, then revalidates fence, lease and phase inside the transaction.
  async function publish(ref: WorkRef, change: (draft: ConversationStoreState, work: WorkRecord, conversation: ConversationRecord) => void): Promise<void> {
    const stored = (await store.read()).work.find(work => work.id === ref.workId);
    if (!stored) throw new PublicationError('stale_work');
    await policy.withAccepted(stored.authority, [], () => store.transaction(draft => {
      const work = draft.work.find(item => item.id === ref.workId);
      if (!work || work.phase !== 'claimed' || work.fence !== ref.fence || (work.leaseUntil ?? 0) <= clock.now()) throw new PublicationError('stale_work');
      change(draft, work, draft.conversations[work.conversationId]);
    }));
  }

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
          if (work.phase !== 'pending' && work.phase !== 'claimed') continue;
          // Serial per conversation: only the oldest unfinished work item is eligible.
          if (seen.has(work.conversationId)) continue;
          seen.add(work.conversationId);
          if (work.phase === 'claimed' && (work.leaseUntil ?? 0) > now) continue;
          const conversation = draft.conversations[work.conversationId];
          work.phase = 'claimed';
          work.fence = `${draft.generation}.${randomId('')}`;
          work.leaseUntil = now + leaseMs;
          return { workId: work.id, fence: work.fence, conversationId: work.conversationId, message: work.message, context: conversation.context };
        }
        return null;
      });
    },

    renew(ref) {
      return publish(ref, (_draft, work) => { work.leaseUntil = clock.now() + leaseMs; });
    },

    async reply(ref, outputId, message) {
      const parsed = parseMessage(message, { company: true });
      const payload = canonical({ reply: parsed });
      await publish(ref, (_draft, work, conversation) => {
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
      return publish(ref, (draft, work, conversation) => {
        work.phase = outcome;
        delete work.fence;
        delete work.leaseUntil;
        if (outcome === 'failed') {
          addEvent(conversation, { type: 'message', message: { id: randomId('msg_'), role: 'company', sender: 'agent', text: 'Sorry, something went wrong and this request could not be completed.' } });
        }
        const busy = draft.work.some(item => item.conversationId === conversation.id && (item.phase === 'pending' || item.phase === 'claimed'));
        if (!busy && conversation.status === 'working') setState(conversation, 'idle');
      });
    },
  };
}
