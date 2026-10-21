export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export type JsonObject = { [key: string]: Json };
export type Sender = 'agent' | 'human';
export type Status = 'working' | 'idle' | 'queued' | 'closed';
export interface Message { id: string; sender: Sender; text?: string; data?: JsonObject; context?: JsonObject; [key: string]: unknown }
export interface RecordedMessage extends Message { role: 'user' | 'company' }
export interface ConversationRequest { message: Message; parent_conversation_id?: string; [key: string]: unknown }
export interface ConversationState { conversation_id: string; status: Status; responder: Sender; [key: string]: unknown }
export interface ConversationEvent { id: string; type: string; created_at: string; [key: string]: unknown }
export type KnownEvent =
  | (ConversationEvent & { type: 'message'; message: RecordedMessage })
  | (ConversationEvent & { type: 'state'; status: Status; responder: Sender })
  | (ConversationEvent & { type: 'authorization'; error: 'sign_in_required'; scope?: string })
  | (ConversationEvent & { type: 'authorization'; error: 'insufficient_scope'; scope: string })
  | (ConversationEvent & { type: 'user_requested'; reason: string })
  | (ConversationEvent & { type: 'direct_opened' | 'direct_closed'; conversation_id: string });
export interface EventPage extends ConversationState { events: ConversationEvent[]; cursor: string | null; has_more: boolean }
export interface TokenResponse { access_token: string; token_type: 'DPoP' | 'Bearer'; expires_in: number; scope: string; session_id: string; signed_in: boolean; refresh_token?: string; refresh_token_expires_in?: number; [key: string]: unknown }
export interface ProtocolErrorBody { error: string; error_description?: string; error_uri?: string; extension?: string; conversation_id?: string; [key: string]: unknown }

export class ValidationError extends Error {
  constructor(readonly field: string) { super(`Invalid protocol field: ${field}`); this.name = 'ValidationError'; }
}
export function validateJson(value: unknown): void {
  const stack: { value: unknown; depth: number }[] = [{ value, depth: 0 }];
  while (stack.length) {
    const current = stack.pop()!;
    if (current.depth > 64) throw new ValidationError('json.depth');
    if (current.value === null || typeof current.value === 'string' || typeof current.value === 'boolean') continue;
    if (typeof current.value === 'number' && Number.isFinite(current.value)) continue;
    if (typeof current.value !== 'object' || (Object.getPrototypeOf(current.value) !== Object.prototype && !Array.isArray(current.value))) throw new ValidationError('json');
    for (const child of Object.values(current.value)) stack.push({ value: child, depth: current.depth + 1 });
  }
}
export function object(value: unknown, field = 'document'): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new ValidationError(field);
  validateJson(value);
  return value as Record<string, unknown>;
}
export function string(value: unknown, field: string, nonempty = true): string {
  if (typeof value !== 'string' || (nonempty && !value.length)) throw new ValidationError(field);
  return value;
}
export function member(value: unknown, values: readonly unknown[], field: string): void {
  if (!values.includes(value)) throw new ValidationError(field);
}
export function id(value: unknown, field: string): string {
  const result = string(value, field);
  if (!/^[A-Za-z0-9_-]{1,256}$/.test(result)) throw new ValidationError(field);
  return result;
}
function positive(value: unknown, field: string): void {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) throw new ValidationError(field);
}
export function parseMessage(value: unknown, options: { recorded?: boolean; company?: boolean } = {}): Message | RecordedMessage {
  const message = { ...object(value, 'message') };
  id(message.id, 'message.id'); member(message.sender, ['agent', 'human'], 'message.sender');
  if (!['text', 'data', 'context'].some(key => key in message)) throw new ValidationError('message.content');
  if ('text' in message) string(message.text, 'message.text', false);
  if ('data' in message) object(message.data, 'message.data');
  if (options.recorded) member(message.role, ['user', 'company'], 'message.role'); else delete message.role;
  if ('context' in message) {
    if (options.company || message.role === 'company') throw new ValidationError('message.context');
    const context = object(message.context, 'message.context');
    if ('user_available' in context) member(context.user_available, [true, false], 'message.context.user_available');
    if ('locale' in context) {
      const locale = string(context.locale, 'message.context.locale');
      try { new Intl.Locale(locale); } catch { throw new ValidationError('message.context.locale'); }
    }
    if ('time_zone' in context) {
      const zone = string(context.time_zone, 'message.context.time_zone');
      if (/^[+-]/.test(zone)) throw new ValidationError('message.context.time_zone');
      try { new Intl.DateTimeFormat('en', { timeZone: zone }); } catch { throw new ValidationError('message.context.time_zone'); }
    }
  }
  return message as Message;
}
export function parseConversationRequest(value: unknown): ConversationRequest {
  const request = object(value);
  if ('parent_conversation_id' in request) id(request.parent_conversation_id, 'parent_conversation_id');
  return { ...request, message: parseMessage(request.message) };
}
export function parseConversationState(value: unknown): ConversationState {
  const state = object(value); id(state.conversation_id, 'conversation_id');
  member(state.status, ['working', 'idle', 'queued', 'closed'], 'status'); member(state.responder, ['agent', 'human'], 'responder');
  return state as ConversationState;
}
export function parseEvent(value: unknown): ConversationEvent {
  const event = object(value, 'event'); id(event.id, 'event.id'); string(event.type, 'event.type');
  const date = string(event.created_at, 'event.created_at');
  const parts = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|([+-])(\d{2}):(\d{2}))$/.exec(date);
  if (!parts) throw new ValidationError('event.created_at');
  const [, year, month, day, hour, minute, second, , offsetHour = '0', offsetMinute = '0'] = parts;
  const days = new Date(`${year}-${month}-01T00:00:00Z`); days.setUTCMonth(days.getUTCMonth() + 1); days.setUTCDate(0);
  if (+month < 1 || +month > 12 || +day < 1 || +day > days.getUTCDate() || +hour > 23 || +minute > 59 || +second > 60 || +offsetHour > 23 || +offsetMinute > 59) throw new ValidationError('event.created_at');
  switch (event.type) {
    case 'message': parseMessage(event.message, { recorded: true }); break;
    case 'state': member(event.status, ['working', 'idle', 'queued', 'closed'], 'event.status'); member(event.responder, ['agent', 'human'], 'event.responder'); break;
    case 'authorization': member(event.error, ['sign_in_required', 'insufficient_scope'], 'event.error'); if (event.error === 'insufficient_scope' || 'scope' in event) string(event.scope, 'event.scope', false); break;
    case 'user_requested': string(event.reason, 'event.reason', false); break;
    case 'direct_opened': case 'direct_closed': id(event.conversation_id, 'event.conversation_id'); break;
  }
  return event as ConversationEvent;
}
export function parseEventPage(value: unknown, requestCursor?: string): EventPage {
  const page = parseConversationState(value);
  if (!Array.isArray(page.events)) throw new ValidationError('events');
  page.events.forEach(parseEvent); member(page.has_more, [true, false], 'has_more');
  if (page.cursor === null) {
    if (requestCursor !== undefined || page.events.length || page.has_more) throw new ValidationError('cursor');
  } else {
    string(page.cursor, 'cursor');
    const expected = page.events.length ? page.events.at(-1).id : requestCursor;
    if (expected !== undefined && page.cursor !== expected) throw new ValidationError('cursor');
  }
  return page as EventPage;
}
export function parseTokenResponse(value: unknown): TokenResponse {
  const token = object(value); string(token.access_token, 'access_token'); string(token.session_id, 'session_id'); string(token.scope, 'scope', false);
  member(token.token_type, ['DPoP', 'Bearer'], 'token_type'); member(token.signed_in, [true, false], 'signed_in'); positive(token.expires_in, 'expires_in');
  if ('refresh_token' in token) string(token.refresh_token, 'refresh_token');
  if ('refresh_token_expires_in' in token) positive(token.refresh_token_expires_in, 'refresh_token_expires_in');
  return token as TokenResponse;
}
export function parseProtocolError(value: unknown): ProtocolErrorBody {
  const error = object(value); string(error.error, 'error');
  for (const key of ['error_description', 'error_uri']) if (key in error) string(error[key], key, false);
  if (error.error === 'extension_required' || 'extension' in error) string(error.extension, 'extension');
  if (error.error === 'direct_conversation_open' || 'conversation_id' in error) id(error.conversation_id, 'conversation_id');
  return error as ProtocolErrorBody;
}
export function parseReadOptions(url: URL, maxWaitSeconds: number): { cursor?: string; waitSeconds: number } {
  if (!Number.isSafeInteger(maxWaitSeconds) || maxWaitSeconds < 0) throw new ValidationError('maxWaitSeconds');
  for (const key of ['wait', 'cursor']) if (url.searchParams.getAll(key).length > 1) throw new ValidationError(key);
  const wait = url.searchParams.get('wait') ?? '0';
  if (!/^\d+$/.test(wait)) throw new ValidationError('wait');
  const cursor = url.searchParams.get('cursor');
  if (cursor !== null) string(cursor, 'cursor');
  return { ...(cursor === null ? {} : { cursor }), waitSeconds: Number(BigInt(wait) > BigInt(maxWaitSeconds) ? maxWaitSeconds : BigInt(wait)) };
}
export function retryAfterMilliseconds(value: string | null, nowMs: number): number | undefined {
  if (!value) return undefined;
  if (/^\d+$/.test(value)) { const ms = Number(value) * 1000; return Number.isSafeInteger(ms) ? ms : Infinity; } // too large to wait: let the caller's maxDelay check surface it
  if (!/^[A-Za-z]{3}, \d{2} [A-Za-z]{3} \d{4} \d{2}:\d{2}:\d{2} GMT$/.test(value)) return undefined;
  const date = Date.parse(value); return Number.isFinite(date) ? Math.max(0, date - nowMs) : undefined;
}
export interface AssertionClaims { iss: string; sub: string; aud: string; iat: number; exp: number; jti: string; [key: string]: unknown }
export interface DpopClaims { jti: string; htm: string; htu: string; iat: number; ath?: string; nonce?: string; [key: string]: unknown }
// Session and client assertions (spec 4.1/4.2): aud is the issuer as a single string, exp - iat <= 300s.
export function parseAssertionClaims(value: unknown): AssertionClaims {
  const claims = object(value, 'claims');
  for (const key of ['iss', 'sub', 'aud', 'jti']) string(claims[key], key);
  // 128 random bits is at least 16 bytes; cap length since jti lands in the replay store. Encoding is not constrained.
  if ((claims.jti as string).length < 16 || (claims.jti as string).length > 256) throw new ValidationError('jti');
  positive(claims.iat, 'iat'); positive(claims.exp, 'exp');
  if ((claims.exp as number) <= (claims.iat as number) || (claims.exp as number) - (claims.iat as number) > 300) throw new ValidationError('exp');
  return claims as AssertionClaims;
}
// DPoP proof payload (spec 4.3); htu carries no query or fragment.
export function parseDpopClaims(value: unknown): DpopClaims {
  const claims = object(value, 'claims');
  string(claims.jti, 'jti'); string(claims.htm, 'htm'); positive(claims.iat, 'iat');
  const htu = string(claims.htu, 'htu');
  try { const url = new URL(htu); if (url.protocol !== 'https:' || url.search || url.hash || htu.includes('?') || htu.includes('#')) throw 0; } catch { throw new ValidationError('htu'); }
  for (const key of ['ath', 'nonce']) if (key in claims) string(claims[key], key);
  return claims as DpopClaims;
}
