import { parse, serialize, getMember } from '@agentsig/structured-fields';
import { canonical, id, object, string, ValidationError } from './wire.js';
import type { JsonObject } from './wire.js';
import { secureUrl } from '../network/transport.js';

export interface BusinessOperation {
  operation_id: string; revision: string; summary: string; terms?: JsonObject; expires_at: string;
  [key: string]: unknown;
}
export interface OperationApproval { operation_id: string; revision: string; [key: string]: unknown }
export const operationsV2 = { version: '2' } as const;
export function supportsOperations(document: { extensions?: unknown }): boolean {
  const extensions = document.extensions;
  return !!extensions && typeof extensions === 'object' && !Array.isArray(extensions)
    && (extensions as Record<string, { version?: unknown }>).operations?.version === '2';
}
export function parseBusinessOperation(value: unknown): BusinessOperation {
  const operation = object(value, 'operation');
  id(operation.operation_id, 'operation.operation_id'); id(operation.revision, 'operation.revision');
  string(operation.summary, 'operation.summary');
  if ('terms' in operation) object(operation.terms, 'operation.terms');
  const date = string(operation.expires_at, 'operation.expires_at');
  const match = /^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:[Zz]|[+-](\d{2}):(\d{2}))$/.exec(date);
  if (!match) throw new ValidationError('operation.expires_at');
  const [, y, m, d, h, min, s, oh = '0', om = '0'] = match;
  const monthEnd = new Date(0); monthEnd.setUTCFullYear(+y, +m, 0);
  const days = monthEnd.getUTCDate();
  if (+m < 1 || +m > 12 || +d < 1 || +d > days || +h > 23 || +min > 59 || +s > 60 || +oh > 23 || +om > 59 || !Number.isFinite(operationExpiry(date))) throw new ValidationError('operation.expires_at');
  return structuredClone(operation) as BusinessOperation;
}
/** RFC3339 permits a leap second; JavaScript Date.parse does not. */
export function operationExpiry(value: string): number {
  return /:60(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})$/.test(value)
    ? Date.parse(value.replace(/:60(?=\.\d+|[Zz]|[+-])/, ':59')) + 1000 : Date.parse(value);
}
export function parseOperationApproval(value: unknown): OperationApproval {
  const approval = object(value, 'approval');
  id(approval.operation_id, 'approval.operation_id'); id(approval.revision, 'approval.revision');
  return { ...approval } as OperationApproval;
}
export function parseApprovalHeader(value: string | null): OperationApproval | undefined {
  if (value === null) return;
  try {
    const dictionary = parse(value, 'dictionary');
    const text = (name: string) => { const member = getMember(dictionary, name); return member?.kind === 'item' && member.bare.kind === 'string' ? member.bare.value : undefined; };
    return parseOperationApproval({ operation_id: text('operation_id'), revision: text('revision') });
  } catch { return; } // Invalid Structured Fields are ignored as a whole (RFC 9651 section 2.2).
}
export function approvalHeader(value: OperationApproval): string {
  const approval = parseOperationApproval(value);
  return serialize({ kind: 'dictionary', entries: [
    ['operation_id', { kind: 'item', bare: { kind: 'string', value: approval.operation_id }, parameters: [] }],
    ['revision', { kind: 'item', bare: { kind: 'string', value: approval.revision }, parameters: [] }],
  ] });
}
export const approvalMetaKey = 'personalagentprotocol.org/approval';
export function mcpApproval(params: unknown): OperationApproval | undefined {
  const meta = object(params, 'params')._meta;
  if (meta === undefined) return;
  const value = object(meta, '_meta')[approvalMetaKey];
  return value === undefined ? undefined : parseOperationApproval(value);
}
export type OperationRequest =
  | { channel: 'api'; method: string; url: string; body: string | null }
  | { channel: 'mcp'; url: string; name: string; arguments: JsonObject }
  | { channel: 'conversation'; endpoint: string; conversationId: string };
export function operationRequest(value: OperationRequest): OperationRequest {
  object(value, 'operation.request');
  if (value.channel === 'api') {
    secureUrl(value.url); if (!/^[A-Z]+$/.test(value.method) || !(value.body === null || typeof value.body === 'string')) throw new ValidationError('operation.request');
  } else if (value.channel === 'mcp') { secureUrl(value.url); string(value.name, 'tool.name'); object(value.arguments, 'tool.arguments'); }
  else if (value.channel === 'conversation') { secureUrl(value.endpoint); id(value.conversationId, 'conversation_id'); }
  else throw new ValidationError('operation.channel');
  return structuredClone(value);
}
export function requestFingerprint(value: OperationRequest): string { return canonical(operationRequest(value)); }
export function operationRequiredResponse(operation: BusinessOperation): Response {
  return Response.json({ error: 'approval_required', operation: parseBusinessOperation(operation) }, { status: 403, headers: { 'Cache-Control': 'no-store' } });
}
export function operationToolError(operation: BusinessOperation): JsonObject {
  const parsed = parseBusinessOperation(operation);
  return { isError: true, content: [{ type: 'text', text: parsed.summary }], structuredContent: { operation: parsed as unknown as JsonObject } };
}

/** Base64 preserves exact API body bytes. Bind the complete URL, including its query. */
export async function captureApiOperationRequest(request: Request): Promise<Extract<OperationRequest, { channel: 'api' }>> {
  return { channel: 'api', method: request.method, url: request.url, body: request.body === null ? null : Buffer.from(await request.clone().arrayBuffer()).toString('base64') };
}
