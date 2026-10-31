import { randomBytes, createHash } from 'node:crypto';
import { AuthorityError } from './auth/authority.js';
import type { AuthorityPolicy, Principal } from './auth/authority.js';
import type { MetadataResolver } from './network/discovery.js';
import { canonical, id, validateJson } from './protocol/wire.js';
import type { Json } from './protocol/wire.js';
import { operationRequiredResponse, operationToolError, operationExpiry, parseBusinessOperation, parseOperationApproval, requestFingerprint, supportsOperations } from './protocol/operations.js';
import type { BusinessOperation, OperationApproval, OperationRequest } from './protocol/operations.js';

export type BusinessOwner = { companyId: string; clientId: string; userId: string } &
  ({ accountId: string } | { sessionId: string; sessionInstanceId: string; sessionGeneration: string });
export interface OperationRevision { operation: BusinessOperation; request: OperationRequest }
export interface BusinessOperationRecord {
  version: 1; id: string; owner: BusinessOwner; scopes: string[];
  revisions: Record<string, OperationRevision>;
  execution?: { revision: string; key: string; claimedAt: number; retainUntil: number; phase: 'uncertain' | 'completed'; result?: Json };
}
/** Cross-process serializable transaction for one business action. Keep tombstones/claims forever until explicit safe retirement.
 * Local effects MUST enlist in this transaction; roll back records and effects on any throw, including commit failure.
 * External effects MUST NOT run inside it. Implementations reject unknown versions and return detached snapshots.
 */
export interface BusinessOperationStore {
  transaction<T>(operationId: string, action: (slot: { record?: BusinessOperationRecord }) => Promise<T>): Promise<T>;
}
export interface OperationInput {
  /** Host-selected business identity, stable across revisions/retries; never take this from an untrusted approval. */
  operationId: string; principal: Principal; request: OperationRequest; scopes: readonly string[]; approval?: OperationApproval;
  proposal(): { summary: string; terms?: BusinessOperation['terms']; expires_at: string };
}
export type OperationOutcome = { kind: 'approval_required'; operation: BusinessOperation } | { kind: 'pending'; retryAfter: number } | { kind: 'completed'; result: Json; replay: boolean };
export interface ExternalOperationEffect {
  /** Host guarantees one durable effect per key, including concurrent callers and retries after process death. */
  execute(input: { key: string; operation: BusinessOperation }): Promise<Json>;
  /** Never return absent until the old worker cannot later commit outside the same idempotency fence. */
  reconcile(input: { key: string; operation: BusinessOperation }): Promise<{ kind: 'pending' } | { kind: 'completed'; result: Json } | { kind: 'absent' }>;
}
export class BusinessOperationError extends Error {
  constructor(readonly code: 'operation_not_found' | 'extension_required') { super(code); }
  response(): Response {
    return this.code === 'extension_required'
      ? new Response(null, { status: 403, headers: { 'WWW-Authenticate': 'Bearer error="extension_required", extension="operations"', 'Cache-Control': 'no-store' } })
      : Response.json({ error: this.code }, { status: 404, headers: { 'Cache-Control': 'no-store' } });
  }
}
function owner(principal: Principal): BusinessOwner {
  if (!principal.sessionId || !principal.userId || !principal.sessionInstanceId || !principal.sessionGeneration) throw new AuthorityError('invalid_session');
  const base = { companyId: principal.issuer, clientId: principal.clientId, userId: principal.userId };
  if (principal.accountId) return { ...base, accountId: principal.accountId };
  if (!principal.sessionInstanceId || !principal.sessionGeneration) throw new AuthorityError('invalid_session');
  return { ...base, sessionId: principal.sessionId, sessionInstanceId: principal.sessionInstanceId, sessionGeneration: principal.sessionGeneration };
}
function owned(record: BusinessOperationRecord, principal: Principal): void {
  const o = record.owner;
  if (o.companyId !== principal.issuer || o.clientId !== principal.clientId || o.userId !== principal.userId) throw new BusinessOperationError('operation_not_found');
  if ('accountId' in o) {
    if (!principal.accountId) throw new AuthorityError('account_required', { scope: record.scopes.join(' ') });
    if (o.accountId !== principal.accountId) throw new BusinessOperationError('operation_not_found');
  } else if (o.sessionId !== principal.sessionId || o.sessionInstanceId !== principal.sessionInstanceId || o.sessionGeneration !== principal.sessionGeneration) throw new BusinessOperationError('operation_not_found');
}
export function operationPendingResponse(retryAfter = 1): Response {
  return Response.json({ error: 'operation_pending' }, { status: 503, headers: { 'Retry-After': String(retryAfter), 'Cache-Control': 'no-store' } });
}
export function createBusinessOperations(options: { companyId: string; metadata: MetadataResolver; policy: AuthorityPolicy; store: BusinessOperationStore; now?: () => number; retentionMs?: number; maxRevisions?: number; effectTimeoutMs?: number }) {
  const effectTimeoutMs = options.effectTimeoutMs ?? 30000;
  if (!Number.isSafeInteger(effectTimeoutMs) || effectTimeoutMs < 1) throw new TypeError('effectTimeoutMs');
  const maxRevisions = options.maxRevisions ?? 1000;
  if (!Number.isSafeInteger(maxRevisions) || maxRevisions < 1) throw new TypeError('maxRevisions');
  const now = options.now ?? Date.now, retentionMs = options.retentionMs ?? 86400000;
  if (!Number.isSafeInteger(retentionMs) || retentionMs < 0) throw new TypeError('operation retention');
  async function gate<T>(input: OperationInput, action: (record: BusinessOperationRecord) => Promise<T>): Promise<T> {
    id(input.operationId, 'operation_id'); requestFingerprint(input.request);
    owner(input.principal); // Every channel requires a verified Poppy Session, including signed-in MCP.
    if (input.principal.issuer !== options.companyId) throw new AuthorityError('invalid_session');
    if (!supportsOperations(await options.metadata.resolveClient(input.principal.clientId))) throw new BusinessOperationError('extension_required');
    return options.policy.withCurrent(input.principal, input.scopes, () => options.store.transaction(input.operationId, async slot => {
      if (slot.record && slot.record.version !== 1) throw new Error('unsupported business operation version');
      const record = slot.record ?? { version: 1, id: input.operationId, owner: owner(input.principal), scopes: [...input.scopes], revisions: {} };
      owned(record, input.principal);
      if (canonical(record.scopes.slice().sort()) !== canonical([...input.scopes].sort())) throw new TypeError('operation scope contract changed');
      slot.record = record;
      return action(record);
    }));
  }
  function inspect(record: BusinessOperationRecord, input: OperationInput): OperationOutcome | OperationRevision {
    const approval = input.approval && parseOperationApproval(input.approval);
    // Ownership and current authority precede receipt replay, even for expired revisions.
    if (record.execution) {
      if (record.execution.phase === 'completed' && record.execution.result !== undefined) return { kind: 'completed', result: structuredClone(record.execution.result), replay: true };
      if (record.execution.phase === 'uncertain') return { kind: 'pending', retryAfter: 1 };
    }
    const revision = !record.execution && approval?.operation_id === record.id ? (Object.hasOwn(record.revisions, approval.revision) ? record.revisions[approval.revision] : undefined) : undefined;
    if (revision && operationExpiry(revision.operation.expires_at) > now() && requestFingerprint(revision.request) === requestFingerprint(input.request)) return revision;
    const proposed = input.proposal();
    const operation = parseBusinessOperation({ ...proposed, operation_id: record.id, revision: randomBytes(24).toString('base64url') });
    if (operationExpiry(operation.expires_at) <= now()) throw new TypeError('proposal already expired');
    // Completed/uncertain actions are never reopened, even after receipt cleanup or a new revision.
    if (record.execution) return { kind: 'approval_required', operation };
    for (const [key, value] of Object.entries(record.revisions)) if (operationExpiry(value.operation.expires_at) <= now()) delete record.revisions[key];
    if (Object.keys(record.revisions).length >= maxRevisions) throw new AuthorityError('rate_limited', {retryAfter:60});
    record.revisions[operation.revision] = { operation, request: structuredClone(input.request) };
    return { kind: 'approval_required', operation };
  }
  function claim(record: BusinessOperationRecord, revision: OperationRevision): void {
    record.execution = { revision: revision.operation.revision, key: createHash('sha256').update(canonical([options.companyId, record.id])).digest('base64url'), claimedAt: now(),
      retainUntil: Math.max(operationExpiry(revision.operation.expires_at), now() + retentionMs), phase: 'uncertain' };
  }
  function complete(record: BusinessOperationRecord, result: Json, input: OperationInput): OperationOutcome {
    if (record.execution?.phase === 'completed') return inspect(record, input) as OperationOutcome;
    validateJson(result); record.execution!.phase = 'completed'; record.execution!.result = structuredClone(result);
    return { kind: 'completed', result: structuredClone(result), replay: false };
  }
  async function externalResult<T>(action: () => Promise<T>): Promise<{ ok: true; value: T } | { ok: false }> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        Promise.resolve().then(action).then(value => ({ok:true as const,value}), () => ({ok:false as const})),
        new Promise<{ok:false}>(resolve => { timer = setTimeout(() => resolve({ok:false}), effectTimeoutMs); }),
      ]);
    } finally { clearTimeout(timer); }
  }
  return {
    /** No effect: proposes terms or returns an existing execution's state. */
    propose(input: OperationInput): Promise<OperationOutcome> { return gate({ ...input, approval: undefined }, async record => inspect(record, { ...input, approval: undefined }) as OperationOutcome); },
    /** Only same-database effects. The host must use this store's coordinator/transaction handle. No network I/O. */
    local(input: OperationInput, effect: (revision: BusinessOperation) => Promise<Json>): Promise<OperationOutcome> {
      return gate(input, async record => {
        const found = inspect(record, input); if ('kind' in found) return found;
        claim(record, found);
        const result = await effect(structuredClone(found.operation));
        return complete(record, result, input);
      });
    },
    async external(input: OperationInput, effect: ExternalOperationEffect): Promise<OperationOutcome> {
      const selected = await gate(input, async record => {
        const found = inspect(record, input);
        if ('kind' in found) return { outcome: found };
        claim(record, found); return { key: record.execution!.key, operation: structuredClone(found.operation) };
      });
      if ('outcome' in selected) return selected.outcome!;
      await options.policy.withCurrent(input.principal, input.scopes, async () => {});
      const attempted = await externalResult(async () => {
        const result = await effect.execute({ key: selected.key!, operation: selected.operation! }); validateJson(result); return result;
      });
      if (!attempted.ok) return { kind: 'pending', retryAfter: 1 };
      return gate(input, async record => complete(record, attempted.value, input));
    },
    /** Explicit host reconciliation only; a lease expiring never releases an execution claim. */
    async reconcile(input: OperationInput, effect: ExternalOperationEffect): Promise<OperationOutcome> {
      const selected = await gate(input, async record => {
        if (!record.execution) throw new BusinessOperationError('operation_not_found');
        if (record.execution.phase === 'completed') {
          if (record.execution.result === undefined) return { outcome: inspect(record, input) as OperationOutcome };
          return { outcome: { kind: 'completed', result: record.execution.result, replay: true } as OperationOutcome };
        }
        return { key: record.execution.key, operation: structuredClone(record.revisions[record.execution.revision].operation) };
      });
      if ('outcome' in selected) return selected.outcome!;
      const checked = await externalResult(() => effect.reconcile({ key: selected.key!, operation: selected.operation! }));
      if (!checked.ok) return { kind: 'pending', retryAfter: 1 };
      let resolved = checked.value;
      if (resolved.kind === 'pending') return { kind: 'pending', retryAfter: 1 };
      if (resolved.kind === 'absent') {
        // Reuse the durable downstream key: a paused original worker still cannot cause a second effect.
        await options.policy.withCurrent(input.principal, input.scopes, async () => {});
        const attempted = await externalResult(() => effect.execute({ key: selected.key!, operation: selected.operation! }));
        if (!attempted.ok) return { kind: 'pending', retryAfter: 1 };
        resolved = { kind: 'completed', result: attempted.value };
      }
      const result = resolved.result;
      return gate(input, async record => {
        return complete(record, result, input);
      });
    },
    /** Drop protected result bodies only after retention; retain the action fence and never re-execute it. */
    prune(operationId: string): Promise<void> {
      return options.store.transaction(operationId, async slot => {
        const record = slot.record;
        if (record?.version !== undefined && record.version !== 1) throw new Error('unsupported business operation version');
        if (record?.execution?.phase === 'completed' && record.execution.retainUntil < now()) { delete record.execution.result; record.revisions = {}; }
      });
    },
  };
}

export function operationApiResponse(outcome: OperationOutcome, success: (result: Json) => Response = result => Response.json(result)): Response {
  return outcome.kind === 'approval_required' ? operationRequiredResponse(outcome.operation) : outcome.kind === 'pending' ? operationPendingResponse(outcome.retryAfter) : success(outcome.result);
}
/** A tool's missing extension is an ordinary tool error, not an OAuth refusal of the whole MCP client. */
export function operationMcpResponse(outcome: OperationOutcome | BusinessOperationError): Response {
  if (outcome instanceof BusinessOperationError) return Response.json({isError:true,content:[{type:'text',text:'This tool requires user approval through Operations v2.'}]});
  return outcome.kind === 'pending' ? operationPendingResponse(outcome.retryAfter) : Response.json(outcome.kind === 'approval_required' ? operationToolError(outcome.operation) : outcome.result);
}
