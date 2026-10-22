import type { IssuerState } from './index.js';
export const clientRevisionKey = (clientId: string) => `revision ${clientId}`;
export const accountRevisionKey = (clientId: string, accountId: string) => `revoked ${JSON.stringify([clientId, accountId])}`;
export type IssuerSelection =
  | { kind: 'metadata' }
  | { kind: 'token'; clientId: string; sessionId?: string; codeHash?: string; refreshHash?: string; replayKeys: string[]; at: number }
  | { kind: 'revoke'; refreshHash: string; replayKey: string }
  | { kind: 'principal'; sessionId: string; grantId?: string }
  | { kind: 'browser'; sessionId: string; replayKey?: string }
  | { kind: 'access'; hash: string }
  | { kind: 'authorize'; clientId: string; at: number }
  | { kind: 'authorization'; id: string; revocationKey?: string }
  | { kind: 'disconnect'; clientId: string; accountId: string }
  | { kind: 'sign_in'; ids: string[]; clientId?: string; sessionId?: string; accessHash?: string; replayKeys: string[]; at: number };
export interface IssuerStore {
  read(selection: IssuerSelection): Promise<IssuerState>;
  transaction<T>(selection: IssuerSelection, change: (draft: IssuerState) => T): Promise<T>;
}
