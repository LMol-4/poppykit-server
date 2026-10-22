import type { IssuerState } from './index.js';
export type IssuerSelection =
  | { kind: 'metadata' }
  | { kind: 'token'; clientId: string; sessionId?: string; codeHash?: string; refreshHash?: string; replayKeys: string[]; at: number }
  | { kind: 'revoke'; refreshHash: string; replayKey: string }
  | { kind: 'principal'; sessionId: string; grantId?: string }
  | { kind: 'access'; hash: string }
  | { kind: 'authorize'; clientId: string; at: number }
  | { kind: 'authorization'; id: string }
  | { kind: 'disconnect'; clientId: string; accountId: string };
export interface IssuerStore {
  read(selection: IssuerSelection): Promise<IssuerState>;
  transaction<T>(selection: IssuerSelection, change: (draft: IssuerState) => T): Promise<T>;
}
