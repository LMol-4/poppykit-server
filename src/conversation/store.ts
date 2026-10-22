import type { ConversationStoreState } from './service.js';
export type ConversationSelection = { conversationId?: string; messageKey?: string; workId?: string; claimAt?: number; append?: boolean; cursorCheck?: string; events?: { cursor?: string; limit: number; maxBytes?: number } };
export interface ConversationStore {
  pruneEvents?(conversationId: string, before: number, limit?: number): Promise<number>;
  read(selection: ConversationSelection): Promise<ConversationStoreState>;
  transaction<T>(selection: ConversationSelection, change: (draft: ConversationStoreState) => T): Promise<T>;
}
/** Notifications are hints: subscribe before reading, then reconcile durable state on wake or timeout. */
export interface ConversationNotifications {
  subscribe(conversationId: string, wake: () => void): () => void;
  publish(conversationId: string): void;
}

/** Local acceleration only. Cross-process/lost hints use the service reconciliation interval. */
export function createConversationNotifications(): ConversationNotifications {
  const listeners = new Map<string, Set<() => void>>();
  return {
    subscribe(id, wake) { const set = listeners.get(id) ?? new Set(); set.add(wake); listeners.set(id, set); return () => { set.delete(wake); if (!set.size) listeners.delete(id); }; },
    publish(id) { for (const wake of listeners.get(id) ?? []) { try { wake(); } catch { /* A failed hint cannot change a committed outcome. */ } } },
  };
}
