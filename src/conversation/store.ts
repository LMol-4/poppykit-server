import type { ConversationStoreState } from './service.js';
export type ConversationSelection = { conversationId?: string; messageKey?: string; workId?: string; claimAt?: number };
export interface ConversationStore {
  read(selection: ConversationSelection): Promise<ConversationStoreState>;
  transaction<T>(selection: ConversationSelection, change: (draft: ConversationStoreState) => T): Promise<T>;
}
/** Notifications are hints: subscribe before reading, then reconcile durable state on wake or timeout. */
export interface ConversationNotifications {
  subscribe(conversationId: string, wake: () => void): () => void;
  publish(conversationId: string): void;
}
