import { runConversationAdapterContract } from '../../dist/adapter-contract.js';
import { initialConversationState } from '../../dist/index.js';
import { memoryStore } from './support.mjs';

// Two handles on one in-memory state, standing in for two connections to one durable namespace.
runConversationAdapterContract(async () => {
  const store = memoryStore(initialConversationState());
  return { store, second: { read: () => store.read(), transaction: change => store.transaction(change) }, close: async () => {} };
});
