import { runConversationAdapterContract } from '../../dist/adapter-contract.js';
import { initialConversationState } from '../../dist/index.js';
import { memoryStore } from './support.mjs';

// Two handles on one in-memory state, standing in for two connections to one durable namespace.
runConversationAdapterContract(async () => {
  const store = memoryStore(initialConversationState());
  store.inspect = () => store.read(); store.adminTransaction = change => store.transaction(change);
  return { store, second: { inspect: () => store.read(), adminTransaction: change => store.transaction(change), read: () => store.read(), transaction: (selection, change) => store.transaction(selection, change) }, close: async () => {} };
});

