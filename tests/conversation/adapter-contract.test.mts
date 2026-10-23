import type {ConversationStoreState} from '../../dist/conversation/service.js';
import { runConversationAdapterContract } from '../../dist/adapter-contract.js';
import { initialConversationState } from '../../dist/index.js';
import { memoryStore } from './support.mjs';

// Two handles on one in-memory state, standing in for two connections to one durable namespace.
runConversationAdapterContract(async () => {
  const base=memoryStore(initialConversationState());
  const store=Object.assign(base,{inspect:()=>base.read(),adminTransaction:<T,>(change:(state:ConversationStoreState)=>T)=>base.transaction(change)});
  return { store, second: { inspect: () => store.read(), adminTransaction: change => store.transaction(change), read: () => store.read(), transaction: (selection, change) => store.transaction(selection, change) }, close: async () => {} };
});
