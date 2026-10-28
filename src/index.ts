export { AuthorityError } from './auth/authority.js';
export type { Principal, WorkRevocationPolicy, AcceptedAuthority, AuthorityCoordinator, AuthorityPolicy, RequestAuthenticator, ResourceEndpoint, ExternalAuthorityAdapter, AuthorityErrorCode } from './auth/authority.js';
export { createRequestAuthenticator } from './auth/authenticator.js';
export * from './conversation/service.js';

export type { ConversationStore, ConversationSelection, ConversationNotifications } from './conversation/store.js';

export { createConversationNotifications } from './conversation/store.js';
export { createBrowserSessions } from './browser.js';
export type { BrowserBinding, BrowserSession, BrowserSessionAuthority, BrowserCookieStore } from './browser.js';
export { createFeedbackHandler } from './feedback.js';
export type { FeedbackReport } from './feedback.js';
export { mcpResourceMetadata, mcpAuthorizationError } from './mcp.js';

export type { Author, AuthorType, Message, RecordedMessage, ConversationRequest, ConversationState, ConversationEvent, KnownEvent, EventPage } from './protocol/wire.js';
