# API reference

All public entry points ship TypeScript declarations in `dist`. Use editor
completion for complete options and results; this map identifies the integration seams.

| Entry point | Main exports | Guide |
| --- | --- | --- |
| `@poppykit/server` | `createRequestAuthenticator`, `AuthorityError`, authority types | [authentication](AUTH.md) |
| `@poppykit/server` | `createConversationService`, `createConversationNotifications` | [delivery](DELIVERY.md) |
| `@poppykit/server` | `createBrowserSessions`, `createFeedbackHandler`, MCP metadata/error helpers | [integrations](INTEGRATIONS.md) |
| `@poppykit/server/reference-auth` | `createReferenceIssuer`, `createMetadataResolver`, `createNodeTransport` | [authentication](AUTH.md) |
| `@poppykit/server/sqlite` | `SqliteCompanyDatabase` | [storage](STORAGE.md) |
| `@poppykit/server/adapter-contract` | adapter verification helpers | [storage](STORAGE.md) |

Conversation workers claim accepted work, enforce account/scopes, publish replies
and finish work through service operations. External effects require application
idempotency and reconciliation. Existing issuers implement `ExternalAuthorityAdapter`
and do not need the optional reference issuer. Your framework owns HTTPS routing,
trusted public URLs, ingress limits, request cancellation and private-error handling.

Run the [quickstart](examples/quickstart.mjs) without a listener or external service.
