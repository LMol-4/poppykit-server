# API reference

All public entry points ship TypeScript declarations in `dist`. Use editor
completion for complete options and results; this map identifies the integration seams.

| Entry point | Main exports | Guide |
| --- | --- | --- |
| `@poppykit/server` | `createSessionAuthority`, `createRequestAuthenticator`, `AuthorityError`, Session/authority types | [authentication](AUTH.md) |
| `@poppykit/server` | `createConversationService`, `createConversationNotifications` | [delivery](DELIVERY.md) |
| `@poppykit/server` | `Author`, `AuthorType`, `Message`, `RecordedMessage`, conversation/event types | [delivery](DELIVERY.md) |
| `@poppykit/server` | `createBrowserSessions`, `createFeedbackHandler`, MCP metadata/error helpers | [integrations](INTEGRATIONS.md) |
| `@poppykit/server/reference-auth` | `createReferenceIssuer`, `createMetadataResolver`, `createNodeTransport` | [authentication](AUTH.md) |
| `@poppykit/server/sqlite` | `SqliteCompanyDatabase` | [storage](STORAGE.md) |
| `@poppykit/server/adapter-contract` | `runSessionAdapterContract`, `runBrowserCookieAdapterContract`, issuer/conversation adapter contracts | [storage](STORAGE.md) |

Conversation workers claim accepted work, enforce account/scopes, publish replies
and finish work through service operations. External effects require application
idempotency and reconciliation. Existing issuers implement `ExternalAuthorityAdapter`
and do not need the optional reference issuer. Your framework owns HTTPS routing,
trusted public URLs, ingress limits, request cancellation and private-error handling.

Direct reference issuers now require `authorizationResultCipher` before
`beginAuthorization`; same-decision `completeAuthorization` recovers the encrypted
callback through its original validity window. See [AUTH.md](AUTH.md) for custody,
revocation and one-time exchange limits. SessionStore admission and BrowserCookieStore one-use authorization are new
custom-adapter contracts; see STORAGE.md.

Run the [quickstart](examples/quickstart.mjs) without a listener or external service.

The optional Postgres entry point ships its adapters, `createPostgresPool`,
`postgresMigration`, `migratePostgres` and schema-version export; see [storage](STORAGE.md).
TypeScript Postgres consumers also install `@types/pg@8.23.1` as a development dependency.

## Business Operations v2

See [OPERATIONS.md](OPERATIONS.md) for the complete consent/effect contract. Root exports include `BusinessOperation`, `OperationApproval`, `OperationRequest`, `operationsV2`, `supportsOperations`, `parseBusinessOperation`, `parseOperationApproval`, `parseApprovalHeader`, `approvalHeader`, `mcpApproval`, `approvalMetaKey`, `captureApiOperationRequest`, `operationExpiry`, `operationRequiredResponse` and `operationToolError`.

Server exports `createBusinessOperations`, `BusinessOperationError`, `operationApiResponse`, `operationMcpResponse`, `operationPendingResponse`, `BusinessOwner`, `OperationRevision`, `BusinessOperationRecord`, `BusinessOperationStore`, `OperationInput`, `OperationOutcome` and `ExternalOperationEffect`. Both company databases expose `businessOperations(namespace)` and scoped `withTransaction`; the adapter-contract subpath exports `runBusinessOperationAdapterContract`. Conversation options accept `operations:metadata`, and `operationContext(work)` returns its accepted binding/approval.
