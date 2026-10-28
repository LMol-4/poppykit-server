# Changelog

## 0.4.0 — 2026-10-28

Target pinned Personal Agent Protocol draft 0.3. Break discovery, proof-key grants, author, browser joining and MCP Token Exchange contracts. Upgrade issuer state 3→4; stop old writers and reset conversation state to version 2. Require explicit company history scopes.

Local migration candidate only. Publication and deployment require separate approval.

## 0.3.1

Support Node 24.21.0 and later within Node 24 under the owner-accepted runtime policy.
Build, verification and publication tooling read .node-version.

## 0.3.0

Require Node 24 >=24.22.1 within 24.x. Enforce current-token expiry after waits and
at streamed delivery while preserving already-accepted work's authority ceiling.
Deduplicate reserved string output IDs and retain refresh-token ancestors through
fixed grant expiry so replay revokes descendants. Direct Sign-In hosts must supply
the documented durable `authorizationResultCipher`; identical decisions recover
their original encrypted callback. Before public enablement, revoke pre-upgrade
live grant lineages and obtain fresh consent, or prove their fixed expiry.
Required release verification now includes isolated PostgreSQL contracts.

## 0.2.0 (release candidate)

Add bundled Postgres company stores/coordinator with explicit migrations, atomic host transaction composition, savepoints and pool lifecycle.

## 0.1.1

Documentation refresh: registry installation, runnable quickstarts, focused guides
and the tagged GitHub/OIDC release runbook. No runtime API, storage format or
third-party dependency change.

## 0.1.0

Initial MIT development release, published manually. Discovery, safe HTTPS, all
three sign-in methods, targeted durable storage and recovery, conversations and
API/browser/feedback hooks. The CLI uses the client SDK with trusted secure-backend
adapters. J8 established strict typed tests and exact installed-artifact checks.

Version 0.x may still change APIs/storage; future changes must explain compatibility,
migration/reset and security implications. No stable 1.0 or external-host certification
is promised. Older private 0.0.0 candidates retain their own historical evidence.
