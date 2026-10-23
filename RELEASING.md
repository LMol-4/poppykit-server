# Release preparation and owner runbook

These packages are private, unpublished development version **0.0.0**. Their
metadata records **UNLICENSED** because no public license grant has been selected.
That is a reserved-rights state, not a new license. Do not remove private, select
a license, reserve package names or publish without owner authorization.

## Verification graph

Every push, pull request and manual CI run calls the same repository-local
`.github/workflows/verify.yml`. Documentation-only changes run the graph too;
there are no path filters. A clean GitHub-hosted Linux job builds and packs once.
The release manifest binds full source SHAs, package/version, filenames, byte
counts, SHA256 and npm SHA512 integrity to those unchanged tarballs.

| Job | Responsibility |
| --- | --- |
| candidate | Typecheck/build from exact source, pack once, record/upload identity |
| fast | Documentation links/fences and small unit checks |
| contracts | Storage, authentication, network and conversation contracts |
| integration | API/browser/feedback and independent peers; CLI installs all pinned candidates |
| packaged-linux/windows/macos | Install unchanged tarballs; startup, exports, SQLite and representative platform behavior |
| validation | Release failure simulations, registry/toolchain guards and actual workflow wiring assertions |
| gate | Always report; require each allowlisted job result to equal success and recheck artifact identity |

All deterministic source tests run once on Linux, partitioned by
`.github/test-groups.json`. Its runner rejects unassigned/duplicate test files.
The CLI does not rerun complete SDK suites. It checks out the exact full client
and server SHAs in its candidate JSON files, builds/installs their tarballs, and
tests the combined package boundary. The SDKs have no dependency on one another;
the server candidate is a CLI integration peer, not a production CLI dependency.
Private cross-repository checkouts require owner-provided read access; no local
untracked sibling directory is assumed.

Node 24.12.0 is the supported CI baseline on GitHub-hosted ubuntu-latest,
windows-latest and macos-latest. Later Node majors are not separately certified.
The CLI checks unsupported Node 22.17.1 once on Linux. Most JavaScript/type checks
do not need an OS-by-runtime matrix. Packaged OS checks exercise installed shims,
paths/SQLite and the CLI's generic encrypted-backend/lifecycle fixture. They do
not certify a production OS keyring, physical terminal, browser engine or KMS.

SDK ordinary CI may restore a pnpm cache keyed by its frozen lockfile; installed
dependencies are never shared across OSes. Release-context verification restores
no dependency cache. The unpublished CLI dependency is supplied explicitly as a
tarball; SDK lockfiles and full commit/version pins govern inputs, with exact
TypeScript 5.9.3/@types-node 24.10.0/undici-types 7.16.0 tooling. No privileged
release consumes a pull-request cache, artifact or check-name lookup. Artifacts
are downloaded from this run only, and their manifest digest comes from the
candidate job output. Failure logs retain seven days; candidates retain fourteen.
Expired/missing artifacts require a new complete verification run.

## Release workflow and fail-closed gate

`release.yml` is manual dispatch only. Dispatch an existing owner-approved
`vVERSION` tag, supply the full tagged commit, matching version/tag, and
leave `publish=false` for verification only. A branch dispatch, wrong SHA,
version/tag mismatch, moved tag or missing/changed artifact is rejected. Do not
push a tag merely to test workflow syntax. All actions are pinned to immutable
commits; reusable verification is the same commit as its caller.

The allowlist is candidate, fast, contracts, integration, packaged-linux,
packaged-windows, packaged-macos and validation. Missing, empty, failed, canceled
and skipped results all fail. The always-running gate has no permission to
publish. The publisher needs the reusable verification workflow to succeed AND
its ready output to be exactly true AND explicit publish selection. It then
rechecks source/commit/ref/version, manifest digest, every tarball, unchanged
packed metadata, private/license policy, npm/toolchain and registry state.

Only the publishing job requests `id-token: write`. It runs on GitHub-hosted
Linux in protected environment `npm`. There is no publish credential in PR CI,
no workflow_run artifact promotion, no checkout of PR code in a privileged job,
no build/install/pack in the publisher, and no automatic publication on push/tag.
Publication uses `npm publish TESTED_TARBALL --access public --provenance --ignore-scripts`.
It publishes the unchanged bytes downloaded and checked in that job. Publication
is serialized per repository and is never canceled by a newer release run.

Safe local tests execute the gate with failed/canceled/missing/skipped checks,
wrong commit/version/tag/ref, missing artifact, tampered tarball/manifest and an
absent trusted digest. Registry tests reject an existing version, unauthorized or
uncertain registry responses, unsupported tools and mismatched dependency bytes.
These simulations and actionlint validate code/wiring. They do not prove GitHub
environment settings, npm ownership or OIDC exchange work.

Any documentation/package-metadata/source change after J6 creates a new candidate.
J6 evidence applies only to J6's recorded commits/digests. Re-run this complete
graph on final commits/tarballs and retain the new manifests/platform results.
Never label changed bytes publishable using old evidence. A passing Windows
local run does not substitute for actual hosted Linux/macOS jobs.

## Owner configuration — external, not performed by this repository

Rechecked against [npm trusted publishers](https://docs.npmjs.com/trusted-publishers/),
[GitHub secure use](https://docs.github.com/en/actions/reference/security/secure-use),
[OIDC](https://docs.github.com/en/actions/concepts/security/openid-connect), and
[deployment environments](https://docs.github.com/en/actions/how-tos/deploy/configure-and-manage-deployments/manage-environments)
on **2026-10-23**. Recheck those live requirements before first publication:

1. Confirm npm scope/package-name ownership and authorized maintainers. Select
   the actual license, add its complete license file to the allowlist if applicable,
   choose a public semantic version and record release notes. Only then authorize
   changing private to false and UNLICENSED to the owner's selected license.
   Confirm repository.url exactly matches the actual GitHub repository.
2. Protect main, release tags, Actions files/scripts and candidate pins with
   repository rules and review/CODEOWNERS appropriate to the actual team. Require
   the complete verification result for the exact commit. Prevent unreviewed
   workflow changes or tag replacement. Read-only PR permissions and trusted
   publishing cannot enforce these owner settings themselves.
3. Create environment `npm` in each package repository with required reviewers,
   self-approval restrictions, protected release-tag rules and no admin bypass
   where the repository plan supports them. Confirm feature availability; an
   unprotected environment name alone provides no approval barrier. Add environment
   variable `NPM_PUBLISH_ENABLED=true` only after setup/authorization. Missing
   or false configuration fails the publisher's check.
4. Configure each npm package's trusted publisher for GitHub owner `LMol-4`,
   the corresponding `poppykit-client`, `poppykit-server` or `poppykit-cli`
   repository, workflow filename **release.yml**, and environment **npm**.
   Match spelling/case and the initiating workflow identity. verify.yml is a
   reusable verifier, not the publishing workflow. Reassess identity if introducing
   a reusable publisher or changing callers; workflow_call/dispatch identity has
   documented caller nuances. This setup authorizes a workflow identity, not its
   test results. The gate supplies the independent verification condition.
5. npm currently requires npm >=11.5.1 and Node >=22.14.0 for trusted publishing;
   this workflow uses Node24.12.0 and checks npm's version without upgrading it.
   GitHub-hosted runners are supported; self-hosted runners are not supported for
   this npm path. GitHub permissions must permit OIDC. No NODE_AUTH_TOKEN is set.
   Do not silently fall back to a long-lived publish token when OIDC fails.
6. Verify provenance requirements, repository visibility and package visibility
   in the current npm documentation. Trusted publishing generates provenance
   automatically for supported public packages/public repositories; explicit
   --provenance must not be treated as proof without checking the registry record.
   A private-source repository may need an owner-approved alternative or visibility
   decision; do not claim provenance supported where it is not.
7. Current npm publisher configurations require first successful use within two
   days or expire; configure near the authorized release. npm supports up to ten
   configurations, with separate direct-publish/staging/dist-tag permissions.
   Grant only this workflow's required direct publication capability, review other
   publishers/tokens and restrict alternative access according to owner policy.
   Keep recovery access separate from the normal workflow.

## First publication and bootstrap

A new package may need first publication using authorized npm-owner authentication
before package settings/trusted publishing are available. npm name availability
has not been established by creating a GitHub repository. The owner must confirm
the current bootstrap flow and explicitly authorize it. Do not place bootstrap
tokens in PR workflows or temporarily make publication unconditional.

Prepare a license/version-ready candidate, run the exact full verification graph,
retain/download the unchanged manifest/tarball and verify its digest. If the first
publication must be manual, an authorized owner uses their own current npm login/
2FA or narrowly scoped supported bootstrap credential to publish those exact bytes,
then removes temporary credentials and configures the trusted publisher. Record
the resulting version/integrity/provenance. A dry run is not proof of bootstrap
permissions or production OIDC authentication. Current 0.0.0/private candidates
cannot be published through the prepared workflow.

## Package order, existing versions and partial recovery

Release by actual production dependencies: client and server are independent;
either SDK can publish first. Publish the client before a CLI version requiring
that exact client version. The CLI registry guard requires the published client's
dist.integrity to match its tested candidate tarball. If it differs, stop and
reconcile/retest the actual dependency; do not silently replace tested bytes.

Before publishing, npm view must confirm that this package version is absent.
Only a structured E404 is considered absent; auth/network/registry failures stop.
An existing version stops publication even after an uncertain earlier response.
Inspect npm's published version, integrity, provenance and intended dist-tag using
read-only registry commands. Never overwrite or blindly republish. If the exact
bytes already published, record that success and resume the remaining package's
separate verified release. Multi-repository releases are not atomic. Do not unpublish
a successful dependency as rollback. If correction is required, choose a new
version, update dependent pins/lockfiles/release notes and verify a new candidate.

This runbook does not authorize publication, tag pushes, package ownership changes,
external settings, deployment or demo implementation.
