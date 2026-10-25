# Releasing

Use the tagged GitHub Actions workflow, not a local rebuild. Packages are MIT;
0.1.0 was manually bootstrapped. Version 0.1.1 refreshes documentation without
changing runtime APIs. Each new version needs its own source/artifact evidence.

## Before tagging

- Confirm npm ownership, unused versions, supported Node 24.x (at least 24.21.0) and npm>=11.5.1.
  Keep the pinned compiler/dependencies; do not upgrade tooling during a release.
- Update version, changelog and shipped docs. CLI's client dependency and both
  candidate JSON files must match exact final SDK versions/full source SHAs.
- Review the full diff and run typecheck, build, tests and documentation checks.
  Preserve the existing API/storage/security contracts and historical evidence.
- Protect source, workflow files, pins and release tags with repository review/rules.
  All actions are commit-pinned; release verification never restores a PR cache.
- Verify GitHub environment **npm**: variable **NPM_PUBLISH_ENABLED=true**,
  intended required reviewer, no admin bypass, and allowed deployment tags **v***.
  Reviewers approve the real pending deployment; automation must not approve for them.
- Configure the npm package's GitHub trusted publisher: owner **LMol-4**, this
  package repository, workflow **release.yml**, environment **npm**. Match case.
  Enable **direct npm publish** permission; this workflow does not stage a publish.
  Configure near the release: unused configurations expire after two days. Public
  source/package visibility and supported GitHub-hosted runners are required for
  this provenance path. Do not supply NODE_AUTH_TOKEN or fall back to a long-lived
  token if OIDC fails. Confirm current [npm requirements](https://docs.npmjs.com/trusted-publishers/).

## Publish exact tagged source

Client and server are independent. Publish client before CLI: the CLI registry
guard requires its tested client tarball integrity to equal the published one.

1. Merge reviewed source to main. Record the full SHA and create/push an approved
   immutable **vVERSION** tag at that exact commit. Never move or replace a tag.

   ```sh
   git tag vVERSION FULL_SHA
   git push origin refs/tags/vVERSION
   ```
2. Dispatch **Release** from that tag, with matching version, tag and full commit.
   Optional `publish=false` rehearses verification only. A later publishing dispatch
   is a new run with newly identified artifacts; it does not reuse a rehearsal's bytes.
3. Dispatch with `publish=true` when authorized. Example (replace all placeholders):

   ```sh
   gh workflow run release.yml --repo LMol-4/PACKAGE --ref vVERSION -f version=VERSION -f tag=vVERSION -f commit=FULL_SHA -f publish=true
   ```

4. Wait for candidate, fast, contracts, integration, packaged-linux/windows/macos,
   validation, postgres and gate to succeed. The postgres job uses its own disposable PostgreSQL17 cluster and the same-run checked candidate/harness; zero discovery or any skipped database case fails. Missing, failed, canceled or skipped prerequisites
   fail closed. Then follow the Actions environment-approval link. Do not bypass it.
5. The publisher rechecks source/tag/ref/version, trusted manifest digest, unchanged
   tarball metadata/bytes, owner enablement, registry absence and dependency integrity.
   It publishes the same-run tested tarball with `--access public --provenance
   --ignore-scripts`; it never installs, builds or packs again.
6. Save run URL, full source SHAs, manifest SHA256, filenames, versions, byte counts,
   tarball SHA256/npm SHA512 and registry integrity/provenance. Download before the
   14-day candidate retention expires. Verify registry bytes, a clean exact-version
   registry install, exported modules and the real npm CLI shim.

Ordinary main/tag CI is useful evidence but is not a tagged Release/OIDC publishing
run. A dry run or green tests alone do not prove npm authentication or provenance.
The separate checked test-harness artifact is source/output-hash bound, used only
by unprivileged verification jobs, and never published in an npm package.

## Failure and partial release

Stop on tag/source/version/digest mismatch, unknown registry responses or changed
client integrity. Do not weaken gates, repack approved bytes, change pins silently,
force an overwrite or use a token fallback. Inspect the failed job and preserve logs.
For OIDC/auth failure check publisher spelling/case, workflow/environment identity,
expiry, reviewer approval, permissions and npm/toolchain support before a new run.

If a version already exists, compare its registry integrity and provenance with the
saved receipt. Matching successful publication is recorded, never republished.
For partial publication, finish only absent packages; verify the published client's
exact bytes before CLI. If bytes differ or a fix is needed, use a reviewed new
version and complete verification. A source checkout rollback cannot undo an npm
publication or external side effect. Deprecation, dist-tag changes, unpublish and
replacement versions need separate owner authorization; never delete evidence.

## Verification limits

Deterministic source suites run once per verification graph on Linux; exhaustive
file groups reject omissions/duplicates. Packaged jobs test actual installed JS,
exports/declarations/content/SQLite and representative platform behavior; CLI also
tests real shims, auth/retry processes and API/browser/feedback wiring. They do not
certify a production keyring, physical terminal, browser engine, KMS or TLS deployment.
Windows GNU tar is given archive basename plus directory cwd to avoid drive-colon
remote parsing. Failure logs retain seven days. Expired/missing artifacts require a
new full run, not relabeling old results. See [CONTRIBUTING.md](CONTRIBUTING.md).
