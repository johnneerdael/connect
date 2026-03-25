# `connect` Design: Bundled Keychain Secrets and macOS Release Signing

## Summary

This design reduces repeated keychain prompts by changing `connect` from multiple per-profile secret entries to a single bundled secret record per profile, backed by process-local caching for the lifetime of one CLI invocation. It also adds optional macOS release signing in GitHub Actions so shipped binaries and installers can carry a stable Apple code-signing identity when the required secrets are configured.

The intent is practical:

- reduce keychain unlock prompts during normal `connect` usage
- preserve existing add/edit/remove behavior for passwords, private keys, and key passphrases
- avoid invasive changes to the rest of the application
- make signed macOS releases reproducible without breaking unsigned local builds or forked CI

## Goals

- store one keychain item per profile instead of one keychain item per secret field
- ensure repeated secret reads within a single `connect` process do not trigger repeated keychain access
- preserve partial secret edits so `connect edit` can change one secret field without clobbering the others
- keep the current `SecretStore` interface stable for the rest of the app
- add optional macOS signing to the release workflow using GitHub Actions secrets

## Non-Goals

- no notarization in this round
- no long-lived cross-process secret agent or credential daemon
- no change to the CLI surface for secret management
- no platform-specific signing changes for Linux or Windows
- no migration away from OS-native secret stores

## Current Problem

Today the keyring backend stores separate entries for:

- password
- private key
- key passphrase

That means one profile access can require multiple keychain reads. On platforms like macOS, this increases the chance of repeated access prompts. In addition, current macOS release packaging builds an installer but does not code-sign the binary or package, which weakens the stability of Keychain trust decisions across runs.

## Secret Storage Design

### One bundled secret record per profile

Each profile will map to one keychain entry. The entry payload will be a serialized secret bundle containing:

- optional password
- optional private key
- optional key passphrase

The bundle is application-internal and opaque to the rest of the codebase. The `SecretStore` interface remains field-oriented, but the keyring backend will load and update the whole bundle under the hood.

### Serialization format

Use a simple versioned JSON document for the stored bundle.

Suggested shape:

```json
{
  "version": 1,
  "password": "optional",
  "private_key": "optional",
  "key_passphrase": "optional"
}
```

Rationale:

- human-decodable for debugging if needed
- easy to evolve with a `version` field
- no additional dependency required beyond existing serialization support or a minimal implementation

If all fields are empty after an update, the keychain entry should be deleted rather than storing an empty bundle.

### Entry naming

The keychain backend should use one suffix per profile, for example `profile`.

Current multiple suffixes:

- `password`
- `private-key`
- `key-passphrase`

New single suffix:

- `profile`

The effective keyring key remains logically scoped by:

- service name: `connect`
- account/user key: `<profile>:profile`

## Merge-Safe Edit Behavior

Secret edits must remain partial and non-destructive.

Behavior requirements:

- setting a password updates only the password field in the bundle
- importing a private key updates only the private key field
- setting a key passphrase updates only the key passphrase field
- metadata-only edits do not rewrite or remove the stored secret bundle
- profile deletion removes the bundled keychain entry

Update algorithm:

1. load the existing bundle if present
2. merge only the provided secret-field updates
3. write back the merged bundle
4. refresh the process-local cache

This preserves current add/edit semantics without exposing bundle details to the rest of the application.

## Process-Local Secret Cache

### Purpose

Reduce repeated keychain reads during a single `connect` invocation.

### Behavior

- first secret read for a profile loads the bundled keychain record
- the decoded bundle is cached in memory for the lifetime of the `KeyringSecretStore`
- subsequent reads for the same profile use the in-memory cache
- writes update both the keychain entry and the in-memory cache
- profile deletion removes the keychain entry and invalidates the cache entry

### Scope and limits

- cache is per-process only
- no persistence across separate CLI invocations
- no background refresh
- cache remains scoped to a single profile bundle, not a global preload of all profiles

This keeps secret residency in memory narrow while eliminating repeated lookups during one run.

## Migration Strategy

The keyring backend must support a smooth transition from legacy multi-entry storage.

Read path:

1. try to load the new bundled profile entry
2. if absent, attempt to read legacy field-specific entries
3. if legacy entries exist, assemble a bundle in memory
4. write the assembled bundle to the new single-entry location
5. optionally delete the legacy entries after a successful migration write

Write path:

- always write only the bundled entry format

Delete path:

- delete the bundled entry
- also remove any legacy entries defensively, if present

This allows existing users to migrate lazily on first access without a separate migration command.

## SecretStore Boundary

The public `SecretStore` trait remains stable:

- `set_password`
- `get_password`
- `set_private_key`
- `get_private_key`
- `set_key_passphrase`
- `get_key_passphrase`
- `delete_profile_secrets`

Only the keyring-backed implementation changes. This avoids churn in:

- profile add/edit flows
- auth logic
- doctor checks
- tests built around field-oriented semantics

## macOS Release Signing Design

### Scope

Add optional signing to GitHub Actions for tagged macOS releases.

When signing secrets are configured, the workflow should:

- import the Developer ID Application certificate into a temporary keychain
- import the Developer ID Installer certificate into a temporary keychain
- sign the `connect` binary before packaging
- build the macOS installer package
- sign the `.pkg` with the installer identity

When signing secrets are absent, the workflow should:

- continue producing an unsigned macOS package
- avoid failing forks or local reuse of the workflow

### GitHub Actions secrets

The workflow will document and use:

- `MACOS_DEVELOPER_ID_APPLICATION_P12`
- `MACOS_DEVELOPER_ID_INSTALLER_P12`
- `MACOS_DEVELOPER_ID_P12_PASSWORD`
- `MACOS_KEYCHAIN_PASSWORD`

Optional future secret:

- `MACOS_TEAM_ID`

The certificate secrets are expected to be base64-encoded `.p12` payloads.

### Workflow behavior

On macOS release jobs:

1. detect whether the required signing secrets are present
2. if present:
   - create a temporary keychain
   - import both certificates
   - unlock the keychain
   - configure key partition access for codesign/productsign
   - codesign the built `connect` binary
   - package the installer
   - sign the installer package
3. if absent:
   - build the unsigned binary and installer as today

### Local development behavior

Local builds remain unsigned by default. The CI workflow becomes the primary release-signing path, not a local requirement.

## Error Handling

### Secret bundle handling

- invalid or undecodable bundle payloads should return a clear secret-store error
- partial legacy migration should prefer preserving data over eager cleanup
- failed migration writes must not delete legacy entries

### Signing

- missing signing secrets should not fail the macOS build
- malformed signing inputs should fail the signing step clearly when signing is enabled
- signing failures should fail the macOS packaging job for that run

## Testing Plan

### Secret storage

- unit tests for bundle encode/decode round-trips
- tests that field-specific setters update only the intended field
- tests that metadata-only edits leave bundle contents unchanged
- tests that deleting profile secrets removes bundled and legacy entries
- tests that legacy multi-entry secrets migrate into the bundled format
- tests that repeated reads hit the process-local cache after first load

### Application behavior

- existing profile add/edit tests continue to validate secret-edit behavior
- doctor tests continue to validate secret availability against the new storage backend

### Release workflow

- packaging asset tests updated as needed for signing-aware macOS packaging
- workflow logic should be structured so unsigned packaging remains testable without CI secrets

### Verification before release

- `cargo test`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo build --release`

Real macOS signing validation still depends on GitHub Actions secrets being configured in the target repository.

## Rollout Notes

- lazy migration avoids forcing users through a manual upgrade step
- signed macOS releases should improve the stability of Keychain trust prompts, but OS policy still ultimately controls access prompts
- process-local caching reduces prompts within one run even before signed releases are adopted

