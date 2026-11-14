# mu-auth

Reusable `#![no_std]` + `alloc` (`#![forbid(unsafe_code)]`) authorization core for the MuConsole and platform subsystem ecosystem, providing subsystem-owned policies, composable Policy Folios, a separate `RoleFolioIndex`, single-baseline role lifecycles with independent hard/idle TTL leases, subsystem operational status models, and an optional `github-oauth` edge header, invite, and Passkey verification adapter.

## Architecture

- **Policies (`subsystem`)**: Subsystems (`system`, `ci`, `cd`, `ab_deploy`, `repository`, `observability`, `model_runner`, `platform`) declare atomic positive capability tokens (`<subsystem>:<resource>.<action>`) and immutable `FolioOrigin::Subsystem` starter folios via `SubsystemSecurityManifest`.
- **Policy Folios (`folio`)**: `FolioCatalog` enforces an acyclic `includes` DAG, rejects unknown `PolicyId` or `FolioId` references fail-closed, protects `FolioOrigin::Subsystem` folios from mutation, and computes strictly additive transitive `PolicySet` unions (zero `Deny` rules).
- **Roles & Leases (`role`, `session`)**: `RoleCatalog` enforces a single canonical `PinnedBaseline` role per catalog (`anonymous` reserved and mapped to `[]` in `RoleFolioIndex`), validates `+`-free `display_name` metadata, clamps `Timed` roles to `60 <= idle_ttl_secs <= hard_ttl_secs <= 1800`, and tracks independent non-renewable `hard_expires_at_ms` and explicit-activity `idle_expires_at_ms` leases per active role.
- **Subsystem Status (`subsystem`)**: `SubsystemStatus` (`live`, `in-maintenance`, `partial-maintenance`, `offline`, `degraded`) and `MaintenanceOverride` represent generic 5-state operational health without leaking internal infrastructure identifiers.
- **Edge Auth, Invites & WebAuthn (`github-oauth` feature)**:
  - `GithubEdgeAuthAdapter` inspects `(&str, &str)` header slices, verifying `X-Proxy-Secret` in constant time (`subtle`) or a trusted loopback peer before extracting `X-Forwarded-User`, plus fail-closed secret-file helpers.
  - HMAC-SHA256 `inv_<id>.<hmac>` invite tokens bind only `invite_id` and expiry so invite fulfillment grants strictly the single canonical `PinnedBaseline` role, alongside RFC 3986 `/oauth2/start?rd=` and `/oauth2/sign_out?rd=` helpers.
  - WebAuthn Passkey enrollment and `StepUpVerifier` via `webauthn-rs-core` omit `authenticatorAttachment`, set `attestation: "none"` and `userVerification: "preferred"`, support `ES256`/`EdDSA`/`RS256`, and support both 1Password (`sign_count == 0`) and physical FIDO2 security keys (`stored_count > 0 || new_count > 0` clone check).

## Feature Flags

| Feature        | Default     | Dependencies                                                                    | Scope                                                                          |
| -------------- | ----------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `default`      | Yes (empty) | `core`, `alloc`, `serde` (`no_std`)                                             | Pure policy, folio DAG, role lease, status core (`wasm32` + host + RISC-V)     |
| `std`          | No          | Enables `serde/std`                                                             | File-backed secret resolution helpers (`resolve_secret_*`)                     |
| `github-oauth` | No          | `std`, `hmac`, `sha2`, `hex`, `subtle`, `url`, `webauthn-rs-core`, `serde_json` | Framework-agnostic edge proxy adapter, HMAC invites, WebAuthn Passkey verifier |

## License

`mu-auth` is licensed under the GNU Lesser General Public License version 3.0 with the LGPL-3.0 Linking Exception (`LGPL-3.0-only WITH LGPL-3.0-linking-exception`). See [LICENSE](LICENSE), [COPYING](COPYING), and [LINKING-EXCEPTION](LINKING-EXCEPTION).
