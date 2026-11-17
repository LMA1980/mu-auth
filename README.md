# mu-auth

Reusable `#![no_std]` + `alloc` (`#![forbid(unsafe_code)]`) authorization core for the MuConsole and platform subsystem ecosystem, providing subsystem-owned policies, composable Policy Folios, a separate `RoleFolioIndex`, single-baseline role lifecycles with independent hard/idle TTL leases, subsystem operational status models, and an optional `github-oauth` edge header, invite, and Passkey verification adapter.

## Architecture

- **Policies (`subsystem`)**: Subsystems (`system`, `ci`, `cd`, `ab_deploy`, `repository`, `observability`, `model_runner`, `platform`) declare atomic positive capability tokens (`<subsystem>:<resource>.<action>`) and immutable `FolioOrigin::Subsystem` starter folios via `SubsystemSecurityManifest`.
- **Policy Folios (`folio`)**: `FolioCatalog` enforces an acyclic `includes` DAG, rejects unknown `PolicyId` or `FolioId` references fail-closed, protects `FolioOrigin::Subsystem` folios from mutation, and computes strictly additive transitive `PolicySet` unions (zero `Deny` rules).
- **Roles & Leases (`role`, `session`)**: `RoleCatalog` enforces a single canonical `PinnedBaseline` role per catalog (`anonymous` reserved and mapped to `[]` in `RoleFolioIndex`), validates `+`-free `display_name` metadata, clamps `Timed` roles (including renewable leases) to `60 <= idle_ttl_secs <= hard_ttl_secs` with cumulative `hard_ttl_secs + max_renewals * renew_extend_secs <= 1800` (`HOST_TIMED_ROLE_CEILING_SECS`), and tracks independent `hard_expires_at_ms` and explicit-activity `idle_expires_at_ms` leases per active role (including the canonical Passkey-gated `super-operator` role: 2m idle, 15m session, single +15m last-2m Passkey renewal across all 8 subsystems via `canonical_super_operator_folios()`).
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

## Ecosystem Integration

`mu-auth` serves as the shared policy, folio, role-lease, and edge/WebAuthn verification core across the platform ecosystem:

- [**`mu-console`**](https://github.com/LMA1980/mu-console) (`mu-console-protocol`, `mu-console-data`, `mu-console-ui`): Evaluates `mu-auth` policy folios, role leases, and Passkey step-up challenges across capability-gated console areas.
- [**`mu-ci-controller`**](https://github.com/LMA1980/mu-ci-controller): Exposes the `/api/auth/*` authority backed by `mu-auth` edge identity verification, HMAC invites, and WebAuthn Passkey step-up leases.
- [**`mu-cd-controller`**](https://github.com/LMA1980/mu-cd-controller) (`CdAuthorizer`): Gates continuous delivery promotion, deployment, and rollback operations using `mu-auth` capability policies.
- [**`mu-observable-hub`**](https://github.com/LMA1980/mu-observable-hub) (`MuAuthFolioVerifier`): Enforces `mu-auth` policy folio authorization on observability and analytics endpoints.
- [**`jero-manager`**](https://github.com/LMA1980/jero-manager): Gates `/api/mr/v1/*` inference control-plane endpoints using `mu-auth` policy evaluation.

## License

`mu-auth` is licensed under the GNU Lesser General Public License version 3.0 with the LGPL-3.0 Linking Exception (`LGPL-3.0-only WITH LGPL-3.0-linking-exception`). See [LICENSE](LICENSE), [COPYING](COPYING), and [LINKING-EXCEPTION](LINKING-EXCEPTION).
