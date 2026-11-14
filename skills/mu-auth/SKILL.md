---
name: mu-auth
description: "Implement and consume the 4-layer authorization core in mu-auth: subsystem policies across 8 subsystems, composable PolicyFolio DAGs, RoleFolioIndex, single-baseline role leases, SubsystemStatus, and optional github-oauth edge/invite/WebAuthn adapters."
---

# `mu-auth` Authorization Core & Edge Adapters

Use these invariants whenever consuming or modifying `mu-auth`:

## 1. Feature Boundaries (`no_std` Core vs. `github-oauth`)

- Keep `default = []` strictly `#![no_std]`, `#![forbid(unsafe_code)]`, and `alloc`-only with zero web, HTTP framework, DOM, or filesystem dependencies so WASM frontends (`mu-console-ui`), shared protocols (`mu-console-protocol`), and servers link cleanly.
- Place host-side helpers (`std` secret loaders, `GithubEdgeAuthAdapter`, `inv_<id>.<hmac>` invite signing/verification, and WebAuthn Passkey enrollment/`StepUpVerifier`) behind the `github-oauth` (or `std`) Cargo feature.

## 2. Four-Layer Authorization Model

- **Subsystems & Policies**: All 8 subsystems (`system`, `ci`, `cd`, `ab_deploy`, `repository`, `observability`, `model_runner`, `platform`) declare atomic positive `Policy` tokens (`<subsystem>:<resource>.<action>`) and immutable `FolioOrigin::Subsystem` starter folios via `SubsystemSecurityManifest`. Keep grants strictly additive (zero `Deny` rules), keep `cd` read-only and ecosystem-agnostic, and never define a manual `ab:promote` policy.
- **PolicyFolios (`FolioCatalog`)**: `FolioOrigin::Subsystem` folios cannot be overwritten or deleted by operators. Operator-authored `FolioOrigin::Operator` folios may compose subsystem folios and policies, validated fail-closed for acyclic `includes` edges (DFS) and valid `PolicyId`/`FolioId` references.
- **Roles & Leases (`RoleCatalog`, `RoleFolioIndex`)**: Every catalog has **exact one** `PinnedBaseline` role (which cannot be named `"anonymous"`, `display_name` forbids `+` and control characters). `RoleFolioIndex` maps `RoleId -> BTreeSet<FolioId>` with `anonymous -> []` by default. `Timed` roles enforce `60 <= idle_ttl_secs <= hard_ttl_secs <= 1800` (`HOST_TIMED_ROLE_CEILING_SECS`), never accept client-supplied TTL overrides, and track independent non-renewable `hard_expires_at_ms` and explicit-activity `idle_expires_at_ms` deadlines per active role.
- **Mandatory Zero-Passkey Gate**: Authenticated users with `passkey_count == 0` evaluate with `passkey_enrollment_required = true` and an empty effective `PolicySet` until a Passkey is enrolled.

## 3. Edge Proxy, Invites & 1Password / FIDO2 WebAuthn

- `GithubEdgeAuthAdapter` inspects `(&str, &str)` header slices, requiring a constant-time (`subtle`) `X-Proxy-Secret` match (or explicitly trusted loopback peer) before reading `X-Forwarded-User`. Secret file helpers read, trim, and fail closed (`None`) on any I/O or empty error.
- Signed `inv_<id>.<hmac>` tokens bind only `invite_id` and expiry (`expires_at_ms`), granting strictly the canonical `PinnedBaseline` role on redemption.
- WebAuthn ceremonies omit `authenticatorAttachment`, set `attestation: "none"` and `userVerification: "preferred"`, enable `ES256`/`EdDSA`/`RS256`, and only reject non-increasing `sign_count` when `stored_count > 0 || new_count > 0` so 1Password synced passkeys (`sign_count == 0`) and physical FIDO2 keys both verify cleanly.
