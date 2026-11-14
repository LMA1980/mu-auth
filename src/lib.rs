#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Reusable `#![no_std]` + `alloc` authorization core for `mu-console` and platform services.
//!
//! Layers provided under `default = []` (`#![no_std]` + `alloc`):
//! - [`subsystem`]: 8 canonical subsystems, 5-state [`SubsystemStatus`], atomic positive [`Policy`] definitions, and starter manifests.
//! - [`folio`]: [`FolioCatalog`] topological DAG validator, immutable [`FolioOrigin::Subsystem`] guards, and additive [`PolicySet`] resolver.
//! - [`role`]: [`RoleCatalog`] enforcing the single canonical `PinnedBaseline` role, `+`-free display names, `Timed` TTL bounds, and [`RoleFolioIndex`].
//! - [`session`]: [`Principal`], independent per-role [`RoleLease`] / [`RoleLeases`], mandatory zero-Passkey gate, and [`evaluate_session`].
//!
//! Additional host adapters enabled behind Cargo features:
//! - `std`: [`secret`] fail-closed secret path & environment resolution helpers.
//! - `github-oauth`: [`edge`] proxy header verification, [`invite`] `inv_<id>.<hmac>` tokens + RFC 3986 `/oauth2/*` URL builders, and [`webauthn`] 1Password / FIDO2 Passkey verifier.

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod error;
pub mod folio;
pub mod role;
pub mod session;
pub mod subsystem;

#[cfg(feature = "std")]
pub mod secret;

#[cfg(feature = "github-oauth")]
pub mod edge;
#[cfg(feature = "github-oauth")]
pub mod invite;
#[cfg(feature = "github-oauth")]
pub mod webauthn;

pub use error::{AuthError, FolioError};
pub use folio::{FolioCatalog, PolicySet};
pub use role::{
    validate_display_name, RoleActivation, RoleCatalog, RoleFolioIndex, RoleId, RoleSpec,
    StepUpRequirement, ANONYMOUS_ROLE_ID, HOST_TIMED_ROLE_CEILING_SECS, MIN_TIMED_ROLE_TTL_SECS,
};
pub use session::{
    evaluate_session, evaluate_session_with_disabled_subsystems, AuthAuthority, Principal,
    RoleLease, RoleLeases, SessionEvaluation,
};
pub use subsystem::{
    canonical_ab_deploy_manifest, canonical_cd_manifest, canonical_ci_manifest,
    canonical_manifests, canonical_model_runner_manifest, canonical_observability_manifest,
    canonical_platform_manifest, canonical_repository_manifest, canonical_system_manifest, FolioId,
    FolioOrigin, MaintenanceMode, MaintenanceOverride, Policy, PolicyFolio, PolicyId, SubsystemId,
    SubsystemSecurityManifest, SubsystemStatus,
};

#[cfg(feature = "std")]
pub use secret::{
    resolve_secret_env, resolve_secret_file, resolve_secret_value, resolve_secret_with_file_var,
};

#[cfg(feature = "github-oauth")]
pub use edge::{
    constant_time_str_eq, EdgeAuthConfig, EdgeIdentity, GithubEdgeAuthAdapter, GithubLogin,
    HEADER_FORWARDED_EMAIL, HEADER_FORWARDED_USER, HEADER_PROXY_SECRET,
};
#[cfg(feature = "github-oauth")]
pub use invite::{
    build_oauth_sign_out_url, build_oauth_start_url, parse_invite_token, percent_encode_rfc3986,
    InviteCodec, InviteFulfillment, ParsedInviteToken, SignedInvite,
};
#[cfg(feature = "github-oauth")]
pub use webauthn::{
    AuthenticationOutcome, ElevationLease, EnrollmentChallenge, PasskeyRecord,
    PendingAuthentication, PendingRegistration, StepUpChallenge, StepUpVerification,
    StepUpVerifier, WebauthnConfig, WebauthnPasskeyService, DEFAULT_WEBAUTHN_CHALLENGE_TTL_SECS,
    SUPPORTED_PASSKEY_ALGORITHMS,
};
