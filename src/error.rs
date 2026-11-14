//! Error types for the `mu-auth` policy folio, role lifecycle, edge auth, invite, and WebAuthn layers.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use serde::{Deserialize, Serialize};

/// Errors produced by `#![no_std]` policy, folio DAG, role catalog, lease, and session validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FolioError {
    /// Identifier failed strict syntax rules.
    InvalidIdentifier {
        /// Identifier category (`"policy"`, `"folio"`, or `"role"`).
        kind: &'static str,
        /// Rejected value.
        value: String,
    },
    /// Human-readable display name violated naming constraints (empty, `'+'`, or control characters).
    InvalidDisplayName {
        /// Reason the display name was rejected.
        reason: &'static str,
        /// Rejected value.
        value: String,
    },
    /// Reserved role identifier (such as `"anonymous"`) cannot be registered in `RoleCatalog`.
    ReservedRoleId(String),
    /// Duplicate policy identifier in a manifest or catalog.
    DuplicatePolicy(String),
    /// Duplicate folio identifier in a manifest.
    DuplicateFolio(String),
    /// Duplicate role identifier in a role catalog.
    DuplicateRole(String),
    /// Referenced policy does not exist in `FolioCatalog`.
    UnknownPolicy(String),
    /// Referenced folio does not exist in `FolioCatalog`.
    UnknownFolio(String),
    /// Referenced role does not exist in `RoleCatalog`.
    UnknownRole(String),
    /// Attempted to delete a folio still referenced by another folio's `includes`.
    FolioStillReferenced {
        /// Folio being deleted.
        folio: String,
        /// Another folio still including it.
        referenced_by: String,
    },
    /// Cyclic dependency detected across `PolicyFolio::includes`.
    CyclicFolioInclude {
        /// Cycle path observed during topological DFS.
        cycle: Vec<String>,
    },
    /// Operator attempted to create, overwrite, or delete a subsystem-owned immutable folio.
    ImmutableSubsystemFolio(String),
    /// Catalog does not define a canonical `PinnedBaseline` role.
    MissingPinnedBaseline,
    /// Catalog attempted to define more than one `PinnedBaseline` role.
    MultiplePinnedBaselines {
        /// Already registered canonical baseline role ID.
        existing: String,
        /// Conflicting duplicate baseline role ID.
        duplicate: String,
    },
    /// Caller attempted to deactivate the canonical `PinnedBaseline` role.
    CannotDeactivatePinnedBaseline(String),
    /// `Timed` role TTL violates `MIN_TIMED_ROLE_TTL_SECS <= idle <= hard`.
    InvalidTimedTtlBounds {
        /// Configured idle TTL in seconds.
        idle_ttl_secs: u64,
        /// Configured hard TTL in seconds.
        hard_ttl_secs: u64,
        /// Minimum allowed TTL in seconds.
        min_ttl_secs: u64,
    },
    /// `Timed` role TTL exceeds the host ceiling (`HOST_TIMED_ROLE_CEILING_SECS`).
    TtlExceedsCeiling {
        /// Requested TTL in seconds.
        requested_secs: u64,
        /// Enforced host ceiling in seconds.
        ceiling_secs: u64,
    },
    /// `Timed` roles must require `StepUpRequirement::Passkey`.
    TimedRoleRequiresPasskey(String),
    /// Policy prefix or subsystem assignment does not match its declaring `SubsystemSecurityManifest`.
    PolicySubsystemMismatch {
        /// Policy identifier.
        policy: String,
        /// Expected subsystem prefix.
        expected_prefix: &'static str,
        /// Declaring subsystem.
        subsystem: String,
    },
    /// Subsystem folio metadata does not match its declaring `SubsystemSecurityManifest`.
    FolioSubsystemMismatch {
        /// Folio identifier.
        folio: String,
        /// Expected subsystem identifier.
        expected_subsystem: String,
    },
    /// Caller is not bound to the requested role or is anonymous.
    UnauthorizedActivation {
        /// Role requested for activation.
        role: String,
    },
    /// Authenticated user must enroll at least one Passkey before baseline access activates.
    PasskeyEnrollmentRequired,
    /// Requested role activation requires a fresh Passkey step-up assertion.
    StepUpRequired {
        /// Role requiring step-up verification.
        role: String,
    },
    /// Fail-closed authorization denial with zero disclosure of account/invite state.
    AuthorizationDenied,
}

impl fmt::Display for FolioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentifier { kind, value } => {
                write!(f, "invalid {kind} identifier: {value:?}")
            }
            Self::InvalidDisplayName { reason, value } => {
                write!(f, "invalid display name ({reason}): {value:?}")
            }
            Self::ReservedRoleId(id) => write!(f, "reserved role identifier: {id:?}"),
            Self::DuplicatePolicy(id) => write!(f, "duplicate policy identifier: {id}"),
            Self::DuplicateFolio(id) => write!(f, "duplicate folio identifier: {id}"),
            Self::DuplicateRole(id) => write!(f, "duplicate role identifier: {id}"),
            Self::UnknownPolicy(id) => write!(f, "unknown policy identifier: {id}"),
            Self::UnknownFolio(id) => write!(f, "unknown folio identifier: {id}"),
            Self::UnknownRole(id) => write!(f, "unknown role identifier: {id}"),
            Self::FolioStillReferenced {
                folio,
                referenced_by,
            } => write!(f, "folio {folio} is still included by {referenced_by}"),
            Self::CyclicFolioInclude { cycle } => {
                write!(f, "cyclic folio include graph: {}", cycle.join(" -> "))
            }
            Self::ImmutableSubsystemFolio(id) => {
                write!(f, "subsystem folio {id} is immutable")
            }
            Self::MissingPinnedBaseline => {
                write!(f, "role catalog must define a canonical PinnedBaseline role")
            }
            Self::MultiplePinnedBaselines {
                existing,
                duplicate,
            } => write!(
                f,
                "role catalog defines multiple PinnedBaseline roles: {existing} and {duplicate}"
            ),
            Self::CannotDeactivatePinnedBaseline(id) => {
                write!(f, "cannot deactivate canonical PinnedBaseline role {id}")
            }
            Self::InvalidTimedTtlBounds {
                idle_ttl_secs,
                hard_ttl_secs,
                min_ttl_secs,
            } => write!(
                f,
                "invalid timed role TTL bounds: idle={idle_ttl_secs}s, hard={hard_ttl_secs}s (min={min_ttl_secs}s, idle <= hard)"
            ),
            Self::TtlExceedsCeiling {
                requested_secs,
                ceiling_secs,
            } => write!(
                f,
                "requested timed role TTL {requested_secs}s exceeds host ceiling {ceiling_secs}s"
            ),
            Self::TimedRoleRequiresPasskey(id) => {
                write!(f, "timed role {id} must require Passkey step-up")
            }
            Self::PolicySubsystemMismatch {
                policy,
                expected_prefix,
                subsystem,
            } => write!(
                f,
                "policy {policy} does not match expected prefix {expected_prefix}:* for subsystem {subsystem}"
            ),
            Self::FolioSubsystemMismatch {
                folio,
                expected_subsystem,
            } => write!(
                f,
                "folio {folio} owner does not match subsystem {expected_subsystem}"
            ),
            Self::UnauthorizedActivation { role } => {
                write!(f, "principal is not authorized to activate role {role}")
            }
            Self::PasskeyEnrollmentRequired => {
                write!(f, "Passkey enrollment required before session activation")
            }
            Self::StepUpRequired { role } => {
                write!(f, "Passkey step-up verification required to activate role {role}")
            }
            Self::AuthorizationDenied => write!(f, "authorization denied"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FolioError {}

/// Unified error returned across core policy evaluation and optional `github-oauth` adapters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthError {
    /// Core policy, folio, role, or session invariant failure.
    Folio(FolioError),
    /// Proxy adapter was configured without an active shared secret or trusted loopback allowance.
    MissingProxySecret,
    /// `X-Proxy-Secret` header did not match the configured shared secret.
    InvalidProxySecret,
    /// Verified proxy request did not carry a valid `X-Forwarded-User` header.
    MissingForwardedUser,
    /// Security-sensitive header appeared more than once.
    DuplicateHeader(&'static str),
    /// Security-sensitive header failed syntax or character validation.
    InvalidHeaderValue(&'static str),
    /// Peer address is neither a trusted loopback socket nor authorized via `X-Proxy-Secret`.
    UntrustedProxySource,
    /// Invite token failed structural validation or constant-time HMAC verification.
    InvalidInviteToken,
    /// Invite token passed expiration timestamp.
    InviteExpired,
    /// Redirect parameter (`rd`) failed open-redirect validation.
    InvalidRedirectTarget,
    /// Cryptographic primitive or key configuration failed.
    CryptoFailure(&'static str),
    /// WebAuthn ceremony challenge is missing, already consumed, or expired.
    ChallengeNotFoundOrExpired,
    /// WebAuthn challenge ID or state failed single-use replay protection.
    ChallengeReplay,
    /// WebAuthn ceremony validation failed.
    WebAuthnVerificationFailed(String),
    /// Authenticator signature counter did not advance monotonically when non-zero.
    CloneDetected,
    /// Authenticator backup eligibility attempted a forbidden `true -> false` downgrade.
    BackupEligibilityDowngrade,
    /// Adapter or WebAuthn RP configuration is invalid.
    InvalidServerConfig(&'static str),
}

impl From<FolioError> for AuthError {
    fn from(err: FolioError) -> Self {
        Self::Folio(err)
    }
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Folio(err) => err.fmt(f),
            Self::MissingProxySecret => write!(f, "proxy secret is not configured"),
            Self::InvalidProxySecret => write!(f, "invalid proxy secret header"),
            Self::MissingForwardedUser => write!(f, "missing X-Forwarded-User header"),
            Self::DuplicateHeader(name) => write!(f, "duplicate security header: {name}"),
            Self::InvalidHeaderValue(name) => write!(f, "invalid header value: {name}"),
            Self::UntrustedProxySource => write!(f, "untrusted proxy source"),
            Self::InvalidInviteToken => write!(f, "invalid invite token"),
            Self::InviteExpired => write!(f, "invite token expired"),
            Self::InvalidRedirectTarget => write!(f, "invalid redirect target"),
            Self::CryptoFailure(msg) => write!(f, "cryptographic error: {msg}"),
            Self::ChallengeNotFoundOrExpired => {
                write!(f, "WebAuthn challenge not found or expired")
            }
            Self::ChallengeReplay => write!(f, "WebAuthn challenge already consumed"),
            Self::WebAuthnVerificationFailed(msg) => {
                write!(f, "WebAuthn verification failed: {msg}")
            }
            Self::CloneDetected => {
                write!(
                    f,
                    "authenticator signature counter regression (possible clone)"
                )
            }
            Self::BackupEligibilityDowngrade => {
                write!(f, "authenticator backup eligibility downgrade rejected")
            }
            Self::InvalidServerConfig(msg) => write!(f, "invalid server configuration: {msg}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AuthError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Folio(err) => Some(err),
            _ => None,
        }
    }
}
