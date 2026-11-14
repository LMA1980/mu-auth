//! End-user WebAuthn Passkey enrollment and `StepUpVerifier` supporting 1Password (`sign_count == 0`)
//! and physical FIDO2 hardware security keys.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use url::Url;
use webauthn_rs_core::error::WebauthnError;
use webauthn_rs_core::proto::{
    AttestationConveyancePreference, AuthenticationState, COSEAlgorithm, CreationChallengeResponse,
    Credential, CredentialID, PublicKeyCredential, RegisterPublicKeyCredential, RegistrationState,
    RequestChallengeResponse, UserVerificationPolicy,
};
use webauthn_rs_core::WebauthnCore;

use crate::edge::GithubLogin;
use crate::error::AuthError;
use crate::role::RoleSpec;
use crate::session::RoleLease;

/// Default single-use WebAuthn challenge lifetime (60 seconds).
pub const DEFAULT_WEBAUTHN_CHALLENGE_TTL_SECS: u64 = 60;

/// Supported Passkey / FIDO2 COSE signing algorithms (`ES256`, `EdDSA`, `RS256`).
pub const SUPPORTED_PASSKEY_ALGORITHMS: [COSEAlgorithm; 3] = [
    COSEAlgorithm::ES256,
    COSEAlgorithm::EDDSA,
    COSEAlgorithm::RS256,
];

/// Relying Party settings binding WebAuthn ceremonies to RP ID and origin(s).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebauthnConfig {
    /// Human-readable Relying Party name displayed in Passkey prompts.
    pub rp_name: String,
    /// Relying Party ID matching the origin's effective domain.
    pub rp_id: String,
    /// Strictly allowed HTTPS (or localhost dev) origin URLs.
    pub allowed_origins: Vec<Url>,
    /// Single-use challenge TTL in seconds (default 60s).
    pub challenge_ttl_secs: u64,
}

impl WebauthnConfig {
    /// Creates and validates [`WebauthnConfig`] with default 60-second challenge TTL.
    pub fn new(
        rp_name: impl Into<String>,
        rp_id: impl Into<String>,
        allowed_origins: Vec<Url>,
    ) -> Result<Self, AuthError> {
        Self::with_ttl(
            rp_name,
            rp_id,
            allowed_origins,
            DEFAULT_WEBAUTHN_CHALLENGE_TTL_SECS,
        )
    }

    /// Creates and validates [`WebauthnConfig`] with an explicit single-use challenge TTL (`> 0`).
    pub fn with_ttl(
        rp_name: impl Into<String>,
        rp_id: impl Into<String>,
        allowed_origins: Vec<Url>,
        challenge_ttl_secs: u64,
    ) -> Result<Self, AuthError> {
        let rp_name = rp_name.into();
        let rp_id = rp_id.into();
        if rp_name.trim().is_empty()
            || rp_id.trim().is_empty()
            || allowed_origins.is_empty()
            || challenge_ttl_secs == 0
        {
            return Err(AuthError::InvalidServerConfig(
                "WebauthnConfig requires non-empty rp_name, rp_id, allowed_origins, and positive challenge_ttl_secs",
            ));
        }
        for origin in &allowed_origins {
            let host = origin
                .host_str()
                .ok_or(AuthError::InvalidServerConfig("origin missing host"))?;
            if host != rp_id {
                return Err(AuthError::InvalidServerConfig(
                    "allowed_origins host must match rp_id",
                ));
            }
        }
        Ok(Self {
            rp_name,
            rp_id,
            allowed_origins,
            challenge_ttl_secs,
        })
    }
}

/// Persisted user Passkey credential record stored per GitHub operator account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyRecord {
    /// Base64url-friendly raw WebAuthn credential identifier.
    pub credential_id: CredentialID,
    /// Optional user-assigned credential label (e.g. `"1Password"` or `"FIDO2 Key"`).
    pub label: Option<String>,
    /// Underlying `webauthn-rs-core` verified credential public key and metadata.
    pub credential: Credential,
    /// Latest recorded authenticator signature counter (`0` allowed for synced Passkeys).
    pub sign_count: u32,
    /// Enrollment timestamp (`epoch_ms`).
    pub created_at_ms: u64,
    /// Timestamp (`epoch_ms`) of last verified assertion.
    pub last_used_at_ms: Option<u64>,
}

/// Public client registration payload paired with single-use challenge identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrollmentChallenge {
    /// Server-tracked single-use challenge identifier (`hex` encoded random challenge).
    pub challenge_id: String,
    /// Standard `PublicKeyCredentialCreationOptions` envelope for `navigator.credentials.create()`.
    pub options: CreationChallengeResponse,
    /// Challenge expiry timestamp (`epoch_ms`).
    pub expires_at_ms: u64,
}

/// Public client authentication payload paired with single-use challenge identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpChallenge {
    /// Server-tracked single-use challenge identifier.
    pub challenge_id: String,
    /// Standard `PublicKeyCredentialRequestOptions` envelope for `navigator.credentials.get()`.
    pub options: RequestChallengeResponse,
    /// Challenge expiry timestamp (`epoch_ms`).
    pub expires_at_ms: u64,
}

/// Serializable pending registration state for external (e.g. DuckDB) challenge storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRegistration {
    /// Authenticated GitHub login bound to this challenge.
    pub login: GithubLogin,
    /// Expected RP ID at time of issue.
    pub rp_id: String,
    /// Single-use expiry timestamp (`epoch_ms`).
    pub expires_at_ms: u64,
    /// Cryptographic `webauthn-rs-core` registration ceremony state.
    pub state: RegistrationState,
}

/// Serializable pending authentication state for external challenge storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingAuthentication {
    /// Authenticated GitHub login bound to this challenge.
    pub login: GithubLogin,
    /// Expected RP ID at time of issue.
    pub rp_id: String,
    /// Single-use expiry timestamp (`epoch_ms`).
    pub expires_at_ms: u64,
    /// Cryptographic `webauthn-rs-core` authentication ceremony state.
    pub state: AuthenticationState,
}

/// Verified Passkey assertion metadata including updated counter & credential record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthenticationOutcome {
    /// Credential ID used to satisfy the WebAuthn assertion.
    pub credential_id: CredentialID,
    /// Updated Passkey record reflecting any incremented counter or backup flag transitions.
    pub updated_credential: PasskeyRecord,
    /// Authenticator UV flag observed in `authData`.
    pub user_verified: bool,
    /// New authenticator counter value (`0` for synced 1Password passkeys, monotonic on FIDO2).
    pub new_sign_count: u32,
}

/// Server-derived time-bounded elevation lease minted after Passkey step-up verification.
///
/// `hard_expires_at_ms` and `idle_expires_at_ms` are derived strictly from `RoleSpec` ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElevationLease {
    /// Elevated role ID.
    pub role: crate::role::RoleId,
    /// GitHub account whose Passkey verified step-up.
    pub login: GithubLogin,
    /// Credential ID that satisfied the step-up challenge.
    pub credential_id: CredentialID,
    /// Activation timestamp (`epoch_ms`).
    pub activated_at_ms: u64,
    /// Server-enforced non-renewable hard deadline (`epoch_ms`).
    pub hard_expires_at_ms: u64,
    /// Server-enforced explicit-activity idle deadline (`epoch_ms`).
    pub idle_expires_at_ms: u64,
    /// Underlying [`RoleLease`] passed into [`crate::session::RoleLeases`].
    pub role_lease: RoleLease,
}

impl ElevationLease {
    /// Derives [`ElevationLease`] strictly from server [`RoleSpec`] bounds and verified Passkey output.
    pub fn from_role_spec(
        login: GithubLogin,
        credential_id: CredentialID,
        role_spec: &RoleSpec,
        now_ms: u64,
    ) -> Result<Self, AuthError> {
        let role_lease = RoleLease::from_role_spec(role_spec, now_ms)?;
        Ok(Self {
            role: role_lease.role.clone(),
            login,
            credential_id,
            activated_at_ms: role_lease.activated_at_ms,
            hard_expires_at_ms: role_lease.hard_expires_at_ms,
            idle_expires_at_ms: role_lease.idle_expires_at_ms,
            role_lease,
        })
    }
}

/// Result returned by [`StepUpVerifier`] combining credential state update and server `ElevationLease`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepUpVerification {
    /// Verified assertion details and updated [`PasskeyRecord`] counter/flags.
    pub outcome: AuthenticationOutcome,
    /// Server-clamped [`ElevationLease`] ready to activate in [`crate::session::RoleLeases`].
    pub lease: ElevationLease,
}

/// Trait abstracting Passkey step-up assertion verification across HTTP controllers.
pub trait StepUpVerifier: Send + Sync {
    /// Verifies a WebAuthn step-up assertion and mints a server-bounded [`ElevationLease`].
    fn verify_step_up(
        &self,
        login: &GithubLogin,
        credentials: &[PasskeyRecord],
        challenge_id: &str,
        response: &PublicKeyCredential,
        role_spec: &RoleSpec,
        now_ms: u64,
    ) -> Result<StepUpVerification, AuthError>;
}

/// Thread-safe WebAuthn Passkey enrollment & single-use challenge verifier built on `webauthn-rs-core`.
#[derive(Debug)]
pub struct WebauthnPasskeyService {
    config: WebauthnConfig,
    core: WebauthnCore,
    pending_registrations: Mutex<HashMap<String, PendingRegistration>>,
    pending_authentications: Mutex<HashMap<String, PendingAuthentication>>,
}

impl WebauthnPasskeyService {
    /// Initializes a RP-bound [`WebauthnPasskeyService`].
    pub fn new(config: WebauthnConfig) -> Self {
        let core = WebauthnCore::new_unsafe_experts_only(
            &config.rp_name,
            &config.rp_id,
            config.allowed_origins.clone(),
            Duration::from_secs(config.challenge_ttl_secs),
            None,
            None,
        );
        Self {
            config,
            core,
            pending_registrations: Mutex::new(HashMap::new()),
            pending_authentications: Mutex::new(HashMap::new()),
        }
    }

    /// Underlying WebAuthn configuration.
    #[must_use]
    pub fn config(&self) -> &WebauthnConfig {
        &self.config
    }

    /// Starts Passkey enrollment (omitting `authenticatorAttachment`, `attestation: "none"`,
    /// `userVerification: "preferred"`, and `ES256`/`EdDSA`/`RS256` algorithms).
    pub fn begin_registration(
        &self,
        login: &GithubLogin,
        user_unique_id: &[u8],
        existing_credentials: &[PasskeyRecord],
        now_ms: u64,
    ) -> Result<EnrollmentChallenge, AuthError> {
        let (challenge, pending) =
            self.prepare_registration(login, user_unique_id, existing_credentials, now_ms)?;
        let mut guard = self
            .pending_registrations
            .lock()
            .map_err(|_| AuthError::CryptoFailure("registration challenge store poisoned"))?;
        guard.retain(|_, entry| now_ms < entry.expires_at_ms);
        guard.insert(challenge.challenge_id.clone(), pending);
        Ok(challenge)
    }

    /// Stateless registration start returning both client challenge and external [`PendingRegistration`].
    pub fn prepare_registration(
        &self,
        login: &GithubLogin,
        user_unique_id: &[u8],
        existing_credentials: &[PasskeyRecord],
        now_ms: u64,
    ) -> Result<(EnrollmentChallenge, PendingRegistration), AuthError> {
        if user_unique_id.is_empty() {
            return Err(AuthError::InvalidServerConfig(
                "user_unique_id must not be empty",
            ));
        }
        let excluded: Vec<CredentialID> = existing_credentials
            .iter()
            .map(|c| c.credential_id.clone())
            .collect();

        let builder = self
            .core
            .new_challenge_register_builder(user_unique_id, login.as_str(), login.as_str())
            .map_err(map_webauthn_error)?
            .authenticator_attachment(None)
            .attestation(AttestationConveyancePreference::None)
            .user_verification_policy(UserVerificationPolicy::Preferred)
            .credential_algorithms(SUPPORTED_PASSKEY_ALGORITHMS.to_vec())
            .exclude_credentials((!excluded.is_empty()).then_some(excluded))
            .require_resident_key(false)
            .reject_synchronised_authenticators(false);

        let (options, state) = self
            .core
            .generate_challenge_register(builder)
            .map_err(map_webauthn_error)?;

        let challenge_id = hex::encode(options.public_key.challenge.as_slice());
        let expires_at_ms =
            now_ms.saturating_add(self.config.challenge_ttl_secs.saturating_mul(1000));

        let challenge = EnrollmentChallenge {
            challenge_id,
            options,
            expires_at_ms,
        };
        let pending = PendingRegistration {
            login: login.clone(),
            rp_id: self.config.rp_id.clone(),
            expires_at_ms,
            state,
        };
        Ok((challenge, pending))
    }

    /// Completes Passkey enrollment using the internal single-use store.
    ///
    /// Challenges are consumed atomically prior to verification so replay attempts always fail.
    pub fn finish_registration(
        &self,
        login: &GithubLogin,
        challenge_id: &str,
        response: &RegisterPublicKeyCredential,
        label: Option<&str>,
        now_ms: u64,
    ) -> Result<PasskeyRecord, AuthError> {
        let pending = {
            let mut guard = self
                .pending_registrations
                .lock()
                .map_err(|_| AuthError::CryptoFailure("registration challenge store poisoned"))?;
            guard.remove(challenge_id)
        }
        .ok_or(AuthError::ChallengeNotFoundOrExpired)?;

        self.complete_registration(login, &pending, response, label, now_ms)
    }

    /// Stateless registration completion against an externally persisted [`PendingRegistration`].
    pub fn complete_registration(
        &self,
        login: &GithubLogin,
        pending: &PendingRegistration,
        response: &RegisterPublicKeyCredential,
        label: Option<&str>,
        now_ms: u64,
    ) -> Result<PasskeyRecord, AuthError> {
        if pending.rp_id != self.config.rp_id || pending.login != *login {
            return Err(AuthError::Folio(
                crate::error::FolioError::AuthorizationDenied,
            ));
        }
        if now_ms >= pending.expires_at_ms {
            return Err(AuthError::ChallengeNotFoundOrExpired);
        }

        let clean_label = match label {
            Some(raw) => Some(crate::role::validate_display_name(raw)?),
            None => None,
        };

        let credential = self
            .core
            .register_credential(response, &pending.state, None)
            .map_err(map_webauthn_error)?;

        let sign_count = credential.counter;
        let credential_id = credential.cred_id.clone();

        Ok(PasskeyRecord {
            credential_id,
            label: clean_label,
            credential,
            sign_count,
            created_at_ms: now_ms,
            last_used_at_ms: None,
        })
    }

    /// Starts single-use WebAuthn step-up assertion ceremony in internal challenge storage.
    pub fn begin_authentication(
        &self,
        login: &GithubLogin,
        credentials: &[PasskeyRecord],
        now_ms: u64,
    ) -> Result<StepUpChallenge, AuthError> {
        let (challenge, pending) = self.prepare_authentication(login, credentials, now_ms)?;
        let mut guard = self
            .pending_authentications
            .lock()
            .map_err(|_| AuthError::CryptoFailure("authentication challenge store poisoned"))?;
        guard.retain(|_, entry| now_ms < entry.expires_at_ms);
        guard.insert(challenge.challenge_id.clone(), pending);
        Ok(challenge)
    }

    /// Stateless authentication start returning challenge options and [`PendingAuthentication`].
    pub fn prepare_authentication(
        &self,
        login: &GithubLogin,
        credentials: &[PasskeyRecord],
        now_ms: u64,
    ) -> Result<(StepUpChallenge, PendingAuthentication), AuthError> {
        if credentials.is_empty() {
            return Err(AuthError::Folio(
                crate::error::FolioError::PasskeyEnrollmentRequired,
            ));
        }

        let creds: Vec<Credential> = credentials.iter().map(|r| r.credential.clone()).collect();
        let builder = self
            .core
            .new_challenge_authenticate_builder(creds, Some(UserVerificationPolicy::Preferred))
            .map_err(map_webauthn_error)?;

        let (options, state) = self
            .core
            .generate_challenge_authenticate(builder)
            .map_err(map_webauthn_error)?;

        let challenge_id = hex::encode(options.public_key.challenge.as_slice());
        let expires_at_ms =
            now_ms.saturating_add(self.config.challenge_ttl_secs.saturating_mul(1000));

        let challenge = StepUpChallenge {
            challenge_id,
            options,
            expires_at_ms,
        };
        let pending = PendingAuthentication {
            login: login.clone(),
            rp_id: self.config.rp_id.clone(),
            expires_at_ms,
            state,
        };
        Ok((challenge, pending))
    }

    /// Completes assertion verification using internal single-use store (consuming challenge).
    pub fn finish_authentication(
        &self,
        login: &GithubLogin,
        credentials: &[PasskeyRecord],
        challenge_id: &str,
        response: &PublicKeyCredential,
        now_ms: u64,
    ) -> Result<AuthenticationOutcome, AuthError> {
        let pending = {
            let mut guard = self
                .pending_authentications
                .lock()
                .map_err(|_| AuthError::CryptoFailure("authentication challenge store poisoned"))?;
            guard.remove(challenge_id)
        }
        .ok_or(AuthError::ChallengeNotFoundOrExpired)?;

        self.complete_authentication(login, credentials, &pending, response, now_ms)
    }

    /// Stateless assertion completion enforcing non-zero FIDO2 clone checks while allowing `0 -> 0`
    /// for synced 1Password Passkeys.
    pub fn complete_authentication(
        &self,
        login: &GithubLogin,
        credentials: &[PasskeyRecord],
        pending: &PendingAuthentication,
        response: &PublicKeyCredential,
        now_ms: u64,
    ) -> Result<AuthenticationOutcome, AuthError> {
        if pending.rp_id != self.config.rp_id || pending.login != *login {
            return Err(AuthError::Folio(
                crate::error::FolioError::AuthorizationDenied,
            ));
        }
        if now_ms >= pending.expires_at_ms {
            return Err(AuthError::ChallengeNotFoundOrExpired);
        }

        let record = credentials
            .iter()
            .find(|rec| rec.credential_id.as_slice() == response.raw_id.as_slice())
            .ok_or_else(|| AuthError::WebAuthnVerificationFailed("credential not found".into()))?;

        let mut stored_cred = record.credential.clone();
        // Ensure persisted record counter is synced with stored Credential struct.
        stored_cred.counter = record.sign_count.max(stored_cred.counter);
        let stored_count = stored_cred.counter;

        let result = self
            .core
            .authenticate_single_credential(response, &pending.state, &stored_cred)
            .map_err(map_webauthn_error)?;

        let new_count = result.counter();
        // Enforce monotonic signature counter ONLY when either stored or observed counter is non-zero.
        if (stored_count > 0 || new_count > 0) && new_count <= stored_count {
            return Err(AuthError::CloneDetected);
        }

        stored_cred.counter = new_count;
        stored_cred.backup_eligible = result.backup_eligible();
        stored_cred.backup_state = result.backup_state();

        let mut updated = record.clone();
        updated.credential = stored_cred;
        updated.sign_count = new_count;
        updated.last_used_at_ms = Some(now_ms);

        Ok(AuthenticationOutcome {
            credential_id: result.cred_id().clone(),
            updated_credential: updated,
            user_verified: result.user_verified(),
            new_sign_count: new_count,
        })
    }
}

impl StepUpVerifier for WebauthnPasskeyService {
    fn verify_step_up(
        &self,
        login: &GithubLogin,
        credentials: &[PasskeyRecord],
        challenge_id: &str,
        response: &PublicKeyCredential,
        role_spec: &RoleSpec,
        now_ms: u64,
    ) -> Result<StepUpVerification, AuthError> {
        let outcome =
            self.finish_authentication(login, credentials, challenge_id, response, now_ms)?;
        let lease = ElevationLease::from_role_spec(
            login.clone(),
            outcome.credential_id.clone(),
            role_spec,
            now_ms,
        )?;
        Ok(StepUpVerification { outcome, lease })
    }
}

fn map_webauthn_error(err: WebauthnError) -> AuthError {
    match err {
        WebauthnError::CredentialPossibleCompromise => AuthError::CloneDetected,
        WebauthnError::CredentialBackupEligibilityInconsistent => {
            AuthError::BackupEligibilityDowngrade
        }
        WebauthnError::ChallengeNotFound => AuthError::ChallengeNotFoundOrExpired,
        other => AuthError::WebAuthnVerificationFailed(format!("{other:?}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::role::RoleId;
    use alloc::vec;

    #[test]
    fn config_rejects_mismatched_origin_or_zero_ttl_and_derives_server_elevation_lease() {
        let bad_origin = Url::parse("https://other.example.org").unwrap();
        assert!(matches!(
            WebauthnConfig::new("Console", "console.example.org", vec![bad_origin]),
            Err(AuthError::InvalidServerConfig(_))
        ));

        let origin = Url::parse("https://console.example.org").unwrap();
        let cfg = WebauthnConfig::new("Console", "console.example.org", vec![origin]).unwrap();
        assert_eq!(cfg.challenge_ttl_secs, 60);

        let role = RoleSpec::timed(
            RoleId::new("platform-admin").unwrap(),
            Some("Platform Admin"),
            "admin",
            900,
            180,
        )
        .unwrap();
        let login = GithubLogin::new("operator").unwrap();
        let lease = ElevationLease::from_role_spec(login, vec![1, 2, 3], &role, 10_000).unwrap();
        assert_eq!(lease.hard_expires_at_ms, 10_000 + 900_000);
        assert_eq!(lease.idle_expires_at_ms, 10_000 + 180_000);
    }

    #[cfg(not(miri))]
    #[test]
    fn registration_options_omit_attachment_and_enable_all_supported_algs() {
        let origin = Url::parse("https://console.example.org").unwrap();
        let cfg = WebauthnConfig::new("Console", "console.example.org", vec![origin]).unwrap();
        let svc = WebauthnPasskeyService::new(cfg);
        let login = GithubLogin::new("operator").unwrap();

        let challenge = svc
            .begin_registration(&login, b"user-uid-1", &[], 1_000)
            .unwrap();
        let json = serde_json::to_string(&challenge.options).unwrap();
        assert!(!json.contains("authenticatorAttachment"));
        assert!(json.contains("\"attestation\":\"none\""));
        assert!(json.contains("\"userVerification\":\"preferred\""));

        let algs: Vec<i64> = challenge
            .options
            .public_key
            .pub_key_cred_params
            .iter()
            .map(|p| p.alg)
            .collect();
        assert_eq!(algs, vec![-7, -8, -257]);
    }
}
