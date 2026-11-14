//! `PinnedBaseline`-only `inv_<id>.<hmac>` invite token codec and RFC 3986 `/oauth2/{start,sign_out}` URL helpers.

use alloc::format;
use alloc::string::{String, ToString};
use core::fmt;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::edge::GithubLogin;
use crate::error::AuthError;
use crate::role::{RoleCatalog, RoleId};
use crate::secret::{resolve_secret_value, resolve_secret_with_file_var};

type HmacSha256 = Hmac<Sha256>;

const INVITE_DOMAIN_PREFIX: &[u8] = b"mu-auth:invite:v1\0";

/// Signed onboarding invite bound solely to `invite_id` and `expires_at_ms` (never role lists).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedInvite {
    /// Compact opaque invite identifier (`inv_<invite_id>.<hmac>`).
    pub invite_id: String,
    /// Lowercase 64-character HMAC-SHA256 hex signature.
    pub hmac_hex: String,
    /// Full wire invite token (`inv_<invite_id>.<hmac_hex>`).
    pub token: String,
    /// Expiry timestamp (`epoch_ms`).
    pub expires_at_ms: u64,
    /// Single canonical baseline role granted upon fulfillment.
    pub granted_role: RoleId,
}

/// Validated parsed view of a presented `inv_<id>.<hmac>` token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedInviteToken {
    /// Extracted invite identifier without `inv_` prefix.
    pub invite_id: String,
    /// Extracted 64-character hex HMAC tag.
    pub hmac_hex: String,
    /// Decoded 32-byte raw HMAC tag.
    pub mac_bytes: [u8; 32],
}

/// Result of fulfilling a single-baseline invite for an authenticated GitHub account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InviteFulfillment {
    /// Fulfilled invite identifier.
    pub invite_id: String,
    /// Bound GitHub account receiving baseline access.
    pub github_login: GithubLogin,
    /// Always strictly equals `RoleCatalog::pinned_baseline().id`.
    pub granted_role: RoleId,
    /// Invite expiration bound into the HMAC tag (`epoch_ms`).
    pub expires_at_ms: u64,
}

/// HMAC-SHA256 signer and constant-time verifier for `inv_<id>.<hmac>` onboarding tokens.
///
/// Tokens bind ONLY `invite_id` and `expires_at_ms` — role lists (`Vec<RoleId>`) are never
/// encoded or accepted in invites; fulfillment strictly yields the canonical `PinnedBaseline` role.
#[derive(Clone, PartialEq, Eq)]
pub struct InviteCodec {
    signing_key: String,
}

impl fmt::Debug for InviteCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InviteCodec")
            .field("signing_key", &"[REDACTED]")
            .finish()
    }
}

impl InviteCodec {
    /// Creates an [`InviteCodec`] from a literal key or file-path specification (fail-closed).
    pub fn new(signing_key: impl AsRef<str>) -> Result<Self, AuthError> {
        let resolved = resolve_secret_value(signing_key.as_ref())
            .ok_or(AuthError::CryptoFailure("missing invite signing key"))?;
        Ok(Self {
            signing_key: resolved,
        })
    }

    /// Loads [`InviteCodec`] from environment variables using fail-closed file resolution.
    pub fn from_env(env_var: &str, file_env_var: &str) -> Result<Self, AuthError> {
        let resolved = resolve_secret_with_file_var(env_var, file_env_var)
            .ok_or(AuthError::CryptoFailure("missing invite signing key"))?;
        Ok(Self {
            signing_key: resolved,
        })
    }

    /// Signs `(invite_id, expires_at_ms)` into an `inv_<id>.<hmac>` token granting ONLY `PinnedBaseline`.
    pub fn sign_invite(
        &self,
        invite_id: &str,
        expires_at_ms: u64,
        role_catalog: &RoleCatalog,
    ) -> Result<SignedInvite, AuthError> {
        role_catalog.validate()?;
        validate_invite_id(invite_id)?;
        let mac = self.compute_mac_bytes(invite_id, expires_at_ms)?;
        let hmac_hex = hex::encode(mac);
        let token = format!("inv_{invite_id}.{hmac_hex}");
        Ok(SignedInvite {
            invite_id: invite_id.to_string(),
            hmac_hex,
            token,
            expires_at_ms,
            granted_role: role_catalog.pinned_baseline().id.clone(),
        })
    }

    /// Verifies `inv_<id>.<hmac>` syntax, constant-time MAC over `(invite_id, expected_expires_at_ms)`,
    /// and non-expiration (`now_ms < expected_expires_at_ms`).
    pub fn verify_invite(
        &self,
        raw_token: &str,
        expected_expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<ParsedInviteToken, AuthError> {
        let parsed = parse_invite_token(raw_token)?;
        let expected_mac = self.compute_mac_bytes(&parsed.invite_id, expected_expires_at_ms)?;
        let valid: bool = parsed.mac_bytes.ct_eq(&expected_mac).into();
        if !valid {
            return Err(AuthError::InvalidInviteToken);
        }
        if now_ms >= expected_expires_at_ms {
            return Err(AuthError::InviteExpired);
        }
        Ok(parsed)
    }

    /// Verifies and fulfills an invite, binding `github_login` strictly to the canonical `PinnedBaseline` role.
    pub fn fulfill_baseline_invite(
        &self,
        raw_token: &str,
        expected_expires_at_ms: u64,
        now_ms: u64,
        role_catalog: &RoleCatalog,
        github_login: &GithubLogin,
    ) -> Result<InviteFulfillment, AuthError> {
        role_catalog.validate()?;
        let parsed = self.verify_invite(raw_token, expected_expires_at_ms, now_ms)?;
        Ok(InviteFulfillment {
            invite_id: parsed.invite_id,
            github_login: github_login.clone(),
            granted_role: role_catalog.pinned_baseline().id.clone(),
            expires_at_ms: expected_expires_at_ms,
        })
    }

    /// Signs a self-contained invite encoding expiry inside `invite_id` as `<nonce>_<expires_ms_hex>`.
    pub fn sign_self_expiring_invite(
        &self,
        nonce: &str,
        expires_at_ms: u64,
        role_catalog: &RoleCatalog,
    ) -> Result<SignedInvite, AuthError> {
        validate_invite_id(nonce)?;
        let invite_id = format!("{nonce}_{expires_at_ms:x}");
        self.sign_invite(&invite_id, expires_at_ms, role_catalog)
    }

    /// Verifies a self-expiring `inv_<nonce>_<expires_ms_hex>.<hmac>` token in constant time.
    pub fn verify_self_expiring_invite(
        &self,
        raw_token: &str,
        now_ms: u64,
    ) -> Result<(ParsedInviteToken, u64), AuthError> {
        let parsed = parse_invite_token(raw_token)?;
        let Some((nonce, exp_hex)) = parsed.invite_id.rsplit_once('_') else {
            return Err(AuthError::InvalidInviteToken);
        };
        if nonce.is_empty() {
            return Err(AuthError::InvalidInviteToken);
        }
        let expires_at_ms =
            u64::from_str_radix(exp_hex, 16).map_err(|_| AuthError::InvalidInviteToken)?;
        let expected_mac = self.compute_mac_bytes(&parsed.invite_id, expires_at_ms)?;
        let valid: bool = parsed.mac_bytes.ct_eq(&expected_mac).into();
        if !valid {
            return Err(AuthError::InvalidInviteToken);
        }
        if now_ms >= expires_at_ms {
            return Err(AuthError::InviteExpired);
        }
        Ok((parsed, expires_at_ms))
    }

    fn compute_mac_bytes(
        &self,
        invite_id: &str,
        expires_at_ms: u64,
    ) -> Result<[u8; 32], AuthError> {
        let mut mac = HmacSha256::new_from_slice(self.signing_key.as_bytes())
            .map_err(|_| AuthError::CryptoFailure("invalid HMAC signing key length"))?;
        mac.update(INVITE_DOMAIN_PREFIX);
        mac.update(invite_id.as_bytes());
        mac.update(b"\0");
        mac.update(&expires_at_ms.to_be_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

/// Parses structural `inv_<invite_id>.<64_hex_chars>` syntax without verifying cryptographic signature.
pub fn parse_invite_token(raw_token: &str) -> Result<ParsedInviteToken, AuthError> {
    let trimmed = raw_token.trim();
    if trimmed != raw_token {
        return Err(AuthError::InvalidInviteToken);
    }
    let Some((prefix, hmac_hex)) = trimmed.split_once('.') else {
        return Err(AuthError::InvalidInviteToken);
    };
    let Some(invite_id) = prefix.strip_prefix("inv_") else {
        return Err(AuthError::InvalidInviteToken);
    };
    validate_invite_id(invite_id)?;
    if hmac_hex.len() != 64
        || !hmac_hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(AuthError::InvalidInviteToken);
    }
    let decoded = hex::decode(hmac_hex).map_err(|_| AuthError::InvalidInviteToken)?;
    let mac_bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| AuthError::InvalidInviteToken)?;

    Ok(ParsedInviteToken {
        invite_id: invite_id.to_string(),
        hmac_hex: hmac_hex.to_string(),
        mac_bytes,
    })
}

fn validate_invite_id(invite_id: &str) -> Result<(), AuthError> {
    if invite_id.len() < 4
        || invite_id.len() > 80
        || !invite_id
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_'))
    {
        return Err(AuthError::InvalidInviteToken);
    }
    Ok(())
}

/// Validates a safe same-origin relative redirect target `rd` and builds `/oauth2/start?rd=...`.
///
/// Rejects open redirects (`https://...`, `//evil.example`, `/\evil`, control chars, backslashes).
pub fn build_oauth_start_url(redirect_path: &str) -> Result<String, AuthError> {
    let validated = validate_relative_redirect(redirect_path)?;
    Ok(format!(
        "/oauth2/start?rd={}",
        percent_encode_rfc3986(validated)
    ))
}

/// Validates a safe same-origin relative redirect target `rd` and builds `/oauth2/sign_out?rd=...`.
///
/// Rejects open redirects (`https://...`, `//evil.example`, `/\evil`, control chars, backslashes).
pub fn build_oauth_sign_out_url(redirect_path: &str) -> Result<String, AuthError> {
    let validated = validate_relative_redirect(redirect_path)?;
    Ok(format!(
        "/oauth2/sign_out?rd={}",
        percent_encode_rfc3986(validated)
    ))
}

fn validate_relative_redirect(rd: &str) -> Result<&str, AuthError> {
    if !rd.starts_with('/')
        || rd.starts_with("//")
        || rd.starts_with("/\\")
        || rd.contains('\\')
        || rd.chars().any(char::is_control)
    {
        return Err(AuthError::InvalidRedirectTarget);
    }
    Ok(rd)
}

/// Percent-encodes `input` per RFC 3986 unreserved characters (`ALPHA / DIGIT / "-" / "." / "_" / "~"`).
#[must_use]
pub fn percent_encode_rfc3986(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len() * 3);
    for &byte in input.as_bytes() {
        let is_unreserved = matches!(
            byte,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
        );
        if is_unreserved {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::role::{RoleSpec, StepUpRequirement};

    fn catalog() -> RoleCatalog {
        RoleCatalog::from_roles([
            RoleSpec::pinned_baseline(RoleId::new("member").unwrap(), Some("Member"), "baseline")
                .unwrap(),
            RoleSpec::elective(
                RoleId::new("operator").unwrap(),
                Some("Operator"),
                "elective",
                StepUpRequirement::Passkey,
            )
            .unwrap(),
        ])
        .unwrap()
    }

    #[test]
    fn signs_verifies_and_fulfills_only_pinned_baseline_invite() {
        let roles = catalog();
        let codec = InviteCodec::new("invite-signing-secret-key").unwrap();
        let login = GithubLogin::new("octocat").unwrap();

        let signed = codec.sign_invite("abc123def456", 50_000, &roles).unwrap();
        assert!(signed.token.starts_with("inv_abc123def456."));
        assert_eq!(signed.granted_role.as_str(), "member");

        let fulfilled = codec
            .fulfill_baseline_invite(&signed.token, 50_000, 10_000, &roles, &login)
            .unwrap();
        assert_eq!(fulfilled.granted_role.as_str(), "member");
        assert_eq!(fulfilled.github_login.as_str(), "octocat");

        // Wrong expiry fails constant-time HMAC check without leaking validity
        assert_eq!(
            codec.verify_invite(&signed.token, 99_999, 10_000),
            Err(AuthError::InvalidInviteToken)
        );
        // Past expiry rejects with InviteExpired
        assert_eq!(
            codec.verify_invite(&signed.token, 50_000, 50_000),
            Err(AuthError::InviteExpired)
        );
        // Wrong signing key rejects
        let wrong_codec = InviteCodec::new("other-key").unwrap();
        assert_eq!(
            wrong_codec.verify_invite(&signed.token, 50_000, 10_000),
            Err(AuthError::InvalidInviteToken)
        );
    }

    #[test]
    fn rfc3986_oauth_urls_and_open_redirect_blocking() {
        let start = build_oauth_start_url("/platform?tab=invites&invite=inv_123").unwrap();
        assert_eq!(
            start,
            "/oauth2/start?rd=%2Fplatform%3Ftab%3Dinvites%26invite%3Dinv_123"
        );

        let sign_out = build_oauth_sign_out_url("/").unwrap();
        assert_eq!(sign_out, "/oauth2/sign_out?rd=%2F");

        assert_eq!(
            build_oauth_start_url("https://evil.example/phish"),
            Err(AuthError::InvalidRedirectTarget)
        );
        assert_eq!(
            build_oauth_start_url("//evil.example/phish"),
            Err(AuthError::InvalidRedirectTarget)
        );
        assert_eq!(
            build_oauth_sign_out_url("/\\evil.example"),
            Err(AuthError::InvalidRedirectTarget)
        );
    }
}
