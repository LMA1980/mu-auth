//! Framework-agnostic `oauth2-proxy` edge header verification adapter.

use alloc::string::{String, ToString};
use core::fmt;
use core::net::IpAddr;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::AuthError;
use crate::secret::{resolve_secret_value, resolve_secret_with_file_var};

/// Header carrying the authenticated GitHub login injected by `oauth2-proxy` / reverse proxy.
pub const HEADER_FORWARDED_USER: &str = "x-forwarded-user";

/// Optional informational header carrying forwarded email address.
pub const HEADER_FORWARDED_EMAIL: &str = "x-forwarded-email";

/// Shared secret header proving the request traversed the trusted reverse proxy.
pub const HEADER_PROXY_SECRET: &str = "x-proxy-secret";

/// Validated ASCII GitHub login extracted from verified edge proxy headers.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct GithubLogin(String);

impl GithubLogin {
    /// Validates a GitHub username (`1..=39` ASCII `[A-Za-z0-9-]`, no leading/trailing `-`, no `--`).
    pub fn new(raw: impl Into<String>) -> Result<Self, AuthError> {
        let raw = raw.into();
        let trimmed = raw.trim();
        if trimmed.is_empty()
            || trimmed.len() > 39
            || trimmed.len() != raw.len()
            || trimmed.starts_with('-')
            || trimmed.ends_with('-')
            || trimmed.contains("--")
            || !trimmed
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-'))
        {
            return Err(AuthError::InvalidHeaderValue("X-Forwarded-User"));
        }
        Ok(Self(raw))
    }

    /// Underlying username slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Canonical lowercase representation for case-insensitive principal matching.
    #[must_use]
    pub fn to_lowercase(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

impl fmt::Debug for GithubLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("GithubLogin").field(&self.0).finish()
    }
}

impl fmt::Display for GithubLogin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for GithubLogin {
    type Err = AuthError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl<'de> Deserialize<'de> for GithubLogin {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Verified edge identity extracted after authenticating the proxy boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeIdentity {
    /// Validated GitHub username from `X-Forwarded-User`.
    pub login: GithubLogin,
    /// Optional forwarded email header when validated alongside user identity.
    pub email: Option<String>,
    /// `true` when `X-Proxy-Secret` matched in constant time.
    pub verified_via_secret: bool,
    /// `true` when request arrived from an explicitly trusted loopback peer without secret.
    pub verified_via_loopback: bool,
}

/// Configuration governing proxy-trust boundary checks for [`GithubEdgeAuthAdapter`].
#[derive(Clone, PartialEq, Eq)]
pub struct EdgeAuthConfig {
    proxy_secret: Option<String>,
    allow_loopback_without_secret: bool,
}

impl fmt::Debug for EdgeAuthConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EdgeAuthConfig")
            .field(
                "proxy_secret",
                &self.proxy_secret.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "allow_loopback_without_secret",
                &self.allow_loopback_without_secret,
            )
            .finish()
    }
}

impl EdgeAuthConfig {
    /// Builds an adapter requiring constant-time `X-Proxy-Secret` verification.
    pub fn with_proxy_secret(secret: impl AsRef<str>) -> Result<Self, AuthError> {
        let resolved =
            resolve_secret_value(secret.as_ref()).ok_or(AuthError::MissingProxySecret)?;
        Ok(Self {
            proxy_secret: Some(resolved),
            allow_loopback_without_secret: false,
        })
    }

    /// Builds an adapter from optional secret value (resolving path if path-like) and explicit
    /// loopback-trust opt-in.
    ///
    /// Fails closed (`MissingProxySecret`) when neither a valid secret nor loopback opt-in is enabled.
    pub fn with_secret_and_loopback(
        secret: Option<&str>,
        allow_loopback_without_secret: bool,
    ) -> Result<Self, AuthError> {
        let resolved = match secret {
            Some(raw) => Some(resolve_secret_value(raw).ok_or(AuthError::MissingProxySecret)?),
            None => None,
        };
        if resolved.is_none() && !allow_loopback_without_secret {
            return Err(AuthError::MissingProxySecret);
        }
        Ok(Self {
            proxy_secret: resolved,
            allow_loopback_without_secret,
        })
    }

    /// Loads proxy configuration from environment variables using fail-closed file resolution.
    pub fn from_env(
        secret_env_var: &str,
        secret_file_env_var: &str,
        allow_loopback_without_secret: bool,
    ) -> Result<Self, AuthError> {
        let secret = resolve_secret_with_file_var(secret_env_var, secret_file_env_var);
        if secret.is_none() && !allow_loopback_without_secret {
            return Err(AuthError::MissingProxySecret);
        }
        Ok(Self {
            proxy_secret: secret,
            allow_loopback_without_secret,
        })
    }

    /// Returns `true` when a non-empty proxy secret is configured.
    #[must_use]
    pub fn has_proxy_secret(&self) -> bool {
        self.proxy_secret.is_some()
    }

    /// Returns `true` when loopback peers without `X-Proxy-Secret` are explicitly trusted.
    #[must_use]
    pub fn allows_loopback_without_secret(&self) -> bool {
        self.allow_loopback_without_secret
    }
}

/// Framework-agnostic edge proxy verifier operating on `(&str, &str)` header slices.
#[derive(Debug, Clone)]
pub struct GithubEdgeAuthAdapter {
    config: EdgeAuthConfig,
}

impl GithubEdgeAuthAdapter {
    /// Creates a new [`GithubEdgeAuthAdapter`] from validated [`EdgeAuthConfig`].
    #[must_use]
    pub fn new(config: EdgeAuthConfig) -> Self {
        Self { config }
    }

    /// Verifies proxy trust headers and extracts optional caller identity from `(&str, &str)` slices.
    ///
    /// - Rejects duplicate `X-Proxy-Secret` or `X-Forwarded-User` headers.
    /// - Rejects invalid/mismatched `X-Proxy-Secret` even when `X-Forwarded-User` is absent.
    /// - Rejects spoofed `X-Forwarded-User` headers arriving without a valid `X-Proxy-Secret`
    ///   (unless arriving from loopback with `allow_loopback_without_secret` explicitly enabled).
    /// - Returns `Ok(None)` cleanly for unauthenticated/anonymous traffic carrying no `X-Forwarded-User`.
    pub fn authenticate_headers(
        &self,
        headers: &[(&str, &str)],
        peer_ip: Option<IpAddr>,
    ) -> Result<Option<EdgeIdentity>, AuthError> {
        self.authenticate_header_iter(headers.iter().copied(), peer_ip)
    }

    /// Verifies proxy trust headers from an arbitrary header iterator (`(&str, &str)` pairs).
    pub fn authenticate_header_iter<'a>(
        &self,
        headers: impl IntoIterator<Item = (&'a str, &'a str)>,
        peer_ip: Option<IpAddr>,
    ) -> Result<Option<EdgeIdentity>, AuthError> {
        let mut forwarded_user: Option<&str> = None;
        let mut forwarded_email: Option<&str> = None;
        let mut proxy_secret: Option<&str> = None;

        for (name, value) in headers {
            if name.eq_ignore_ascii_case(HEADER_FORWARDED_USER) {
                if forwarded_user.is_some() {
                    return Err(AuthError::DuplicateHeader("X-Forwarded-User"));
                }
                forwarded_user = Some(value);
            } else if name.eq_ignore_ascii_case(HEADER_PROXY_SECRET) {
                if proxy_secret.is_some() {
                    return Err(AuthError::DuplicateHeader("X-Proxy-Secret"));
                }
                proxy_secret = Some(value);
            } else if name.eq_ignore_ascii_case(HEADER_FORWARDED_EMAIL) {
                if forwarded_email.is_some() {
                    return Err(AuthError::DuplicateHeader("X-Forwarded-Email"));
                }
                forwarded_email = Some(value);
            }
        }

        let peer_is_loopback = peer_ip.is_some_and(|ip| ip.is_loopback());
        let mut verified_via_secret = false;
        let mut verified_via_loopback = false;

        if let Some(presented_secret) = proxy_secret {
            let Some(expected) = &self.config.proxy_secret else {
                return Err(AuthError::InvalidProxySecret);
            };
            if !constant_time_str_eq(presented_secret, expected) {
                return Err(AuthError::InvalidProxySecret);
            }
            verified_via_secret = true;
        } else if self.config.allow_loopback_without_secret && peer_is_loopback {
            verified_via_loopback = true;
        }

        let Some(raw_user) = forwarded_user else {
            return Ok(None);
        };

        if !verified_via_secret && !verified_via_loopback {
            return if self.config.proxy_secret.is_some() {
                Err(AuthError::InvalidProxySecret)
            } else {
                Err(AuthError::UntrustedProxySource)
            };
        }

        let login = GithubLogin::new(raw_user)?;
        let email = match forwarded_email {
            Some(raw_email) => {
                let trimmed = raw_email.trim();
                if trimmed.is_empty() {
                    None
                } else if trimmed.chars().any(char::is_control) {
                    return Err(AuthError::InvalidHeaderValue("X-Forwarded-Email"));
                } else {
                    Some(trimmed.to_string())
                }
            }
            None => None,
        };

        Ok(Some(EdgeIdentity {
            login,
            email,
            verified_via_secret,
            verified_via_loopback,
        }))
    }

    /// Requires a verified authenticated [`EdgeIdentity`], failing closed on anonymous traffic.
    pub fn require_authenticated_headers(
        &self,
        headers: &[(&str, &str)],
        peer_ip: Option<IpAddr>,
    ) -> Result<EdgeIdentity, AuthError> {
        self.authenticate_headers(headers, peer_ip)?
            .ok_or(AuthError::MissingForwardedUser)
    }

    /// Access underlying [`EdgeAuthConfig`].
    #[must_use]
    pub fn config(&self) -> &EdgeAuthConfig {
        &self.config
    }
}

/// Constant-time string comparison using fixed-width SHA-256 digests so lengths do not short-circuit.
#[must_use]
pub fn constant_time_str_eq(lhs: &str, rhs: &str) -> bool {
    let lhs_digest = Sha256::digest(lhs.as_bytes());
    let rhs_digest = Sha256::digest(rhs.as_bytes());
    lhs_digest.as_slice().ct_eq(rhs_digest.as_slice()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn authenticates_constant_time_secret_and_rejects_spoofing() {
        let cfg = EdgeAuthConfig::with_proxy_secret("super-secret-proxy-key").unwrap();
        let adapter = GithubEdgeAuthAdapter::new(cfg);

        // Redacted debug check
        let dbg_str = alloc::format!("{:?}", adapter.config());
        assert!(!dbg_str.contains("super-secret-proxy-key"));
        assert!(dbg_str.contains("[REDACTED]"));

        // Valid secret + forwarded user
        let id = adapter
            .authenticate_headers(
                &[
                    ("X-Proxy-Secret", "super-secret-proxy-key"),
                    ("X-Forwarded-User", "LMA1980"),
                    ("X-Forwarded-Email", "dev@example.org"),
                ],
                None,
            )
            .unwrap()
            .expect("authenticated");
        assert_eq!(id.login.as_str(), "LMA1980");
        assert_eq!(id.login.to_lowercase(), "lma1980");
        assert!(id.verified_via_secret);
        assert!(!id.verified_via_loopback);

        // Wrong secret fails even without X-Forwarded-User
        assert_eq!(
            adapter.authenticate_headers(&[("X-Proxy-Secret", "wrong")], None),
            Err(AuthError::InvalidProxySecret)
        );

        // Spoofed X-Forwarded-User without secret fails even on loopback unless opted in
        assert_eq!(
            adapter.authenticate_headers(
                &[("X-Forwarded-User", "LMA1980")],
                Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            ),
            Err(AuthError::InvalidProxySecret)
        );

        // Duplicate headers fail closed
        assert_eq!(
            adapter.authenticate_headers(
                &[
                    ("X-Proxy-Secret", "super-secret-proxy-key"),
                    ("X-Forwarded-User", "alice"),
                    ("x-forwarded-user", "bob"),
                ],
                None,
            ),
            Err(AuthError::DuplicateHeader("X-Forwarded-User"))
        );

        // Anonymous request without headers yields None
        assert_eq!(adapter.authenticate_headers(&[], None).unwrap(), None);
    }

    #[test]
    fn loopback_opt_in_only_trusts_loopback_peers() {
        let cfg = EdgeAuthConfig::with_secret_and_loopback(None, true).unwrap();
        let adapter = GithubEdgeAuthAdapter::new(cfg);

        let local_id = adapter
            .require_authenticated_headers(
                &[("X-Forwarded-User", "operator-1")],
                Some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            )
            .unwrap();
        assert!(local_id.verified_via_loopback);

        let remote = adapter.require_authenticated_headers(
            &[("X-Forwarded-User", "operator-1")],
            Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))),
        );
        assert_eq!(remote, Err(AuthError::UntrustedProxySource));
    }
}
