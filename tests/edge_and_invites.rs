#![cfg(feature = "github-oauth")]
//! Integration tests for fail-closed secrets, framework-agnostic edge proxy adapter,
//! single-baseline HMAC invites, and RFC 3986 `/oauth2/{start,sign_out}` builders (#338–#339).

use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use mu_auth::{
    build_oauth_sign_out_url, build_oauth_start_url, resolve_secret_file, resolve_secret_value,
    resolve_secret_with_file_var, AuthError, EdgeAuthConfig, GithubEdgeAuthAdapter, GithubLogin,
    InviteCodec, RoleCatalog, RoleId, RoleSpec, StepUpRequirement,
};

fn role_catalog() -> RoleCatalog {
    RoleCatalog::from_roles([
        RoleSpec::pinned_baseline(RoleId::new("viewer").unwrap(), Some("Viewer"), "baseline")
            .unwrap(),
        RoleSpec::timed(
            RoleId::new("platform-admin").unwrap(),
            Some("Platform Admin"),
            "admin",
            1800,
            300,
        )
        .unwrap(),
        RoleSpec::elective(
            RoleId::new("ci-operator").unwrap(),
            Some("CI Operator"),
            "ci",
            StepUpRequirement::Passkey,
        )
        .unwrap(),
    ])
    .unwrap()
}

fn unique_temp_dir(label: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("mu-auth-{label}-{}-{nanos}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn secret_loader_fails_closed_on_missing_or_empty_files() {
    let dir = unique_temp_dir("secret-test");
    let valid_path = dir.join("webhook.secret");
    let empty_path = dir.join("empty.secret");
    let missing_path = dir.join("does-not-exist.secret");

    std::fs::write(&valid_path, "  top-secret-42 \r\n").unwrap();
    std::fs::write(&empty_path, " \n\t ").unwrap();

    assert_eq!(
        resolve_secret_file(&valid_path),
        Some("top-secret-42".into())
    );
    assert_eq!(resolve_secret_file(&empty_path), None);
    assert_eq!(resolve_secret_file(&missing_path), None);

    // Path-like strings never fall back to returning the path string itself
    assert_eq!(resolve_secret_value(missing_path.to_str().unwrap()), None);

    let env_lit = format!("MU_AUTH_TEST_LIT_{}", std::process::id());
    let env_file = format!("MU_AUTH_TEST_FILE_{}", std::process::id());
    std::env::set_var(&env_lit, "literal-fallback");
    std::env::set_var(&env_file, missing_path.to_str().unwrap());
    assert_eq!(resolve_secret_with_file_var(&env_lit, &env_file), None);

    std::env::set_var(&env_file, valid_path.to_str().unwrap());
    assert_eq!(
        resolve_secret_with_file_var(&env_lit, &env_file),
        Some("top-secret-42".into())
    );

    std::env::remove_var(&env_lit);
    std::env::remove_var(&env_file);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn edge_adapter_enforces_secret_header_hygiene_and_loopback_boundary() {
    assert_eq!(
        EdgeAuthConfig::with_secret_and_loopback(None, false),
        Err(AuthError::MissingProxySecret)
    );

    let cfg = EdgeAuthConfig::with_proxy_secret("edge-shared-secret-value").unwrap();
    let adapter = GithubEdgeAuthAdapter::new(cfg);

    let remote_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)));
    let loopback = Some(IpAddr::V4(Ipv4Addr::LOCALHOST));

    // Spoofed X-Forwarded-User without secret is always rejected
    assert_eq!(
        adapter.authenticate_headers(&[("X-Forwarded-User", "LMA1980")], remote_ip),
        Err(AuthError::InvalidProxySecret)
    );
    assert_eq!(
        adapter.authenticate_headers(&[("X-Forwarded-User", "LMA1980")], loopback),
        Err(AuthError::InvalidProxySecret)
    );

    // Mismatched X-Proxy-Secret is rejected even without X-Forwarded-User
    assert_eq!(
        adapter.authenticate_headers(&[("x-proxy-secret", "edge-shared-secret-valuX")], remote_ip),
        Err(AuthError::InvalidProxySecret)
    );

    // Valid secret + valid login succeeds regardless of peer IP and case-insensitive header keys
    let verified = adapter
        .require_authenticated_headers(
            &[
                ("x-proxy-secret", "edge-shared-secret-value"),
                ("x-forwarded-user", "octo-cat"),
            ],
            remote_ip,
        )
        .unwrap();
    assert_eq!(verified.login.as_str(), "octo-cat");
    assert!(verified.verified_via_secret);

    // Rejects invalid GitHub login characters or control chars
    assert_eq!(
        adapter.require_authenticated_headers(
            &[
                ("X-Proxy-Secret", "edge-shared-secret-value"),
                ("X-Forwarded-User", "bad+user"),
            ],
            remote_ip,
        ),
        Err(AuthError::InvalidHeaderValue("X-Forwarded-User"))
    );
}

#[test]
fn invite_tokens_only_bind_id_and_expiry_and_grant_pinned_baseline() {
    let roles = role_catalog();
    let codec = InviteCodec::new("hmac-invite-signing-secret").unwrap();
    let login = GithubLogin::new("new-member").unwrap();

    let signed = codec.sign_invite("invid_0001", 100_000, &roles).unwrap();
    assert_eq!(signed.granted_role.as_str(), "viewer");

    let fulfilled = codec
        .fulfill_baseline_invite(&signed.token, 100_000, 50_000, &roles, &login)
        .unwrap();
    assert_eq!(fulfilled.granted_role.as_str(), "viewer");

    // Self-expiring invite workflow
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let dynamic_prefix = format!("inv{seed:08x}");
    let self_exp = codec
        .sign_self_expiring_invite(&dynamic_prefix, 200_000, &roles)
        .unwrap();
    let (parsed, exp) = codec
        .verify_self_expiring_invite(&self_exp.token, 199_999)
        .unwrap();
    assert_eq!(exp, 200_000);
    assert!(parsed.invite_id.starts_with(&format!("{dynamic_prefix}_")));
    assert_eq!(
        codec.verify_self_expiring_invite(&self_exp.token, 200_000),
        Err(AuthError::InviteExpired)
    );

    // Tampered token rejects
    let tampered = format!("{}0", &signed.token[..signed.token.len() - 1]);
    assert_eq!(
        codec.verify_invite(&tampered, 100_000, 50_000),
        Err(AuthError::InvalidInviteToken)
    );

    // RFC 3986 redirect URLs
    assert_eq!(
        build_oauth_start_url("/observability?tab=logs&q=a b").unwrap(),
        "/oauth2/start?rd=%2Fobservability%3Ftab%3Dlogs%26q%3Da%20b"
    );
    assert_eq!(
        build_oauth_sign_out_url("/platform").unwrap(),
        "/oauth2/sign_out?rd=%2Fplatform"
    );
}
