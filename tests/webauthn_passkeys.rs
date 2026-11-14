#![cfg(feature = "github-oauth")]
//! Cryptographic end-to-end WebAuthn Passkey tests covering 1Password (`sign_count == 0`),
//! physical FIDO2 keys (monotonic non-zero counter + clone rejection), single-use 60s challenges,
//! RP ID / origin binding, and `StepUpVerifier` server-ceiling `ElevationLease` derivation (#340).

use std::collections::BTreeMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use crypto_glue::ecdsa_p256::{EcdsaP256PrivateKey, EcdsaP256SigningKey};
use crypto_glue::s256::Sha256;
use crypto_glue::traits::{Digest, SignatureEncoding, Signer, ToSec1Point};
use serde_cbor_2::Value as CborValue;
use url::Url;
use webauthn_rs_core::proto::{
    AuthenticatorAssertionResponseRaw, AuthenticatorAttestationResponseRaw, PublicKeyCredential,
    RegisterPublicKeyCredential,
};

use mu_auth::{
    AuthError, GithubLogin, RoleId, RoleSpec, StepUpVerifier, WebauthnConfig,
    WebauthnPasskeyService,
};

struct VirtualAuthenticator {
    rp_id: String,
    origin: String,
    cred_id: Vec<u8>,
    signing_key: EcdsaP256SigningKey,
    pub_x: Vec<u8>,
    pub_y: Vec<u8>,
    backup_eligible: bool,
    backup_state: bool,
    sign_count: u32,
}

impl VirtualAuthenticator {
    fn new_synced_authenticator(rp_id: &str, origin: &str, cred_id: Vec<u8>) -> Self {
        Self::new(rp_id, origin, cred_id, true, true, 0)
    }

    fn new_fido2_key(rp_id: &str, origin: &str, cred_id: Vec<u8>, initial_count: u32) -> Self {
        Self::new(rp_id, origin, cred_id, false, false, initial_count)
    }

    fn new(
        rp_id: &str,
        origin: &str,
        cred_id: Vec<u8>,
        backup_eligible: bool,
        backup_state: bool,
        sign_count: u32,
    ) -> Self {
        let priv_key: EcdsaP256PrivateKey = crypto_glue::ecdsa_p256::new_key();
        let pub_key = priv_key.public_key();
        let point = pub_key.to_sec1_point(false);
        let pub_x = point.x().expect("x coordinate").to_vec();
        let pub_y = point.y().expect("y coordinate").to_vec();
        let signing_key = EcdsaP256SigningKey::from(&priv_key);
        Self {
            rp_id: rp_id.to_string(),
            origin: origin.to_string(),
            cred_id,
            signing_key,
            pub_x,
            pub_y,
            backup_eligible,
            backup_state,
            sign_count,
        }
    }

    fn create_registration_response(&self, challenge_bytes: &[u8]) -> RegisterPublicKeyCredential {
        let mut flags: u8 = 0x01 | 0x04 | 0x40; // UP | UV | AT
        if self.backup_eligible {
            flags |= 0x08;
        }
        if self.backup_state {
            flags |= 0x10;
        }

        let rp_id_hash = Sha256::digest(self.rp_id.as_bytes());

        // COSE EC2 P-256 public key map
        let mut cose_map = BTreeMap::new();
        cose_map.insert(CborValue::Integer(1), CborValue::Integer(2)); // kty = EC2
        cose_map.insert(CborValue::Integer(3), CborValue::Integer(-7)); // alg = ES256
        cose_map.insert(CborValue::Integer(-1), CborValue::Integer(1)); // crv = P-256
        cose_map.insert(CborValue::Integer(-2), CborValue::Bytes(self.pub_x.clone()));
        cose_map.insert(CborValue::Integer(-3), CborValue::Bytes(self.pub_y.clone()));
        let cose_cbor = serde_cbor_2::to_vec(&CborValue::Map(cose_map)).unwrap();

        let mut auth_data = Vec::new();
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&self.sign_count.to_be_bytes());
        auth_data.extend_from_slice(&[0u8; 16]); // AAGUID
        auth_data.extend_from_slice(&(self.cred_id.len() as u16).to_be_bytes());
        auth_data.extend_from_slice(&self.cred_id);
        auth_data.extend_from_slice(&cose_cbor);

        let mut att_obj = BTreeMap::new();
        att_obj.insert(
            CborValue::Text("fmt".into()),
            CborValue::Text("none".into()),
        );
        att_obj.insert(
            CborValue::Text("attStmt".into()),
            CborValue::Map(BTreeMap::new()),
        );
        att_obj.insert(
            CborValue::Text("authData".into()),
            CborValue::Bytes(auth_data),
        );
        let attestation_object = serde_cbor_2::to_vec(&CborValue::Map(att_obj)).unwrap();

        let client_data = serde_json::json!({
            "type": "webauthn.create",
            "challenge": URL_SAFE_NO_PAD.encode(challenge_bytes),
            "origin": self.origin,
            "crossOrigin": false,
        });
        let client_data_json = serde_json::to_vec(&client_data).unwrap();

        let b64_id = URL_SAFE_NO_PAD.encode(&self.cred_id);
        RegisterPublicKeyCredential {
            id: b64_id.clone(),
            raw_id: self.cred_id.clone(),
            response: AuthenticatorAttestationResponseRaw {
                attestation_object,
                client_data_json,
                transports: None,
            },
            type_: "public-key".into(),
            extensions: Default::default(),
        }
    }

    fn create_assertion_response(
        &self,
        challenge_bytes: &[u8],
        sign_count: u32,
        override_origin: Option<&str>,
    ) -> PublicKeyCredential {
        let mut flags: u8 = 0x01 | 0x04; // UP | UV
        if self.backup_eligible {
            flags |= 0x08;
        }
        if self.backup_state {
            flags |= 0x10;
        }

        let rp_id_hash = Sha256::digest(self.rp_id.as_bytes());
        let mut auth_data = Vec::with_capacity(37);
        auth_data.extend_from_slice(&rp_id_hash);
        auth_data.push(flags);
        auth_data.extend_from_slice(&sign_count.to_be_bytes());

        let client_data = serde_json::json!({
            "type": "webauthn.get",
            "challenge": URL_SAFE_NO_PAD.encode(challenge_bytes),
            "origin": override_origin.unwrap_or(&self.origin),
            "crossOrigin": false,
        });
        let client_data_json = serde_json::to_vec(&client_data).unwrap();
        let client_data_hash = Sha256::digest(&client_data_json);

        let mut signed_msg = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        signed_msg.extend_from_slice(&auth_data);
        signed_msg.extend_from_slice(&client_data_hash);

        let sig: crypto_glue::ecdsa_p256::EcdsaP256Signature = self.signing_key.sign(&signed_msg);
        let der_sig = sig.to_der().to_vec();

        PublicKeyCredential {
            id: URL_SAFE_NO_PAD.encode(&self.cred_id),
            raw_id: self.cred_id.clone(),
            response: AuthenticatorAssertionResponseRaw {
                authenticator_data: auth_data,
                client_data_json,
                signature: der_sig,
                user_handle: None,
            },
            extensions: Default::default(),
            type_: "public-key".into(),
        }
    }
}

fn passkey_service() -> WebauthnPasskeyService {
    let origin = Url::parse("https://console.example.org").unwrap();
    let cfg = WebauthnConfig::new("MuConsole", "console.example.org", vec![origin]).unwrap();
    WebauthnPasskeyService::new(cfg)
}

#[test]
fn synced_vault_passkey_enrolls_and_verifies_repeatedly_with_sign_count_zero() {
    // Models 1Password and other synced cloud-backed passkey authenticators (BE=1, BS=1, sign_count=0).
    let svc = passkey_service();
    let login = GithubLogin::new("LMA1980").unwrap();
    let op_auth = VirtualAuthenticator::new_synced_authenticator(
        "console.example.org",
        "https://console.example.org",
        b"op-cred-id-0001".to_vec(),
    );

    // Enrollment options omit authenticatorAttachment, request attestation=none, UV=preferred
    let reg_chal = svc
        .begin_registration(&login, b"uid-lma1980", &[], 1_000)
        .unwrap();
    let reg_json = serde_json::to_string(&reg_chal.options).unwrap();
    assert!(!reg_json.contains("authenticatorAttachment"));
    assert!(reg_json.contains("\"attestation\":\"none\""));
    assert!(reg_json.contains("\"userVerification\":\"preferred\""));

    let reg_rsp =
        op_auth.create_registration_response(reg_chal.options.public_key.challenge.as_slice());
    let record = svc
        .finish_registration(
            &login,
            &reg_chal.challenge_id,
            &reg_rsp,
            Some("1Password Synced"),
            2_000,
        )
        .unwrap();
    assert_eq!(record.sign_count, 0);
    assert_eq!(record.label.as_deref(), Some("1Password Synced"));

    // Replay of consumed registration challenge fails
    assert_eq!(
        svc.finish_registration(&login, &reg_chal.challenge_id, &reg_rsp, None, 2_500)
            .unwrap_err(),
        AuthError::ChallengeNotFoundOrExpired
    );

    // Multiple assertions reporting sign_count == 0 all verify cleanly for 1Password passkeys
    let admin_role = RoleSpec::timed(
        RoleId::new("platform-admin").unwrap(),
        Some("Platform Admin"),
        "admin step-up",
        900,
        180,
    )
    .unwrap();

    let mut creds = vec![record];
    for step_t in [10_000_u64, 30_000_u64] {
        let auth_chal = svc.begin_authentication(&login, &creds, step_t).unwrap();
        let assert_rsp = op_auth.create_assertion_response(
            auth_chal.options.public_key.challenge.as_slice(),
            0,
            None,
        );
        let verified = svc
            .verify_step_up(
                &login,
                &creds,
                &auth_chal.challenge_id,
                &assert_rsp,
                &admin_role,
                step_t + 1_000,
            )
            .unwrap();
        assert_eq!(verified.outcome.new_sign_count, 0);
        assert_eq!(verified.lease.hard_expires_at_ms, step_t + 1_000 + 900_000);
        assert_eq!(verified.lease.idle_expires_at_ms, step_t + 1_000 + 180_000);
        creds = vec![verified.outcome.updated_credential];

        // Single-use assertion challenge replay fails fail-closed
        assert_eq!(
            svc.verify_step_up(
                &login,
                &creds,
                &auth_chal.challenge_id,
                &assert_rsp,
                &admin_role,
                step_t + 1_500,
            )
            .unwrap_err(),
            AuthError::ChallengeNotFoundOrExpired
        );
    }
}

#[test]
fn fido2_hardware_key_enforces_monotonic_counter_and_detects_clones() {
    let svc = passkey_service();
    let login = GithubLogin::new("hw-operator").unwrap();
    let hw = VirtualAuthenticator::new_fido2_key(
        "console.example.org",
        "https://console.example.org",
        b"yubikey-cred-1".to_vec(),
        10,
    );

    let reg_chal = svc
        .begin_registration(&login, b"uid-hw", &[], 1_000)
        .unwrap();
    let reg_rsp = hw.create_registration_response(reg_chal.options.public_key.challenge.as_slice());
    let rec = svc
        .finish_registration(
            &login,
            &reg_chal.challenge_id,
            &reg_rsp,
            Some("Hardware FIDO2"),
            2_000,
        )
        .unwrap();
    assert_eq!(rec.sign_count, 10);

    // Advancing counter 10 -> 11 succeeds and updates stored record
    let c1 = svc
        .begin_authentication(&login, std::slice::from_ref(&rec), 5_000)
        .unwrap();
    let a1 = hw.create_assertion_response(c1.options.public_key.challenge.as_slice(), 11, None);
    let out1 = svc
        .finish_authentication(
            &login,
            std::slice::from_ref(&rec),
            &c1.challenge_id,
            &a1,
            6_000,
        )
        .unwrap();
    assert_eq!(out1.new_sign_count, 11);
    assert_eq!(out1.updated_credential.sign_count, 11);

    // Cloned / stale non-zero counter 11 <= 11 fails with CloneDetected
    let updated = out1.updated_credential;
    let c2 = svc
        .begin_authentication(&login, std::slice::from_ref(&updated), 10_000)
        .unwrap();
    let cloned_rsp =
        hw.create_assertion_response(c2.options.public_key.challenge.as_slice(), 11, None);
    let clone_err = svc
        .finish_authentication(
            &login,
            std::slice::from_ref(&updated),
            &c2.challenge_id,
            &cloned_rsp,
            11_000,
        )
        .unwrap_err();
    assert_eq!(clone_err, AuthError::CloneDetected);

    // Origin mismatch is rejected
    let c3 = svc
        .begin_authentication(&login, std::slice::from_ref(&updated), 20_000)
        .unwrap();
    let evil_origin_rsp = hw.create_assertion_response(
        c3.options.public_key.challenge.as_slice(),
        12,
        Some("https://phish.example.org"),
    );
    assert!(matches!(
        svc.finish_authentication(
            &login,
            std::slice::from_ref(&updated),
            &c3.challenge_id,
            &evil_origin_rsp,
            21_000
        ),
        Err(AuthError::WebAuthnVerificationFailed(_))
    ));

    // Expired 60s challenge fails fail-closed
    let c4 = svc
        .begin_authentication(&login, std::slice::from_ref(&updated), 30_000)
        .unwrap();
    let late_rsp =
        hw.create_assertion_response(c4.options.public_key.challenge.as_slice(), 13, None);
    assert_eq!(
        svc.finish_authentication(&login, &[updated], &c4.challenge_id, &late_rsp, 90_000)
            .unwrap_err(),
        AuthError::ChallengeNotFoundOrExpired
    );
}
