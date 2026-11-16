//! Pure `#![no_std]`-core public API integration tests for `mu-auth` (#329–#335).

use std::collections::BTreeSet;

use mu_auth::{
    canonical_manifests, canonical_super_operator_folios, evaluate_session, AuthAuthority,
    FolioCatalog, FolioError, FolioId, FolioOrigin, MaintenanceOverride, PolicyFolio, PolicyId,
    Principal, RoleActivation, RoleCatalog, RoleFolioIndex, RoleId, RoleLeases, RoleSpec,
    StepUpRequirement, SubsystemId, SubsystemStatus, HOST_TIMED_ROLE_CEILING_SECS,
    SUPER_OPERATOR_HARD_TTL_SECS, SUPER_OPERATOR_IDLE_TTL_SECS, SUPER_OPERATOR_MAX_RENEWALS,
    SUPER_OPERATOR_RENEW_EXTEND_SECS, SUPER_OPERATOR_RENEW_WINDOW_SECS, SUPER_OPERATOR_ROLE_ID,
};

fn rid(raw: &str) -> RoleId {
    RoleId::new(raw).expect("valid role id")
}

fn fid(raw: &str) -> FolioId {
    FolioId::new(raw).expect("valid folio id")
}

fn pid(raw: &str) -> PolicyId {
    PolicyId::new(raw).expect("valid policy id")
}

fn baseline_authority() -> AuthAuthority {
    let folio_catalog = FolioCatalog::with_canonical_manifests();
    let role_catalog = RoleCatalog::from_roles([
        RoleSpec::pinned_baseline(rid("viewer"), Some("Console Viewer"), "baseline").unwrap(),
        RoleSpec::elective(
            rid("ci-ops"),
            Some("CI Operator"),
            "elective CI ops",
            StepUpRequirement::None,
        )
        .unwrap(),
        RoleSpec::elective(
            rid("reg-ops"),
            Some("Registry Operator"),
            "elective registry ops",
            StepUpRequirement::Passkey,
        )
        .unwrap(),
        RoleSpec::timed(
            rid("ab-rollback"),
            Some("AB Rollback"),
            "emergency A/B rollback",
            600,
            120,
        )
        .unwrap(),
        RoleSpec::timed(
            rid("plat-admin"),
            Some("Platform Admin"),
            "platform administration",
            1800,
            300,
        )
        .unwrap(),
    ])
    .unwrap();

    let mut index = RoleFolioIndex::new();
    index
        .set_role_folios(
            rid("viewer"),
            BTreeSet::from([fid("folio:system:dashboard"), fid("folio:cd:read")]),
            &folio_catalog,
            &role_catalog,
        )
        .unwrap();
    index
        .set_role_folios(
            rid("ci-ops"),
            BTreeSet::from([fid("folio:ci:operate")]),
            &folio_catalog,
            &role_catalog,
        )
        .unwrap();
    index
        .set_role_folios(
            rid("reg-ops"),
            BTreeSet::from([fid("folio:reg:operate")]),
            &folio_catalog,
            &role_catalog,
        )
        .unwrap();
    index
        .set_role_folios(
            rid("ab-rollback"),
            BTreeSet::from([fid("folio:ab:operate")]),
            &folio_catalog,
            &role_catalog,
        )
        .unwrap();
    index
        .set_role_folios(
            rid("plat-admin"),
            BTreeSet::from([fid("folio:platform:admin")]),
            &folio_catalog,
            &role_catalog,
        )
        .unwrap();

    AuthAuthority::new(folio_catalog, role_catalog, index).unwrap()
}

#[test]
fn all_8_subsystems_ecosystem_agnostic_cd_and_zero_ab_promote() {
    let manifests = canonical_manifests();
    assert_eq!(manifests.len(), 8);

    let folio_catalog = FolioCatalog::with_canonical_manifests();
    for manifest in &manifests {
        for folio in &manifest.folios {
            assert_eq!(folio.origin, FolioOrigin::Subsystem);
            assert_eq!(folio.owner_subsystem, Some(manifest.subsystem));
            let resolved = folio_catalog.resolve_folio(&folio.id).unwrap();
            assert!(!resolved.is_empty());
        }
    }

    let cd = folio_catalog.resolve_folio(&fid("folio:cd:read")).unwrap();
    assert!(cd.contains(&pid("cd:runs.read")));
    assert!(cd.contains(&pid("cd:steps.read")));
    assert_eq!(cd.len(), 2);

    let ab = folio_catalog
        .resolve_folio(&fid("folio:ab:operate"))
        .unwrap();
    assert!(ab.contains(&pid("ab:slots.read")));
    assert!(ab.contains(&pid("ab:gate.logs.read")));
    assert!(ab.contains(&pid("ab:rollback")));
    assert!(!ab.contains_str("ab:promote"));
}

#[test]
fn operator_composite_folios_support_multi_hop_dag_and_forbid_cycles_or_subsystem_edits() {
    let mut catalog = FolioCatalog::with_canonical_manifests();

    let s1 = PolicyFolio::operator(
        fid("folio:op:readonly-bundle"),
        "Readonly Bundle",
        "ci + obs + cd read",
        BTreeSet::from([
            fid("folio:ci:read"),
            fid("folio:obs:read"),
            fid("folio:cd:read"),
        ]),
        BTreeSet::new(),
    )
    .unwrap();
    catalog.upsert_operator_folio(s1).unwrap();

    let s2 = PolicyFolio::operator(
        fid("folio:op:sre-triage"),
        "SRE Triage",
        "extends readonly bundle",
        BTreeSet::from([fid("folio:op:readonly-bundle")]),
        BTreeSet::from([pid("mr:models.read")]),
    )
    .unwrap();
    catalog.upsert_operator_folio(s2).unwrap();

    let triage = catalog.resolve_folio(&fid("folio:op:sre-triage")).unwrap();
    assert!(triage.contains(&pid("ci:queue.read")));
    assert!(triage.contains(&pid("obs:traces.read")));
    assert!(triage.contains(&pid("cd:runs.read")));
    assert!(triage.contains(&pid("mr:models.read")));

    // Self-cycle and indirect cycle fail without corrupting prior state
    let self_loop = PolicyFolio::operator(
        fid("folio:op:sre-triage"),
        "SRE Triage",
        "self loop",
        BTreeSet::from([fid("folio:op:sre-triage")]),
        BTreeSet::new(),
    )
    .unwrap();
    assert!(matches!(
        catalog.upsert_operator_folio(self_loop),
        Err(FolioError::CyclicFolioInclude { .. })
    ));

    let indirect = PolicyFolio::operator(
        fid("folio:op:readonly-bundle"),
        "Readonly Bundle",
        "cycle back",
        BTreeSet::from([fid("folio:op:sre-triage")]),
        BTreeSet::new(),
    )
    .unwrap();
    assert!(matches!(
        catalog.upsert_operator_folio(indirect),
        Err(FolioError::CyclicFolioInclude { .. })
    ));

    // Subsystem folios cannot be overwritten or deleted
    assert!(matches!(
        catalog.remove_operator_folio(&fid("folio:platform:admin")),
        Err(FolioError::ImmutableSubsystemFolio(_))
    ));
}

#[test]
fn role_catalog_baseline_display_name_and_anonymous_lockdown_invariants() {
    let mut auth = baseline_authority();

    // Anonymous starts completely locked down
    let anon = auth
        .evaluate_session(&Principal::Anonymous, &RoleLeases::new(), 1_000)
        .unwrap();
    assert!(anon.is_anonymous);
    assert!(anon.policies.is_empty());

    // Operator explicitly opts anonymous into status + public CI queue only
    auth.role_folio_index
        .set_anonymous_folios(
            BTreeSet::from([fid("folio:system:status"), fid("folio:ci:anon-queue")]),
            &auth.folio_catalog,
        )
        .unwrap();
    let anon_public = auth
        .evaluate_session(&Principal::Anonymous, &RoleLeases::new(), 1_000)
        .unwrap();
    assert!(anon_public.has_policy_str("system:status.read"));
    assert!(anon_public.has_policy_str("ci:queue.read"));
    assert!(!anon_public.has_policy_str("ci:jobs.read"));
    assert!(!anon_public.has_policy_str("platform:roles.read"));

    // Cannot replace or delete canonical PinnedBaseline role
    assert!(matches!(
        auth.role_catalog.remove_role(&rid("viewer")),
        Err(FolioError::MissingPinnedBaseline)
    ));
    let demote = RoleSpec::elective(
        rid("viewer"),
        Some("Viewer"),
        "cannot demote baseline",
        StepUpRequirement::None,
    )
    .unwrap();
    assert!(matches!(
        auth.role_catalog.upsert_role(demote),
        Err(FolioError::MissingPinnedBaseline)
    ));

    // Rejects '+' and control characters on PolicyFolio and RoleSpec
    assert!(matches!(
        PolicyFolio::operator(
            fid("folio:op:bad"),
            "Ops+Lead",
            "bad display",
            BTreeSet::new(),
            BTreeSet::new()
        ),
        Err(FolioError::InvalidDisplayName { .. })
    ));
}

#[test]
fn timed_leases_enforce_server_ceilings_step_up_and_independent_expiry() {
    let auth = baseline_authority();

    assert_eq!(HOST_TIMED_ROLE_CEILING_SECS, 1800);
    assert!(matches!(
        RoleSpec::timed(rid("bad"), None, "too long", 1801, 300),
        Err(FolioError::TtlExceedsCeiling { .. })
    ));

    let user = Principal::Authenticated {
        login: "LMA1980".into(),
        passkey_count: 1,
        bound_roles: BTreeSet::from([rid("ci-ops"), rid("ab-rollback"), rid("plat-admin")]),
    };
    let mut leases = RoleLeases::for_login(&auth.role_catalog, &user);

    // Step-up required before activating Elective(Passkey) or Timed roles
    assert!(matches!(
        leases.activate_timed(
            &auth.role_catalog,
            &user,
            &rid("ab-rollback"),
            10_000,
            false
        ),
        Err(FolioError::StepUpRequired { .. })
    ));
    // Unbound role fails closed even with step-up
    assert!(matches!(
        leases.enable_elective(&auth.role_catalog, &user, &rid("reg-ops"), true),
        Err(FolioError::UnauthorizedActivation { .. })
    ));
    // Cannot disable PinnedBaseline
    assert!(matches!(
        leases.disable_role(&auth.role_catalog, &rid("viewer")),
        Err(FolioError::CannotDeactivatePinnedBaseline(_))
    ));

    leases
        .enable_elective(&auth.role_catalog, &user, &rid("ci-ops"), false)
        .unwrap();
    leases
        .activate_timed(&auth.role_catalog, &user, &rid("ab-rollback"), 10_000, true)
        .unwrap();
    leases
        .activate_timed(&auth.role_catalog, &user, &rid("plat-admin"), 10_000, true)
        .unwrap();

    // Tamper check: inflating persisted lease deadlines beyond server RoleSpec is clamped fail-closed!
    leases
        .timed_leases
        .get_mut(&rid("ab-rollback"))
        .unwrap()
        .hard_expires_at_ms = 9_999_999_999;
    leases
        .timed_leases
        .get_mut(&rid("ab-rollback"))
        .unwrap()
        .idle_expires_at_ms = 9_999_999_999;

    // At t = 10s + 120s = 130_000ms, clamped idle_ttl=120s forces ab-rollback expiry!
    let eval_at_130s = evaluate_session(
        &auth.folio_catalog,
        &auth.role_catalog,
        &auth.role_folio_index,
        &user,
        &leases,
        130_000,
    )
    .unwrap();
    assert!(!eval_at_130s.has_role_str("ab-rollback"));
    assert!(!eval_at_130s.has_policy_str("ab:rollback"));
    assert!(eval_at_130s.has_role_str("plat-admin"));
    assert!(eval_at_130s.has_role_str("ci-ops"));
    assert!(eval_at_130s.has_role_str("viewer"));

    // Real non-tampered lease activity extension never extends hard_expires_at_ms
    let mut fresh = RoleLeases::for_login(&auth.role_catalog, &user);
    fresh
        .activate_timed(&auth.role_catalog, &user, &rid("ab-rollback"), 0, true)
        .unwrap();
    let hard_deadline = fresh.timed_leases[&rid("ab-rollback")].hard_expires_at_ms;
    assert_eq!(hard_deadline, 600_000);
    // Repeated activity up to 550s keeps extending idle capped at 600s hard deadline
    for t in [60_000, 150_000, 250_000, 350_000, 450_000, 550_000] {
        assert!(fresh.record_activity(t).is_empty());
    }
    let lease = &fresh.timed_leases[&rid("ab-rollback")];
    assert_eq!(lease.hard_expires_at_ms, 600_000);
    assert_eq!(lease.idle_expires_at_ms, 600_000);
    assert!(lease.is_active(599_999));
    assert!(!lease.is_active(600_000));
}

#[test]
fn maintenance_override_handles_all_5_states_and_autoclear() {
    assert_eq!(SubsystemId::OPERATIONAL.len(), 7);
    let statuses = [
        (SubsystemStatus::Live, "live"),
        (SubsystemStatus::InMaintenance, "in-maintenance"),
        (SubsystemStatus::PartialMaintenance, "partial-maintenance"),
        (SubsystemStatus::Offline, "offline"),
        (SubsystemStatus::Degraded, "degraded"),
    ];
    for (st, wire) in statuses {
        assert_eq!(st.as_str(), wire);
        #[cfg(feature = "github-oauth")]
        {
            let json = serde_json::to_string(&st).unwrap();
            assert_eq!(json, format!("\"{wire}\""));
            let back: SubsystemStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(back, st);
        }
    }

    let ov = MaintenanceOverride::new(
        SubsystemId::ModelRunner,
        SubsystemStatus::InMaintenance,
        Some("Planned runtime maintenance".into()),
        Some("LMA1980".into()),
        1_000,
        Some(300),
    );
    assert_eq!(
        MaintenanceOverride::resolve_effective(SubsystemStatus::Live, Some(&ov), 300_999),
        SubsystemStatus::InMaintenance
    );
    assert_eq!(
        MaintenanceOverride::resolve_effective(SubsystemStatus::Live, Some(&ov), 301_000),
        SubsystemStatus::Live
    );
}

#[test]
fn super_operator_grants_all_subsystems_enforces_idle_and_allows_single_last_2m_passkey_renewal() {
    let manifests = canonical_manifests();
    let expected_policies: BTreeSet<PolicyId> = manifests
        .iter()
        .flat_map(|m| m.policies.iter().map(|p| p.id.clone()))
        .collect();
    assert_eq!(expected_policies.len(), 47);

    let mut auth = baseline_authority();
    let super_spec = RoleSpec::super_operator();
    assert_eq!(super_spec.id.as_str(), SUPER_OPERATOR_ROLE_ID);
    assert_eq!(super_spec.step_up, StepUpRequirement::Passkey);
    assert_eq!(
        super_spec.activation,
        RoleActivation::Timed {
            hard_ttl_secs: SUPER_OPERATOR_HARD_TTL_SECS,
            idle_ttl_secs: SUPER_OPERATOR_IDLE_TTL_SECS,
            renew_window_secs: SUPER_OPERATOR_RENEW_WINDOW_SECS,
            renew_extend_secs: SUPER_OPERATOR_RENEW_EXTEND_SECS,
            max_renewals: SUPER_OPERATOR_MAX_RENEWALS,
        }
    );
    auth.role_catalog.upsert_role(super_spec).unwrap();
    auth.role_folio_index
        .set_role_folios(
            rid(SUPER_OPERATOR_ROLE_ID),
            BTreeSet::from(canonical_super_operator_folios()),
            &auth.folio_catalog,
            &auth.role_catalog,
        )
        .unwrap();

    let non_renewable = RoleSpec::timed(rid("ci-temp"), None, "Non-renewable", 300, 120).unwrap();
    auth.role_catalog.upsert_role(non_renewable).unwrap();
    auth.role_folio_index
        .set_role_folios(
            rid("ci-temp"),
            BTreeSet::from([fid("folio:ci:read")]),
            &auth.folio_catalog,
            &auth.role_catalog,
        )
        .unwrap();

    // Validation rejects invalid renewal bounds and cumulative TTL > 1800s.
    assert!(matches!(
        RoleSpec::timed_renewable(rid("bad-win"), None, "too big win", 300, 120, 301, 300, 1),
        Err(FolioError::InvalidTimedRenewalBounds { .. })
    ));
    assert!(matches!(
        RoleSpec::timed_renewable(
            rid("over-ceil"),
            None,
            "cumulative over 1800",
            900,
            120,
            120,
            901,
            1
        ),
        Err(FolioError::TtlExceedsCeiling {
            requested_secs: 1801,
            ceiling_secs: 1800
        })
    ));

    let principal = Principal::Authenticated {
        login: "LMA1980".into(),
        passkey_count: 1,
        bound_roles: BTreeSet::from([rid("viewer"), rid(SUPER_OPERATOR_ROLE_ID), rid("ci-temp")]),
    };

    let mut leases = RoleLeases::for_login(&auth.role_catalog, &principal);
    assert!(matches!(
        leases.activate_timed(
            &auth.role_catalog,
            &principal,
            &rid(SUPER_OPERATOR_ROLE_ID),
            0,
            false
        ),
        Err(FolioError::StepUpRequired { .. })
    ));

    leases
        .activate_timed(
            &auth.role_catalog,
            &principal,
            &rid(SUPER_OPERATOR_ROLE_ID),
            0,
            true,
        )
        .unwrap();
    leases
        .activate_timed(&auth.role_catalog, &principal, &rid("ci-temp"), 0, true)
        .unwrap();

    // All 47 policies across all 8 subsystems are active immediately upon activation.
    let eval_initial = auth.evaluate_session(&principal, &leases, 1_000).unwrap();
    let granted_initial: BTreeSet<PolicyId> = eval_initial.policies.iter().cloned().collect();
    assert_eq!(granted_initial, expected_policies);

    // Non-renewable timed lease rejects renewal while active.
    assert!(matches!(
        leases.renew_timed(
            &auth.role_catalog,
            &principal,
            &rid("ci-temp"),
            50_000,
            true
        ),
        Err(FolioError::LeaseNotRenewable { .. })
    ));

    // Activity keep-alive sustains the 2m idle timer up to the final 2m window, whereas no
    // activity for 120s expires the idle timer independently.
    for t in [
        100_000, 200_000, 300_000, 400_000, 500_000, 600_000, 700_000, 779_000,
    ] {
        leases.record_activity(t);
    }
    let lease_before = &leases.timed_leases[&rid(SUPER_OPERATOR_ROLE_ID)];
    assert!(!lease_before.can_renew(779_000));
    assert!(matches!(
        leases.renew_timed(
            &auth.role_catalog,
            &principal,
            &rid(SUPER_OPERATOR_ROLE_ID),
            779_000,
            true
        ),
        Err(FolioError::RenewalWindowNotReached {
            seconds_remaining: 121,
            renew_window_secs: 120,
            ..
        })
    ));

    // Inside final 2m (13m00s = 780_000ms), Passkey confirmation is still mandatory.
    assert!(leases.timed_leases[&rid(SUPER_OPERATOR_ROLE_ID)].can_renew(780_000));
    assert!(matches!(
        leases.renew_timed(
            &auth.role_catalog,
            &principal,
            &rid(SUPER_OPERATOR_ROLE_ID),
            780_000,
            false
        ),
        Err(FolioError::StepUpRequired { .. })
    ));

    // Renewing with Passkey at 13m00s extends hard deadline to 30m (1_800_000ms) and resets idle to +2m.
    let renewed = leases
        .renew_timed(
            &auth.role_catalog,
            &principal,
            &rid(SUPER_OPERATOR_ROLE_ID),
            780_000,
            true,
        )
        .unwrap()
        .clone();
    assert_eq!(renewed.hard_expires_at_ms, 1_800_000);
    assert_eq!(renewed.idle_expires_at_ms, 900_000);
    assert_eq!(renewed.renewals_used, 1);
    assert!(!renewed.can_renew(780_000));

    // Second renewal fails fail-closed even within last 2m of the extended window.
    leases.record_activity(850_000);
    assert!(matches!(
        leases.renew_timed(
            &auth.role_catalog,
            &principal,
            &rid(SUPER_OPERATOR_ROLE_ID),
            850_000,
            true
        ),
        Err(FolioError::RenewalLimitReached {
            max_renewals: 1,
            ..
        })
    ));

    // `evaluate_session` preserves the extended hard deadline past the original 15m mark.
    leases.record_activity(950_000);
    let eval_extended = auth.evaluate_session(&principal, &leases, 950_000).unwrap();
    assert!(eval_extended.has_role_str(SUPER_OPERATOR_ROLE_ID));
    let granted_extended: BTreeSet<PolicyId> = eval_extended.policies.iter().cloned().collect();
    assert_eq!(granted_extended, expected_policies);

    // Leaving the session idle for >= 2m expires super-operator cleanly.
    let eval_idle_expired = auth
        .evaluate_session(&principal, &leases, 1_070_000)
        .unwrap();
    assert!(!eval_idle_expired.has_role_str(SUPER_OPERATOR_ROLE_ID));
}
