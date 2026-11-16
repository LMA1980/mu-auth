//! Principals, independent per-role `RoleLease` tracking, and session policy evaluation.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

use crate::error::FolioError;
use crate::folio::{FolioCatalog, PolicySet};
use crate::role::{
    RoleActivation, RoleCatalog, RoleFolioIndex, RoleId, RoleSpec, StepUpRequirement,
    HOST_TIMED_ROLE_CEILING_SECS,
};
use crate::subsystem::{FolioId, SubsystemId};

/// Authenticated or anonymous caller identity supplied to policy evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Principal {
    /// Unauthenticated visitor restricted to `RoleFolioIndex::anonymous_folios()` (`[]` by default).
    Anonymous,
    /// Bound GitHub operator/member account with Passkey enrollment count and persistent role bindings.
    Authenticated {
        /// Immutable GitHub username from verified edge proxy (`X-Forwarded-User`).
        login: String,
        /// Number of enrolled Passkeys; `0` enforces mandatory post-login Passkey gate.
        passkey_count: usize,
        /// Dormant `Elective` / `Timed` roles assigned to this user (in addition to canonical baseline).
        bound_roles: BTreeSet<RoleId>,
    },
}

/// Independent time-bounded lease for a single active `Timed` role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleLease {
    /// Elevated `Timed` role identifier.
    pub role: RoleId,
    /// Lease activation timestamp (`epoch_ms`).
    pub activated_at_ms: u64,
    /// Most recent explicit user activity timestamp (`epoch_ms`).
    #[serde(default)]
    pub last_activity_at_ms: u64,
    /// Hard expiry deadline (`epoch_ms`), extendable only within spec renewal bounds.
    pub hard_expires_at_ms: u64,
    /// Explicit-activity idle expiry deadline (`epoch_ms`), capped by `hard_expires_at_ms`.
    pub idle_expires_at_ms: u64,
    /// Configured server hard TTL in seconds.
    pub hard_ttl_secs: u64,
    /// Configured server idle TTL in seconds.
    pub idle_ttl_secs: u64,
    /// Window in seconds before hard expiry when Passkey renewal opens (`0` = non-renewable).
    #[serde(default)]
    pub renew_window_secs: u64,
    /// Hard-deadline extension granted per approved Passkey renewal in seconds.
    #[serde(default)]
    pub renew_extend_secs: u64,
    /// Maximum number of renewals permitted during one session (`0` = non-renewable).
    #[serde(default)]
    pub max_renewals: u32,
    /// Count of renewals already consumed during this lease.
    #[serde(default)]
    pub renewals_used: u32,
}

impl RoleLease {
    /// Derives a lease exclusively from server [`RoleSpec`] TTL ceilings (never client parameters).
    pub fn from_role_spec(spec: &RoleSpec, now_ms: u64) -> Result<Self, FolioError> {
        spec.validate()?;
        let RoleActivation::Timed {
            hard_ttl_secs,
            idle_ttl_secs,
            renew_window_secs,
            renew_extend_secs,
            max_renewals,
        } = spec.activation
        else {
            return Err(FolioError::UnauthorizedActivation {
                role: spec.id.to_string(),
            });
        };

        let hard_expires_at_ms = now_ms.saturating_add(hard_ttl_secs.saturating_mul(1000));
        let idle_expires_at_ms = now_ms
            .saturating_add(idle_ttl_secs.saturating_mul(1000))
            .min(hard_expires_at_ms);

        Ok(Self {
            role: spec.id.clone(),
            activated_at_ms: now_ms,
            last_activity_at_ms: now_ms,
            hard_expires_at_ms,
            idle_expires_at_ms,
            hard_ttl_secs,
            idle_ttl_secs,
            renew_window_secs,
            renew_extend_secs,
            max_renewals,
            renewals_used: 0,
        })
    }

    /// Number of Passkey-confirmed renewals remaining for this lease.
    #[must_use]
    pub const fn renewals_remaining(&self) -> u32 {
        self.max_renewals.saturating_sub(self.renewals_used)
    }

    /// Returns `true` when the lease is active, has renewals remaining, and is within its final `renew_window_secs`.
    #[must_use]
    pub fn can_renew(&self, now_ms: u64) -> bool {
        self.is_active(now_ms)
            && self.renewals_remaining() > 0
            && self.renew_window_secs > 0
            && self.renew_extend_secs > 0
            && self.hard_remaining_secs(now_ms) <= self.renew_window_secs
    }

    /// Effective earliest deadline across hard and idle limits.
    #[must_use]
    pub fn effective_expires_at_ms(&self) -> u64 {
        self.hard_expires_at_ms.min(self.idle_expires_at_ms)
    }

    /// Returns `true` when `now_ms < min(hard_expires_at_ms, idle_expires_at_ms)`.
    #[must_use]
    pub fn is_active(&self, now_ms: u64) -> bool {
        now_ms < self.effective_expires_at_ms()
    }

    /// Whole seconds remaining until non-renewable hard expiry (`[seconds_remaining]` display).
    #[must_use]
    pub fn hard_remaining_secs(&self, now_ms: u64) -> u64 {
        self.hard_expires_at_ms
            .saturating_sub(now_ms)
            .div_ceil(1000)
    }

    /// Whole seconds remaining until idle expiry (`[idle_timer]` display).
    #[must_use]
    pub fn idle_remaining_secs(&self, now_ms: u64) -> u64 {
        self.idle_expires_at_ms
            .saturating_sub(now_ms)
            .div_ceil(1000)
    }

    /// Whole seconds remaining before effective expiration (`min(hard, idle)`).
    #[must_use]
    pub fn seconds_remaining(&self, now_ms: u64) -> u64 {
        self.effective_expires_at_ms()
            .saturating_sub(now_ms)
            .div_ceil(1000)
    }

    /// Refreshes ONLY `idle_expires_at_ms` on explicit user activity while active.
    ///
    /// Never extends `hard_expires_at_ms` and never resurrects an expired lease.
    pub fn touch_activity(&mut self, now_ms: u64) -> bool {
        if !self.is_active(now_ms) {
            return false;
        }
        self.last_activity_at_ms = self.last_activity_at_ms.max(now_ms);
        self.idle_expires_at_ms = now_ms
            .saturating_add(self.idle_ttl_secs.saturating_mul(1000))
            .min(self.hard_expires_at_ms);
        true
    }
}

/// Active role selections and independent `Timed` role leases for an authenticated session.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RoleLeases {
    /// Canonical `PinnedBaseline` role active after Passkey enrollment gate passes.
    pub baseline_role: Option<RoleId>,
    /// Explicitly enabled `Elective` roles (dormant at login).
    pub elective_roles: BTreeSet<RoleId>,
    /// Active independent `Timed` role leases (dormant at login).
    pub timed_leases: BTreeMap<RoleId, RoleLease>,
}

impl RoleLeases {
    /// Empty session state with no active roles.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Initializes clean login session state with minimum privilege:
    /// - `Anonymous` or `passkey_count == 0`: zero active roles
    /// - `passkey_count > 0`: ONLY canonical `PinnedBaseline`; `Elective` and `Timed` stay dormant
    pub fn for_login(role_catalog: &RoleCatalog, principal: &Principal) -> Self {
        match principal {
            Principal::Anonymous => Self::new(),
            Principal::Authenticated { passkey_count, .. } => {
                if *passkey_count == 0 {
                    Self::new()
                } else {
                    Self {
                        baseline_role: Some(role_catalog.pinned_baseline().id.clone()),
                        elective_roles: BTreeSet::new(),
                        timed_leases: BTreeMap::new(),
                    }
                }
            }
        }
    }

    /// Enables an `Elective` role bound to `principal`, enforcing Passkey gate & step-up if configured.
    pub fn enable_elective(
        &mut self,
        role_catalog: &RoleCatalog,
        principal: &Principal,
        role: &RoleId,
        step_up_verified: bool,
    ) -> Result<(), FolioError> {
        let Principal::Authenticated {
            passkey_count,
            bound_roles,
            ..
        } = principal
        else {
            return Err(FolioError::AuthorizationDenied);
        };

        if *passkey_count == 0 {
            return Err(FolioError::PasskeyEnrollmentRequired);
        }

        let spec = role_catalog
            .get(role)
            .ok_or_else(|| FolioError::UnknownRole(role.to_string()))?;

        match spec.activation {
            RoleActivation::PinnedBaseline => {
                self.baseline_role = Some(spec.id.clone());
                Ok(())
            }
            RoleActivation::Elective => {
                if !bound_roles.contains(role) {
                    return Err(FolioError::UnauthorizedActivation {
                        role: role.to_string(),
                    });
                }
                if spec.step_up == StepUpRequirement::Passkey && !step_up_verified {
                    return Err(FolioError::StepUpRequired {
                        role: role.to_string(),
                    });
                }
                self.elective_roles.insert(spec.id.clone());
                Ok(())
            }
            RoleActivation::Timed { .. } => Err(FolioError::StepUpRequired {
                role: role.to_string(),
            }),
        }
    }

    /// Activates an independent `Timed` role strictly from server [`RoleSpec`] TTL bounds.
    ///
    /// Existing active leases on other roles remain completely independent.
    pub fn activate_timed(
        &mut self,
        role_catalog: &RoleCatalog,
        principal: &Principal,
        role: &RoleId,
        now_ms: u64,
        step_up_verified: bool,
    ) -> Result<&RoleLease, FolioError> {
        let Principal::Authenticated {
            passkey_count,
            bound_roles,
            ..
        } = principal
        else {
            return Err(FolioError::AuthorizationDenied);
        };

        if *passkey_count == 0 {
            return Err(FolioError::PasskeyEnrollmentRequired);
        }
        if !bound_roles.contains(role) {
            return Err(FolioError::UnauthorizedActivation {
                role: role.to_string(),
            });
        }

        let spec = role_catalog
            .get(role)
            .ok_or_else(|| FolioError::UnknownRole(role.to_string()))?;

        if !matches!(spec.activation, RoleActivation::Timed { .. }) {
            return Err(FolioError::UnauthorizedActivation {
                role: role.to_string(),
            });
        }
        if spec.step_up == StepUpRequirement::Passkey && !step_up_verified {
            return Err(FolioError::StepUpRequired {
                role: role.to_string(),
            });
        }

        let lease = RoleLease::from_role_spec(spec, now_ms)?;
        self.baseline_role = Some(role_catalog.pinned_baseline().id.clone());
        self.timed_leases.insert(spec.id.clone(), lease);
        Ok(self
            .timed_leases
            .get(role)
            .expect("inserted lease must be present"))
    }

    /// Extends an active renewable `Timed` lease during its final `renew_window_secs`
    /// after fresh Passkey step-up verification.
    pub fn renew_timed(
        &mut self,
        role_catalog: &RoleCatalog,
        principal: &Principal,
        role: &RoleId,
        now_ms: u64,
        step_up_verified: bool,
    ) -> Result<&RoleLease, FolioError> {
        let Principal::Authenticated {
            passkey_count,
            bound_roles,
            ..
        } = principal
        else {
            return Err(FolioError::AuthorizationDenied);
        };

        if *passkey_count == 0 {
            return Err(FolioError::PasskeyEnrollmentRequired);
        }
        if !bound_roles.contains(role) {
            return Err(FolioError::UnauthorizedActivation {
                role: role.to_string(),
            });
        }

        let spec = role_catalog
            .get(role)
            .ok_or_else(|| FolioError::UnknownRole(role.to_string()))?;

        let RoleActivation::Timed {
            hard_ttl_secs,
            idle_ttl_secs,
            renew_window_secs,
            renew_extend_secs,
            max_renewals,
        } = spec.activation
        else {
            return Err(FolioError::UnauthorizedActivation {
                role: role.to_string(),
            });
        };

        if spec.step_up == StepUpRequirement::Passkey && !step_up_verified {
            return Err(FolioError::StepUpRequired {
                role: role.to_string(),
            });
        }

        let Some(existing) = self.timed_leases.get(role) else {
            return Err(FolioError::UnauthorizedActivation {
                role: role.to_string(),
            });
        };
        if !existing.is_active(now_ms) {
            self.timed_leases.remove(role);
            return Err(FolioError::UnauthorizedActivation {
                role: role.to_string(),
            });
        }
        if max_renewals == 0 || renew_window_secs == 0 || renew_extend_secs == 0 {
            return Err(FolioError::LeaseNotRenewable {
                role: role.to_string(),
            });
        }

        let lease = self
            .timed_leases
            .get_mut(role)
            .expect("verified active lease must be present");
        if lease.renewals_used >= max_renewals {
            return Err(FolioError::RenewalLimitReached {
                role: role.to_string(),
                max_renewals,
            });
        }

        let hard_remaining = lease.hard_remaining_secs(now_ms);
        if hard_remaining > renew_window_secs {
            return Err(FolioError::RenewalWindowNotReached {
                role: role.to_string(),
                seconds_remaining: hard_remaining,
                renew_window_secs,
            });
        }

        lease.renewals_used = lease.renewals_used.saturating_add(1);
        let allowed_cumulative_secs = hard_ttl_secs
            .saturating_add(u64::from(lease.renewals_used).saturating_mul(renew_extend_secs))
            .min(HOST_TIMED_ROLE_CEILING_SECS);
        let server_hard_cap = lease
            .activated_at_ms
            .saturating_add(allowed_cumulative_secs.saturating_mul(1000));
        lease.hard_expires_at_ms = lease
            .hard_expires_at_ms
            .saturating_add(renew_extend_secs.saturating_mul(1000))
            .min(server_hard_cap);
        lease.last_activity_at_ms = lease.last_activity_at_ms.max(now_ms);
        lease.idle_expires_at_ms = now_ms
            .saturating_add(idle_ttl_secs.saturating_mul(1000))
            .min(lease.hard_expires_at_ms);
        lease.hard_ttl_secs = hard_ttl_secs;
        lease.idle_ttl_secs = idle_ttl_secs;
        lease.renew_window_secs = renew_window_secs;
        lease.renew_extend_secs = renew_extend_secs;
        lease.max_renewals = max_renewals;

        Ok(self
            .timed_leases
            .get(role)
            .expect("renewed lease must be present"))
    }

    /// Explicitly toggles off an `Elective` or `Timed` role; forbids disabling `PinnedBaseline`.
    pub fn disable_role(
        &mut self,
        role_catalog: &RoleCatalog,
        role: &RoleId,
    ) -> Result<bool, FolioError> {
        if *role == role_catalog.pinned_baseline().id {
            return Err(FolioError::CannotDeactivatePinnedBaseline(role.to_string()));
        }
        let removed_elective = self.elective_roles.remove(role);
        let removed_timed = self.timed_leases.remove(role).is_some();
        Ok(removed_elective || removed_timed)
    }

    /// Records explicit user activity (`touch_activity`) across all currently active `Timed` leases.
    ///
    /// Already-expired leases stay deactivated and are pruned independently.
    pub fn record_activity(&mut self, now_ms: u64) -> Vec<RoleId> {
        let mut expired = Vec::new();
        for (id, lease) in &mut self.timed_leases {
            if !lease.touch_activity(now_ms) {
                expired.push(id.clone());
            }
        }
        for id in &expired {
            self.timed_leases.remove(id);
        }
        expired
    }

    /// Removes only `Timed` leases whose independent hard or idle deadline elapsed at `now_ms`.
    pub fn prune_expired(&mut self, now_ms: u64) -> Vec<RoleId> {
        let expired: Vec<RoleId> = self
            .timed_leases
            .iter()
            .filter_map(|(id, lease)| (!lease.is_active(now_ms)).then_some(id.clone()))
            .collect();
        for id in &expired {
            self.timed_leases.remove(id);
        }
        expired
    }
}

/// Complete authorization outcome evaluated for a principal at a concrete instant `now_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionEvaluation {
    /// `true` when principal is [`Principal::Anonymous`].
    pub is_anonymous: bool,
    /// Authenticated GitHub login if present.
    pub principal_login: Option<String>,
    /// `true` when authenticated principal has 0 enrolled Passkeys (holds baseline until enrollment).
    pub passkey_enrollment_required: bool,
    /// Effective active roles contributing folios at `now_ms`.
    pub active_roles: BTreeSet<RoleId>,
    /// Currently valid `Timed` leases surviving independent expiry checks.
    pub active_timed_leases: Vec<RoleLease>,
    /// `Timed` role leases found expired at `now_ms`.
    pub expired_timed_roles: Vec<RoleId>,
    /// Distinct folios granted by active roles (or anonymous index).
    pub active_folios: BTreeSet<FolioId>,
    /// Subsystems temporarily suppressed across policy evaluation.
    pub disabled_subsystems: BTreeSet<SubsystemId>,
    /// Additive union of effective positive policies (filtered by `disabled_subsystems`).
    pub policies: PolicySet,
}

impl SessionEvaluation {
    /// Returns `true` if `policy_str` is granted in the evaluated session.
    #[must_use]
    pub fn has_policy_str(&self, policy_str: &str) -> bool {
        self.policies.contains_str(policy_str)
    }

    /// Returns `true` if `folio_str` was active during evaluation.
    #[must_use]
    pub fn has_folio_str(&self, folio_str: &str) -> bool {
        self.active_folios.iter().any(|f| f.as_str() == folio_str)
    }

    /// Returns `true` if `role_str` is currently active.
    #[must_use]
    pub fn has_role_str(&self, role_str: &str) -> bool {
        self.active_roles.iter().any(|r| r.as_str() == role_str)
    }
}

/// Evaluates effective policies for `principal` and `leases` at `now_ms` (fail-closed).
pub fn evaluate_session(
    folio_catalog: &FolioCatalog,
    role_catalog: &RoleCatalog,
    role_folio_index: &RoleFolioIndex,
    principal: &Principal,
    leases: &RoleLeases,
    now_ms: u64,
) -> Result<SessionEvaluation, FolioError> {
    let no_disabled = BTreeSet::new();
    evaluate_session_with_disabled_subsystems(
        folio_catalog,
        role_catalog,
        role_folio_index,
        principal,
        leases,
        now_ms,
        &no_disabled,
    )
}

/// Evaluates effective policies at `now_ms` while stripping grants from `disabled_subsystems`.
pub fn evaluate_session_with_disabled_subsystems(
    folio_catalog: &FolioCatalog,
    role_catalog: &RoleCatalog,
    role_folio_index: &RoleFolioIndex,
    principal: &Principal,
    leases: &RoleLeases,
    now_ms: u64,
    disabled_subsystems: &BTreeSet<SubsystemId>,
) -> Result<SessionEvaluation, FolioError> {
    folio_catalog.validate_graph()?;
    role_catalog.validate()?;
    role_folio_index.validate(folio_catalog, Some(role_catalog))?;

    match principal {
        Principal::Anonymous => {
            let active_folios = role_folio_index.anonymous_folios().clone();
            let mut policies = folio_catalog.resolve_folios(active_folios.iter())?;
            policies.exclude_subsystems(disabled_subsystems);
            Ok(SessionEvaluation {
                is_anonymous: true,
                principal_login: None,
                passkey_enrollment_required: false,
                active_roles: BTreeSet::new(),
                active_timed_leases: Vec::new(),
                expired_timed_roles: Vec::new(),
                active_folios,
                disabled_subsystems: disabled_subsystems.clone(),
                policies,
            })
        }
        Principal::Authenticated {
            login,
            passkey_count,
            bound_roles,
        } => {
            if *passkey_count == 0 {
                return Ok(SessionEvaluation {
                    is_anonymous: false,
                    principal_login: Some(login.clone()),
                    passkey_enrollment_required: true,
                    active_roles: BTreeSet::new(),
                    active_timed_leases: Vec::new(),
                    expired_timed_roles: Vec::new(),
                    active_folios: BTreeSet::new(),
                    disabled_subsystems: disabled_subsystems.clone(),
                    policies: PolicySet::new(),
                });
            }

            let mut active_roles = BTreeSet::new();
            let baseline = role_catalog.pinned_baseline();
            active_roles.insert(baseline.id.clone());

            for role_id in &leases.elective_roles {
                if !bound_roles.contains(role_id) {
                    continue;
                }
                if let Some(spec) = role_catalog.get(role_id) {
                    if matches!(spec.activation, RoleActivation::Elective) {
                        active_roles.insert(role_id.clone());
                    }
                }
            }

            let mut active_timed_leases = Vec::new();
            let mut expired_timed_roles = Vec::new();

            for (role_id, lease) in &leases.timed_leases {
                if lease.role != *role_id || !bound_roles.contains(role_id) {
                    expired_timed_roles.push(role_id.clone());
                    continue;
                }
                let Some(spec) = role_catalog.get(role_id) else {
                    expired_timed_roles.push(role_id.clone());
                    continue;
                };
                let RoleActivation::Timed {
                    hard_ttl_secs,
                    idle_ttl_secs,
                    renew_window_secs,
                    renew_extend_secs,
                    max_renewals,
                } = spec.activation
                else {
                    expired_timed_roles.push(role_id.clone());
                    continue;
                };

                // Clamp deserialized lease deadlines strictly to current server RoleSpec ceilings.
                let clamped_renewals = lease.renewals_used.min(max_renewals);
                let allowed_hard_secs = hard_ttl_secs
                    .saturating_add(u64::from(clamped_renewals).saturating_mul(renew_extend_secs))
                    .min(HOST_TIMED_ROLE_CEILING_SECS);
                let server_hard_cap = lease
                    .activated_at_ms
                    .saturating_add(allowed_hard_secs.saturating_mul(1000));
                let clamped_hard_expires = lease.hard_expires_at_ms.min(server_hard_cap);
                let clamped_activity = lease
                    .last_activity_at_ms
                    .max(lease.activated_at_ms)
                    .min(now_ms);
                let server_idle_cap = clamped_activity
                    .saturating_add(idle_ttl_secs.saturating_mul(1000))
                    .min(clamped_hard_expires)
                    .min(lease.idle_expires_at_ms);

                let clamped = RoleLease {
                    role: lease.role.clone(),
                    activated_at_ms: lease.activated_at_ms,
                    last_activity_at_ms: clamped_activity,
                    hard_expires_at_ms: clamped_hard_expires,
                    idle_expires_at_ms: server_idle_cap,
                    hard_ttl_secs,
                    idle_ttl_secs,
                    renew_window_secs,
                    renew_extend_secs,
                    max_renewals,
                    renewals_used: clamped_renewals,
                };

                if clamped.is_active(now_ms) {
                    active_roles.insert(role_id.clone());
                    active_timed_leases.push(clamped);
                } else {
                    expired_timed_roles.push(role_id.clone());
                }
            }

            let mut active_folios = BTreeSet::new();
            for role_id in &active_roles {
                if let Some(folios) = role_folio_index.folios_for_role(role_id) {
                    for f in folios {
                        active_folios.insert(f.clone());
                    }
                }
            }

            let mut policies = folio_catalog.resolve_folios(active_folios.iter())?;
            policies.exclude_subsystems(disabled_subsystems);

            Ok(SessionEvaluation {
                is_anonymous: false,
                principal_login: Some(login.clone()),
                passkey_enrollment_required: false,
                active_roles,
                active_timed_leases,
                expired_timed_roles,
                active_folios,
                disabled_subsystems: disabled_subsystems.clone(),
                policies,
            })
        }
    }
}

/// Bundled authorization snapshot holding folio, role, index, and subsystem toggle state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthAuthority {
    /// Subsystem & operator folio registry.
    pub folio_catalog: FolioCatalog,
    /// Validated role catalog with single canonical `PinnedBaseline`.
    pub role_catalog: RoleCatalog,
    /// Role-to-folio indirection table (`anonymous -> []` by default).
    pub role_folio_index: RoleFolioIndex,
    /// Temporarily disabled subsystems stripped during evaluation.
    pub disabled_subsystems: BTreeSet<SubsystemId>,
}

impl AuthAuthority {
    /// Creates an [`AuthAuthority`] after validating all cross-layer references fail-closed.
    pub fn new(
        folio_catalog: FolioCatalog,
        role_catalog: RoleCatalog,
        role_folio_index: RoleFolioIndex,
    ) -> Result<Self, FolioError> {
        folio_catalog.validate_graph()?;
        role_catalog.validate()?;
        role_folio_index.validate(&folio_catalog, Some(&role_catalog))?;
        Ok(Self {
            folio_catalog,
            role_catalog,
            role_folio_index,
            disabled_subsystems: BTreeSet::new(),
        })
    }

    /// Suppresses all grants belonging to `subsystem` across subsequent session evaluations.
    pub fn disable_subsystem(&mut self, subsystem: SubsystemId) {
        self.disabled_subsystems.insert(subsystem);
    }

    /// Re-enables grants belonging to `subsystem`.
    pub fn enable_subsystem(&mut self, subsystem: SubsystemId) -> bool {
        self.disabled_subsystems.remove(&subsystem)
    }

    /// Evaluates `principal` and `leases` at `now_ms`.
    pub fn evaluate_session(
        &self,
        principal: &Principal,
        leases: &RoleLeases,
        now_ms: u64,
    ) -> Result<SessionEvaluation, FolioError> {
        evaluate_session_with_disabled_subsystems(
            &self.folio_catalog,
            &self.role_catalog,
            &self.role_folio_index,
            principal,
            leases,
            now_ms,
            &self.disabled_subsystems,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::subsystem::FolioId;
    use alloc::vec;

    fn rid(raw: &str) -> RoleId {
        RoleId::new(raw).expect("valid role id")
    }

    fn fid(raw: &str) -> FolioId {
        FolioId::new(raw).expect("valid folio id")
    }

    fn setup_authority() -> AuthAuthority {
        let folio_catalog = FolioCatalog::with_canonical_manifests();
        let role_catalog = RoleCatalog::from_roles([
            RoleSpec::pinned_baseline(rid("member"), Some("Member"), "baseline").unwrap(),
            RoleSpec::elective(
                rid("ci-ops"),
                Some("CI Operator"),
                "elective",
                StepUpRequirement::None,
            )
            .unwrap(),
            RoleSpec::timed(rid("ab-emerg"), Some("AB Emergency"), "timed", 600, 120).unwrap(),
            RoleSpec::timed(
                rid("plat-admin"),
                Some("Platform Admin"),
                "timed",
                1800,
                300,
            )
            .unwrap(),
        ])
        .unwrap();

        let mut index = RoleFolioIndex::new();
        index
            .set_role_folios(
                rid("member"),
                BTreeSet::from([fid("folio:system:dashboard")]),
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
                rid("ab-emerg"),
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
    fn anonymous_lockdown_zero_passkey_gate_and_independent_leases() {
        let mut auth = setup_authority();
        let empty = RoleLeases::new();

        // Anonymous default lockdown (`anonymous -> []`)
        let anon_eval = auth
            .evaluate_session(&Principal::Anonymous, &empty, 1_000)
            .unwrap();
        assert!(anon_eval.policies.is_empty());

        // 0-Passkey authenticated user is held at mandatory enrollment gate
        let no_passkey = Principal::Authenticated {
            login: "operator".into(),
            passkey_count: 0,
            bound_roles: BTreeSet::from([rid("ci-ops"), rid("ab-emerg"), rid("plat-admin")]),
        };
        let gate_eval = auth.evaluate_session(&no_passkey, &empty, 1_000).unwrap();
        assert!(gate_eval.passkey_enrollment_required);
        assert!(gate_eval.policies.is_empty());

        // Enrolled user starts with ONLY PinnedBaseline
        let enrolled = Principal::Authenticated {
            login: "operator".into(),
            passkey_count: 1,
            bound_roles: BTreeSet::from([rid("ci-ops"), rid("ab-emerg"), rid("plat-admin")]),
        };
        let mut leases = RoleLeases::for_login(&auth.role_catalog, &enrolled);
        let login_eval = auth.evaluate_session(&enrolled, &leases, 1_000).unwrap();
        assert!(!login_eval.passkey_enrollment_required);
        assert!(login_eval.has_role_str("member"));
        assert!(!login_eval.has_role_str("ci-ops"));
        assert!(login_eval.has_policy_str("system:dashboard.read"));
        assert!(!login_eval.has_policy_str("ci:jobs.restart"));

        // Enable Elective and two independent Timed roles
        leases
            .enable_elective(&auth.role_catalog, &enrolled, &rid("ci-ops"), false)
            .unwrap();
        leases
            .activate_timed(&auth.role_catalog, &enrolled, &rid("ab-emerg"), 1_000, true)
            .unwrap();
        leases
            .activate_timed(
                &auth.role_catalog,
                &enrolled,
                &rid("plat-admin"),
                1_000,
                true,
            )
            .unwrap();

        // Advance to 121s: ab-emerg idle (120s) expires, plat-admin (300s), ci-ops, member survive!
        let at_121s = auth.evaluate_session(&enrolled, &leases, 121_000).unwrap();
        assert!(!at_121s.has_role_str("ab-emerg"));
        assert!(!at_121s.has_policy_str("ab:rollback"));
        assert!(at_121s.has_role_str("plat-admin"));
        assert!(at_121s.has_policy_str("platform:roles.write"));
        assert!(at_121s.has_role_str("ci-ops"));
        assert!(at_121s.has_policy_str("ci:jobs.restart"));

        // Explicit activity cannot resurrect already-expired ab-emerg, and never moves plat-admin hard deadline
        let expired = leases.record_activity(121_000);
        assert_eq!(expired, vec![rid("ab-emerg")]);
        assert_eq!(
            leases.timed_leases[&rid("plat-admin")].hard_expires_at_ms,
            1_000 + 1_800 * 1_000
        );

        // Disabling CI area strips ci:* policies while keeping platform & system intact
        auth.disable_subsystem(SubsystemId::Ci);
        let disabled_eval = auth.evaluate_session(&enrolled, &leases, 121_000).unwrap();
        assert!(!disabled_eval.has_policy_str("ci:jobs.restart"));
        assert!(!disabled_eval.has_policy_str("ci:queue.read"));
        assert!(disabled_eval.has_policy_str("platform:roles.write"));
        assert!(disabled_eval.has_policy_str("system:status.read"));
    }
}
