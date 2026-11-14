//! Role specifications, single canonical `PinnedBaseline` catalog invariant, and `RoleFolioIndex`.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use core::fmt;
use core::ops::Deref;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::FolioError;
use crate::folio::FolioCatalog;
use crate::subsystem::{is_valid_slug, FolioId};

/// Hard host ceiling for any short-lived `Timed` elevated role (30 minutes).
pub const HOST_TIMED_ROLE_CEILING_SECS: u64 = 1800;

/// Minimum allowed hard or idle TTL for `Timed` elevated roles (1 minute).
pub const MIN_TIMED_ROLE_TTL_SECS: u64 = 60;

/// Reserved pseudo-role identifier used in index documentation; rejected in `RoleCatalog`.
pub const ANONYMOUS_ROLE_ID: &str = "anonymous";

/// Validates human-facing display names, rejecting blanks, `'+'`, and control characters.
pub fn validate_display_name(raw: &str) -> Result<String, FolioError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(FolioError::InvalidDisplayName {
            reason: "display name cannot be empty",
            value: raw.to_string(),
        });
    }
    if raw.contains('+') {
        return Err(FolioError::InvalidDisplayName {
            reason: "display name must not contain '+'",
            value: raw.to_string(),
        });
    }
    if raw.chars().any(char::is_control) {
        return Err(FolioError::InvalidDisplayName {
            reason: "display name must not contain control characters",
            value: raw.to_string(),
        });
    }
    Ok(trimmed.to_string())
}

/// Immutable lowercase ASCII role identifier (`[a-z0-9_-]`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct RoleId(String);

impl RoleId {
    /// Validates and constructs a [`RoleId`].
    pub fn new(raw: impl Into<String>) -> Result<Self, FolioError> {
        let raw = raw.into();
        if !is_valid_slug(&raw) || raw.len() > 64 {
            return Err(FolioError::InvalidIdentifier {
                kind: "role",
                value: raw,
            });
        }
        Ok(Self(raw))
    }

    /// Returns `true` if this identifier is the reserved `"anonymous"` pseudo-role.
    #[must_use]
    pub fn is_anonymous(&self) -> bool {
        self.0 == ANONYMOUS_ROLE_ID
    }

    /// Underlying role string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for RoleId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for RoleId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RoleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for RoleId {
    type Err = FolioError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl<'de> Deserialize<'de> for RoleId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Step-up verification required before activating a role during an existing login session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepUpRequirement {
    /// No additional WebAuthn assertion is needed to toggle this role.
    None,
    /// Fresh single-use Passkey WebAuthn assertion is required before enabling this role.
    Passkey,
}

/// Activation lifecycle governing when and how long a role may be enabled in a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RoleActivation {
    /// Exactly one canonical catalog role active at baseline login (after mandatory Passkey gate).
    PinnedBaseline,
    /// Dormant at login until explicitly toggled on/off by a bound user.
    Elective,
    /// Dormant at login; requires Passkey step-up and expires independently via hard + idle TTLs.
    Timed {
        /// Non-renewable hard lease ceiling in seconds (`<= HOST_TIMED_ROLE_CEILING_SECS`).
        hard_ttl_secs: u64,
        /// Explicit-activity idle deadline in seconds (`60 <= idle_ttl_secs <= hard_ttl_secs`).
        idle_ttl_secs: u64,
    },
}

/// Validated role definition registered in [`RoleCatalog`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleSpec {
    /// Immutable lowercase ASCII role ID (`"anonymous"` rejected).
    pub id: RoleId,
    /// Optional human-readable label (`+`-free and control-char-free).
    pub display_name: Option<String>,
    /// Concise role summary.
    pub description: String,
    /// Activation lifecycle (`PinnedBaseline`, `Elective`, or `Timed`).
    pub activation: RoleActivation,
    /// Required verification gate (`Passkey` mandatory for `Timed` roles).
    pub step_up: StepUpRequirement,
}

impl RoleSpec {
    /// Constructs and validates a [`RoleSpec`].
    pub fn new(
        id: RoleId,
        display_name: Option<&str>,
        description: impl Into<String>,
        activation: RoleActivation,
        step_up: StepUpRequirement,
    ) -> Result<Self, FolioError> {
        let display_name = match display_name {
            Some(name) => Some(validate_display_name(name)?),
            None => None,
        };
        let spec = Self {
            id,
            display_name,
            description: description.into(),
            activation,
            step_up,
        };
        spec.validate()?;
        Ok(spec)
    }

    /// Constructs a canonical `PinnedBaseline` role (`StepUpRequirement::None`).
    pub fn pinned_baseline(
        id: RoleId,
        display_name: Option<&str>,
        description: impl Into<String>,
    ) -> Result<Self, FolioError> {
        Self::new(
            id,
            display_name,
            description,
            RoleActivation::PinnedBaseline,
            StepUpRequirement::None,
        )
    }

    /// Constructs an `Elective` role dormant until user toggle.
    pub fn elective(
        id: RoleId,
        display_name: Option<&str>,
        description: impl Into<String>,
        step_up: StepUpRequirement,
    ) -> Result<Self, FolioError> {
        Self::new(
            id,
            display_name,
            description,
            RoleActivation::Elective,
            step_up,
        )
    }

    /// Constructs a short-lived `Timed` role requiring `StepUpRequirement::Passkey`.
    pub fn timed(
        id: RoleId,
        display_name: Option<&str>,
        description: impl Into<String>,
        hard_ttl_secs: u64,
        idle_ttl_secs: u64,
    ) -> Result<Self, FolioError> {
        Self::new(
            id,
            display_name,
            description,
            RoleActivation::Timed {
                hard_ttl_secs,
                idle_ttl_secs,
            },
            StepUpRequirement::Passkey,
        )
    }

    /// Validates all naming, reserved-ID, and TTL ceiling invariants.
    pub fn validate(&self) -> Result<(), FolioError> {
        if self.id.is_anonymous() {
            return Err(FolioError::ReservedRoleId(self.id.to_string()));
        }
        if let Some(name) = &self.display_name {
            let _ = validate_display_name(name)?;
        }
        if let RoleActivation::Timed {
            hard_ttl_secs,
            idle_ttl_secs,
        } = self.activation
        {
            if hard_ttl_secs > HOST_TIMED_ROLE_CEILING_SECS {
                return Err(FolioError::TtlExceedsCeiling {
                    requested_secs: hard_ttl_secs,
                    ceiling_secs: HOST_TIMED_ROLE_CEILING_SECS,
                });
            }
            if idle_ttl_secs > HOST_TIMED_ROLE_CEILING_SECS {
                return Err(FolioError::TtlExceedsCeiling {
                    requested_secs: idle_ttl_secs,
                    ceiling_secs: HOST_TIMED_ROLE_CEILING_SECS,
                });
            }
            if idle_ttl_secs < MIN_TIMED_ROLE_TTL_SECS
                || hard_ttl_secs < MIN_TIMED_ROLE_TTL_SECS
                || idle_ttl_secs > hard_ttl_secs
            {
                return Err(FolioError::InvalidTimedTtlBounds {
                    idle_ttl_secs,
                    hard_ttl_secs,
                    min_ttl_secs: MIN_TIMED_ROLE_TTL_SECS,
                });
            }
            if self.step_up != StepUpRequirement::Passkey {
                return Err(FolioError::TimedRoleRequiresPasskey(self.id.to_string()));
            }
        }
        Ok(())
    }

    /// Returns the display name when set, otherwise falls back to the immutable role ID.
    #[must_use]
    pub fn effective_display_name(&self) -> &str {
        self.display_name.as_deref().unwrap_or(self.id.as_str())
    }
}

/// Catalog of validated [`RoleSpec`] definitions enforcing the single canonical `PinnedBaseline` invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleCatalog {
    roles: BTreeMap<RoleId, RoleSpec>,
    baseline_id: RoleId,
}

impl RoleCatalog {
    /// Builds and validates a [`RoleCatalog`] from an iterator of [`RoleSpec`] values.
    ///
    /// Rejects catalogs with 0 or >1 `PinnedBaseline` roles, duplicate IDs, reserved `"anonymous"`,
    /// or `Timed` TTL ceiling violations.
    pub fn from_roles(roles: impl IntoIterator<Item = RoleSpec>) -> Result<Self, FolioError> {
        let mut map = BTreeMap::new();
        let mut baseline_id: Option<RoleId> = None;

        for mut spec in roles {
            spec.validate()?;
            if let Some(name) = &spec.display_name {
                spec.display_name = Some(validate_display_name(name)?);
            }
            if map.contains_key(&spec.id) {
                return Err(FolioError::DuplicateRole(spec.id.to_string()));
            }
            if matches!(spec.activation, RoleActivation::PinnedBaseline) {
                if let Some(existing) = &baseline_id {
                    return Err(FolioError::MultiplePinnedBaselines {
                        existing: existing.to_string(),
                        duplicate: spec.id.to_string(),
                    });
                }
                baseline_id = Some(spec.id.clone());
            }
            map.insert(spec.id.clone(), spec);
        }

        let Some(baseline_id) = baseline_id else {
            return Err(FolioError::MissingPinnedBaseline);
        };

        Ok(Self {
            roles: map,
            baseline_id,
        })
    }

    /// Re-validates all invariants (for example after untrusted deserialization).
    pub fn validate(&self) -> Result<(), FolioError> {
        let mut seen_baseline: Option<&RoleId> = None;
        for (key, spec) in &self.roles {
            if key != &spec.id {
                return Err(FolioError::InvalidIdentifier {
                    kind: "role",
                    value: key.to_string(),
                });
            }
            spec.validate()?;
            if matches!(spec.activation, RoleActivation::PinnedBaseline) {
                if let Some(existing) = seen_baseline {
                    return Err(FolioError::MultiplePinnedBaselines {
                        existing: existing.to_string(),
                        duplicate: spec.id.to_string(),
                    });
                }
                seen_baseline = Some(&spec.id);
            }
        }
        let Some(actual_baseline) = seen_baseline else {
            return Err(FolioError::MissingPinnedBaseline);
        };
        if actual_baseline != &self.baseline_id {
            return Err(FolioError::MultiplePinnedBaselines {
                existing: self.baseline_id.to_string(),
                duplicate: actual_baseline.to_string(),
            });
        }
        Ok(())
    }

    /// Inserts or updates a role while preserving the single canonical `PinnedBaseline` invariant.
    pub fn upsert_role(&mut self, spec: RoleSpec) -> Result<(), FolioError> {
        spec.validate()?;
        let is_new_baseline = matches!(spec.activation, RoleActivation::PinnedBaseline);
        if is_new_baseline && spec.id != self.baseline_id {
            return Err(FolioError::MultiplePinnedBaselines {
                existing: self.baseline_id.to_string(),
                duplicate: spec.id.to_string(),
            });
        }
        if !is_new_baseline && spec.id == self.baseline_id {
            return Err(FolioError::MissingPinnedBaseline);
        }
        self.roles.insert(spec.id.clone(), spec);
        Ok(())
    }

    /// Removes a non-baseline role from the catalog.
    pub fn remove_role(&mut self, id: &RoleId) -> Result<RoleSpec, FolioError> {
        if *id == self.baseline_id {
            return Err(FolioError::MissingPinnedBaseline);
        }
        self.roles
            .remove(id)
            .ok_or_else(|| FolioError::UnknownRole(id.to_string()))
    }

    /// Returns the single canonical `PinnedBaseline` role specification.
    #[must_use]
    pub fn pinned_baseline(&self) -> &RoleSpec {
        self.roles
            .get(&self.baseline_id)
            .expect("RoleCatalog always maintains a valid PinnedBaseline entry")
    }

    /// Looks up a role specification by ID.
    #[must_use]
    pub fn get(&self, id: &RoleId) -> Option<&RoleSpec> {
        self.roles.get(id)
    }

    /// Iterates all roles in deterministic ID order.
    pub fn iter(&self) -> impl Iterator<Item = &RoleSpec> {
        self.roles.values()
    }
}

/// Separate Role-to-Folio assignment table enforcing mandatory folio indirection.
///
/// `anonymous` defaults to `[]` (login-only lockdown until explicitly configured by the operator).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RoleFolioIndex {
    anonymous: BTreeSet<FolioId>,
    role_folios: BTreeMap<RoleId, BTreeSet<FolioId>>,
}

impl RoleFolioIndex {
    /// Creates an empty [`RoleFolioIndex`] where `anonymous -> []` (login-only lockdown).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the folios assigned to unauthenticated (`Anonymous`) visitors.
    #[must_use]
    pub fn anonymous_folios(&self) -> &BTreeSet<FolioId> {
        &self.anonymous
    }

    /// Sets the folios granted to unauthenticated visitors after validating against `folio_catalog`.
    pub fn set_anonymous_folios(
        &mut self,
        folios: BTreeSet<FolioId>,
        folio_catalog: &FolioCatalog,
    ) -> Result<(), FolioError> {
        for folio_id in &folios {
            if folio_catalog.folio(folio_id).is_none() {
                return Err(FolioError::UnknownFolio(folio_id.to_string()));
            }
        }
        self.anonymous = folios;
        Ok(())
    }

    /// Assigns folios to a registered role after fail-closed catalog verification.
    pub fn set_role_folios(
        &mut self,
        role: RoleId,
        folios: BTreeSet<FolioId>,
        folio_catalog: &FolioCatalog,
        role_catalog: &RoleCatalog,
    ) -> Result<(), FolioError> {
        if role.is_anonymous() {
            return Err(FolioError::ReservedRoleId(role.to_string()));
        }
        if role_catalog.get(&role).is_none() {
            return Err(FolioError::UnknownRole(role.to_string()));
        }
        for folio_id in &folios {
            if folio_catalog.folio(folio_id).is_none() {
                return Err(FolioError::UnknownFolio(folio_id.to_string()));
            }
        }
        if folios.is_empty() {
            self.role_folios.remove(&role);
        } else {
            self.role_folios.insert(role, folios);
        }
        Ok(())
    }

    /// Removes all folio assignments for a role.
    pub fn clear_role(&mut self, role: &RoleId) -> Option<BTreeSet<FolioId>> {
        self.role_folios.remove(role)
    }

    /// Returns the direct folios mapped to `role`, or an empty slice-like set when unmapped.
    #[must_use]
    pub fn folios_for_role(&self, role: &RoleId) -> Option<&BTreeSet<FolioId>> {
        self.role_folios.get(role)
    }

    /// Validates all anonymous and role-to-folio bindings fail-closed against the catalogs.
    pub fn validate(
        &self,
        folio_catalog: &FolioCatalog,
        role_catalog: Option<&RoleCatalog>,
    ) -> Result<(), FolioError> {
        for folio_id in &self.anonymous {
            if folio_catalog.folio(folio_id).is_none() {
                return Err(FolioError::UnknownFolio(folio_id.to_string()));
            }
        }
        for (role_id, folios) in &self.role_folios {
            if role_id.is_anonymous() {
                return Err(FolioError::ReservedRoleId(role_id.to_string()));
            }
            if let Some(rc) = role_catalog {
                if rc.get(role_id).is_none() {
                    return Err(FolioError::UnknownRole(role_id.to_string()));
                }
            }
            for folio_id in folios {
                if folio_catalog.folio(folio_id).is_none() {
                    return Err(FolioError::UnknownFolio(folio_id.to_string()));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rid(raw: &str) -> RoleId {
        RoleId::new(raw).expect("valid role id")
    }

    #[test]
    fn enforces_single_pinned_baseline_and_rejects_anonymous_role() {
        let viewer = RoleSpec::pinned_baseline(rid("viewer"), Some("Viewer"), "baseline").unwrap();
        let oncall = RoleSpec::timed(rid("oncall"), Some("Oncall"), "timed", 900, 300).unwrap();

        assert!(matches!(
            RoleCatalog::from_roles([oncall.clone()]),
            Err(FolioError::MissingPinnedBaseline)
        ));

        let extra_baseline =
            RoleSpec::pinned_baseline(rid("viewer2"), Some("Viewer 2"), "dup").unwrap();
        assert!(matches!(
            RoleCatalog::from_roles([viewer.clone(), extra_baseline]),
            Err(FolioError::MultiplePinnedBaselines { .. })
        ));

        assert!(matches!(
            RoleSpec::pinned_baseline(rid("anonymous"), Some("Anon"), "bad"),
            Err(FolioError::ReservedRoleId(_))
        ));
        let raw_anon = RoleSpec {
            id: rid("anonymous"),
            display_name: Some("Anon".into()),
            description: "bad".into(),
            activation: RoleActivation::PinnedBaseline,
            step_up: StepUpRequirement::None,
        };
        assert!(matches!(
            RoleCatalog::from_roles([raw_anon]),
            Err(FolioError::ReservedRoleId(_))
        ));

        let catalog = RoleCatalog::from_roles([viewer, oncall]).expect("valid catalog");
        assert_eq!(catalog.pinned_baseline().id.as_str(), "viewer");
    }

    #[test]
    fn rejects_plus_control_chars_and_timed_ttl_violations() {
        assert!(matches!(
            RoleSpec::elective(
                rid("ops"),
                Some("Ops+Admin"),
                "contains plus",
                StepUpRequirement::None
            ),
            Err(FolioError::InvalidDisplayName { .. })
        ));
        assert!(matches!(
            RoleSpec::elective(
                rid("ops"),
                Some("Ops\nAdmin"),
                "contains control",
                StepUpRequirement::None
            ),
            Err(FolioError::InvalidDisplayName { .. })
        ));
        assert!(matches!(
            RoleSpec::timed(rid("ops"), Some("Ops"), "over ceiling", 1801, 300),
            Err(FolioError::TtlExceedsCeiling {
                requested_secs: 1801,
                ceiling_secs: 1800
            })
        ));
        assert!(matches!(
            RoleSpec::timed(rid("ops"), Some("Ops"), "too short", 60, 59),
            Err(FolioError::InvalidTimedTtlBounds { .. })
        ));
        assert!(matches!(
            RoleSpec::timed(rid("ops"), Some("Ops"), "idle exceeds hard", 300, 600),
            Err(FolioError::InvalidTimedTtlBounds { .. })
        ));
        assert!(matches!(
            RoleSpec::new(
                rid("ops"),
                None,
                "timed without passkey",
                RoleActivation::Timed {
                    hard_ttl_secs: 300,
                    idle_ttl_secs: 120
                },
                StepUpRequirement::None
            ),
            Err(FolioError::TimedRoleRequiresPasskey(_))
        ));
    }
}
