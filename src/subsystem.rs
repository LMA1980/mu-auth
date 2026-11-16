//! Subsystem identifiers, operational status models, atomic policies, and canonical subsystem manifests.

use alloc::collections::BTreeSet;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt;
use core::ops::Deref;
use core::str::FromStr;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::FolioError;
use crate::role::validate_display_name;

/// Canonical platform subsystems represented in `mu-auth`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubsystemId {
    /// Cross-cutting system shell, public status, and overview dashboards.
    System,
    /// Continuous Integration (`mu-ci`).
    Ci,
    /// Ecosystem-agnostic Continuous Delivery history (`mu-cd`).
    Cd,
    /// Host A|B deployment slots and emergency rollback (`mu-cd` A|B lane).
    #[serde(alias = "ab-deploy", alias = "ab_deploy")]
    AbDeploy,
    /// Package registry and content-addressed artifact storage (`mu-registry`).
    Repository,
    /// Telemetry, traces, metrics, and ingress rules (`mu-observable`).
    Observability,
    /// Distributed LLM inference runtime status and connection endpoints.
    #[serde(alias = "model-runner", alias = "model_runner")]
    ModelRunner,
    /// Platform identity, invites, roles, folios, maintenance, and audit activity (`platform`).
    Platform,
}

impl SubsystemId {
    /// All 8 subsystems including `System`.
    pub const ALL: [Self; 8] = [
        Self::System,
        Self::Ci,
        Self::Cd,
        Self::AbDeploy,
        Self::Repository,
        Self::Observability,
        Self::ModelRunner,
        Self::Platform,
    ];

    /// The 7 operational platform subsystems tracked for health & maintenance status.
    pub const OPERATIONAL: [Self; 7] = [
        Self::Ci,
        Self::Cd,
        Self::AbDeploy,
        Self::Repository,
        Self::Observability,
        Self::ModelRunner,
        Self::Platform,
    ];

    /// Canonical `snake_case` subsystem identifier string.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Ci => "ci",
            Self::Cd => "cd",
            Self::AbDeploy => "ab_deploy",
            Self::Repository => "repository",
            Self::Observability => "observability",
            Self::ModelRunner => "model_runner",
            Self::Platform => "platform",
        }
    }

    /// Canonical policy namespace prefix (`<prefix>:<resource>.<action>`).
    #[must_use]
    pub const fn policy_prefix(&self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Ci => "ci",
            Self::Cd => "cd",
            Self::AbDeploy => "ab",
            Self::Repository => "reg",
            Self::Observability => "obs",
            Self::ModelRunner => "mr",
            Self::Platform => "platform",
        }
    }

    /// Resolves a subsystem from its canonical policy prefix.
    #[must_use]
    pub fn from_policy_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "system" => Some(Self::System),
            "ci" => Some(Self::Ci),
            "cd" => Some(Self::Cd),
            "ab" => Some(Self::AbDeploy),
            "reg" => Some(Self::Repository),
            "obs" => Some(Self::Observability),
            "mr" => Some(Self::ModelRunner),
            "platform" => Some(Self::Platform),
            _ => None,
        }
    }
}

impl fmt::Display for SubsystemId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SubsystemId {
    type Err = FolioError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "system" => Ok(Self::System),
            "ci" => Ok(Self::Ci),
            "cd" => Ok(Self::Cd),
            "ab_deploy" | "ab-deploy" | "ab" => Ok(Self::AbDeploy),
            "repository" | "reg" => Ok(Self::Repository),
            "observability" | "obs" => Ok(Self::Observability),
            "model_runner" | "model-runner" | "mr" => Ok(Self::ModelRunner),
            "platform" => Ok(Self::Platform),
            _ => Err(FolioError::InvalidIdentifier {
                kind: "subsystem",
                value: s.to_string(),
            }),
        }
    }
}

/// Generic 5-state operational health classification exposed to console status views.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum SubsystemStatus {
    /// Subsystem probes report normal healthy operation.
    #[default]
    Live,
    /// Scheduled maintenance window is active; operators expect downtime.
    #[serde(alias = "in_maintenance")]
    InMaintenance,
    /// Partial maintenance affects part of the subsystem while core capacity remains up.
    #[serde(alias = "partial_maintenance")]
    PartialMaintenance,
    /// Subsystem is unreachable or shut down outside a planned maintenance override.
    Offline,
    /// Subsystem is operational with elevated errors or reduced capacity.
    Degraded,
}

impl SubsystemStatus {
    /// Canonical `kebab-case` wire representation.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::InMaintenance => "in-maintenance",
            Self::PartialMaintenance => "partial-maintenance",
            Self::Offline => "offline",
            Self::Degraded => "degraded",
        }
    }

    /// Returns `true` when the status represents a planned maintenance state.
    #[must_use]
    pub const fn is_maintenance(&self) -> bool {
        matches!(self, Self::InMaintenance | Self::PartialMaintenance)
    }

    /// Returns `true` when SLO alerting should suppress outage problem cards.
    #[must_use]
    pub const fn suppresses_slo_alerts(&self) -> bool {
        matches!(
            self,
            Self::InMaintenance | Self::PartialMaintenance | Self::Offline
        )
    }
}

impl fmt::Display for SubsystemStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SubsystemStatus {
    type Err = FolioError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "live" => Ok(Self::Live),
            "in-maintenance" | "in_maintenance" => Ok(Self::InMaintenance),
            "partial-maintenance" | "partial_maintenance" => Ok(Self::PartialMaintenance),
            "offline" => Ok(Self::Offline),
            "degraded" => Ok(Self::Degraded),
            _ => Err(FolioError::InvalidIdentifier {
                kind: "subsystem_status",
                value: s.to_string(),
            }),
        }
    }
}

/// Operator maintenance control mode (`Auto` probe-driven or explicit manual override).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MaintenanceMode {
    /// Status tracks live health probes automatically.
    #[default]
    Auto,
    /// Explicit operator override pins the subsystem to a chosen status.
    Manual(SubsystemStatus),
}

/// Manual maintenance override for an operational subsystem with optional auto-clear deadline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceOverride {
    /// Target subsystem identifier.
    pub subsystem: SubsystemId,
    /// Pinned operational state while override is active.
    pub status: SubsystemStatus,
    /// Generic operator-provided status note (kept free of internal hostnames/IPs).
    pub reason: Option<String>,
    /// GitHub login of the operator who updated the override.
    pub updated_by: Option<String>,
    /// Timestamp (`epoch_ms`) when override was set.
    pub updated_at_ms: u64,
    /// Optional automatic expiry timestamp (`epoch_ms`), after which probes resume.
    pub auto_clear_at_ms: Option<u64>,
}

impl MaintenanceOverride {
    /// Creates a manual maintenance override with optional auto-clear duration in seconds.
    #[must_use]
    pub fn new(
        subsystem: SubsystemId,
        status: SubsystemStatus,
        reason: Option<String>,
        updated_by: Option<String>,
        updated_at_ms: u64,
        auto_clear_duration_secs: Option<u64>,
    ) -> Self {
        let auto_clear_at_ms = auto_clear_duration_secs
            .map(|secs| updated_at_ms.saturating_add(secs.saturating_mul(1000)));
        Self {
            subsystem,
            status,
            reason,
            updated_by,
            updated_at_ms,
            auto_clear_at_ms,
        }
    }

    /// Returns `true` if this override has not auto-cleared at `now_ms`.
    #[must_use]
    pub fn is_active(&self, now_ms: u64) -> bool {
        self.auto_clear_at_ms
            .is_none_or(|deadline| now_ms < deadline)
    }

    /// Resolves the effective status given a live health probe and optional active override.
    #[must_use]
    pub fn resolve_effective(
        probe_status: SubsystemStatus,
        override_opt: Option<&Self>,
        now_ms: u64,
    ) -> SubsystemStatus {
        match override_opt {
            Some(ov) if ov.is_active(now_ms) => ov.status,
            _ => probe_status,
        }
    }
}

/// Validated atomic policy identifier (`<subsystem_prefix>:<resource>.<action>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct PolicyId(String);

impl PolicyId {
    /// Validates and constructs a [`PolicyId`].
    pub fn new(raw: impl Into<String>) -> Result<Self, FolioError> {
        let raw = raw.into();
        let Some((prefix, rest)) = raw.split_once(':') else {
            return Err(FolioError::InvalidIdentifier {
                kind: "policy",
                value: raw,
            });
        };
        if SubsystemId::from_policy_prefix(prefix).is_none()
            || !is_valid_policy_segment(rest)
            || raw.len() > 128
        {
            return Err(FolioError::InvalidIdentifier {
                kind: "policy",
                value: raw,
            });
        }
        Ok(Self(raw))
    }

    /// Returns the owning subsystem inferred from the canonical policy prefix.
    #[must_use]
    pub fn subsystem(&self) -> SubsystemId {
        let prefix = self.0.split(':').next().unwrap_or_default();
        SubsystemId::from_policy_prefix(prefix).unwrap_or(SubsystemId::System)
    }

    /// Underlying policy string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for PolicyId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for PolicyId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for PolicyId {
    type Err = FolioError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl<'de> Deserialize<'de> for PolicyId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Validated PolicyFolio identifier (`folio:<namespace>:<slug>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct FolioId(String);

impl FolioId {
    /// Validates and constructs a [`FolioId`].
    pub fn new(raw: impl Into<String>) -> Result<Self, FolioError> {
        let raw = raw.into();
        let Some(rest) = raw.strip_prefix("folio:") else {
            return Err(FolioError::InvalidIdentifier {
                kind: "folio",
                value: raw,
            });
        };
        let Some((namespace, slug)) = rest.split_once(':') else {
            return Err(FolioError::InvalidIdentifier {
                kind: "folio",
                value: raw,
            });
        };
        if !is_valid_slug(namespace)
            || !is_valid_slug(slug)
            || slug.contains(':')
            || raw.len() > 128
        {
            return Err(FolioError::InvalidIdentifier {
                kind: "folio",
                value: raw,
            });
        }
        Ok(Self(raw))
    }

    /// Underlying folio string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Deref for FolioId {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for FolioId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for FolioId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for FolioId {
    type Err = FolioError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl<'de> Deserialize<'de> for FolioId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::new(raw).map_err(serde::de::Error::custom)
    }
}

/// Atomic capability token declared by an owning subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Canonical capability token (`<subsystem>:<resource>.<action>`).
    pub id: PolicyId,
    /// Owning subsystem.
    pub subsystem: SubsystemId,
    /// Concise peer-engineering capability description.
    pub description: String,
}

impl Policy {
    /// Declares a new [`Policy`] validated against its owning subsystem prefix.
    pub fn new(
        id: PolicyId,
        subsystem: SubsystemId,
        description: impl Into<String>,
    ) -> Result<Self, FolioError> {
        let expected_prefix = subsystem.policy_prefix();
        if id.subsystem() != subsystem {
            return Err(FolioError::PolicySubsystemMismatch {
                policy: id.to_string(),
                expected_prefix,
                subsystem: subsystem.as_str().to_string(),
            });
        }
        Ok(Self {
            id,
            subsystem,
            description: description.into(),
        })
    }
}

/// Ownership provenance determining whether a [`PolicyFolio`] is immutable or operator-editable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolioOrigin {
    /// Declared by an owning subsystem manifest; immutable via operator APIs.
    Subsystem,
    /// Authored by the platform operator; mutable and removable when unreferenced.
    Operator,
}

/// Composable positive-grant grouping of policies and included child folios.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFolio {
    /// Unique folio identifier (`folio:<namespace>:<slug>`).
    pub id: FolioId,
    /// Operator-facing label (`+`-free and control-char-free).
    pub display_name: String,
    /// Concise summary of granted capabilities.
    pub description: String,
    /// Origin ownership (`Subsystem` immutable vs `Operator` mutable).
    pub origin: FolioOrigin,
    /// Owning subsystem when `origin == FolioOrigin::Subsystem`.
    pub owner_subsystem: Option<SubsystemId>,
    /// Transitive child folios included additively.
    pub includes: BTreeSet<FolioId>,
    /// Direct positive policies granted by this folio (zero `Deny` rules).
    pub policies: BTreeSet<PolicyId>,
}

impl PolicyFolio {
    /// Constructs an immutable subsystem starter folio.
    pub fn subsystem(
        id: FolioId,
        owner_subsystem: SubsystemId,
        display_name: impl AsRef<str>,
        description: impl Into<String>,
        includes: BTreeSet<FolioId>,
        policies: BTreeSet<PolicyId>,
    ) -> Result<Self, FolioError> {
        let display_name = validate_display_name(display_name.as_ref())?;
        Ok(Self {
            id,
            display_name,
            description: description.into(),
            origin: FolioOrigin::Subsystem,
            owner_subsystem: Some(owner_subsystem),
            includes,
            policies,
        })
    }

    /// Constructs a mutable operator composite folio.
    pub fn operator(
        id: FolioId,
        display_name: impl AsRef<str>,
        description: impl Into<String>,
        includes: BTreeSet<FolioId>,
        policies: BTreeSet<PolicyId>,
    ) -> Result<Self, FolioError> {
        let display_name = validate_display_name(display_name.as_ref())?;
        Ok(Self {
            id,
            display_name,
            description: description.into(),
            origin: FolioOrigin::Operator,
            owner_subsystem: None,
            includes,
            policies,
        })
    }
}

/// Declarative bundle of policies and starter folios registered by a subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubsystemSecurityManifest {
    /// Declaring subsystem.
    pub subsystem: SubsystemId,
    /// Atomic positive policies owned by this subsystem.
    pub policies: Vec<Policy>,
    /// Immutable starter folios owned by this subsystem.
    pub folios: Vec<PolicyFolio>,
}

fn is_valid_policy_segment(seg: &str) -> bool {
    !seg.is_empty()
        && !seg.starts_with('.')
        && !seg.ends_with('.')
        && !seg.contains("..")
        && seg
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.'))
}

pub(crate) fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && !slug.starts_with('-')
        && !slug.ends_with('-')
        && slug
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

fn p(raw: &str, subsystem: SubsystemId, desc: &str) -> Policy {
    let id = PolicyId::new(raw).expect("canonical policy ID must be valid");
    Policy::new(id, subsystem, desc).expect("canonical policy prefix must match subsystem")
}

fn pid(raw: &str) -> PolicyId {
    PolicyId::new(raw).expect("canonical policy ID must be valid")
}

fn fid(raw: &str) -> FolioId {
    FolioId::new(raw).expect("canonical folio ID must be valid")
}

/// Canonical manifest for [`SubsystemId::System`].
#[must_use]
pub fn canonical_system_manifest() -> SubsystemSecurityManifest {
    let s = SubsystemId::System;
    SubsystemSecurityManifest {
        subsystem: s,
        policies: vec![
            p(
                "system:status.read",
                s,
                "Read public sanitized 5-state subsystem status",
            ),
            p(
                "system:dashboard.read",
                s,
                "Read system overview summary metrics",
            ),
        ],
        folios: vec![
            PolicyFolio::subsystem(
                fid("folio:system:status"),
                s,
                "System Status Read",
                "Read sanitized operational status across subsystems",
                BTreeSet::new(),
                BTreeSet::from([pid("system:status.read")]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:system:dashboard"),
                s,
                "System Dashboard Read",
                "Read sanitized system overview dashboard summary",
                BTreeSet::from([fid("folio:system:status")]),
                BTreeSet::from([pid("system:dashboard.read")]),
            )
            .expect("canonical folio"),
        ],
    }
}

/// Canonical manifest for [`SubsystemId::Ci`].
#[must_use]
pub fn canonical_ci_manifest() -> SubsystemSecurityManifest {
    let s = SubsystemId::Ci;
    SubsystemSecurityManifest {
        subsystem: s,
        policies: vec![
            p(
                "ci:queue.read",
                s,
                "Read public CI queue depth and running stage summary",
            ),
            p(
                "ci:repos.public.read",
                s,
                "Read public CI repository pipelines and statuses",
            ),
            p(
                "ci:repos.private.read",
                s,
                "Read private CI repositories and stage telemetry",
            ),
            p(
                "ci:jobs.read",
                s,
                "Read detailed CI job and stage execution history",
            ),
            p(
                "ci:jobs.logs.read",
                s,
                "Stream and inspect CI stage build/test logs",
            ),
            p(
                "ci:nodes.read",
                s,
                "Read CI worker node registration and slot state",
            ),
            p(
                "ci:sandboxes.read",
                s,
                "Read CI sandbox isolation telemetry",
            ),
            p(
                "ci:ha.read",
                s,
                "Read CI HA quorum and controller lease status",
            ),
            p("ci:jobs.resume", s, "Resume paused or waiting CI jobs"),
            p("ci:jobs.restart", s, "Restart CI pipeline stages"),
            p(
                "ci:ha.write",
                s,
                "Execute CI HA failover or leader maintenance transitions",
            ),
        ],
        folios: vec![
            PolicyFolio::subsystem(
                fid("folio:ci:anon-queue"),
                s,
                "CI Public Queue Read",
                "Read public repository CI status and sanitized queue state",
                BTreeSet::new(),
                BTreeSet::from([pid("ci:queue.read"), pid("ci:repos.public.read")]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:ci:read"),
                s,
                "CI Read",
                "Read all CI jobs, logs, nodes, sandboxes, and HA status",
                BTreeSet::from([fid("folio:ci:anon-queue")]),
                BTreeSet::from([
                    pid("ci:repos.private.read"),
                    pid("ci:jobs.read"),
                    pid("ci:jobs.logs.read"),
                    pid("ci:nodes.read"),
                    pid("ci:sandboxes.read"),
                    pid("ci:ha.read"),
                ]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:ci:operate"),
                s,
                "CI Operate",
                "Read CI telemetry and resume, restart, or manage HA state",
                BTreeSet::from([fid("folio:ci:read")]),
                BTreeSet::from([
                    pid("ci:jobs.resume"),
                    pid("ci:jobs.restart"),
                    pid("ci:ha.write"),
                ]),
            )
            .expect("canonical folio"),
        ],
    }
}

/// Canonical manifest for [`SubsystemId::Cd`] (ecosystem-agnostic and strictly read-only).
#[must_use]
pub fn canonical_cd_manifest() -> SubsystemSecurityManifest {
    let s = SubsystemId::Cd;
    SubsystemSecurityManifest {
        subsystem: s,
        policies: vec![
            p(
                "cd:runs.read",
                s,
                "Read ecosystem-agnostic CD pipeline delivery runs",
            ),
            p(
                "cd:steps.read",
                s,
                "Read ecosystem-agnostic CD step statuses and logs",
            ),
        ],
        folios: vec![PolicyFolio::subsystem(
            fid("folio:cd:read"),
            s,
            "CD Read",
            "Read ecosystem-agnostic continuous delivery runs and step outcomes",
            BTreeSet::new(),
            BTreeSet::from([pid("cd:runs.read"), pid("cd:steps.read")]),
        )
        .expect("canonical folio")],
    }
}

/// Canonical manifest for [`SubsystemId::AbDeploy`] (automated promotion only; zero manual `ab:promote`).
#[must_use]
pub fn canonical_ab_deploy_manifest() -> SubsystemSecurityManifest {
    let s = SubsystemId::AbDeploy;
    SubsystemSecurityManifest {
        subsystem: s,
        policies: vec![
            p(
                "ab:slots.read",
                s,
                "Read A/B live and staging slot health and versions",
            ),
            p(
                "ab:gate.logs.read",
                s,
                "Read automated sandboxed integration test gate logs",
            ),
            p(
                "ab:rollback",
                s,
                "Trigger emergency rollback to previous healthy A/B snapshot",
            ),
        ],
        folios: vec![
            PolicyFolio::subsystem(
                fid("folio:ab:read"),
                s,
                "A/B Deploy Read",
                "Read A/B deployment slot status and automated gate outcomes",
                BTreeSet::new(),
                BTreeSet::from([pid("ab:slots.read")]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:ab:gate-logs"),
                s,
                "A/B Gate Logs Read",
                "Read A/B slot status and sandboxed integration gate logs",
                BTreeSet::from([fid("folio:ab:read")]),
                BTreeSet::from([pid("ab:gate.logs.read")]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:ab:operate"),
                s,
                "A/B Deploy Operate",
                "Inspect A/B slots, gate logs, and perform emergency rollback",
                BTreeSet::from([fid("folio:ab:gate-logs")]),
                BTreeSet::from([pid("ab:rollback")]),
            )
            .expect("canonical folio"),
        ],
    }
}

/// Canonical manifest for [`SubsystemId::Repository`].
#[must_use]
pub fn canonical_repository_manifest() -> SubsystemSecurityManifest {
    let s = SubsystemId::Repository;
    SubsystemSecurityManifest {
        subsystem: s,
        policies: vec![
            p(
                "reg:packages.read",
                s,
                "Read published registry packages and release metadata",
            ),
            p(
                "reg:canaries.read",
                s,
                "Read registry artifact canary rollout records",
            ),
            p(
                "reg:taints.read",
                s,
                "Read quarantined/tainted release digest markers",
            ),
            p(
                "reg:cas.read",
                s,
                "Inspect CAS blob digests and retention state",
            ),
            p(
                "reg:bundles.write",
                s,
                "Manage release bundle promotion or deprecation markers",
            ),
            p(
                "reg:taints.write",
                s,
                "Mark or clear taints on compromised release digests",
            ),
        ],
        folios: vec![
            PolicyFolio::subsystem(
                fid("folio:reg:read"),
                s,
                "Repository Read",
                "Read registry packages, canaries, taints, and CAS blobs",
                BTreeSet::new(),
                BTreeSet::from([
                    pid("reg:packages.read"),
                    pid("reg:canaries.read"),
                    pid("reg:taints.read"),
                    pid("reg:cas.read"),
                ]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:reg:operate"),
                s,
                "Repository Operate",
                "Read registry artifacts and manage release bundles or digest taints",
                BTreeSet::from([fid("folio:reg:read")]),
                BTreeSet::from([pid("reg:bundles.write"), pid("reg:taints.write")]),
            )
            .expect("canonical folio"),
        ],
    }
}

/// Canonical manifest for [`SubsystemId::Observability`].
#[must_use]
pub fn canonical_observability_manifest() -> SubsystemSecurityManifest {
    let s = SubsystemId::Observability;
    SubsystemSecurityManifest {
        subsystem: s,
        policies: vec![
            p(
                "obs:logs.read",
                s,
                "Query sanitized OpenTelemetry log records",
            ),
            p(
                "obs:smartscape.read",
                s,
                "Read service topology and dependency graph",
            ),
            p(
                "obs:traces.read",
                s,
                "Inspect distributed W3C trace waterfalls",
            ),
            p(
                "obs:problems.read",
                s,
                "Read active SLO degradation and problem cards",
            ),
            p(
                "obs:metrics.read",
                s,
                "Read hardware and service benchmark telemetry",
            ),
            p(
                "obs:store.read",
                s,
                "Inspect DuckDB/Parquet analytics store status",
            ),
            p(
                "obs:ingress.read",
                s,
                "Inspect telemetry collector ingress status",
            ),
            p(
                "obs:ingress.write",
                s,
                "Administer OTLP ingress credentials and routing",
            ),
        ],
        folios: vec![
            PolicyFolio::subsystem(
                fid("folio:obs:logs"),
                s,
                "Observability Logs Read",
                "Read sanitized observability log records",
                BTreeSet::new(),
                BTreeSet::from([pid("obs:logs.read")]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:obs:read"),
                s,
                "Observability Read",
                "Read logs, traces, metrics, Smartscape, problems, and store views",
                BTreeSet::from([fid("folio:obs:logs")]),
                BTreeSet::from([
                    pid("obs:smartscape.read"),
                    pid("obs:traces.read"),
                    pid("obs:problems.read"),
                    pid("obs:metrics.read"),
                    pid("obs:store.read"),
                    pid("obs:ingress.read"),
                ]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:obs:ingress-admin"),
                s,
                "Observability Ingress Admin",
                "Read observability data and administer collector ingress rules",
                BTreeSet::from([fid("folio:obs:read")]),
                BTreeSet::from([pid("obs:ingress.write")]),
            )
            .expect("canonical folio"),
        ],
    }
}

/// Canonical manifest for [`SubsystemId::ModelRunner`].
#[must_use]
pub fn canonical_model_runner_manifest() -> SubsystemSecurityManifest {
    let s = SubsystemId::ModelRunner;
    SubsystemSecurityManifest {
        subsystem: s,
        policies: vec![
            p(
                "mr:models.read",
                s,
                "Read resident models and mlock ceiling telemetry",
            ),
            p("mr:queue.read", s, "Read inference admission queue depths"),
            p(
                "mr:openai_api.read",
                s,
                "Read generic OpenAI-compatible API endpoint parameters",
            ),
            p(
                "mr:wireguard_vpn.read",
                s,
                "Read sanitized WireGuard peer connection configuration",
            ),
        ],
        folios: vec![
            PolicyFolio::subsystem(
                fid("folio:mr:read"),
                s,
                "Model-Runner Status Read",
                "Read resident models, memory headroom, and prompt queue depth",
                BTreeSet::new(),
                BTreeSet::from([pid("mr:models.read"), pid("mr:queue.read")]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:mr:connect"),
                s,
                "Model-Runner Connection Read",
                "Read Model-Runner status plus OpenAI API and WireGuard connection details",
                BTreeSet::from([fid("folio:mr:read")]),
                BTreeSet::from([pid("mr:openai_api.read"), pid("mr:wireguard_vpn.read")]),
            )
            .expect("canonical folio"),
        ],
    }
}

/// Canonical manifest for [`SubsystemId::Platform`] (replacing legacy IAM naming).
#[must_use]
pub fn canonical_platform_manifest() -> SubsystemSecurityManifest {
    let s = SubsystemId::Platform;
    SubsystemSecurityManifest {
        subsystem: s,
        policies: vec![
            p(
                "platform:maintenance.read",
                s,
                "Read active subsystem maintenance windows",
            ),
            p(
                "platform:users.read",
                s,
                "Read bound platform user accounts and role assignments",
            ),
            p(
                "platform:invites.read",
                s,
                "Read active and redeemed onboarding invites",
            ),
            p(
                "platform:roles.read",
                s,
                "Read RoleCatalog role definitions and TTL bounds",
            ),
            p(
                "platform:folios.read",
                s,
                "Read PolicyFolio DAG and RoleFolioIndex mappings",
            ),
            p(
                "platform:activity.read",
                s,
                "Read platform authorization and audit activity log",
            ),
            p(
                "platform:maintenance.write",
                s,
                "Configure subsystem maintenance overrides",
            ),
            p(
                "platform:users.write",
                s,
                "Manage bound platform users and role bindings",
            ),
            p(
                "platform:invites.write",
                s,
                "Mint or revoke baseline onboarding invites",
            ),
            p(
                "platform:roles.write",
                s,
                "Author and update RoleCatalog and RoleFolioIndex entries",
            ),
            p(
                "platform:folios.write",
                s,
                "Author and update Operator composite PolicyFolios",
            ),
        ],
        folios: vec![
            PolicyFolio::subsystem(
                fid("folio:platform:read"),
                s,
                "Platform Read",
                "Read maintenance state, users, invites, roles, folios, and audit logs",
                BTreeSet::new(),
                BTreeSet::from([
                    pid("platform:maintenance.read"),
                    pid("platform:users.read"),
                    pid("platform:invites.read"),
                    pid("platform:roles.read"),
                    pid("platform:folios.read"),
                    pid("platform:activity.read"),
                ]),
            )
            .expect("canonical folio"),
            PolicyFolio::subsystem(
                fid("folio:platform:admin"),
                s,
                "Platform Admin",
                "Full administrative control over maintenance, users, invites, roles, and folios",
                BTreeSet::from([fid("folio:platform:read")]),
                BTreeSet::from([
                    pid("platform:maintenance.write"),
                    pid("platform:users.write"),
                    pid("platform:invites.write"),
                    pid("platform:roles.write"),
                    pid("platform:folios.write"),
                ]),
            )
            .expect("canonical folio"),
        ],
    }
}

/// Returns canonical manifests for all 8 platform subsystems.
#[must_use]
pub fn canonical_manifests() -> [SubsystemSecurityManifest; 8] {
    [
        canonical_system_manifest(),
        canonical_ci_manifest(),
        canonical_cd_manifest(),
        canonical_ab_deploy_manifest(),
        canonical_repository_manifest(),
        canonical_observability_manifest(),
        canonical_model_runner_manifest(),
        canonical_platform_manifest(),
    ]
}

/// Returns the 8 top-level canonical subsystem folios bound to `super-operator`.
#[must_use]
pub fn canonical_super_operator_folios() -> [FolioId; 8] {
    [
        FolioId::new("folio:system:dashboard").expect("canonical folio id"),
        FolioId::new("folio:ci:operate").expect("canonical folio id"),
        FolioId::new("folio:cd:read").expect("canonical folio id"),
        FolioId::new("folio:ab:operate").expect("canonical folio id"),
        FolioId::new("folio:reg:operate").expect("canonical folio id"),
        FolioId::new("folio:obs:ingress-admin").expect("canonical folio id"),
        FolioId::new("folio:mr:connect").expect("canonical folio id"),
        FolioId::new("folio:platform:admin").expect("canonical folio id"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_manifests_cover_all_8_subsystems_without_ab_promote() {
        let manifests = canonical_manifests();
        assert_eq!(manifests.len(), 8);
        assert_eq!(SubsystemId::ALL.len(), 8);
        assert_eq!(SubsystemId::OPERATIONAL.len(), 7);
        assert!(!SubsystemId::OPERATIONAL.contains(&SubsystemId::System));

        let all_policy_ids: Vec<&str> = manifests
            .iter()
            .flat_map(|m| m.policies.iter().map(|p| p.id.as_str()))
            .collect();
        assert!(!all_policy_ids.contains(&"ab:promote"));
        assert!(all_policy_ids.contains(&"ab:rollback"));
        assert!(all_policy_ids.contains(&"cd:runs.read"));
        assert!(all_policy_ids.contains(&"platform:maintenance.write"));
        assert!(all_policy_ids.contains(&"mr:wireguard_vpn.read"));
    }

    #[test]
    fn subsystem_status_serde_roundtrip_and_maintenance_override_autoclear() {
        let parsed: SubsystemStatus = "in_maintenance".parse().expect("parse snake_case");
        assert_eq!(parsed, SubsystemStatus::InMaintenance);
        assert_eq!(parsed.as_str(), "in-maintenance");
        assert!(parsed.is_maintenance());
        assert!(parsed.suppresses_slo_alerts());

        let ov = MaintenanceOverride::new(
            SubsystemId::Ci,
            SubsystemStatus::PartialMaintenance,
            Some("Planned runner upgrade".into()),
            Some("operator".into()),
            1_000,
            Some(60),
        );
        assert_eq!(
            MaintenanceOverride::resolve_effective(SubsystemStatus::Live, Some(&ov), 60_999),
            SubsystemStatus::PartialMaintenance
        );
        assert_eq!(
            MaintenanceOverride::resolve_effective(SubsystemStatus::Live, Some(&ov), 61_000),
            SubsystemStatus::Live
        );
    }

    #[test]
    fn reject_policy_prefix_mismatch() {
        let wrong_id = PolicyId::new("ci:jobs.read").expect("valid syntax");
        let err = Policy::new(wrong_id, SubsystemId::Platform, "mismatch").unwrap_err();
        assert!(matches!(err, FolioError::PolicySubsystemMismatch { .. }));
    }
}
