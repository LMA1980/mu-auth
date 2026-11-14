//! PolicyFolio catalog, DFS cycle/reference validator, and additive PolicySet resolver.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::iter::FromIterator;
use serde::{Deserialize, Serialize};

use crate::error::FolioError;
use crate::role::validate_display_name;
use crate::subsystem::{
    canonical_manifests, FolioId, FolioOrigin, Policy, PolicyFolio, PolicyId, SubsystemId,
    SubsystemSecurityManifest,
};

/// Additive-only set of granted [`PolicyId`] tokens (zero `Deny` rules).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicySet {
    policies: BTreeSet<PolicyId>,
}

impl PolicySet {
    /// Empty [`PolicySet`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a positive policy grant into the set.
    pub fn insert(&mut self, policy: PolicyId) -> bool {
        self.policies.insert(policy)
    }

    /// Inserts all policies from another [`PolicySet`] (additive union).
    pub fn merge(&mut self, other: &Self) {
        for policy in &other.policies {
            self.policies.insert(policy.clone());
        }
    }

    /// Returns `true` if `policy` is present.
    #[must_use]
    pub fn contains(&self, policy: &PolicyId) -> bool {
        self.policies.contains(policy)
    }

    /// Returns `true` if `policy_str` is granted by this set.
    #[must_use]
    pub fn contains_str(&self, policy_str: &str) -> bool {
        self.policies.iter().any(|p| p.as_str() == policy_str)
    }

    /// Returns `true` if any policy belonging to `subsystem` is granted.
    #[must_use]
    pub fn has_subsystem_access(&self, subsystem: SubsystemId) -> bool {
        self.policies.iter().any(|p| p.subsystem() == subsystem)
    }

    /// Retains only policies whose owning subsystem is NOT in `disabled_subsystems`.
    pub fn exclude_subsystems(&mut self, disabled_subsystems: &BTreeSet<SubsystemId>) {
        if disabled_subsystems.is_empty() {
            return;
        }
        self.policies
            .retain(|policy| !disabled_subsystems.contains(&policy.subsystem()));
    }

    /// Returns a filtered view of policies owned by `subsystem`.
    #[must_use]
    pub fn for_subsystem(&self, subsystem: SubsystemId) -> BTreeSet<PolicyId> {
        self.policies
            .iter()
            .filter(|p| p.subsystem() == subsystem)
            .cloned()
            .collect()
    }

    /// Number of granted policies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Returns `true` when zero policies are granted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }

    /// Iterates granted policies in deterministic sorted order.
    pub fn iter(&self) -> impl Iterator<Item = &PolicyId> {
        self.policies.iter()
    }

    /// Underlying sorted `BTreeSet`.
    #[must_use]
    pub fn as_set(&self) -> &BTreeSet<PolicyId> {
        &self.policies
    }
}

impl FromIterator<PolicyId> for PolicySet {
    fn from_iter<T: IntoIterator<Item = PolicyId>>(iter: T) -> Self {
        Self {
            policies: iter.into_iter().collect(),
        }
    }
}

/// Validated registry of subsystem-owned [`Policy`] definitions and composable [`PolicyFolio`] DAG nodes.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct FolioCatalog {
    policies: BTreeMap<PolicyId, Policy>,
    folios: BTreeMap<FolioId, PolicyFolio>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VisitMark {
    Visiting,
    Visited,
}

impl FolioCatalog {
    /// Creates an empty [`FolioCatalog`].
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a [`FolioCatalog`] preloaded with canonical manifests for all 8 subsystems.
    #[must_use]
    pub fn with_canonical_manifests() -> Self {
        let mut catalog = Self::new();
        for manifest in canonical_manifests() {
            catalog
                .register_manifest(manifest)
                .expect("canonical manifests must form a valid acyclic catalog");
        }
        catalog
    }

    /// Registers an immutable subsystem manifest atomically (failing closed on conflict, dangling ref, or cycle).
    pub fn register_manifest(
        &mut self,
        manifest: SubsystemSecurityManifest,
    ) -> Result<(), FolioError> {
        let mut staged = self.clone();
        let expected_prefix = manifest.subsystem.policy_prefix();

        for policy in manifest.policies {
            if policy.subsystem != manifest.subsystem || policy.id.subsystem() != manifest.subsystem
            {
                return Err(FolioError::PolicySubsystemMismatch {
                    policy: policy.id.to_string(),
                    expected_prefix,
                    subsystem: manifest.subsystem.as_str().to_string(),
                });
            }
            if staged.policies.contains_key(&policy.id) {
                return Err(FolioError::DuplicatePolicy(policy.id.to_string()));
            }
            staged.policies.insert(policy.id.clone(), policy);
        }

        for mut folio in manifest.folios {
            folio.display_name = validate_display_name(&folio.display_name)?;
            if folio.origin != FolioOrigin::Subsystem {
                return Err(FolioError::FolioSubsystemMismatch {
                    folio: folio.id.to_string(),
                    expected_subsystem: manifest.subsystem.as_str().to_string(),
                });
            }
            if folio.owner_subsystem != Some(manifest.subsystem) {
                return Err(FolioError::FolioSubsystemMismatch {
                    folio: folio.id.to_string(),
                    expected_subsystem: manifest.subsystem.as_str().to_string(),
                });
            }
            if staged.folios.contains_key(&folio.id) {
                return Err(FolioError::DuplicateFolio(folio.id.to_string()));
            }
            staged.folios.insert(folio.id.clone(), folio);
        }

        staged.validate_graph()?;
        *self = staged;
        Ok(())
    }

    /// Inserts or updates a mutable [`FolioOrigin::Operator`] folio atomically.
    ///
    /// Rejects creating or overwriting [`FolioOrigin::Subsystem`] folios, rejects unknown `PolicyId`
    /// or `FolioId` references fail-closed, and rejects cycles via topological DFS.
    pub fn upsert_operator_folio(&mut self, mut folio: PolicyFolio) -> Result<(), FolioError> {
        if folio.origin != FolioOrigin::Operator || folio.owner_subsystem.is_some() {
            return Err(FolioError::ImmutableSubsystemFolio(folio.id.to_string()));
        }
        if let Some(existing) = self.folios.get(&folio.id) {
            if existing.origin == FolioOrigin::Subsystem {
                return Err(FolioError::ImmutableSubsystemFolio(folio.id.to_string()));
            }
        }
        folio.display_name = validate_display_name(&folio.display_name)?;

        let mut staged = self.clone();
        staged.folios.insert(folio.id.clone(), folio);
        staged.validate_graph()?;
        *self = staged;
        Ok(())
    }

    /// Removes an unreferenced [`FolioOrigin::Operator`] folio.
    pub fn remove_operator_folio(&mut self, id: &FolioId) -> Result<PolicyFolio, FolioError> {
        let Some(existing) = self.folios.get(id) else {
            return Err(FolioError::UnknownFolio(id.to_string()));
        };
        if existing.origin == FolioOrigin::Subsystem {
            return Err(FolioError::ImmutableSubsystemFolio(id.to_string()));
        }
        for other in self.folios.values() {
            if other.id != *id && other.includes.contains(id) {
                return Err(FolioError::FolioStillReferenced {
                    folio: id.to_string(),
                    referenced_by: other.id.to_string(),
                });
            }
        }
        Ok(self
            .folios
            .remove(id)
            .expect("verified folio exists before removal"))
    }

    /// Validates every policy/folio reference and ensures `includes` edges form a strict DAG.
    pub fn validate_graph(&self) -> Result<(), FolioError> {
        for folio in self.folios.values() {
            let _ = validate_display_name(&folio.display_name)?;
            for policy_id in &folio.policies {
                if !self.policies.contains_key(policy_id) {
                    return Err(FolioError::UnknownPolicy(policy_id.to_string()));
                }
            }
            for child_id in &folio.includes {
                if !self.folios.contains_key(child_id) {
                    return Err(FolioError::UnknownFolio(child_id.to_string()));
                }
            }
        }

        let mut marks: BTreeMap<&FolioId, VisitMark> = BTreeMap::new();
        let mut stack: Vec<&FolioId> = Vec::new();
        for folio_id in self.folios.keys() {
            if !marks.contains_key(folio_id) {
                self.dfs_detect_cycle(folio_id, &mut marks, &mut stack)?;
            }
        }
        Ok(())
    }

    fn dfs_detect_cycle<'a>(
        &'a self,
        node: &'a FolioId,
        marks: &mut BTreeMap<&'a FolioId, VisitMark>,
        stack: &mut Vec<&'a FolioId>,
    ) -> Result<(), FolioError> {
        marks.insert(node, VisitMark::Visiting);
        stack.push(node);

        let folio = self
            .folios
            .get(node)
            .ok_or_else(|| FolioError::UnknownFolio(node.to_string()))?;

        for child in &folio.includes {
            match marks.get(child).copied() {
                None => self.dfs_detect_cycle(child, marks, stack)?,
                Some(VisitMark::Visiting) => {
                    let start = stack.iter().position(|id| *id == child).unwrap_or(0);
                    let mut cycle: Vec<String> =
                        stack[start..].iter().map(|id| id.to_string()).collect();
                    cycle.push(child.to_string());
                    return Err(FolioError::CyclicFolioInclude { cycle });
                }
                Some(VisitMark::Visited) => {}
            }
        }

        stack.pop();
        marks.insert(node, VisitMark::Visited);
        Ok(())
    }

    /// Resolves a single [`FolioId`] into its transitive additive [`PolicySet`].
    pub fn resolve_folio(&self, id: &FolioId) -> Result<PolicySet, FolioError> {
        self.resolve_folios([id])
    }

    /// Resolves any collection of [`FolioId`]s into their additive transitive [`PolicySet`] union.
    pub fn resolve_folios<'a>(
        &self,
        ids: impl IntoIterator<Item = &'a FolioId>,
    ) -> Result<PolicySet, FolioError> {
        let mut visited: BTreeSet<&FolioId> = BTreeSet::new();
        let mut out = PolicySet::new();
        for id in ids {
            self.collect_folio_policies(id, &mut visited, &mut out)?;
        }
        Ok(out)
    }

    fn collect_folio_policies<'s>(
        &'s self,
        id: &FolioId,
        visited: &mut BTreeSet<&'s FolioId>,
        out: &mut PolicySet,
    ) -> Result<(), FolioError> {
        let folio = self
            .folios
            .get(id)
            .ok_or_else(|| FolioError::UnknownFolio(id.to_string()))?;

        if !visited.insert(&folio.id) {
            return Ok(());
        }

        for policy_id in &folio.policies {
            if !self.policies.contains_key(policy_id) {
                return Err(FolioError::UnknownPolicy(policy_id.to_string()));
            }
            out.insert(policy_id.clone());
        }
        for included in &folio.includes {
            self.collect_folio_policies(included, visited, out)?;
        }
        Ok(())
    }

    /// Looks up a registered [`Policy`].
    #[must_use]
    pub fn policy(&self, id: &PolicyId) -> Option<&Policy> {
        self.policies.get(id)
    }

    /// Looks up a registered [`PolicyFolio`].
    #[must_use]
    pub fn folio(&self, id: &FolioId) -> Option<&PolicyFolio> {
        self.folios.get(id)
    }

    /// Iterates all registered policies in sorted order.
    pub fn policies(&self) -> impl Iterator<Item = &Policy> {
        self.policies.values()
    }

    /// Iterates all registered folios in sorted order.
    pub fn folios(&self) -> impl Iterator<Item = &PolicyFolio> {
        self.folios.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fid(raw: &str) -> FolioId {
        FolioId::new(raw).expect("valid folio id")
    }

    fn pid(raw: &str) -> PolicyId {
        PolicyId::new(raw).expect("valid policy id")
    }

    #[test]
    fn canonical_dag_resolves_transitive_additive_unions() {
        let catalog = FolioCatalog::with_canonical_manifests();
        let ci_op = catalog
            .resolve_folio(&fid("folio:ci:operate"))
            .expect("resolve ci operate");
        assert!(ci_op.contains(&pid("ci:queue.read")));
        assert!(ci_op.contains(&pid("ci:jobs.read")));
        assert!(ci_op.contains(&pid("ci:jobs.restart")));
        assert!(!ci_op.contains_str("ab:promote"));

        let ab_op = catalog
            .resolve_folio(&fid("folio:ab:operate"))
            .expect("resolve ab operate");
        assert!(ab_op.contains(&pid("ab:slots.read")));
        assert!(ab_op.contains(&pid("ab:gate.logs.read")));
        assert!(ab_op.contains(&pid("ab:rollback")));
    }

    #[test]
    fn rejects_cycle_dangling_refs_and_immutable_subsystem_mutations() {
        let mut catalog = FolioCatalog::with_canonical_manifests();

        let overwrite = PolicyFolio::operator(
            fid("folio:ci:read"),
            "Tampered CI Read",
            "must fail",
            BTreeSet::new(),
            BTreeSet::new(),
        )
        .expect("valid syntax");
        assert!(matches!(
            catalog.upsert_operator_folio(overwrite),
            Err(FolioError::ImmutableSubsystemFolio(_))
        ));

        let dangling_policy = PolicyFolio::operator(
            fid("folio:op:dangling-pol"),
            "Dangling Policy",
            "bad ref",
            BTreeSet::new(),
            BTreeSet::from([pid("ci:nonexistent.read")]),
        )
        .expect("valid syntax");
        assert!(matches!(
            catalog.upsert_operator_folio(dangling_policy),
            Err(FolioError::UnknownPolicy(_))
        ));

        let dangling_folio = PolicyFolio::operator(
            fid("folio:op:dangling-fol"),
            "Dangling Folio",
            "bad ref",
            BTreeSet::from([fid("folio:op:missing")]),
            BTreeSet::new(),
        )
        .expect("valid syntax");
        assert!(matches!(
            catalog.upsert_operator_folio(dangling_folio),
            Err(FolioError::UnknownFolio(_))
        ));

        let a = PolicyFolio::operator(
            fid("folio:op:cycle-a"),
            "Cycle A",
            "first node",
            BTreeSet::new(),
            BTreeSet::from([pid("system:status.read")]),
        )
        .expect("valid");
        catalog.upsert_operator_folio(a).expect("insert a");

        let b = PolicyFolio::operator(
            fid("folio:op:cycle-b"),
            "Cycle B",
            "includes a",
            BTreeSet::from([fid("folio:op:cycle-a")]),
            BTreeSet::new(),
        )
        .expect("valid");
        catalog.upsert_operator_folio(b).expect("insert b");

        // Cannot delete cycle-a while referenced by cycle-b
        assert!(matches!(
            catalog.remove_operator_folio(&fid("folio:op:cycle-a")),
            Err(FolioError::FolioStillReferenced { .. })
        ));

        // Closing cycle a -> b -> a fails atomically without corrupting cycle-a
        let cyclic_a = PolicyFolio::operator(
            fid("folio:op:cycle-a"),
            "Cycle A",
            "creates cycle",
            BTreeSet::from([fid("folio:op:cycle-b")]),
            BTreeSet::new(),
        )
        .expect("valid");
        assert!(matches!(
            catalog.upsert_operator_folio(cyclic_a),
            Err(FolioError::CyclicFolioInclude { .. })
        ));
        assert!(catalog
            .resolve_folio(&fid("folio:op:cycle-b"))
            .expect("state intact")
            .contains(&pid("system:status.read")));
    }
}
