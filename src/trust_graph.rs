//! trust graph.

use crate::did::Did;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

// TrustGraph
// ---------------------------------------------------------------------------

pub struct TrustGraph {
    edges: BTreeMap<Did, BTreeSet<Did>>,
}

impl TrustGraph {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            edges: BTreeMap::new(),
        }
    }

    /// Add a directed trust edge from `truster` to `trustee`.
    pub fn add_trust(&mut self, truster: &Did, trustee: &Did) {
        self.edges
            .entry(truster.clone())
            .or_default()
            .insert(trustee.clone());
    }

    /// Remove a directed trust edge.
    pub fn remove_trust(&mut self, truster: &Did, trustee: &Did) {
        if let Some(set) = self.edges.get_mut(truster) {
            set.remove(trustee);
        }
    }

    /// Check if `from` transitively trusts `to` via BFS.
    #[must_use]
    pub fn is_trusted(&self, from: &Did, to: &Did) -> bool {
        self.trust_path(from, to).is_some()
    }

    /// Find the shortest trust path from `from` to `to`, if one exists.
    #[must_use]
    pub fn trust_path(&self, from: &Did, to: &Did) -> Option<Vec<Did>> {
        if from == to {
            return Some(vec![from.clone()]);
        }

        let mut visited = BTreeSet::new();
        let mut queue = VecDeque::new();
        visited.insert(from.clone());
        queue.push_back(vec![from.clone()]);

        while let Some(path) = queue.pop_front() {
            let current = path.last()?;
            if let Some(neighbors) = self.edges.get(current) {
                for neighbor in neighbors {
                    if neighbor == to {
                        let mut result = path;
                        result.push(neighbor.clone());
                        return Some(result);
                    }
                    if visited.insert(neighbor.clone()) {
                        let mut new_path = path.clone();
                        new_path.push(neighbor.clone());
                        queue.push_back(new_path);
                    }
                }
            }
        }

        None
    }

    /// Return all DIDs directly trusted by `did`.
    #[must_use]
    pub fn trustees_of(&self, did: &Did) -> Vec<Did> {
        self.edges
            .get(did)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default()
    }
}

impl Default for TrustGraph {
    fn default() -> Self {
        Self::new()
    }
}
