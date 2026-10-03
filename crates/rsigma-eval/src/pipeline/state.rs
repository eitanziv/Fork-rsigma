//! Pipeline state tracking.
//!
//! Tracks which transformations have been applied (per-pipeline and per-rule),
//! stores key-value state set by `SetState` transformations, and holds pipeline
//! variables used for placeholder expansion.

use std::collections::{HashMap, HashSet};

use rsigma_parser::DetectionItem;

use super::sources::SourceStatus;

/// Mutable state carried through a pipeline's application to one or more rules.
#[derive(Debug, Clone, Default)]
pub struct PipelineState {
    /// IDs of transformations that have been applied globally (across all rules).
    pub applied_items: HashSet<String>,

    /// IDs of transformations applied to the current rule being processed.
    /// Reset between rules.
    pub rule_applied: HashSet<String>,

    /// IDs of transformations that renamed each field name, keyed by the
    /// current name. A rename moves the source name's IDs to every
    /// destination name. Reset between rules.
    pub field_name_applied: HashMap<String, HashSet<String>>,

    /// IDs of transformations that changed each detection item, keyed by the
    /// item's current content. Reset between rules.
    detection_item_applied: Vec<(DetectionItem, HashSet<String>)>,

    /// ID of the transformation item being applied, if it has one.
    pub(crate) current_item_id: Option<String>,

    /// Whether the pipeline has detection-item `processing_item_applied`
    /// conditions, which need item changes tracked.
    pub(crate) track_detection_items: bool,

    /// Arbitrary key-value state set by `SetState` transformations.
    pub state: HashMap<String, serde_json::Value>,

    /// Pipeline variables from the `vars` section, used for placeholder expansion.
    pub vars: HashMap<String, Vec<String>>,

    /// Resolution status of each dynamic source (keyed by source ID).
    pub source_status: HashMap<String, SourceStatus>,
}

impl PipelineState {
    /// Create a new state initialized with the given pipeline variables.
    pub fn new(vars: HashMap<String, Vec<String>>) -> Self {
        Self {
            vars,
            ..Default::default()
        }
    }

    /// Record that a transformation with the given ID was applied.
    pub fn mark_applied(&mut self, id: &str) {
        self.applied_items.insert(id.to_string());
        self.rule_applied.insert(id.to_string());
    }

    /// Check if a transformation with the given ID was applied (globally or to current rule).
    pub fn was_applied(&self, id: &str) -> bool {
        self.applied_items.contains(id) || self.rule_applied.contains(id)
    }

    /// Record that the transformation `id` renamed `source` to `destinations`.
    /// The destinations inherit the IDs already recorded for `source`.
    pub fn track_field_rename(&mut self, source: &str, destinations: &[String], id: Option<&str>) {
        if destinations.len() == 1 && destinations[0] == source {
            return;
        }
        let mut ids = self.field_name_applied.remove(source).unwrap_or_default();
        if let Some(id) = id {
            ids.insert(id.to_string());
        }
        for destination in destinations {
            self.field_name_applied
                .insert(destination.clone(), ids.clone());
        }
    }

    /// Record renames made by the transformation item being applied.
    pub(crate) fn track_field_renames(&mut self, renames: Vec<(String, Vec<String>)>) {
        let id = self.current_item_id.clone();
        for (source, destinations) in renames {
            self.track_field_rename(&source, &destinations, id.as_deref());
        }
    }

    /// Check if the transformation `id` renamed a field to `field`.
    pub fn field_was_processed_by(&self, field: &str, id: &str) -> bool {
        self.field_name_applied
            .get(field)
            .is_some_and(|ids| ids.contains(id))
    }

    /// Record that the transformation `id` turned `before` into `after`.
    /// `after` inherits the IDs recorded for `before`; with no `before` the
    /// item is new and only carries `id`.
    pub(crate) fn track_detection_item_change(
        &mut self,
        before: Option<&DetectionItem>,
        after: &DetectionItem,
        id: Option<&str>,
    ) {
        let mut ids = before
            .and_then(|before| self.detection_item_ids(before))
            .cloned()
            .unwrap_or_default();
        if let Some(id) = id {
            ids.insert(id.to_string());
        }
        if ids.is_empty() {
            return;
        }
        match self
            .detection_item_applied
            .iter_mut()
            .find(|(item, _)| item == after)
        {
            Some((_, existing)) => existing.extend(ids),
            None => self.detection_item_applied.push((after.clone(), ids)),
        }
    }

    /// Check if the transformation `id` changed `item` into its current form.
    pub fn detection_item_was_processed_by(&self, item: &DetectionItem, id: &str) -> bool {
        self.detection_item_ids(item)
            .is_some_and(|ids| ids.contains(id))
    }

    fn detection_item_ids(&self, item: &DetectionItem) -> Option<&HashSet<String>> {
        self.detection_item_applied
            .iter()
            .find(|(tracked, _)| tracked == item)
            .map(|(_, ids)| ids)
    }

    /// Get a state value.
    pub fn get_state(&self, key: &str) -> Option<&serde_json::Value> {
        self.state.get(key)
    }

    /// Set a state value.
    pub fn set_state(&mut self, key: String, val: serde_json::Value) {
        self.state.insert(key, val);
    }

    /// Check if a state key has a specific string value.
    pub fn state_matches(&self, key: &str, val: &str) -> bool {
        self.state
            .get(key)
            .and_then(|v| v.as_str())
            .is_some_and(|s| s == val)
    }

    /// Reset per-rule tracking (called before processing each rule).
    pub fn reset_rule(&mut self) {
        self.rule_applied.clear();
        self.field_name_applied.clear();
        self.detection_item_applied.clear();
    }

    /// Initialize source status tracking for a set of source IDs.
    /// All sources start in `Pending` state.
    pub fn init_sources(&mut self, source_ids: impl IntoIterator<Item = String>) {
        for id in source_ids {
            self.source_status.insert(id, SourceStatus::Pending);
        }
    }

    /// Mark a source as successfully resolved.
    pub fn mark_source_resolved(&mut self, id: &str) {
        self.source_status
            .insert(id.to_string(), SourceStatus::Resolved);
    }

    /// Mark a source as failed.
    pub fn mark_source_failed(&mut self, id: &str) {
        self.source_status
            .insert(id.to_string(), SourceStatus::Failed);
    }

    /// Get the resolution status of a source.
    pub fn source_status(&self, id: &str) -> Option<SourceStatus> {
        self.source_status.get(id).copied()
    }

    /// Returns `true` if all tracked sources have been resolved.
    pub fn all_sources_resolved(&self) -> bool {
        self.source_status
            .values()
            .all(|s| *s == SourceStatus::Resolved)
    }

    /// Returns source IDs that are still pending resolution.
    pub fn pending_sources(&self) -> Vec<&str> {
        self.source_status
            .iter()
            .filter(|(_, status)| **status == SourceStatus::Pending)
            .map(|(id, _)| id.as_str())
            .collect()
    }
}
