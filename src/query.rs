use std::{cmp::Ordering, collections::BTreeMap};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, StoreError},
    model::DocumentRecord,
};

pub const MAX_QUERY_LIMIT: usize = 10_000;
pub const DEFAULT_QUERY_LIMIT: usize = 100;
pub(crate) const MAX_QUERY_SCAN_ROWS: usize = 100_000;
pub(crate) const MAX_QUERY_SCAN_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetadataField {
    DocumentId,
    Version,
    CreatedSequence,
    ModifiedSequence,
    Deleted,
    KeyId,
    KeyVersion,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum QueryValue {
    String(String),
    Number(u64),
    Bool(bool),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Predicate {
    Eq {
        field: MetadataField,
        value: QueryValue,
    },
    Ne {
        field: MetadataField,
        value: QueryValue,
    },
    Lt {
        field: MetadataField,
        value: QueryValue,
    },
    Le {
        field: MetadataField,
        value: QueryValue,
    },
    Gt {
        field: MetadataField,
        value: QueryValue,
    },
    Ge {
        field: MetadataField,
        value: QueryValue,
    },
    Exists {
        field: MetadataField,
        exists: bool,
    },
    And {
        predicates: Vec<Predicate>,
    },
    Or {
        predicates: Vec<Predicate>,
    },
    /// An opaque marker interpreted only by a trusted client after decryption.
    ClientProtected {
        marker: String,
    },
    /// Reserved for a future leakage-reviewed exact-match token format.
    BlindToken {
        index: String,
        token: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    Ascending,
    Descending,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrderingClause {
    pub field: MetadataField,
    pub direction: Direction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Query {
    pub collection: String,
    pub include_deleted: bool,
    pub predicate: Option<Predicate>,
    pub projection: Option<Vec<MetadataField>>,
    pub order_by: Vec<OrderingClause>,
    pub limit: usize,
    pub cursor: Option<String>,
}

impl Query {
    pub fn collection(collection: impl Into<String>) -> Self {
        Self {
            collection: collection.into(),
            include_deleted: false,
            predicate: None,
            projection: None,
            order_by: Vec::new(),
            limit: DEFAULT_QUERY_LIMIT,
            cursor: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDefinition {
    pub name: String,
    pub collection: String,
    pub fields: Vec<MetadataField>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    ServerVisibleMetadata,
    ClientSideFiltering,
    BlindToken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "access", rename_all = "snake_case")]
pub enum AccessPath {
    DocumentId {
        id: String,
    },
    SecondaryIndex {
        name: String,
        equality_prefix: Vec<QueryValue>,
    },
    CollectionScan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExplainPlan {
    pub mode: ExecutionMode,
    pub access_path: AccessPath,
    pub residual_filter: bool,
    pub requires_client_filter: bool,
    pub order_in_memory: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryRow {
    pub collection: String,
    pub id: String,
    pub fields: BTreeMap<String, QueryValue>,
    pub record: Option<DocumentRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueryResult {
    pub rows: Vec<QueryRow>,
    pub next_cursor: Option<String>,
    pub plan: ExplainPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Cursor {
    order: Vec<Option<QueryValue>>,
    id: String,
}

pub(crate) fn validate_query(query: &Query) -> Result<()> {
    if query.collection.is_empty()
        || query.collection.len() > 1024
        || query.collection.contains('\0')
    {
        return Err(StoreError::InvalidInput("invalid query collection".into()));
    }
    if query.limit == 0 || query.limit > MAX_QUERY_LIMIT {
        return Err(StoreError::InvalidInput(format!(
            "query limit must be between 1 and {MAX_QUERY_LIMIT}"
        )));
    }
    if query.order_by.len() > 8 {
        return Err(StoreError::InvalidInput("too many ordering fields".into()));
    }
    if let Some(projection) = &query.projection
        && projection.len() > 16
    {
        return Err(StoreError::InvalidInput(
            "too many projection fields".into(),
        ));
    }
    if let Some(predicate) = &query.predicate {
        validate_predicate(predicate, 0)?;
        if query.projection.is_some() && requires_client_filter(predicate) {
            return Err(StoreError::InvalidInput(
                "client-side filtering requires full encrypted records".into(),
            ));
        }
    }
    Ok(())
}

fn validate_predicate(predicate: &Predicate, depth: usize) -> Result<()> {
    if depth > 32 {
        return Err(StoreError::InvalidInput(
            "predicate nesting is too deep".into(),
        ));
    }
    match predicate {
        Predicate::And { predicates } | Predicate::Or { predicates } => {
            if predicates.is_empty() || predicates.len() > 256 {
                return Err(StoreError::InvalidInput(
                    "logical predicate has invalid arity".into(),
                ));
            }
            for child in predicates {
                validate_predicate(child, depth + 1)?;
            }
        }
        Predicate::ClientProtected { marker } if marker.is_empty() || marker.len() > 1024 => {
            return Err(StoreError::InvalidInput(
                "invalid protected field marker".into(),
            ));
        }
        Predicate::BlindToken { .. } => {
            return Err(StoreError::InvalidInput(
                "blind-token queries are unavailable until a leakage-reviewed token format is implemented".into(),
            ));
        }
        Predicate::Eq { field, value } | Predicate::Ne { field, value } => {
            validate_field_value(*field, value, false)?;
        }
        Predicate::Lt { field, value }
        | Predicate::Le { field, value }
        | Predicate::Gt { field, value }
        | Predicate::Ge { field, value } => {
            validate_field_value(*field, value, true)?;
        }
        _ => {}
    }
    Ok(())
}

fn validate_field_value(field: MetadataField, value: &QueryValue, ordered: bool) -> Result<()> {
    let valid_type = matches!(
        (field, value),
        (
            MetadataField::DocumentId | MetadataField::KeyId,
            QueryValue::String(_)
        ) | (
            MetadataField::Version
                | MetadataField::CreatedSequence
                | MetadataField::ModifiedSequence
                | MetadataField::KeyVersion,
            QueryValue::Number(_)
        ) | (MetadataField::Deleted, QueryValue::Bool(_))
    );
    if !valid_type || (ordered && matches!(value, QueryValue::Bool(_))) {
        return Err(StoreError::InvalidInput(
            "predicate value type is incompatible with its field/operator".into(),
        ));
    }
    if matches!(value, QueryValue::String(value) if value.len() > 1024 || value.contains('\0')) {
        return Err(StoreError::InvalidInput(
            "invalid query string value".into(),
        ));
    }
    Ok(())
}

pub(crate) fn field_value(record: &DocumentRecord, field: MetadataField) -> Option<QueryValue> {
    let metadata = &record.metadata;
    match field {
        MetadataField::DocumentId => Some(QueryValue::String(metadata.id.clone())),
        MetadataField::Version => Some(QueryValue::Number(metadata.version)),
        MetadataField::CreatedSequence => Some(QueryValue::Number(metadata.created_sequence)),
        MetadataField::ModifiedSequence => Some(QueryValue::Number(metadata.modified_sequence)),
        MetadataField::Deleted => Some(QueryValue::Bool(metadata.deleted)),
        MetadataField::KeyId => record
            .payload
            .as_ref()
            .map(|value| QueryValue::String(value.key_id.clone())),
        MetadataField::KeyVersion => record
            .payload
            .as_ref()
            .map(|value| QueryValue::Number(u64::from(value.key_version))),
    }
}

pub(crate) fn matches_server(record: &DocumentRecord, predicate: &Predicate) -> bool {
    match predicate {
        Predicate::Eq { field, value } => field_value(record, *field).as_ref() == Some(value),
        Predicate::Ne { field, value } => field_value(record, *field)
            .as_ref()
            .is_some_and(|actual| actual != value),
        Predicate::Lt { field, value } => {
            compare_value(field_value(record, *field).as_ref(), value) == Some(Ordering::Less)
        }
        Predicate::Le { field, value } => matches!(
            compare_value(field_value(record, *field).as_ref(), value),
            Some(Ordering::Less | Ordering::Equal)
        ),
        Predicate::Gt { field, value } => {
            compare_value(field_value(record, *field).as_ref(), value) == Some(Ordering::Greater)
        }
        Predicate::Ge { field, value } => matches!(
            compare_value(field_value(record, *field).as_ref(), value),
            Some(Ordering::Greater | Ordering::Equal)
        ),
        Predicate::Exists { field, exists } => field_value(record, *field).is_some() == *exists,
        Predicate::And { predicates } => {
            predicates.iter().all(|value| matches_server(record, value))
        }
        Predicate::Or { predicates } => {
            predicates.iter().any(|value| matches_server(record, value))
        }
        Predicate::ClientProtected { .. } => true,
        Predicate::BlindToken { .. } => false,
    }
}

pub(crate) fn requires_client_filter(predicate: &Predicate) -> bool {
    match predicate {
        Predicate::ClientProtected { .. } => true,
        Predicate::And { predicates } | Predicate::Or { predicates } => {
            predicates.iter().any(requires_client_filter)
        }
        _ => false,
    }
}

pub(crate) fn compare_records(
    left: &DocumentRecord,
    right: &DocumentRecord,
    clauses: &[OrderingClause],
) -> Ordering {
    for clause in clauses {
        let order = compare_optional(
            field_value(left, clause.field).as_ref(),
            field_value(right, clause.field).as_ref(),
        );
        let order = if clause.direction == Direction::Descending {
            order.reverse()
        } else {
            order
        };
        if order != Ordering::Equal {
            return order;
        }
    }
    left.metadata.id.cmp(&right.metadata.id)
}

fn compare_value(left: Option<&QueryValue>, right: &QueryValue) -> Option<Ordering> {
    left.and_then(|left| match (left, right) {
        (QueryValue::String(left), QueryValue::String(right)) => Some(left.cmp(right)),
        (QueryValue::Number(left), QueryValue::Number(right)) => Some(left.cmp(right)),
        (QueryValue::Bool(left), QueryValue::Bool(right)) => Some(left.cmp(right)),
        _ => None,
    })
}

fn compare_optional(left: Option<&QueryValue>, right: Option<&QueryValue>) -> Ordering {
    match (left, right) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (Some(left), Some(right)) => compare_value(Some(left), right)
            .unwrap_or_else(|| value_rank(left).cmp(&value_rank(right))),
    }
}

fn value_rank(value: &QueryValue) -> u8 {
    match value {
        QueryValue::Bool(_) => 1,
        QueryValue::Number(_) => 2,
        QueryValue::String(_) => 3,
    }
}

pub(crate) fn cursor_for(record: &DocumentRecord, clauses: &[OrderingClause]) -> Result<String> {
    let order = clauses
        .iter()
        .map(|clause| field_value(record, clause.field))
        .collect();
    let bytes = serde_json::to_vec(&Cursor {
        order,
        id: record.metadata.id.clone(),
    })
    .map_err(|error| StoreError::Storage(error.to_string()))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

pub(crate) fn decode_cursor(encoded: &str) -> Result<(Vec<Option<QueryValue>>, String)> {
    // Base64 expands by at most 4/3. Reject before decoding so a hostile cursor
    // cannot force an allocation larger than the decoded cursor budget.
    if encoded.len() > (16_usize * 1024 * 4).div_ceil(3) {
        return Err(StoreError::InvalidInput("query cursor is too large".into()));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| StoreError::InvalidInput("invalid query cursor encoding".into()))?;
    if bytes.len() > 16 * 1024 {
        return Err(StoreError::InvalidInput("query cursor is too large".into()));
    }
    let cursor: Cursor = serde_json::from_slice(&bytes)
        .map_err(|_| StoreError::InvalidInput("invalid query cursor".into()))?;
    Ok((cursor.order, cursor.id))
}

pub(crate) fn is_after_cursor(
    record: &DocumentRecord,
    clauses: &[OrderingClause],
    values: &[Option<QueryValue>],
    id: &str,
) -> bool {
    for (index, clause) in clauses.iter().enumerate() {
        let actual = field_value(record, clause.field);
        let expected = values.get(index).and_then(Option::as_ref);
        let mut order = compare_optional(actual.as_ref(), expected);
        if clause.direction == Direction::Descending {
            order = order.reverse();
        }
        if order != Ordering::Equal {
            return order == Ordering::Greater;
        }
    }
    record.metadata.id.as_str() > id
}

pub(crate) fn equality_constraints(
    predicate: &Predicate,
    output: &mut BTreeMap<MetadataField, QueryValue>,
) {
    match predicate {
        Predicate::Eq { field, value } => {
            output.insert(*field, value.clone());
        }
        Predicate::And { predicates } => {
            for predicate in predicates {
                equality_constraints(predicate, output);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod hardening_tests {
    use super::*;

    #[test]
    fn oversized_cursor_is_rejected_before_base64_decode() {
        let oversized = "A".repeat((16_usize * 1024 * 4).div_ceil(3) + 1);
        assert!(decode_cursor(&oversized).is_err());
    }
}
