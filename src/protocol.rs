use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::{
    error::{Result, StoreError},
    model::{EncryptedDocument, MutationRecord, VerifyReport, VersionPrecondition},
    operations::DatabaseStatus,
    query::{ExplainPlan, IndexDefinition, Query, QueryResult},
    store::Store,
};

pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Precondition {
    Any,
    MustNotExist,
    MustExist,
    IfVersion(u64),
}

impl From<Precondition> for VersionPrecondition {
    fn from(value: Precondition) -> Self {
        match value {
            Precondition::Any => Self::Any,
            Precondition::MustNotExist => Self::MustNotExist,
            Precondition::MustExist => Self::MustExist,
            Precondition::IfVersion(version) => Self::IfVersion(version),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PutDocumentRequest {
    pub document: EncryptedDocument,
    pub precondition: Precondition,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteDocumentRequest {
    pub version: u64,
    pub precondition: Precondition,
}

#[derive(Debug, Clone)]
pub enum ProtocolRequest {
    GetDocument {
        collection: String,
        id: String,
    },
    PutDocument(PutDocumentRequest),
    DeleteDocument {
        collection: String,
        id: String,
        request: DeleteDocumentRequest,
    },
    Query(Query),
    Explain(Query),
    Verify,
    ListIndexes {
        collection: String,
    },
    CreateIndex(IndexDefinition),
    DropIndex {
        collection: String,
        name: String,
    },
    RebuildIndex {
        collection: String,
        name: String,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum ProtocolResponse {
    Document(Option<EncryptedDocument>),
    Mutation(MutationRecord),
    Query(QueryResult),
    Explain(ExplainPlan),
    Verify(VerifyReport),
    Indexes(Vec<IndexDefinition>),
    Empty,
}

#[derive(Clone)]
pub struct DatabaseService {
    store: Arc<Store>,
    operations: Arc<Semaphore>,
}

impl DatabaseService {
    pub fn new(store: Arc<Store>) -> Self {
        Self {
            store,
            operations: Arc::new(Semaphore::new(128)),
        }
    }

    pub(crate) fn with_max_concurrent_operations(mut self, limit: usize) -> Self {
        self.operations = Arc::new(Semaphore::new(limit));
        self
    }

    pub async fn execute(&self, request: ProtocolRequest) -> Result<ProtocolResponse> {
        let permit = Arc::clone(&self.operations)
            .acquire_owned()
            .await
            .map_err(|_| StoreError::Storage("database operation admission closed".into()))?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            execute_sync(&store, request)
        })
        .await
        .map_err(|error| StoreError::Storage(format!("database task failed: {error}")))?
    }

    pub fn readiness(&self) -> Result<()> {
        self.store.metadata().map(|_| ())
    }

    pub async fn status(&self) -> Result<DatabaseStatus> {
        let permit = Arc::clone(&self.operations)
            .acquire_owned()
            .await
            .map_err(|_| StoreError::Storage("database operation admission closed".into()))?;
        let store = Arc::clone(&self.store);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            store.status()
        })
        .await
        .map_err(|error| StoreError::Storage(format!("database status task failed: {error}")))?
    }
}

fn execute_sync(store: &Store, request: ProtocolRequest) -> Result<ProtocolResponse> {
    match request {
        ProtocolRequest::GetDocument { collection, id } => {
            Ok(ProtocolResponse::Document(store.get(&collection, &id)?))
        }
        ProtocolRequest::PutDocument(request) => Ok(ProtocolResponse::Mutation(
            store.put_if(&request.document, request.precondition.into())?,
        )),
        ProtocolRequest::DeleteDocument {
            collection,
            id,
            request,
        } => Ok(ProtocolResponse::Mutation(store.delete(
            &collection,
            &id,
            request.version,
            request.precondition.into(),
        )?)),
        ProtocolRequest::Query(query) => Ok(ProtocolResponse::Query(store.query(&query)?)),
        ProtocolRequest::Explain(query) => Ok(ProtocolResponse::Explain(store.explain(&query)?)),
        ProtocolRequest::Verify => Ok(ProtocolResponse::Verify(store.verify()?)),
        ProtocolRequest::ListIndexes { collection } => {
            Ok(ProtocolResponse::Indexes(store.list_indexes(&collection)?))
        }
        ProtocolRequest::CreateIndex(index) => {
            store.create_index(&index)?;
            Ok(ProtocolResponse::Empty)
        }
        ProtocolRequest::DropIndex { collection, name } => {
            store.drop_index(&collection, &name)?;
            Ok(ProtocolResponse::Empty)
        }
        ProtocolRequest::RebuildIndex { collection, name } => {
            store.rebuild_index(&collection, &name)?;
            Ok(ProtocolResponse::Empty)
        }
    }
}
