use axum::{
    Json, Router,
    body::Bytes,
    extract::{Extension, Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::{
    error::StoreError,
    network::{ApiError, AppState, RequestContext},
    protocol::{
        DatabaseService, DeleteDocumentRequest, PROTOCOL_VERSION, ProtocolRequest,
        ProtocolResponse, PutDocumentRequest,
    },
    query::{IndexDefinition, Query},
};

pub(crate) fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health))
        .route("/readyz", get(readiness))
        .route(
            "/v1/documents/{collection}/{id}",
            get(get_document).put(put_document).delete(delete_document),
        )
        .route("/v1/query", post(query))
        .route("/v1/explain", post(explain))
        .route("/v1/verify", get(verify))
        .route("/v1/metrics", get(metrics))
        .route(
            "/v1/indexes/{collection}",
            get(list_indexes).post(create_index),
        )
        .route(
            "/v1/indexes/{collection}/{name}",
            delete(drop_index).put(rebuild_index),
        )
        .fallback(not_found)
        .with_state(state)
}

async fn health(Extension(context): Extension<RequestContext>) -> Json<Value> {
    Json(
        json!({"status": "ok", "protocol_version": PROTOCOL_VERSION, "request_id": context.request_id}),
    )
}

async fn readiness(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
) -> Result<Json<Value>, ApiError> {
    state.service.readiness().map_err(|error| {
        ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "not_ready",
            error.to_string(),
            &context.request_id,
        )
    })?;
    Ok(Json(
        json!({"status": "ready", "protocol_version": PROTOCOL_VERSION, "request_id": context.request_id}),
    ))
}

async fn get_document(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path((collection, id)): Path<(String, String)>,
) -> Result<Json<ProtocolResponse>, ApiError> {
    execute(
        &state.service,
        ProtocolRequest::GetDocument { collection, id },
        &context,
    )
    .await
}

async fn put_document(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path((collection, id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<ProtocolResponse>, ApiError> {
    let request: PutDocumentRequest = parse_json(&body, &context)?;
    if request.document.collection != collection || request.document.id != id {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "identity_mismatch",
            "path and encrypted-envelope identity differ",
            context.request_id,
        ));
    }
    execute(
        &state.service,
        ProtocolRequest::PutDocument(request),
        &context,
    )
    .await
}

async fn delete_document(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path((collection, id)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<ProtocolResponse>, ApiError> {
    let request = parse_json::<DeleteDocumentRequest>(&body, &context)?;
    execute(
        &state.service,
        ProtocolRequest::DeleteDocument {
            collection,
            id,
            request,
        },
        &context,
    )
    .await
}

async fn query(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    body: Bytes,
) -> Result<Json<ProtocolResponse>, ApiError> {
    execute(
        &state.service,
        ProtocolRequest::Query(parse_json::<Query>(&body, &context)?),
        &context,
    )
    .await
}

async fn explain(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    body: Bytes,
) -> Result<Json<ProtocolResponse>, ApiError> {
    execute(
        &state.service,
        ProtocolRequest::Explain(parse_json::<Query>(&body, &context)?),
        &context,
    )
    .await
}

async fn verify(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
) -> Result<Json<ProtocolResponse>, ApiError> {
    execute(&state.service, ProtocolRequest::Verify, &context).await
}

async fn metrics(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
) -> Result<impl IntoResponse, ApiError> {
    let status = state
        .service
        .status()
        .await
        .map_err(|error| store_error(error, &context))?;
    let mut output = state.metrics.prometheus();
    output.push_str(&format!(
        "# TYPE vdb_storage_bytes gauge\nvdb_storage_bytes {}\n# TYPE vdb_storage_fragmented_bytes gauge\nvdb_storage_fragmented_bytes {}\n# TYPE vdb_documents gauge\nvdb_documents {}\n# TYPE vdb_tombstones gauge\nvdb_tombstones {}\n# TYPE vdb_mutations_verified gauge\nvdb_mutations_verified {}\n# TYPE vdb_replication_events gauge\nvdb_replication_events {}\n# TYPE vdb_replication_pending_events gauge\nvdb_replication_pending_events {}\n# TYPE vdb_replication_conflicted_documents gauge\nvdb_replication_conflicted_documents {}\n# TYPE vdb_verification_valid gauge\nvdb_verification_valid {}\n",
        status.storage.stored_bytes,
        status.storage.fragmented_bytes,
        status.storage.documents,
        status.storage.tombstones,
        status.verification.signed_mutations_verified,
        status.replication.events,
        status.replication.pending_events,
        status.replication.conflicted_documents,
        u8::from(status.verification.valid),
    ));
    Ok((
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        output,
    ))
}

async fn list_indexes(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path(collection): Path<String>,
) -> Result<Json<ProtocolResponse>, ApiError> {
    execute(
        &state.service,
        ProtocolRequest::ListIndexes { collection },
        &context,
    )
    .await
}

async fn create_index(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path(collection): Path<String>,
    body: Bytes,
) -> Result<Json<ProtocolResponse>, ApiError> {
    let index = parse_json::<IndexDefinition>(&body, &context)?;
    if index.collection != collection {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "identity_mismatch",
            "path and index collection differ",
            context.request_id,
        ));
    }
    execute(
        &state.service,
        ProtocolRequest::CreateIndex(index),
        &context,
    )
    .await
}

async fn drop_index(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path((collection, name)): Path<(String, String)>,
) -> Result<Json<ProtocolResponse>, ApiError> {
    execute(
        &state.service,
        ProtocolRequest::DropIndex { collection, name },
        &context,
    )
    .await
}

async fn rebuild_index(
    State(state): State<AppState>,
    Extension(context): Extension<RequestContext>,
    Path((collection, name)): Path<(String, String)>,
) -> Result<Json<ProtocolResponse>, ApiError> {
    execute(
        &state.service,
        ProtocolRequest::RebuildIndex { collection, name },
        &context,
    )
    .await
}

async fn not_found(Extension(context): Extension<RequestContext>) -> ApiError {
    ApiError::new(
        StatusCode::NOT_FOUND,
        "not_found",
        "route does not exist",
        context.request_id,
    )
}

fn parse_json<T: DeserializeOwned>(body: &[u8], context: &RequestContext) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| {
        ApiError::new(
            StatusCode::BAD_REQUEST,
            "malformed_json",
            "request body is not valid for this operation",
            &context.request_id,
        )
    })
}

async fn execute(
    service: &DatabaseService,
    request: ProtocolRequest,
    context: &RequestContext,
) -> Result<Json<ProtocolResponse>, ApiError> {
    service
        .execute(request)
        .await
        .map(Json)
        .map_err(|error| store_error(error, context))
}

fn store_error(error: StoreError, context: &RequestContext) -> ApiError {
    let (status, code, message) = match error {
        StoreError::InvalidInput(message) => (StatusCode::BAD_REQUEST, "invalid_input", message),
        StoreError::Conflict { .. } => (StatusCode::CONFLICT, "conflict", error.to_string()),
        StoreError::UnsupportedFormat { .. }
        | StoreError::Corruption(_)
        | StoreError::Storage(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_error",
            "internal server error".into(),
        ),
    };
    ApiError::new(status, code, message, &context.request_id)
}
