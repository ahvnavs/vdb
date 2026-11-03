use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, put},
};
use serde_json::{Value, json};

use crate::{error::StoreError, model::EncryptedDocument, store::Store};

pub fn router(store: Arc<Store>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/v1/{collection}/{id}", put(put_doc).get(get_doc))
        .route("/v1/verify", get(verify))
        .layer(axum::extract::DefaultBodyLimit::max(4 * 1024 * 1024))
        .with_state(store)
}

async fn health() -> Json<Value> {
    Json(json!({"status": "ok"}))
}

async fn put_doc(
    State(store): State<Arc<Store>>,
    Path((collection, id)): Path<(String, String)>,
    Json(mut doc): Json<EncryptedDocument>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    if doc.collection != collection || doc.id != id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "path and envelope identity differ"})),
        ));
    }
    doc.collection = collection;
    doc.id = id;
    store
        .put(&doc)
        .map(|m| Json(json!({"ok": true, "mutation": m})))
        .map_err(internal)
}

async fn get_doc(
    State(store): State<Arc<Store>>,
    Path((collection, id)): Path<(String, String)>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    match store.get(&collection, &id).map_err(internal)? {
        Some(doc) => Ok(Json(json!(doc))),
        None => Err((StatusCode::NOT_FOUND, Json(json!({"error": "not found"})))),
    }
}

async fn verify(State(store): State<Arc<Store>>) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    store.verify().map(|r| Json(json!(r))).map_err(internal)
}

fn internal(err: StoreError) -> (StatusCode, Json<Value>) {
    eprintln!("request failed: {err:#}");
    let (status, message) = match &err {
        StoreError::Conflict { .. } => (StatusCode::CONFLICT, err.to_string()),
        StoreError::InvalidInput(_) => (StatusCode::BAD_REQUEST, err.to_string()),
        _ => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal server error".to_owned(),
        ),
    };
    (status, Json(json!({"error": message})))
}
