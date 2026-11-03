use thiserror::Error;

pub type Result<T> = std::result::Result<T, StoreError>;

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("write conflict for {collection}/{id}: expected {expected}, found {actual}")]
    Conflict {
        collection: String,
        id: String,
        expected: String,
        actual: String,
    },
    #[error("unsupported database format {found}; supported format is {supported}")]
    UnsupportedFormat { found: u32, supported: u32 },
    #[error("database corruption detected: {0}")]
    Corruption(String),
    #[error("storage failure: {0}")]
    Storage(String),
}

impl StoreError {
    pub fn is_corruption(&self) -> bool {
        matches!(self, Self::Corruption(_))
    }
    pub fn is_recoverable(&self) -> bool {
        matches!(self, Self::InvalidInput(_) | Self::Conflict { .. })
    }
}

pub(crate) fn storage(error: impl std::fmt::Display) -> StoreError {
    StoreError::Storage(error.to_string())
}
pub(crate) fn corruption(error: impl std::fmt::Display) -> StoreError {
    StoreError::Corruption(error.to_string())
}
