use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("SQLite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("No lockfile found in current directory or subdirectories")]
    NoLockfileFound,

    #[error("Unsupported lockfile format: {0}")]
    UnsupportedFormat(String),

    #[error("Registry error for {ecosystem}/{package}: {message}")]
    RegistryError {
        ecosystem: String,
        package: String,
        message: String,
    },

    #[error("Cache error: {0}")]
    CacheError(String),

    #[error("Parse error: {0}")]
    ParseError(String),
}

pub type Result<T> = std::result::Result<T, Error>;
