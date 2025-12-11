use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("ssl error: {0}")]
    Ssl(#[from] openssl::error::ErrorStack),

    #[error("http client error: {0}")]
    Client(#[from] reqwest::Error),

    #[error("api error: {0}")]
    Api(String),

    #[error("base64 decoding error: {0}")]
    Decode(#[from] base64::DecodeError),

    #[error("json (de)serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("xml (de)serialization error: {0}")]
    Xml(#[from] serde_xml_rs::Error),

    #[error("custom error: {0}")]
    Custom(String),

    #[error("missing field error: {0}")]
    UninitializedField(#[from] derive_builder::UninitializedFieldError),
}
