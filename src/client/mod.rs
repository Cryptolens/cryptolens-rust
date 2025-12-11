use serde::Serialize;

use crate::Error;

pub type Result<T> = std::result::Result<T, Error>;

pub type Timestamp = u64;

mod key;

pub use key::*;

#[derive(Debug, Default)]
pub struct Client {
    client: reqwest::Client,
}

impl Client {
    pub fn new() -> Self {
        Self::default()
    }
}

impl TryFrom<reqwest::ClientBuilder> for Client {
    type Error = Error;

    fn try_from(builder: reqwest::ClientBuilder) -> Result<Self> {
        let client = builder.build()?;
        Ok(Self { client })
    }
}

#[derive(Serialize)]
struct TokenizedParams<'a, T: Serialize> {
    token: &'a str,
    #[serde(flatten)]
    params: T,
}
