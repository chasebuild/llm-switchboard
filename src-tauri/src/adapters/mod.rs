use async_trait::async_trait;

use crate::ProxyKey;

pub struct AdapterResponse {
    pub status: axum::http::StatusCode,
    pub body: bytes::Bytes,
    pub content_type: String,
}

pub struct AdapterStreamResponse {
    pub status: axum::http::StatusCode,
    pub body: axum::body::Body,
    pub content_type: String,
}

#[async_trait]
pub trait Adapter: Send + Sync {
    fn name(&self) -> &'static str;
    fn supports_stream(&self) -> bool;
    async fn forward_request(
        &self,
        client: &reqwest::Client,
        key: &ProxyKey,
        payload: &serde_json::Value,
        model: &str,
    ) -> Result<AdapterResponse, String>;
    async fn forward_stream(
        &self,
        client: &reqwest::Client,
        key: &ProxyKey,
        payload: &serde_json::Value,
        model: &str,
    ) -> Result<AdapterStreamResponse, String>;
}

mod openai;
mod google;

use google::GoogleAiStudioAdapter;
use openai::OpenAiAdapter;

static OPENAI_ADAPTER: OpenAiAdapter = OpenAiAdapter;
static OPENROUTER_ADAPTER: OpenAiAdapter = OpenAiAdapter;
static GOOGLE_ADAPTER: GoogleAiStudioAdapter = GoogleAiStudioAdapter;

pub fn adapter_for(name: &str) -> Option<&'static dyn Adapter> {
    match name {
        "openai" => Some(&OPENAI_ADAPTER),
        "openrouter" => Some(&OPENROUTER_ADAPTER),
        "google_ai_studio" => Some(&GOOGLE_ADAPTER),
        _ => None,
    }
}
