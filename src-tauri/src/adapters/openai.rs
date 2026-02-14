use async_trait::async_trait;
use futures_util::StreamExt;

use super::{Adapter, AdapterResponse, AdapterStreamResponse};
use crate::ProxyKey;

pub struct OpenAiAdapter;

#[async_trait]
impl Adapter for OpenAiAdapter {
    fn name(&self) -> &'static str {
        "openai"
    }

    fn supports_stream(&self) -> bool {
        true
    }

    async fn forward_request(
        &self,
        client: &reqwest::Client,
        key: &ProxyKey,
        payload: &serde_json::Value,
        model: &str,
    ) -> Result<AdapterResponse, String> {
        let base_url = key.record.base_url.trim_end_matches('/');
        let url = format!("{}/v1/chat/completions", base_url);
        let mut body = payload.clone();
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::Value::String(model.to_string()));
        }
        let response = client
            .post(url)
            .bearer_auth(&key.secret)
            .json(&body)
            .send()
            .await
            .map_err(|err| format!("Request failed: {err}"))?;

        let status = axum::http::StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/json")
            .to_string();
        let body = response
            .bytes()
            .await
            .map_err(|err| format!("Failed to read response: {err}"))?;

        Ok(AdapterResponse {
            status,
            body,
            content_type,
        })
    }

    async fn forward_stream(
        &self,
        client: &reqwest::Client,
        key: &ProxyKey,
        payload: &serde_json::Value,
        model: &str,
    ) -> Result<AdapterStreamResponse, String> {
        let base_url = key.record.base_url.trim_end_matches('/');
        let url = format!("{}/v1/chat/completions", base_url);
        let mut body = payload.clone();
        if let Some(obj) = body.as_object_mut() {
            obj.insert("model".to_string(), serde_json::Value::String(model.to_string()));
            obj.insert("stream".to_string(), serde_json::Value::Bool(true));
        }
        let response = client
            .post(url)
            .bearer_auth(&key.secret)
            .json(&body)
            .send()
            .await
            .map_err(|err| format!("Request failed: {err}"))?;

        let status = axum::http::StatusCode::from_u16(response.status().as_u16())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
        let content_type = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("text/event-stream")
            .to_string();

        let stream = response.bytes_stream().map(|chunk| {
            chunk.map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))
        });
        let body = axum::body::Body::from_stream(stream);

        Ok(AdapterStreamResponse {
            status,
            body,
            content_type,
        })
    }
}
