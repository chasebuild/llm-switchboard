use async_trait::async_trait;

use super::{Adapter, AdapterResponse, AdapterStreamResponse};
use crate::{current_epoch_seconds, ProxyKey};

pub struct GoogleAiStudioAdapter;

#[async_trait]
impl Adapter for GoogleAiStudioAdapter {
    fn name(&self) -> &'static str {
        "google_ai_studio"
    }

    fn supports_stream(&self) -> bool {
        false
    }

    async fn forward_request(
        &self,
        client: &reqwest::Client,
        key: &ProxyKey,
        payload: &serde_json::Value,
        model: &str,
    ) -> Result<AdapterResponse, String> {
        let base_url = key.record.base_url.trim_end_matches('/');
        let url = format!("{}/v1beta/models/{}:generateContent", base_url, model);

        let (contents, generation) = openai_to_gemini(payload);
        let body = serde_json::json!({
            "contents": contents,
            "generationConfig": generation
        });

        let response = client
            .post(url)
            .query(&[("key", key.secret.as_str())])
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

        let bytes = response
            .bytes()
            .await
            .map_err(|err| format!("Failed to read response: {err}"))?;

        if !status.is_success() {
            return Ok(AdapterResponse {
                status,
                body: bytes,
                content_type,
            });
        }

        let response_json: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|err| format!("Failed to parse provider response: {err}"))?;
        let text = response_json
            .get("candidates")
            .and_then(|value| value.as_array())
            .and_then(|arr| arr.first())
            .and_then(|value| value.get("content"))
            .and_then(|value| value.get("parts"))
            .and_then(|value| value.as_array())
            .and_then(|arr| arr.first())
            .and_then(|value| value.get("text"))
            .and_then(|value| value.as_str())
            .unwrap_or("");

        let output = serde_json::json!({
            "id": format!("chatcmpl-{}", uuid::Uuid::new_v4()),
            "object": "chat.completion",
            "created": current_epoch_seconds(),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": text
                    },
                    "finish_reason": "stop"
                }
            ],
            "usage": {
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "total_tokens": 0
            }
        });
        let output_bytes = serde_json::to_vec(&output)
            .map_err(|err| format!("Failed to serialize proxy response: {err}"))?;
        Ok(AdapterResponse {
            status,
            body: bytes::Bytes::from(output_bytes),
            content_type: "application/json".to_string(),
        })
    }

    async fn forward_stream(
        &self,
        _client: &reqwest::Client,
        _key: &ProxyKey,
        _payload: &serde_json::Value,
        _model: &str,
    ) -> Result<AdapterStreamResponse, String> {
        Err("Streaming not supported for this adapter".to_string())
    }
}

fn openai_to_gemini(payload: &serde_json::Value) -> (Vec<serde_json::Value>, serde_json::Value) {
    let mut contents = Vec::new();
    let mut buffer = Vec::new();
    if let Some(messages) = payload.get("messages").and_then(|value| value.as_array()) {
        for message in messages {
            let role = message
                .get("role")
                .and_then(|value| value.as_str())
                .unwrap_or("user");
            let content = message
                .get("content")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let original_role = role;
            let role = match role {
                "assistant" => "model",
                "system" => "user",
                _ => "user",
            };
            let text = if original_role == "system" {
                format!("System: {}", content)
            } else {
                content.to_string()
            };
            buffer.push(serde_json::json!({
                "role": role,
                "parts": [
                    { "text": text }
                ]
            }));
        }
    }
    if !buffer.is_empty() {
        contents.extend(buffer);
    }

    let mut generation = serde_json::json!({});
    if let Some(max_tokens) = payload.get("max_tokens").and_then(|v| v.as_u64()) {
        generation["maxOutputTokens"] = serde_json::Value::Number(max_tokens.into());
    }
    if let Some(temperature) = payload.get("temperature").and_then(|v| v.as_f64()) {
        if let Some(num) = serde_json::Number::from_f64(temperature) {
            generation["temperature"] = serde_json::Value::Number(num);
        }
    }

    (contents, generation)
}
