use axum::{
    extract::{Json, State as AxumState},
    response::IntoResponse,
    routing::{get, post},
    Router,
};
use futures_util::StreamExt;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, State};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use uuid::Uuid;

const SOURCE_URL: &str =
    "https://raw.githubusercontent.com/cheahjs/free-llm-api-resources/main/README.md";
const KEYRING_SERVICE: &str = "freellm-switchboard";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Limits {
    rpm: Option<u32>,
    tpm: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Provider {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    notes: Vec<String>,
    #[serde(default)]
    base_urls: Vec<String>,
    models: Vec<String>,
    limits: Limits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderConfig {
    source_url: String,
    fetched_at: u64,
    providers: Vec<Provider>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncResult {
    config: ProviderConfig,
    new_providers: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
struct KeyRecord {
    id: String,
    provider: String,
    label: String,
    base_url: String,
    #[serde(default = "default_adapter")]
    adapter: String,
    #[serde(default)]
    models: Vec<String>,
    #[serde(default)]
    default_model: Option<String>,
    #[serde(default)]
    model_map: Vec<ModelMap>,
    status: String,
    last_checked: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct KeyList {
    keys: Vec<KeyRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AddKeyPayload {
    provider: String,
    label: String,
    base_url: String,
    adapter: String,
    models: Vec<String>,
    default_model: Option<String>,
    model_map: Vec<ModelMap>,
    secret: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RemoveKeyPayload {
    id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProxyStatus {
    running: bool,
    address: Option<String>,
}

#[derive(Default)]
struct AppState {
    proxy: Mutex<Option<ProxyHandle>>,
    logs: Arc<Mutex<Vec<ProxyLog>>>,
    usage: Arc<Mutex<HashMap<String, UsageWindow>>>,
}

struct ProxyHandle {
    address: SocketAddr,
    shutdown: tokio::sync::oneshot::Sender<()>,
    task: JoinHandle<()>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProxyLog {
    timestamp: u64,
    level: String,
    message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ModelMap {
    from: String,
    to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UsageWindow {
    minute: u64,
    requests: u32,
}

#[derive(Clone)]
struct ProxyState {
    key_path: PathBuf,
    usage_path: PathBuf,
    logs: Arc<Mutex<Vec<ProxyLog>>>,
    usage: Arc<Mutex<HashMap<String, UsageWindow>>>,
    client: reqwest::Client,
}

#[tauri::command]
async fn sync_providers(app: AppHandle) -> Result<SyncResult, String> {
    let markdown = fetch_markdown().await?;
    let providers = parse_markdown(&markdown);
    let config = ProviderConfig {
        source_url: SOURCE_URL.to_string(),
        fetched_at: current_epoch_seconds(),
        providers,
    };

    let previous = read_config(&app).ok().flatten();
    let new_providers = diff_new_providers(previous.as_ref(), &config);

    write_config(&app, &config)?;
    Ok(SyncResult { config, new_providers })
}

#[tauri::command]
fn load_cached_config(app: AppHandle) -> Result<Option<ProviderConfig>, String> {
    read_config(&app)
}

#[tauri::command]
fn list_keys(app: AppHandle) -> Result<Vec<KeyRecord>, String> {
    Ok(read_keys(&app)?.unwrap_or_default().keys)
}

#[tauri::command]
fn add_key(app: AppHandle, payload: AddKeyPayload) -> Result<KeyRecord, String> {
    let mut list = read_keys(&app)?.unwrap_or_default();
    let id = Uuid::new_v4().to_string();
    let label = if payload.label.trim().is_empty() {
        "Default".to_string()
    } else {
        payload.label.trim().to_string()
    };

    let record = KeyRecord {
        id: id.clone(),
        provider: payload.provider.trim().to_string(),
        label,
        base_url: payload.base_url.trim().to_string(),
        adapter: payload.adapter.trim().to_string(),
        models: payload
            .models
            .into_iter()
            .map(|model| model.trim().to_string())
            .filter(|model| !model.is_empty())
            .collect(),
        default_model: payload
            .default_model
            .map(|model| model.trim().to_string())
            .filter(|model| !model.is_empty()),
        model_map: payload
            .model_map
            .into_iter()
            .map(|map| ModelMap {
                from: map.from.trim().to_string(),
                to: map.to.trim().to_string(),
            })
            .filter(|map| !map.from.is_empty() && !map.to.is_empty())
            .collect(),
        status: "Stored".to_string(),
        last_checked: None,
    };

    let username = format!("{}:{}", record.provider, record.id);
    let entry = keyring::Entry::new(KEYRING_SERVICE, &username)
        .map_err(|err| format!("Failed to create keyring entry: {err}"))?;
    entry
        .set_password(&payload.secret)
        .map_err(|err| format!("Failed to store key: {err}"))?;

    list.keys.push(record.clone());
    write_keys(&app, &list)?;
    Ok(record)
}

#[tauri::command]
fn remove_key(app: AppHandle, payload: RemoveKeyPayload) -> Result<(), String> {
    let mut list = read_keys(&app)?.unwrap_or_default();
    let Some(pos) = list.keys.iter().position(|record| record.id == payload.id) else {
        return Ok(());
    };
    let record = list.keys.remove(pos);
    write_keys(&app, &list)?;

    let username = format!("{}:{}", record.provider, record.id);
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &username) {
        let _ = entry.delete_password();
    }
    Ok(())
}

#[tauri::command]
async fn check_key(app: AppHandle, id: String) -> Result<KeyRecord, String> {
    let mut list = read_keys(&app)?.unwrap_or_default();
    let record = list
        .keys
        .iter_mut()
        .find(|record| record.id == id)
        .ok_or_else(|| "Key not found".to_string())?;

    let username = format!("{}:{}", record.provider, record.id);
    let entry = keyring::Entry::new(KEYRING_SERVICE, &username)
        .map_err(|err| format!("Failed to open keyring entry: {err}"))?;
    let secret = match entry.get_password() {
        Ok(secret) => secret,
        Err(_) => {
            record.status = "Missing".to_string();
            record.last_checked = Some(current_epoch_seconds());
            write_keys(&app, &list)?;
            return Ok(record.clone());
        }
    };

    let base_url = record.base_url.trim();
    if base_url.is_empty() {
        record.status = "MissingBaseUrl".to_string();
        record.last_checked = Some(current_epoch_seconds());
        write_keys(&app, &list)?;
        return Ok(record.clone());
    }

    let adapter = record.adapter.trim().to_lowercase();
    let client = reqwest::Client::new();
    let status = match adapter.as_str() {
        "openai" | "openrouter" => {
            let models_url = format!("{}/v1/models", base_url.trim_end_matches('/'));
            match client
                .get(models_url)
                .bearer_auth(&secret)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => "Active",
                Ok(resp) if resp.status().as_u16() == 401 => "Unauthorized",
                Ok(resp) if resp.status().as_u16() == 403 => "Forbidden",
                Ok(resp) if resp.status().as_u16() == 404 => {
                    let test_model = record
                        .default_model
                        .clone()
                        .or_else(|| record.models.first().cloned());
                    if let Some(model) = test_model {
                        let chat_url =
                            format!("{}/v1/chat/completions", base_url.trim_end_matches('/'));
                        let payload = serde_json::json!({
                            "model": model,
                            "messages": [
                                { "role": "user", "content": "ping" }
                            ],
                            "max_tokens": 1
                        });
                        match client
                            .post(chat_url)
                            .bearer_auth(&secret)
                            .json(&payload)
                            .send()
                            .await
                        {
                            Ok(resp) if resp.status().is_success() => "Active",
                            Ok(resp) if resp.status().as_u16() == 401 => "Unauthorized",
                            Ok(resp) if resp.status().as_u16() == 403 => "Forbidden",
                            Ok(resp) => {
                                if resp.status().as_u16() == 429 {
                                    "RateLimited"
                                } else {
                                    "Error"
                                }
                            }
                            Err(_) => "Error",
                        }
                    } else {
                        "NeedsModel"
                    }
                }
                Ok(resp) => {
                    if resp.status().as_u16() == 429 {
                        "RateLimited"
                    } else {
                        "Error"
                    }
                }
                Err(_) => "Error",
            }
        }
        "google_ai_studio" => {
            let test_model = record
                .default_model
                .clone()
                .or_else(|| record.models.first().cloned());
            if let Some(model) = test_model {
                let url = format!(
                    "{}/v1beta/models/{}:generateContent",
                    base_url.trim_end_matches('/'),
                    model
                );
                let payload = serde_json::json!({
                    "contents": [
                        {
                            "role": "user",
                            "parts": [
                                { "text": "ping" }
                            ]
                        }
                    ]
                });
                match client
                    .post(url)
                    .query(&[("key", secret)])
                    .json(&payload)
                    .send()
                    .await
                {
                    Ok(resp) if resp.status().is_success() => "Active",
                    Ok(resp) if resp.status().as_u16() == 401 => "Unauthorized",
                    Ok(resp) if resp.status().as_u16() == 403 => "Forbidden",
                    Ok(resp) if resp.status().as_u16() == 429 => "RateLimited",
                    Ok(_) => "Error",
                    Err(_) => "Error",
                }
            } else {
                "NeedsModel"
            }
        }
        _ => "UnsupportedAdapter",
    };

    record.status = status.to_string();
    record.last_checked = Some(current_epoch_seconds());
    write_keys(&app, &list)?;
    Ok(record.clone())
}

#[tauri::command]
async fn start_proxy(app: AppHandle, state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    let mut guard = state.proxy.lock().map_err(|_| "Proxy lock poisoned")?;
    if let Some(handle) = guard.as_ref() {
        return Ok(ProxyStatus {
            running: true,
            address: Some(format!("http://{}", handle.address)),
        });
    }

    let key_path = key_list_path(&app)?;
    let usage_path = usage_path(&app)?;
    if let Ok(snapshot) = read_usage(&usage_path) {
        if let Ok(mut usage) = state.usage.lock() {
            *usage = snapshot;
        }
    }
    let listener = TcpListener::bind("127.0.0.1:1234")
        .await
        .map_err(|err| format!("Failed to bind proxy: {err}"))?;
    let address = listener
        .local_addr()
        .map_err(|err| format!("Failed to get proxy address: {err}"))?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let app = proxy_router(ProxyState {
        key_path,
        usage_path,
        logs: state.logs.clone(),
        usage: state.usage.clone(),
        client: reqwest::Client::new(),
    });
    let task = tokio::spawn(async move {
        let server = axum::serve(listener, app);
        let _ = server.with_graceful_shutdown(async move {
            let _ = shutdown_rx.await;
        })
        .await;
    });

    *guard = Some(ProxyHandle {
        address,
        shutdown: shutdown_tx,
        task,
    });

    Ok(ProxyStatus {
        running: true,
        address: Some(format!("http://{}", address)),
    })
}

#[tauri::command]
async fn stop_proxy(state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    let mut guard = state.proxy.lock().map_err(|_| "Proxy lock poisoned")?;
    if let Some(handle) = guard.take() {
        let _ = handle.shutdown.send(());
        let _ = handle.task.await;
    }
    Ok(ProxyStatus {
        running: false,
        address: None,
    })
}

#[tauri::command]
fn proxy_status(state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    let guard = state.proxy.lock().map_err(|_| "Proxy lock poisoned")?;
    if let Some(handle) = guard.as_ref() {
        Ok(ProxyStatus {
            running: true,
            address: Some(format!("http://{}", handle.address)),
        })
    } else {
        Ok(ProxyStatus {
            running: false,
            address: None,
        })
    }
}

#[tauri::command]
fn get_logs(state: State<'_, AppState>) -> Result<Vec<ProxyLog>, String> {
    let guard = state.logs.lock().map_err(|_| "Log lock poisoned")?;
    Ok(guard.clone())
}

#[tauri::command]
fn clear_logs(state: State<'_, AppState>) -> Result<(), String> {
    let mut guard = state.logs.lock().map_err(|_| "Log lock poisoned")?;
    guard.clear();
    Ok(())
}

async fn fetch_markdown() -> Result<String, String> {
    let client = reqwest::Client::new();
    let response = client
        .get(SOURCE_URL)
        .send()
        .await
        .map_err(|err| format!("Failed to fetch providers: {err}"))?;

    let response = response
        .error_for_status()
        .map_err(|err| format!("Provider source returned error: {err}"))?;

    response
        .text()
        .await
        .map_err(|err| format!("Failed to read provider source: {err}"))
}

fn parse_markdown(markdown: &str) -> Vec<Provider> {
    let heading_re = Regex::new(r"^###\s+(.*)$").unwrap();
    let link_re = Regex::new(r"\[([^\]]+)\]\([^)]+\)").unwrap();
    let url_re = Regex::new(r"https?://[^\s)]+").unwrap();
    let rpm_re =
        Regex::new(r"(?i)(\d[\d,]*\s*[kK]?)\s*(rpm|requests per minute)").unwrap();
    let tpm_re =
        Regex::new(r"(?i)(\d[\d,]*\s*[kK]?)\s*(tpm|tokens per minute)").unwrap();

    let mut providers: Vec<Provider> = Vec::new();
    let mut current: Option<Provider> = None;
    let mut in_models = false;
    let mut in_description = false;

    for line in markdown.lines() {
        let trimmed = line.trim();
        if let Some(caps) = heading_re.captures(trimmed) {
            if let Some(provider) = current.take() {
                providers.push(provider);
            }

            let raw_name = caps.get(1).map(|m| m.as_str()).unwrap_or_default();
            let name = clean_heading(raw_name, &link_re);
            current = Some(Provider {
                name,
                description: String::new(),
                notes: Vec::new(),
                base_urls: Vec::new(),
                models: Vec::new(),
                limits: Limits {
                    rpm: None,
                    tpm: None,
                },
            });
            in_models = false;
            in_description = true;
            continue;
        }

        let Some(provider) = current.as_mut() else {
            continue;
        };

        if trimmed.is_empty() {
            in_models = false;
            in_description = false;
        }

        if is_models_heading(trimmed) {
            in_models = true;
            in_description = false;
        }

        if in_description && !trimmed.is_empty() && provider.description.is_empty() {
            provider.description = strip_markdown_links(trimmed).trim().to_string();
        }

        if in_models {
            if let Some(models) = parse_models_line(trimmed) {
                for model in models {
                    push_unique(&mut provider.models, model);
                }
            }
        } else if let Some(models) = parse_models_inline(trimmed) {
            for model in models {
                push_unique(&mut provider.models, model);
            }
        }

        if !trimmed.is_empty() && !in_models && !is_limits_heading(trimmed) {
            if trimmed.starts_with('-') || trimmed.starts_with('*') {
                let note = trimmed
                    .trim_start_matches(&['-', '*'][..])
                    .trim()
                    .to_string();
                if !note.is_empty() {
                    provider.notes.push(strip_markdown_links(&note).trim().to_string());
                }
            }
        }

        for cap in url_re.captures_iter(trimmed) {
            if let Some(url) = cap.get(0).map(|m| m.as_str()) {
                if looks_like_base_url(url) {
                    push_unique(&mut provider.base_urls, url.to_string());
                }
            }
        }

        if provider.limits.rpm.is_none() {
            if let Some(caps) = rpm_re.captures(trimmed) {
                if let Some(value) = caps.get(1).map(|m| m.as_str()) {
                    provider.limits.rpm = parse_number(value);
                }
            }
        }

        if provider.limits.tpm.is_none() {
            if let Some(caps) = tpm_re.captures(trimmed) {
                if let Some(value) = caps.get(1).map(|m| m.as_str()) {
                    provider.limits.tpm = parse_number(value);
                }
            }
        }
    }

    if let Some(provider) = current.take() {
        providers.push(provider);
    }

    providers.retain(|provider| !provider.name.is_empty());
    providers
}

fn clean_heading(raw: &str, link_re: &Regex) -> String {
    if let Some(caps) = link_re.captures(raw) {
        return caps.get(1).map(|m| m.as_str()).unwrap_or(raw).trim().to_string();
    }
    raw.trim().to_string()
}

fn is_models_heading(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.starts_with("models")
        || lower.starts_with("model")
        || lower.contains("supported models")
        || lower.contains("available models")
}

fn is_limits_heading(line: &str) -> bool {
    let lower = line.to_lowercase();
    lower.starts_with("limits") || lower.contains("rate limit")
}

fn parse_models_line(line: &str) -> Option<Vec<String>> {
    if let Some(stripped) = line.strip_prefix("- ") {
        return Some(extract_models(stripped));
    }
    if let Some(stripped) = line.strip_prefix("* ") {
        return Some(extract_models(stripped));
    }
    None
}

fn parse_models_inline(line: &str) -> Option<Vec<String>> {
    let lower = line.to_lowercase();
    if lower.starts_with("models:") || lower.starts_with("model:") {
        let parts: Vec<&str> = line.splitn(2, ':').collect();
        if parts.len() == 2 {
            return Some(extract_models(parts[1]));
        }
    }
    None
}

fn extract_models(raw: &str) -> Vec<String> {
    let mut cleaned = raw.replace('`', "");
    cleaned = cleaned.replace("•", "");
    cleaned = cleaned.replace("·", ",");
    cleaned = cleaned.replace(" / ", ",");

    let mut models = Vec::new();
    for part in cleaned.split(',') {
        let trimmed = strip_markdown_links(part).trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() < 2 {
            continue;
        }
        models.push(trimmed);
    }
    models
}

fn strip_markdown_links(text: &str) -> String {
    let link_re = Regex::new(r"\[([^\]]+)\]\([^)]+\)").unwrap();
    link_re
        .replace_all(text, |caps: &regex::Captures| {
            caps.get(1).map(|m| m.as_str()).unwrap_or("")
        })
        .to_string()
}

fn parse_number(raw: &str) -> Option<u32> {
    let trimmed = raw.trim().replace(',', "");
    if trimmed.is_empty() {
        return None;
    }
    let (value, multiplier) = if let Some(stripped) = trimmed.strip_suffix('k') {
        (stripped, 1_000)
    } else if let Some(stripped) = trimmed.strip_suffix('K') {
        (stripped, 1_000)
    } else {
        (trimmed.as_str(), 1)
    };

    value.trim().parse::<u32>().ok().map(|v| v * multiplier)
}

fn default_adapter() -> String {
    "openai".to_string()
}

fn looks_like_base_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    lower.contains("api")
        || lower.contains("openrouter")
        || lower.contains("generativelanguage")
        || lower.contains("openai")
        || lower.contains("groq")
        || lower.contains("cerebras")
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if list.iter().any(|existing| existing == &value) {
        return;
    }
    list.push(value);
}

fn diff_new_providers(previous: Option<&ProviderConfig>, current: &ProviderConfig) -> Vec<String> {
    let Some(previous) = previous else {
        return current
            .providers
            .iter()
            .map(|provider| provider.name.clone())
            .collect();
    };

    current
        .providers
        .iter()
        .filter(|provider| {
            !previous
                .providers
                .iter()
                .any(|old| old.name == provider.name)
        })
        .map(|provider| provider.name.clone())
        .collect()
}

fn config_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("Failed to resolve app data directory: {err}"))?;
    Ok(dir.join("providers.json"))
}

fn write_config(app: &AppHandle, config: &ProviderConfig) -> Result<(), String> {
    let path = config_path(app)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create config directory: {err}"))?;
    }

    let payload =
        serde_json::to_string_pretty(config).map_err(|err| format!("Serialize failed: {err}"))?;
    fs::write(&path, payload).map_err(|err| format!("Failed to write config: {err}"))
}

fn read_config(app: &AppHandle) -> Result<Option<ProviderConfig>, String> {
    let path = config_path(app)?;
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)
        .map_err(|err| format!("Failed to read config from {}: {err}", path.display()))?;
    let config = serde_json::from_str(&contents)
        .map_err(|err| format!("Failed to parse config: {err}"))?;
    Ok(Some(config))
}

fn current_epoch_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn key_list_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("Failed to resolve app data directory: {err}"))?;
    Ok(dir.join("keys.json"))
}

fn read_keys(app: &AppHandle) -> Result<Option<KeyList>, String> {
    let path = key_list_path(app)?;
    if !path.exists() {
        return Ok(None);
    }
    let contents = fs::read_to_string(&path)
        .map_err(|err| format!("Failed to read keys from {}: {err}", path.display()))?;
    let list = serde_json::from_str(&contents)
        .map_err(|err| format!("Failed to parse keys: {err}"))?;
    Ok(Some(list))
}

fn write_keys(app: &AppHandle, list: &KeyList) -> Result<(), String> {
    let path = key_list_path(app)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create key directory: {err}"))?;
    }
    let payload =
        serde_json::to_string_pretty(list).map_err(|err| format!("Serialize failed: {err}"))?;
    fs::write(&path, payload).map_err(|err| format!("Failed to write keys: {err}"))
}

fn proxy_router(state: ProxyState) -> Router {
    Router::new()
        .route("/health", get(health_check))
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(state)
}

async fn health_check(AxumState(state): AxumState<ProxyState>) -> impl IntoResponse {
    append_log(&state.logs, "info", "Health check ping.");
    Json(serde_json::json!({ "status": "ok" }))
}

async fn chat_completions(
    AxumState(state): AxumState<ProxyState>,
    Json(payload): Json<serde_json::Value>,
) -> impl IntoResponse {
    let model = payload
        .get("model")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());

    let stream = payload
        .get("stream")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let model = model.unwrap_or_else(|| "unknown".to_string());
    let mut keys = match load_keys_for_proxy(&state.key_path) {
        Ok(keys) => keys,
        Err(err) => {
            append_log(&state.logs, "error", &err);
            return (
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": {
                        "message": err,
                        "type": "proxy_error"
                    }
                })),
            );
        }
    };

    if keys.is_empty() {
        append_log(&state.logs, "error", "No keys available for proxy.");
        return (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "message": "No keys available.",
                    "type": "proxy_error"
                }
            })),
        );
    }

    let mut candidates: Vec<ProxyKey> = keys
        .into_iter()
        .filter(|key| key.record.base_url.trim().len() > 0)
        .filter(|key| key_supports_model(key, &model))
        .collect();

    if candidates.is_empty() {
        append_log(
            &state.logs,
            "error",
            &format!("No providers support model {model}."),
        );
        return (
            axum::http::StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "message": format!("No providers support model {model}."),
                    "type": "proxy_error"
                }
            })),
        );
    }

    candidates.sort_by_key(|key| usage_for_key(&state.usage, &key.record.id));

    for key in candidates {
        let adapter = key.record.adapter.trim().to_lowercase();

        if stream {
            match forward_stream_request(&state.client, &key, &payload, &model, &adapter).await {
                Ok((status, stream_body, content_type)) => {
                    if status.as_u16() == 429 {
                        append_log(
                            &state.logs,
                            "warn",
                            &format!(
                                "Rate limited for {}. Trying next key.",
                                key.record.provider
                            ),
                        );
                        continue;
                    }
                    increment_usage(&state.usage, &key.record.id);
                    let _ = persist_usage(&state.usage_path, &state.usage);
                    append_log(
                        &state.logs,
                        "info",
                        &format!(
                            "Streaming request served by {} ({})",
                            key.record.provider, key.record.label
                        ),
                    );
                    let mut response = axum::response::Response::new(stream_body);
                    *response.status_mut() = status;
                    response.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        content_type
                            .parse()
                            .unwrap_or_else(|_| "text/event-stream".parse().unwrap()),
                    );
                    return response;
                }
                Err(err) => {
                    append_log(
                        &state.logs,
                        "error",
                        &format!("Provider error for {}: {}", key.record.provider, err),
                    );
                    continue;
                }
            }
        } else {
            let result =
                forward_request(&state.client, &key, &payload, &model, &adapter).await;
            match result {
                Ok((status, body, content_type)) => {
                    if status.as_u16() == 429 {
                        append_log(
                            &state.logs,
                            "warn",
                            &format!(
                                "Rate limited for {}. Trying next key.",
                                key.record.provider
                            ),
                        );
                        continue;
                    }
                    increment_usage(&state.usage, &key.record.id);
                    let _ = persist_usage(&state.usage_path, &state.usage);
                    append_log(
                        &state.logs,
                        "info",
                        &format!(
                            "Request served by {} ({})",
                            key.record.provider, key.record.label
                        ),
                    );
                    let mut response = axum::response::Response::new(body.into());
                    *response.status_mut() = status;
                    response.headers_mut().insert(
                        axum::http::header::CONTENT_TYPE,
                        content_type
                            .parse()
                            .unwrap_or_else(|_| "application/json".parse().unwrap()),
                    );
                    return response;
                }
                Err(err) => {
                    append_log(
                        &state.logs,
                        "error",
                        &format!("Provider error for {}: {}", key.record.provider, err),
                    );
                    continue;
                }
            }
        }
    }

    append_log(&state.logs, "error", "All providers failed for request.");
    (
        axum::http::StatusCode::BAD_GATEWAY,
        Json(serde_json::json!({
            "error": {
                "message": "All providers failed to handle the request.",
                "type": "proxy_error"
            }
        })),
    )
}

#[derive(Debug, Clone)]
struct ProxyKey {
    record: KeyRecord,
    secret: String,
}

fn load_keys_for_proxy(path: &PathBuf) -> Result<Vec<ProxyKey>, String> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read keys from {}: {err}", path.display()))?;
    let list: KeyList =
        serde_json::from_str(&contents).map_err(|err| format!("Failed to parse keys: {err}"))?;

    let mut keys = Vec::new();
    for record in list.keys {
        let username = format!("{}:{}", record.provider, record.id);
        let entry = match keyring::Entry::new(KEYRING_SERVICE, &username) {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let secret = match entry.get_password() {
            Ok(secret) => secret,
            Err(_) => continue,
        };
        keys.push(ProxyKey { record, secret });
    }
    Ok(keys)
}

fn append_log(logs: &Arc<Mutex<Vec<ProxyLog>>>, level: &str, message: &str) {
    let mut guard = match logs.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.push(ProxyLog {
        timestamp: current_epoch_seconds(),
        level: level.to_string(),
        message: message.to_string(),
    });
    if guard.len() > 200 {
        let drain = guard.len() - 200;
        guard.drain(0..drain);
    }
}

fn usage_path(app: &AppHandle) -> Result<PathBuf, String> {
    let dir = app
        .path()
        .app_data_dir()
        .map_err(|err| format!("Failed to resolve app data directory: {err}"))?;
    Ok(dir.join("usage.json"))
}

fn read_usage(path: &PathBuf) -> Result<HashMap<String, UsageWindow>, String> {
    if !path.exists() {
        return Ok(HashMap::new());
    }
    let contents = fs::read_to_string(path)
        .map_err(|err| format!("Failed to read usage from {}: {err}", path.display()))?;
    let usage = serde_json::from_str(&contents)
        .map_err(|err| format!("Failed to parse usage: {err}"))?;
    Ok(usage)
}

fn persist_usage(
    path: &PathBuf,
    usage: &Arc<Mutex<HashMap<String, UsageWindow>>>,
) -> Result<(), String> {
    let guard = usage.lock().map_err(|_| "Usage lock poisoned")?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("Failed to create usage directory: {err}"))?;
    }
    let payload =
        serde_json::to_string_pretty(&*guard).map_err(|err| format!("Serialize failed: {err}"))?;
    fs::write(path, payload).map_err(|err| format!("Failed to write usage: {err}"))
}

fn current_minute() -> u64 {
    current_epoch_seconds() / 60
}

fn usage_for_key(usage: &Arc<Mutex<HashMap<String, UsageWindow>>>, id: &str) -> u32 {
    let mut guard = match usage.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = current_minute();
    let entry = guard.entry(id.to_string()).or_insert(UsageWindow {
        minute: now,
        requests: 0,
    });
    if entry.minute != now {
        entry.minute = now;
        entry.requests = 0;
    }
    entry.requests
}

fn increment_usage(usage: &Arc<Mutex<HashMap<String, UsageWindow>>>, id: &str) {
    let mut guard = match usage.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let now = current_minute();
    let entry = guard.entry(id.to_string()).or_insert(UsageWindow {
        minute: now,
        requests: 0,
    });
    if entry.minute != now {
        entry.minute = now;
        entry.requests = 0;
    }
    entry.requests = entry.requests.saturating_add(1);
}

fn key_supports_model(key: &ProxyKey, requested: &str) -> bool {
    if key.record.models.is_empty() {
        return true;
    }
    if key
        .record
        .models
        .iter()
        .any(|model| model == requested)
    {
        return true;
    }
    key.record
        .model_map
        .iter()
        .any(|map| map.from == requested)
}

fn resolve_model(key: &ProxyKey, requested: &str) -> String {
    if let Some(mapped) = key
        .record
        .model_map
        .iter()
        .find(|map| map.from == requested)
        .map(|map| map.to.clone())
    {
        return mapped;
    }
    if key
        .record
        .models
        .iter()
        .any(|model| model == requested)
    {
        return requested.to_string();
    }
    key.record
        .default_model
        .clone()
        .or_else(|| key.record.models.first().cloned())
        .unwrap_or_else(|| requested.to_string())
}

async fn forward_request(
    client: &reqwest::Client,
    key: &ProxyKey,
    payload: &serde_json::Value,
    requested_model: &str,
    adapter: &str,
) -> Result<(axum::http::StatusCode, bytes::Bytes, String), String> {
    let model = resolve_model(key, requested_model);
    match adapter {
        "openai" | "openrouter" => forward_openai_request(client, key, payload, &model).await,
        "google_ai_studio" => forward_google_request(client, key, payload, &model).await,
        _ => Err("Unsupported adapter".to_string()),
    }
}

async fn forward_stream_request(
    client: &reqwest::Client,
    key: &ProxyKey,
    payload: &serde_json::Value,
    requested_model: &str,
    adapter: &str,
) -> Result<(axum::http::StatusCode, axum::body::Body, String), String> {
    let model = resolve_model(key, requested_model);
    match adapter {
        "openai" | "openrouter" => forward_openai_stream(client, key, payload, &model).await,
        "google_ai_studio" => Err("Streaming not supported for this adapter".to_string()),
        _ => Err("Unsupported adapter".to_string()),
    }
}

async fn forward_openai_request(
    client: &reqwest::Client,
    key: &ProxyKey,
    payload: &serde_json::Value,
    model: &str,
) -> Result<(axum::http::StatusCode, bytes::Bytes, String), String> {
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
    Ok((status, body, content_type))
}

async fn forward_openai_stream(
    client: &reqwest::Client,
    key: &ProxyKey,
    payload: &serde_json::Value,
    model: &str,
) -> Result<(axum::http::StatusCode, axum::body::Body, String), String> {
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
    Ok((status, body, content_type))
}

async fn forward_google_request(
    client: &reqwest::Client,
    key: &ProxyKey,
    payload: &serde_json::Value,
    model: &str,
) -> Result<(axum::http::StatusCode, bytes::Bytes, String), String> {
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
        return Ok((status, bytes, content_type));
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
        "id": format!("chatcmpl-{}", Uuid::new_v4()),
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
    Ok((status, bytes::Bytes::from(output_bytes), "application/json".to_string()))
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

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            sync_providers,
            load_cached_config,
            list_keys,
            add_key,
            remove_key,
            check_key,
            start_proxy,
            stop_proxy,
            proxy_status,
            get_logs,
            clear_logs
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
