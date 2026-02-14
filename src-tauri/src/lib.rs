use axum::{
    extract::{Json, State as AxumState},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use free_llm_parser::{parse_markdown, ProviderConfig};
mod adapters;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, Manager, State};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use uuid::Uuid;

const SOURCE_URL: &str =
    "https://raw.githubusercontent.com/cheahjs/free-llm-api-resources/main/README.md";
const KEYRING_SERVICE: &str = "freellm-switchboard";

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
    Ok(SyncResult {
        config,
        new_providers,
    })
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
    write_keys(&app, &mut list)?;

    let username = format!("{}:{}", record.provider, record.id);
    if let Ok(entry) = keyring::Entry::new(KEYRING_SERVICE, &username) {
        let _ = entry.delete_password();
    }
    Ok(())
}

#[tauri::command]
async fn check_key(app: AppHandle, id: String) -> Result<KeyRecord, String> {
    let mut list = read_keys(&app)?.unwrap_or_default();
    let index = list
        .keys
        .iter()
        .position(|record| record.id == id)
        .ok_or_else(|| "Key not found".to_string())?;
    let record_snapshot = list.keys[index].clone();

    let username = format!("{}:{}", record_snapshot.provider, record_snapshot.id);
    let entry = keyring::Entry::new(KEYRING_SERVICE, &username)
        .map_err(|err| format!("Failed to open keyring entry: {err}"))?;
    let secret = match entry.get_password() {
        Ok(secret) => secret,
        Err(_) => {
            {
                let record = &mut list.keys[index];
                record.status = "Missing".to_string();
                record.last_checked = Some(current_epoch_seconds());
            }
            write_keys(&app, &list)?;
            return Ok(list.keys[index].clone());
        }
    };

    let base_url = record_snapshot.base_url.trim();
    if base_url.is_empty() {
        {
            let record = &mut list.keys[index];
            record.status = "MissingBaseUrl".to_string();
            record.last_checked = Some(current_epoch_seconds());
        }
        write_keys(&app, &list)?;
        return Ok(list.keys[index].clone());
    }

    let adapter = record_snapshot.adapter.trim().to_lowercase();
    let client = reqwest::Client::new();
    let status = match adapter.as_str() {
        "openai" | "openrouter" => {
            let models_url = format!("{}/v1/models", base_url.trim_end_matches('/'));
            match client.get(models_url).bearer_auth(&secret).send().await {
                Ok(resp) if resp.status().is_success() => "Active",
                Ok(resp) if resp.status().as_u16() == 401 => "Unauthorized",
                Ok(resp) if resp.status().as_u16() == 403 => "Forbidden",
                Ok(resp) if resp.status().as_u16() == 404 => {
                    let test_model = record_snapshot
                        .default_model
                        .clone()
                        .or_else(|| record_snapshot.models.first().cloned());
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
            let test_model = record_snapshot
                .default_model
                .clone()
                .or_else(|| record_snapshot.models.first().cloned());
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

    {
        let record = &mut list.keys[index];
        record.status = status.to_string();
        record.last_checked = Some(current_epoch_seconds());
    }
    write_keys(&app, &list)?;
    Ok(list.keys[index].clone())
}

#[tauri::command]
async fn start_proxy(app: AppHandle, state: State<'_, AppState>) -> Result<ProxyStatus, String> {
    {
        let guard = state.proxy.lock().map_err(|_| "Proxy lock poisoned")?;
        if let Some(handle) = guard.as_ref() {
            return Ok(ProxyStatus {
                running: true,
                address: Some(format!("http://{}", handle.address)),
            });
        }
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
        let _ = server
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    let mut guard = state.proxy.lock().map_err(|_| "Proxy lock poisoned")?;
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
    let handle = {
        let mut guard = state.proxy.lock().map_err(|_| "Proxy lock poisoned")?;
        guard.take()
    };
    if let Some(handle) = handle {
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

fn default_adapter() -> String {
    "openai".to_string()
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
    let config =
        serde_json::from_str(&contents).map_err(|err| format!("Failed to parse config: {err}"))?;
    Ok(Some(config))
}

pub(crate) fn current_epoch_seconds() -> u64 {
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
    let list =
        serde_json::from_str(&contents).map_err(|err| format!("Failed to parse keys: {err}"))?;
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
) -> Response {
    let model = payload
        .get("model")
        .and_then(|value| value.as_str())
        .map(|value| value.to_string());

    let stream = payload
        .get("stream")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);

    let model = model.unwrap_or_else(|| "unknown".to_string());
    let keys = match load_keys_for_proxy(&state.key_path) {
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
            )
                .into_response();
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
        )
            .into_response();
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
        )
            .into_response();
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
                            &format!("Rate limited for {}. Trying next key.", key.record.provider),
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
            let result = forward_request(&state.client, &key, &payload, &model, &adapter).await;
            match result {
                Ok((status, body, content_type)) => {
                    if status.as_u16() == 429 {
                        append_log(
                            &state.logs,
                            "warn",
                            &format!("Rate limited for {}. Trying next key.", key.record.provider),
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
        .into_response()
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyKey {
    pub(crate) record: KeyRecord,
    pub(crate) secret: String,
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
    let usage =
        serde_json::from_str(&contents).map_err(|err| format!("Failed to parse usage: {err}"))?;
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
    if key.record.models.iter().any(|model| model == requested) {
        return true;
    }
    key.record.model_map.iter().any(|map| map.from == requested)
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
    if key.record.models.iter().any(|model| model == requested) {
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
    let adapter = adapters::adapter_for(adapter).ok_or("Unsupported adapter".to_string())?;
    let model = resolve_model(key, requested_model);
    let response = adapter
        .forward_request(client, key, payload, &model)
        .await?;
    Ok((response.status, response.body, response.content_type))
}

async fn forward_stream_request(
    client: &reqwest::Client,
    key: &ProxyKey,
    payload: &serde_json::Value,
    requested_model: &str,
    adapter: &str,
) -> Result<(axum::http::StatusCode, axum::body::Body, String), String> {
    let adapter = adapters::adapter_for(adapter).ok_or("Unsupported adapter".to_string())?;
    if !adapter.supports_stream() {
        return Err("Streaming not supported for this adapter".to_string());
    }
    let model = resolve_model(key, requested_model);
    let response = adapter
        .forward_stream(client, key, payload, &model)
        .await?;
    Ok((response.status, response.body, response.content_type))
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
