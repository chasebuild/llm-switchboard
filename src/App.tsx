import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import "./App.css";

type Limits = {
  rpm: number | null;
  tpm: number | null;
};

type Provider = {
  name: string;
  models: string[];
  limits: Limits;
};

type ProviderConfig = {
  source_url: string;
  fetched_at: number;
  providers: Provider[];
};

type SyncResult = {
  config: ProviderConfig;
  new_providers: string[];
};

type KeyRecord = {
  id: string;
  provider: string;
  label: string;
  base_url: string;
  adapter: string;
  models: string[];
  default_model: string | null;
  model_map: { from: string; to: string }[];
  status: string;
  last_checked: number | null;
};

type ProxyStatus = {
  running: boolean;
  address: string | null;
};

function formatTimestamp(timestamp: number | null) {
  if (!timestamp) return "Never synced";
  return new Date(timestamp * 1000).toLocaleString();
}

function summarizeModels(models: string[]) {
  if (models.length === 0) return "No models parsed yet";
  const preview = models.slice(0, 6).join(", ");
  if (models.length <= 6) return preview;
  return `${preview} +${models.length - 6} more`;
}

function App() {
  const [config, setConfig] = useState<ProviderConfig | null>(null);
  const [status, setStatus] = useState("Ready to sync.");
  const [loading, setLoading] = useState(false);
  const [newProviders, setNewProviders] = useState<string[]>([]);
  const [selectedProvider, setSelectedProvider] = useState<Provider | null>(null);
  const [keys, setKeys] = useState<KeyRecord[]>([]);
  const [keyProvider, setKeyProvider] = useState("");
  const [keyLabel, setKeyLabel] = useState("");
  const [keyBaseUrl, setKeyBaseUrl] = useState("");
  const [keyAdapter, setKeyAdapter] = useState("openai");
  const [keyModels, setKeyModels] = useState("");
  const [keyDefaultModel, setKeyDefaultModel] = useState("");
  const [keyModelMap, setKeyModelMap] = useState("");
  const [keySecret, setKeySecret] = useState("");
  const [keyStatus, setKeyStatus] = useState("No keys yet.");
  const [proxyStatus, setProxyStatus] = useState<ProxyStatus>({
    running: false,
    address: null,
  });
  const [proxyMessage, setProxyMessage] = useState("Proxy is stopped.");
  const [proxyLogs, setProxyLogs] = useState<
    { timestamp: number; level: string; message: string }[]
  >([]);
  const [logStatus, setLogStatus] = useState("Logs ready.");
  const [logFilter, setLogFilter] = useState<"all" | "info" | "warn" | "error">(
    "all"
  );

  useEffect(() => {
    invoke<ProviderConfig | null>("load_cached_config")
      .then((cached) => {
        if (cached) {
          setConfig(cached);
          setStatus("Loaded cached providers.");
        }
      })
      .catch((error) => {
        setStatus(`Failed to load cache: ${String(error)}`);
      });
  }, []);

  useEffect(() => {
    if (!config || config.providers.length === 0) {
      setSelectedProvider(null);
      return;
    }
    setSelectedProvider((prev) => {
      if (!prev) return config.providers[0];
      const match = config.providers.find((provider) => provider.name === prev.name);
      return match ?? config.providers[0];
    });
  }, [config]);

  useEffect(() => {
    invoke<KeyRecord[]>("list_keys")
      .then((records) => {
        setKeys(records);
        if (records.length > 0) {
          setKeyStatus(`Loaded ${records.length} key(s).`);
        }
      })
      .catch((error) => {
        setKeyStatus(`Failed to load keys: ${String(error)}`);
      });

    invoke<ProxyStatus>("proxy_status")
      .then((status) => {
        setProxyStatus(status);
        setProxyMessage(status.running ? "Proxy is running." : "Proxy is stopped.");
      })
      .catch((error) => {
        setProxyMessage(`Proxy status unavailable: ${String(error)}`);
      });

    invoke<{ timestamp: number; level: string; message: string }[]>("get_logs")
      .then((logs) => {
        setProxyLogs(logs);
      })
      .catch((error) => {
        setLogStatus(`Failed to load logs: ${String(error)}`);
      });
  }, []);

  useEffect(() => {
    const interval = window.setInterval(() => {
      invoke<{ timestamp: number; level: string; message: string }[]>("get_logs")
        .then((logs) => {
          setProxyLogs(logs);
        })
        .catch((error) => {
          setLogStatus(`Failed to refresh logs: ${String(error)}`);
        });
    }, 2000);
    return () => window.clearInterval(interval);
  }, []);

  const providerCount = config?.providers.length ?? 0;

  const totalModels = useMemo(() => {
    if (!config) return 0;
    return config.providers.reduce((sum, provider) => sum + provider.models.length, 0);
  }, [config]);

  const filteredLogs = useMemo(() => {
    if (logFilter === "all") return proxyLogs;
    return proxyLogs.filter((log) => log.level === logFilter);
  }, [proxyLogs, logFilter]);

  async function syncProviders() {
    setLoading(true);
    setStatus("Syncing providers from GitHub...");
    setNewProviders([]);
    try {
      const result = await invoke<SyncResult>("sync_providers");
      setConfig(result.config);
      setNewProviders(result.new_providers);
      if (result.new_providers.length > 0) {
        setStatus(`Synced. ${result.new_providers.length} new providers found.`);
      } else {
        setStatus("Synced. No new providers found.");
      }
    } catch (error) {
      setStatus(`Sync failed: ${String(error)}`);
    } finally {
      setLoading(false);
    }
  }

  async function addKey() {
    if (!keyProvider.trim() || !keySecret.trim()) {
      setKeyStatus("Provider and secret are required.");
      return;
    }
    setKeyStatus("Saving key...");
    try {
      const record = await invoke<KeyRecord>("add_key", {
        payload: {
          provider: keyProvider,
          label: keyLabel,
          base_url: keyBaseUrl,
          adapter: keyAdapter,
          models: keyModels
            .split(",")
            .map((entry) => entry.trim())
            .filter((entry) => entry.length > 0),
          default_model: keyDefaultModel.trim().length > 0 ? keyDefaultModel : null,
          model_map: parseModelMap(keyModelMap),
          secret: keySecret,
        },
      });
      setKeys((prev) => [...prev, record]);
      setKeyProvider("");
      setKeyLabel("");
      setKeyBaseUrl("");
      setKeyModels("");
      setKeyDefaultModel("");
      setKeyModelMap("");
      setKeySecret("");
      setKeyStatus(`Stored key for ${record.provider}.`);
    } catch (error) {
      setKeyStatus(`Failed to store key: ${String(error)}`);
    }
  }

  async function removeKey(id: string) {
    setKeyStatus("Removing key...");
    try {
      await invoke("remove_key", { payload: { id } });
      setKeys((prev) => prev.filter((record) => record.id !== id));
      setKeyStatus("Key removed.");
    } catch (error) {
      setKeyStatus(`Failed to remove key: ${String(error)}`);
    }
  }

  async function checkKey(id: string) {
    setKeyStatus("Checking key...");
    try {
      const record = await invoke<KeyRecord>("check_key", { id });
      setKeys((prev) => prev.map((item) => (item.id === id ? record : item)));
      setKeyStatus(`Key ${record.label} is ${record.status}.`);
    } catch (error) {
      setKeyStatus(`Failed to check key: ${String(error)}`);
    }
  }

  async function startProxy() {
    setProxyMessage("Starting proxy...");
    try {
      const status = await invoke<ProxyStatus>("start_proxy");
      setProxyStatus(status);
      setProxyMessage(
        status.running ? `Proxy running at ${status.address}` : "Proxy not running."
      );
    } catch (error) {
      setProxyMessage(`Failed to start proxy: ${String(error)}`);
    }
  }

  async function stopProxy() {
    setProxyMessage("Stopping proxy...");
    try {
      const status = await invoke<ProxyStatus>("stop_proxy");
      setProxyStatus(status);
      setProxyMessage(status.running ? "Proxy still running." : "Proxy stopped.");
    } catch (error) {
      setProxyMessage(`Failed to stop proxy: ${String(error)}`);
    }
  }

  async function clearLogs() {
    setLogStatus("Clearing logs...");
    try {
      await invoke("clear_logs");
      setProxyLogs([]);
      setLogStatus("Logs cleared.");
    } catch (error) {
      setLogStatus(`Failed to clear logs: ${String(error)}`);
    }
  }

  function parseModelMap(input: string) {
    const pairs = input
      .split(/[\n,]/)
      .map((entry) => entry.trim())
      .filter((entry) => entry.length > 0);
    const mapped = pairs
      .map((entry) => {
        const [from, to] = entry.split("=").map((part) => part.trim());
        if (!from || !to) return null;
        return { from, to };
      })
      .filter((entry): entry is { from: string; to: string } => Boolean(entry));
    return mapped;
  }

  function applyAdapter(value: string) {
    setKeyAdapter(value);
    if (!keyBaseUrl.trim()) {
      if (value === "openrouter") {
        setKeyBaseUrl("https://openrouter.ai/api/v1");
      }
      if (value === "google_ai_studio") {
        setKeyBaseUrl("https://generativelanguage.googleapis.com");
      }
    }
  }

  function applyProvider(provider: Provider) {
    setKeyProvider(provider.name);
    if (!keyModels.trim() && provider.models.length > 0) {
      setKeyModels(provider.models.join(", "));
    }
    if (!keyDefaultModel.trim() && provider.models.length > 0) {
      setKeyDefaultModel(provider.models[0]);
    }
  }

  return (
    <div className="app">
      <header className="hero">
        <div>
          <p className="eyebrow">FreeLLM Switchboard</p>
          <h1>Local provider sync + rotation control center</h1>
          <p className="subtitle">
            Pull the latest free LLM endpoints, cache provider metadata, and prep your local proxy
            layer.
          </p>
        </div>
        <div className="hero-card">
          <div className="stat">
            <span className="stat-label">Providers</span>
            <span className="stat-value">{providerCount}</span>
          </div>
          <div className="stat">
            <span className="stat-label">Models</span>
            <span className="stat-value">{totalModels}</span>
          </div>
          <div className="stat">
            <span className="stat-label">Last Sync</span>
            <span className="stat-value">{formatTimestamp(config?.fetched_at ?? null)}</span>
          </div>
          <button className="primary" onClick={syncProviders} disabled={loading}>
            {loading ? "Syncing..." : "Sync Providers"}
          </button>
          <p className="status">{status}</p>
        </div>
      </header>

      {newProviders.length > 0 && (
        <section className="notice">
          <h2>New Providers</h2>
          <p>{newProviders.join(", ")}</p>
        </section>
      )}

      <section className="catalog">
        <div className="section-header">
          <h2>Provider Catalog</h2>
          <p>Sync from GitHub to populate the providers list.</p>
        </div>
        <div className="catalog-grid">
          <aside className="provider-list">
            {(config?.providers ?? []).map((provider) => (
              <button
                key={provider.name}
                className={`provider-item ${
                  selectedProvider?.name === provider.name ? "active" : ""
                }`}
                onClick={() => setSelectedProvider(provider)}
              >
                <span>{provider.name}</span>
                <span className="provider-count">{provider.models.length}</span>
              </button>
            ))}
            {providerCount === 0 && (
              <div className="empty-note">No providers available. Run a sync.</div>
            )}
          </aside>
          <div className="provider-detail">
            {selectedProvider ? (
              <>
                <div className="provider-detail-header">
                  <div>
                    <h3>{selectedProvider.name}</h3>
                    <p className="subtitle">
                      Models: {selectedProvider.models.length} · RPM{" "}
                      {selectedProvider.limits.rpm ?? "—"} · TPM{" "}
                      {selectedProvider.limits.tpm ?? "—"}
                    </p>
                  </div>
                  <button className="primary" onClick={() => applyProvider(selectedProvider)}>
                    Use This Provider
                  </button>
                </div>
                <div className="model-list">
                  {selectedProvider.models.length === 0 && (
                    <p className="empty-note">No models parsed yet.</p>
                  )}
                  {selectedProvider.models.map((model) => (
                    <span key={model} className="model-chip">
                      {model}
                    </span>
                  ))}
                </div>
                <div className="provider-doc">
                  <p>
                    Add your API key and base URL below. The proxy will expose this provider through
                    the local OpenAI-compatible endpoint.
                  </p>
                </div>
              </>
            ) : (
              <p className="empty-note">Select a provider to see details.</p>
            )}
          </div>
        </div>
      </section>

      <section className="vault">
        <div className="section-header">
          <h2>Key Vault</h2>
          <p>Local system keychain only. No secrets leave this machine.</p>
        </div>
        <div className="vault-grid">
          <div className="vault-form">
            <h3>Add API Key</h3>
            <label>
              Provider
              <input
                value={keyProvider}
                onChange={(event) => setKeyProvider(event.currentTarget.value)}
                placeholder="Groq, Cerebras, OpenRouter..."
              />
            </label>
            <label>
              Base URL
              <input
                value={keyBaseUrl}
                onChange={(event) => setKeyBaseUrl(event.currentTarget.value)}
                placeholder="https://api.provider.com"
              />
            </label>
            <label>
              Adapter
              <select
                value={keyAdapter}
                onChange={(event) => applyAdapter(event.currentTarget.value)}
              >
                <option value="openai">OpenAI-compatible</option>
                <option value="openrouter">OpenRouter</option>
                <option value="google_ai_studio">Google AI Studio (Gemini)</option>
              </select>
            </label>
            <label>
              Label (optional)
              <input
                value={keyLabel}
                onChange={(event) => setKeyLabel(event.currentTarget.value)}
                placeholder="Personal / Team / Backup"
              />
            </label>
            <label>
              Allowed models (comma-separated)
              <input
                value={keyModels}
                onChange={(event) => setKeyModels(event.currentTarget.value)}
                placeholder="llama-3.1-8b, mixtral-8x7b"
              />
            </label>
            <label>
              Default model for health checks
              <input
                value={keyDefaultModel}
                onChange={(event) => setKeyDefaultModel(event.currentTarget.value)}
                placeholder="llama-3.1-8b"
              />
            </label>
            <label>
              Model mappings (OpenAI=Provider)
              <input
                value={keyModelMap}
                onChange={(event) => setKeyModelMap(event.currentTarget.value)}
                placeholder="gpt-4o-mini=gemini-1.5-flash"
              />
            </label>
            <label>
              Secret
              <input
                type="password"
                value={keySecret}
                onChange={(event) => setKeySecret(event.currentTarget.value)}
                placeholder="Paste API key"
              />
            </label>
            <button className="primary" onClick={addKey}>
              Store Key
            </button>
            <p className="status">{keyStatus}</p>
          </div>
          <div className="vault-list">
            <h3>Stored Keys</h3>
            {keys.length === 0 && <p className="empty-note">No keys stored yet.</p>}
            {keys.map((record) => (
              <div key={record.id} className="key-row">
                <div>
                  <p className="key-title">{record.provider}</p>
                  <p className="key-meta">
                    {record.label} · {record.status}
                  </p>
                  <p className="key-meta">
                    {record.adapter} · {record.base_url || "No base URL"}
                  </p>
                </div>
                <div className="key-actions">
                  <button className="ghost" onClick={() => checkKey(record.id)}>
                    Check
                  </button>
                  <button className="ghost danger" onClick={() => removeKey(record.id)}>
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="proxy">
        <div className="section-header">
          <h2>Local Proxy</h2>
          <p>
            OpenAI-compatible bridge at{" "}
            <span className="mono">http://localhost:1234/v1/chat/completions</span>
          </p>
        </div>
        <div className="proxy-card">
          <div className="proxy-status">
            <span className={`dot ${proxyStatus.running ? "live" : "down"}`} />
            <div>
              <p className="proxy-title">
                {proxyStatus.running ? "Running" : "Stopped"}
              </p>
              <p className="proxy-subtitle">
                {proxyStatus.address ? proxyStatus.address : "No active listener"}
              </p>
            </div>
          </div>
          <div className="proxy-actions">
            <button className="primary" onClick={startProxy} disabled={proxyStatus.running}>
              Start Proxy
            </button>
            <button className="ghost" onClick={stopProxy} disabled={!proxyStatus.running}>
              Stop Proxy
            </button>
          </div>
          <p className="status">{proxyMessage}</p>
        </div>
      </section>

      <section className="logs">
        <div className="section-header">
          <h2>Proxy Logs</h2>
          <div className="log-actions">
            <div className="filter-group">
              {["all", "info", "warn", "error"].map((level) => (
                <button
                  key={level}
                  className={`ghost ${logFilter === level ? "active" : ""}`}
                  onClick={() => setLogFilter(level as typeof logFilter)}
                >
                  {level}
                </button>
              ))}
            </div>
            <button className="ghost" onClick={clearLogs}>
              Clear Logs
            </button>
          </div>
        </div>
        <div className="log-panel">
          {filteredLogs.length === 0 && <p className="empty-note">No log entries yet.</p>}
          {filteredLogs.map((log, index) => (
            <div key={`${log.timestamp}-${index}`} className="log-row">
              <span className={`log-level ${log.level}`}>{log.level}</span>
              <span className="log-time">
                {new Date(log.timestamp * 1000).toLocaleTimeString()}
              </span>
              <span className="log-message">{log.message}</span>
            </div>
          ))}
        </div>
        <p className="status">{logStatus}</p>
      </section>

      <section className="providers">
        <div className="section-header">
          <h2>Provider Inventory</h2>
          <p>
            Source:{" "}
            <span className="mono">
              {config?.source_url ?? "https://raw.githubusercontent.com/.../README.md"}
            </span>
          </p>
        </div>
        <div className="provider-grid">
          {(config?.providers ?? []).map((provider) => (
            <article key={provider.name} className="provider-card">
              <div className="provider-header">
                <h3>{provider.name}</h3>
                <span className="pill">{provider.models.length} models</span>
              </div>
              <div className="limits">
                <div>
                  <span className="label">RPM</span>
                  <span className="value">{provider.limits.rpm ?? "—"}</span>
                </div>
                <div>
                  <span className="label">TPM</span>
                  <span className="value">{provider.limits.tpm ?? "—"}</span>
                </div>
              </div>
              <p className="models">{summarizeModels(provider.models)}</p>
            </article>
          ))}
          {providerCount === 0 && (
            <div className="empty">
              <p>No providers cached yet. Sync to pull the latest list.</p>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}

export default App;
