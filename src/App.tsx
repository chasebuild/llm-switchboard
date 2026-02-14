import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Activity,
  CheckCircle2,
  ChevronRight,
  Cloud,
  Database,
  KeyRound,
  Plug,
  RefreshCw,
  Server,
  ShieldCheck,
} from "lucide-react";

import { Badge } from "./components/ui/badge";
import { Button } from "./components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "./components/ui/card";
import { Input } from "./components/ui/input";
import { Select } from "./components/ui/select";
import { Separator } from "./components/ui/separator";


type Limits = {
  rpm: number | null;
  tpm: number | null;
};

type Provider = {
  name: string;
  description?: string;
  notes?: string[];
  base_urls?: string[];
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
  const preview = models.slice(0, 4).join(", ");
  if (models.length <= 4) return preview;
  return `${preview} +${models.length - 4} more`;
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
    if (!keyBaseUrl.trim() && provider.base_urls && provider.base_urls.length > 0) {
      setKeyBaseUrl(provider.base_urls[0]);
    }
  }

  return (
    <div className="relative min-h-screen overflow-hidden bg-[#0b0d12] text-foreground">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(56,189,248,0.12),_transparent_55%),radial-gradient(circle_at_30%_20%,_rgba(56,189,248,0.08),_transparent_35%),radial-gradient(circle_at_70%_70%,_rgba(15,23,42,0.7),_transparent_60%)]" />
      <div className="pointer-events-none absolute inset-0 bg-[linear-gradient(120deg,_rgba(15,23,42,0.45),_rgba(2,6,23,0.7))]" />

      <header className="sticky top-0 z-30 border-b border-border/70 bg-background/80 backdrop-blur-xl">
        <div className="mx-auto flex w-full max-w-[1400px] flex-wrap items-center justify-between gap-4 px-6 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-primary/15 text-primary">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <p className="text-[0.65rem] uppercase tracking-[0.3em] text-muted-foreground">
                FreeLLM Switchboard
              </p>
              <h1 className="text-xl font-semibold">Provider control center</h1>
            </div>
          </div>

          <div className="hidden xl:flex items-center gap-3 text-sm text-muted-foreground">
            <div className="flex items-center gap-2 rounded-full border border-border/60 bg-muted/40 px-3 py-1">
              <Database className="h-4 w-4 text-primary" />
              <span>{providerCount} providers</span>
            </div>
            <div className="flex items-center gap-2 rounded-full border border-border/60 bg-muted/40 px-3 py-1">
              <Cloud className="h-4 w-4 text-primary" />
              <span>{totalModels} models indexed</span>
            </div>
            <div className="flex items-center gap-2 rounded-full border border-border/60 bg-muted/40 px-3 py-1">
              <Activity className="h-4 w-4 text-primary" />
              <span>Last sync {formatTimestamp(config?.fetched_at ?? null)}</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <Button variant="secondary" onClick={syncProviders} disabled={loading}>
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
              {loading ? "Syncing" : "Sync Providers"}
            </Button>
          </div>
        </div>
      </header>

      <div className="mx-auto flex w-full max-w-[1400px] gap-6 px-6 pb-12 pt-6">
        <aside className="hidden w-64 shrink-0 flex-col gap-6 lg:flex">
          <Card className="border-border/70 bg-card/80">
            <CardHeader>
              <CardTitle className="text-base">Providers</CardTitle>
              <CardDescription>{status}</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {(config?.providers ?? []).map((provider) => (
                <button
                  key={provider.name}
                  className={`flex w-full items-center justify-between rounded-lg border px-3 py-2 text-left text-sm transition hover:border-primary/60 hover:bg-primary/10 ${
                    selectedProvider?.name === provider.name
                      ? "border-primary/60 bg-primary/15 text-foreground"
                      : "border-transparent bg-transparent text-muted-foreground"
                  }`}
                  onClick={() => setSelectedProvider(provider)}
                >
                  <div>
                    <p className="font-medium text-foreground">{provider.name}</p>
                    <p className="text-xs text-muted-foreground">
                      {summarizeModels(provider.models)}
                    </p>
                  </div>
                  <Badge variant="muted">{provider.models.length}</Badge>
                </button>
              ))}
              {providerCount === 0 && (
                <p className="text-sm text-muted-foreground">No providers yet.</p>
              )}
            </CardContent>
          </Card>

          {newProviders.length > 0 && (
            <Card className="border-primary/50 bg-primary/10">
              <CardHeader>
                <CardTitle className="text-base">New providers</CardTitle>
                <CardDescription>Freshly synced from GitHub</CardDescription>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                {newProviders.map((provider) => (
                  <Badge key={provider} variant="default">
                    {provider}
                  </Badge>
                ))}
              </CardContent>
            </Card>
          )}

          <Card className="border-border/70 bg-card/80">
            <CardHeader>
              <CardTitle className="text-base">Quick status</CardTitle>
              <CardDescription>Live proxy + key health</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Proxy</span>
                <Badge variant={proxyStatus.running ? "success" : "muted"}>
                  {proxyStatus.running ? "Running" : "Stopped"}
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Keys stored</span>
                <Badge variant="secondary">{keys.length}</Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-muted-foreground">Key status</span>
                <Badge variant="outline">{keyStatus}</Badge>
              </div>
            </CardContent>
          </Card>
        </aside>

        <main className="flex min-w-0 flex-1 flex-col gap-6">
          <div className="lg:hidden">
            <Card className="border-border/70 bg-card/80">
              <CardHeader>
                <CardTitle className="text-base">Providers</CardTitle>
                <CardDescription>{status}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2">
                {(config?.providers ?? []).map((provider) => (
                  <button
                    key={provider.name}
                    className={`flex w-full items-center justify-between rounded-lg border px-3 py-2 text-left text-sm transition hover:border-primary/60 hover:bg-primary/10 ${
                      selectedProvider?.name === provider.name
                        ? "border-primary/60 bg-primary/15 text-foreground"
                        : "border-transparent bg-transparent text-muted-foreground"
                    }`}
                    onClick={() => setSelectedProvider(provider)}
                  >
                    <div>
                      <p className="font-medium text-foreground">{provider.name}</p>
                      <p className="text-xs text-muted-foreground">
                        {summarizeModels(provider.models)}
                      </p>
                    </div>
                    <Badge variant="muted">{provider.models.length}</Badge>
                  </button>
                ))}
                {providerCount === 0 && (
                  <p className="text-sm text-muted-foreground">No providers yet.</p>
                )}
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-6 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
            <Card className="border-border/70 bg-card/80">
              <CardHeader className="flex flex-col gap-3">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <CardTitle className="text-lg">
                      {selectedProvider ? selectedProvider.name : "Select a provider"}
                    </CardTitle>
                    <CardDescription>
                      {selectedProvider
                        ? `Models ${selectedProvider.models.length} · RPM ${
                            selectedProvider.limits.rpm ?? "—"
                          } · TPM ${selectedProvider.limits.tpm ?? "—"}`
                        : "Choose a provider to see details."}
                    </CardDescription>
                  </div>
                  {selectedProvider && (
                    <Button variant="outline" onClick={() => applyProvider(selectedProvider)}>
                      <Plug className="h-4 w-4" />
                      Use this provider
                    </Button>
                  )}
                </div>
                {selectedProvider?.description && (
                  <p className="text-sm text-muted-foreground">
                    {selectedProvider.description}
                  </p>
                )}
              </CardHeader>
              <CardContent className="space-y-4">
                {selectedProvider ? (
                  <>
                    {selectedProvider.base_urls && selectedProvider.base_urls.length > 0 && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.3em] text-muted-foreground">
                          Base URLs
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {selectedProvider.base_urls.map((url) => (
                            <span
                              key={url}
                              className="rounded-full border border-border/70 bg-muted/40 px-3 py-1 text-xs text-muted-foreground"
                            >
                              {url}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="space-y-2">
                      <div className="flex items-center gap-2 text-xs uppercase tracking-[0.3em] text-muted-foreground">
                        Model catalog
                      </div>
                      {selectedProvider.models.length === 0 && (
                        <p className="text-sm text-muted-foreground">
                          No models parsed yet.
                        </p>
                      )}
                      <div className="flex flex-wrap gap-2">
                        {selectedProvider.models.map((model) => (
                          <span
                            key={model}
                            className="rounded-full border border-border/70 bg-background/40 px-3 py-1 text-xs"
                          >
                            {model}
                          </span>
                        ))}
                      </div>
                    </div>
                    {selectedProvider.notes && selectedProvider.notes.length > 0 && (
                      <div className="space-y-2">
                        <div className="flex items-center gap-2 text-xs uppercase tracking-[0.3em] text-muted-foreground">
                          Notes
                        </div>
                        <div className="space-y-2 text-sm text-muted-foreground">
                          {selectedProvider.notes.map((note, index) => (
                            <p key={`${selectedProvider.name}-note-${index}`}>{note}</p>
                          ))}
                        </div>
                      </div>
                    )}
                    <div className="rounded-lg border border-border/60 bg-muted/30 p-3 text-xs text-muted-foreground">
                      The proxy reads providers from the README. If models are missing, add
                      them manually in the key vault.
                    </div>
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">
                    Select a provider to see details.
                  </p>
                )}
              </CardContent>
            </Card>

            <Card className="border-border/70 bg-card/80">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <KeyRound className="h-5 w-5 text-primary" />
                  Key vault
                </CardTitle>
                <CardDescription>Store secrets, model lists, and adapters.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                    Provider
                  </label>
                  <Input
                    value={keyProvider}
                    onChange={(event) => setKeyProvider(event.currentTarget.value)}
                    placeholder="Groq, Cerebras, OpenRouter..."
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                    Base URL
                  </label>
                  <Input
                    value={keyBaseUrl}
                    onChange={(event) => setKeyBaseUrl(event.currentTarget.value)}
                    placeholder="https://api.provider.com"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                    Adapter
                  </label>
                  <Select
                    value={keyAdapter}
                    onChange={(event) => applyAdapter(event.currentTarget.value)}
                  >
                    <option value="openai">OpenAI-compatible</option>
                    <option value="openrouter">OpenRouter</option>
                    <option value="google_ai_studio">Google AI Studio (Gemini)</option>
                  </Select>
                </div>
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                    Label (optional)
                  </label>
                  <Input
                    value={keyLabel}
                    onChange={(event) => setKeyLabel(event.currentTarget.value)}
                    placeholder="Personal / Team / Backup"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                    Allowed models
                  </label>
                  <Input
                    value={keyModels}
                    onChange={(event) => setKeyModels(event.currentTarget.value)}
                    placeholder="llama-3.1-8b, mixtral-8x7b"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                    Default model for health checks
                  </label>
                  <Input
                    value={keyDefaultModel}
                    onChange={(event) => setKeyDefaultModel(event.currentTarget.value)}
                    placeholder="llama-3.1-8b"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                    Model mappings (OpenAI=Provider)
                  </label>
                  <Input
                    value={keyModelMap}
                    onChange={(event) => setKeyModelMap(event.currentTarget.value)}
                    placeholder="gpt-4o-mini=gemini-1.5-flash"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-xs uppercase tracking-[0.3em] text-muted-foreground">
                    Secret
                  </label>
                  <Input
                    type="password"
                    value={keySecret}
                    onChange={(event) => setKeySecret(event.currentTarget.value)}
                    placeholder="Paste API key"
                  />
                </div>
                <Button className="w-full" onClick={addKey}>
                  <ChevronRight className="h-4 w-4" />
                  Store key
                </Button>
                <p className="text-xs text-muted-foreground">{keyStatus}</p>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="border-border/70 bg-card/80">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Server className="h-5 w-5 text-primary" />
                  Stored keys
                </CardTitle>
                <CardDescription>Health status for each provider key.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {keys.length === 0 && (
                  <p className="text-sm text-muted-foreground">No keys stored yet.</p>
                )}
                {keys.map((record) => (
                  <div
                    key={record.id}
                    className="flex flex-wrap items-center justify-between gap-4 rounded-lg border border-border/70 bg-muted/40 p-4"
                  >
                    <div className="space-y-1">
                      <p className="text-sm font-semibold text-foreground">
                        {record.provider}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {record.label || "No label"} · {record.status}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {record.adapter} · {record.base_url || "No base URL"}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <Button variant="ghost" size="sm" onClick={() => checkKey(record.id)}>
                        Check
                      </Button>
                      <Button
                        variant="destructive"
                        size="sm"
                        onClick={() => removeKey(record.id)}
                      >
                        Remove
                      </Button>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            <Card className="border-border/70 bg-card/80">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-lg">
                  <Plug className="h-5 w-5 text-primary" />
                  Local proxy
                </CardTitle>
                <CardDescription>
                  OpenAI-compatible bridge at
                  <span className="mono ml-1 text-xs">http://localhost:1234/v1/chat/completions</span>
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-3 rounded-lg border border-border/70 bg-muted/40 p-4">
                  <div
                    className={`h-3 w-3 rounded-full ${
                      proxyStatus.running ? "bg-emerald-400" : "bg-rose-400"
                    }`}
                  />
                  <div>
                    <p className="text-sm font-semibold text-foreground">
                      {proxyStatus.running ? "Running" : "Stopped"}
                    </p>
                    <p className="text-xs text-muted-foreground">
                      {proxyStatus.address ? proxyStatus.address : "No active listener"}
                    </p>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button onClick={startProxy} disabled={proxyStatus.running}>
                    Start proxy
                  </Button>
                  <Button variant="secondary" onClick={stopProxy} disabled={!proxyStatus.running}>
                    Stop proxy
                  </Button>
                </div>
                <p className="text-xs text-muted-foreground">{proxyMessage}</p>
              </CardContent>
            </Card>
          </div>

          <Card className="border-border/70 bg-card/80">
            <CardHeader>
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Activity className="h-5 w-5 text-primary" />
                    Proxy logs
                  </CardTitle>
                  <CardDescription>Streaming activity from the local gateway.</CardDescription>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {(["all", "info", "warn", "error"] as const).map((level) => (
                    <Button
                      key={level}
                      size="sm"
                      variant={logFilter === level ? "default" : "ghost"}
                      onClick={() => setLogFilter(level)}
                    >
                      {level}
                    </Button>
                  ))}
                  <Button size="sm" variant="outline" onClick={clearLogs}>
                    Clear logs
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="max-h-[280px] space-y-2 overflow-y-auto rounded-lg border border-border/70 bg-[#0b0f17] p-4 font-mono text-xs">
                {filteredLogs.length === 0 && (
                  <p className="text-muted-foreground">No log entries yet.</p>
                )}
                {filteredLogs.map((log, index) => (
                  <div
                    key={`${log.timestamp}-${index}`}
                    className="grid grid-cols-[70px_90px_1fr] gap-3 text-muted-foreground"
                  >
                    <span
                      className={`font-semibold uppercase ${
                        log.level === "info"
                          ? "text-emerald-300"
                          : log.level === "warn"
                          ? "text-amber-300"
                          : "text-rose-300"
                      }`}
                    >
                      {log.level}
                    </span>
                    <span className="text-slate-400">
                      {new Date(log.timestamp * 1000).toLocaleTimeString()}
                    </span>
                    <span className="text-slate-200">{log.message}</span>
                  </div>
                ))}
              </div>
              <Separator />
              <p className="text-xs text-muted-foreground">{logStatus}</p>
            </CardContent>
          </Card>

          <Card className="border-border/70 bg-card/80">
            <CardContent className="flex flex-wrap items-center justify-between gap-4 py-6">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                <div>
                  <p className="text-sm font-semibold">System ready</p>
                  <p className="text-xs text-muted-foreground">
                    Providers synced from {config?.source_url ?? "GitHub"}
                  </p>
                </div>
              </div>
              <Button variant="ghost">
                <KeyRound className="h-4 w-4" />
                Manage secrets
              </Button>
            </CardContent>
          </Card>
        </main>
      </div>
    </div>
  );
}

export default App;
