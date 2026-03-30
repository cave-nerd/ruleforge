import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Save,
  Trash2,
  RefreshCw,
  CheckCircle2,
  Eye,
  EyeOff,
  Server,
  KeyRound,
  Shield,
  Network,
  Palette,
  Check,
} from "lucide-react";
import { LogEntry } from "../types";
import {
  ThemeMode,
  AccentColor,
  ACCENT_PALETTES,
} from "../hooks/useTheme";

interface SettingsProps {
  opnsenseInterface: string;
  setOpnsenseInterface: (i: string) => void;
  addLog: (level: LogEntry["level"], msg: string) => void;
  themeMode: ThemeMode;
  changeMode: (m: ThemeMode) => void;
  accent: AccentColor;
  changeAccent: (a: AccentColor) => void;
}

interface ConfigSummary {
  host: string;
  verify_tls: boolean;
}

function Section({
  icon: Icon,
  title,
  children,
}: {
  icon: React.ElementType;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="card">
      <div className="flex items-center gap-2 mb-4 pb-3 border-b border-surface-600">
        <Icon size={16} className="text-brand-400" />
        <h2 className="font-semibold text-white">{title}</h2>
      </div>
      {children}
    </div>
  );
}

export default function Settings({
  opnsenseInterface,
  setOpnsenseInterface,
  addLog,
  themeMode,
  changeMode,
  accent,
  changeAccent,
}: SettingsProps) {
  const [host, setHost] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [apiSecret, setApiSecret] = useState("");
  const [verifyTls, setVerifyTls] = useState(true);
  const [showSecret, setShowSecret] = useState(false);
  const [showKey, setShowKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testOk, setTestOk] = useState<string | null>(null);
  // When secrets are loaded from the keyring they live in Rust state only.
  // The fields show a placeholder so the user knows credentials are active.
  const [secretsLoaded, setSecretsLoaded] = useState(false);
  const [iface, setIface] = useState(opnsenseInterface);

  async function saveCredentials() {
    if (!host.trim() || !apiKey.trim() || !apiSecret.trim()) {
      addLog("warn", "Host, API key, and secret are all required.");
      return;
    }
    setSaving(true);
    try {
      // Credentials transit IPC exactly once (to save). After this they live
      // only in the OS keyring and Rust AppState — never sent back to JS.
      await invoke("save_opnsense_config", {
        host: host.trim(),
        apiKey: apiKey.trim(),
        apiSecret: apiSecret.trim(),
        verifyTls,
      });
      addLog("success", "OPNsense credentials saved to system keyring.");
      // Clear sensitive values from React state immediately after saving
      setApiKey("");
      setApiSecret("");
      setSecretsLoaded(true);
    } catch (e) {
      addLog("error", `Failed to save credentials: ${e}`);
    } finally {
      setSaving(false);
    }
  }

  async function loadSavedCredentials() {
    try {
      // Returns {host, verify_tls} only — the API secret stays in Rust state
      const summary = await invoke<ConfigSummary>("load_opnsense_config");
      setHost(summary.host);
      setVerifyTls(summary.verify_tls);
      setApiKey("");
      setApiSecret("");
      setSecretsLoaded(true);
      addLog("success", "Credentials loaded from keyring into Rust state.");
    } catch (e) {
      addLog("info", `No saved credentials found: ${e}`);
    }
  }

  async function clearCredentials() {
    try {
      await invoke("clear_opnsense_config");
      setHost("");
      setApiKey("");
      setApiSecret("");
      setSecretsLoaded(false);
      setTestOk(null);
      addLog("success", "Credentials cleared from keyring and Rust state.");
    } catch (e) {
      addLog("error", String(e));
    }
  }

  async function testConnection() {
    setTesting(true);
    setTestOk(null);
    addLog("info", "Testing OPNsense connection…");
    try {
      // No credentials sent — Rust reads from AppState
      const version = await invoke<string>("test_opnsense_connection");
      setTestOk(version);
      addLog("success", `Connected! OPNsense version: ${version}`);
    } catch (e) {
      addLog("error", `Connection failed: ${e}`);
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="flex flex-col gap-6 p-6 overflow-y-auto h-full">
      <div>
        <h1 className="text-xl font-semibold text-white">Settings</h1>
        <p className="text-sm text-gray-400 mt-0.5">
          Configure OPNsense connection. Credentials are stored in the OS
          secure keyring and never sent back across the IPC bridge.
        </p>
      </div>

      {/* ── Theme & Appearance ───────────────────────────────────────── */}
      <Section icon={Palette} title="Theme & Appearance">
        <div className="space-y-5">
          {/* Mode selector */}
          <div>
            <label className="text-xs text-gray-400 mb-1.5 block">Appearance</label>
            <select
              value={themeMode}
              onChange={(e) => changeMode(e.target.value as ThemeMode)}
              className="input max-w-xs cursor-pointer"
            >
              <option value="system">System (auto)</option>
              <option value="dark">Dark</option>
              <option value="light">Light</option>
            </select>
            <p className="text-xs text-gray-500 mt-2">
              <strong className="text-gray-400">System</strong> follows your OS
              preference. Override with Dark or Light for a fixed look.
            </p>
          </div>

          {/* Accent colour picker */}
          <div>
            <label className="text-xs text-gray-400 mb-2 block">Accent Color</label>
            <div className="flex gap-2 flex-wrap">
              {(Object.keys(ACCENT_PALETTES) as AccentColor[]).map((key) => {
                const palette = ACCENT_PALETTES[key];
                const active = accent === key;
                return (
                  <button
                    key={key}
                    onClick={() => changeAccent(key)}
                    title={palette.label}
                    className={`group relative w-10 h-10 rounded-xl transition-all duration-200 ${
                      active
                        ? "ring-2 ring-offset-2 ring-offset-surface-800 scale-110"
                        : "hover:scale-105 opacity-80 hover:opacity-100"
                    }`}
                    style={{
                      backgroundColor: palette.swatch,
                      ...(active ? { ringColor: palette.swatch } : {}),
                    }}
                  >
                    {active && (
                      <Check
                        size={16}
                        className="absolute inset-0 m-auto text-white drop-shadow-md"
                      />
                    )}
                  </button>
                );
              })}
            </div>
            <p className="text-xs text-gray-500 mt-2">
              Changes the accent color used throughout the interface.
              Currently: <strong className="text-gray-400">{ACCENT_PALETTES[accent].label}</strong>
            </p>
          </div>
        </div>
      </Section>

      <Section icon={Server} title="OPNsense Connection">
        <div className="space-y-4">
          <div>
            <label className="text-xs text-gray-400 mb-1.5 block">Host / IP</label>
            <input
              className="input"
              placeholder="192.168.1.1"
              value={host}
              onChange={(e) => setHost(e.target.value)}
            />
          </div>

          <div>
            <label className="text-xs text-gray-400 mb-1.5 block">API Key</label>
            <div className="relative">
              <input
                className="input pr-10"
                placeholder={secretsLoaded ? "••••••••  (loaded in Rust state)" : "API Key"}
                type={showKey ? "text" : "password"}
                value={apiKey}
                onChange={(e) => { setApiKey(e.target.value); setSecretsLoaded(false); }}
              />
              <button
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
                onClick={() => setShowKey((s) => !s)}
                tabIndex={-1}
                type="button"
              >
                {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          <div>
            <label className="text-xs text-gray-400 mb-1.5 block">API Secret</label>
            <div className="relative">
              <input
                className="input pr-10"
                placeholder={secretsLoaded ? "••••••••  (loaded in Rust state)" : "API Secret"}
                type={showSecret ? "text" : "password"}
                value={apiSecret}
                onChange={(e) => { setApiSecret(e.target.value); setSecretsLoaded(false); }}
              />
              <button
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
                onClick={() => setShowSecret((s) => !s)}
                tabIndex={-1}
                type="button"
              >
                {showSecret ? <EyeOff size={14} /> : <Eye size={14} />}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <input
              id="verify-tls"
              type="checkbox"
              checked={verifyTls}
              onChange={(e) => setVerifyTls(e.target.checked)}
              className="accent-brand-500"
            />
            <label htmlFor="verify-tls" className="text-sm text-gray-300 cursor-pointer">
              Verify TLS certificate (disable only for self-signed dev setups)
            </label>
          </div>

          {testOk && (
            <div className="flex items-center gap-2 p-3 bg-green-500/10 border border-green-500/30 rounded-lg text-sm text-green-300">
              <CheckCircle2 size={14} />
              Connected — OPNsense {testOk}
            </div>
          )}

          <div className="flex gap-2 flex-wrap">
            <button
              onClick={testConnection}
              disabled={testing}
              className="btn-ghost flex items-center gap-2 text-sm"
              type="button"
            >
              {testing ? <RefreshCw size={14} className="animate-spin" /> : <RefreshCw size={14} />}
              Test Connection
            </button>
            <button
              onClick={saveCredentials}
              disabled={saving}
              className="btn-primary flex items-center gap-2 text-sm"
              type="button"
            >
              <Save size={14} />
              {saving ? "Saving…" : "Save to Keyring"}
            </button>
            <button
              onClick={loadSavedCredentials}
              className="btn-ghost flex items-center gap-2 text-sm"
              type="button"
            >
              <KeyRound size={14} />
              Load Saved
            </button>
            <button
              onClick={clearCredentials}
              className="btn-ghost flex items-center gap-2 text-sm text-red-400 hover:text-red-300"
              type="button"
            >
              <Trash2 size={14} />
              Clear
            </button>
          </div>
        </div>
      </Section>

      <Section icon={Network} title="Network Interface">
        <div>
          <label className="text-xs text-gray-400 mb-1.5 block">
            OPNsense interface for generated rules
          </label>
          <input
            className="input max-w-xs"
            placeholder="wan"
            value={iface}
            onChange={(e) => setIface(e.target.value)}
            onBlur={() => setOpnsenseInterface(iface)}
          />
          <p className="text-xs text-gray-500 mt-2">
            Used as the <code className="text-brand-400">interface</code> field in generated rules
            (e.g. <code className="text-brand-400">wan</code>, <code className="text-brand-400">lan</code>, <code className="text-brand-400">opt1</code>).
          </p>
        </div>
      </Section>

      <Section icon={Shield} title="Security Notes">
        <ul className="space-y-2 text-sm text-gray-400">
          <li className="flex items-start gap-2">
            <CheckCircle2 size={14} className="text-green-400 mt-0.5 shrink-0" />
            Credentials transit IPC exactly once (on save). After that the API
            secret lives only in the OS keyring and Rust{" "}
            <code className="text-brand-400">AppState</code> — never returned to JS.
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 size={14} className="text-green-400 mt-0.5 shrink-0" />
            All OPNsense traffic uses TLS via rustls. Secrets are wrapped in{" "}
            <code className="text-brand-400">Zeroizing&lt;String&gt;</code> and
            scrubbed from RAM when the client is dropped.
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 size={14} className="text-green-400 mt-0.5 shrink-0" />
            A full config backup is taken before every rule deployment. Rules are
            reviewed in the Staging Area before anything is applied.
          </li>
          <li className="flex items-start gap-2">
            <CheckCircle2 size={14} className="text-green-400 mt-0.5 shrink-0" />
            The shell capability is scoped to{" "}
            <code className="text-brand-400">nmap</code> and{" "}
            <code className="text-brand-400">tshark</code> only — no other
            binaries can be invoked.
          </li>
        </ul>
      </Section>
    </div>
  );
}
