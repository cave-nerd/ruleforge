import { useEffect, useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { open } from "@tauri-apps/plugin-dialog";
import {
  Activity,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Circle,
  FileSearch,
  Info,
  Plus,
  RefreshCw,
  ShieldCheck,
  Tag,
  Terminal,
  Upload,
  Wifi,
  X,
  Zap,
} from "lucide-react";
import {
  CaptureFinding,
  CaptureResult,
  HostResult,
  LogEntry,
  PortResult,
  RecommendationSet,
  RiskProfile,
  RiskSeverity,
  ScanResult,
} from "../types";

type ScanMode = "nmap-upload" | "nmap-live" | "wireshark";

interface ScanPanelProps {
  scanResult: ScanResult | null;
  setScanResult: (s: ScanResult) => void;
  captureResult: CaptureResult | null;
  setCaptureResult: (r: CaptureResult | null) => void;
  hostTags: Record<string, string[]>;
  setHostTags: (tags: Record<string, string[]>) => void;
  addLog: (level: LogEntry["level"], message: string) => void;
  opnsenseInterface: string;
  onRulesGenerated: (recs: RecommendationSet) => void;
}

// ── Tag system ────────────────────────────────────────────────────────────────

const ROLE_TAGS: { name: string; cls: string; hint: string }[] = [
  // Application tiers
  { name: "frontend",       cls: "bg-blue-900/60 text-blue-300 border-blue-700/60",       hint: "Accepts client traffic; proxies to backend" },
  { name: "backend",        cls: "bg-purple-900/60 text-purple-300 border-purple-700/60", hint: "Internal app tier; reachable from frontend only" },
  { name: "database",       cls: "bg-orange-900/60 text-orange-300 border-orange-700/60", hint: "Data tier; reachable from backend/frontend only" },
  { name: "cache",          cls: "bg-yellow-900/60 text-yellow-300 border-yellow-700/60", hint: "Cache layer; reachable from backend/frontend only" },
  // Infrastructure
  { name: "router",         cls: "bg-sky-900/60 text-sky-300 border-sky-700/60",          hint: "Layer-3 router or gateway; manages inter-VLAN routing" },
  { name: "firewall",       cls: "bg-red-950/70 text-red-300 border-red-800/60",          hint: "Perimeter or internal firewall appliance" },
  { name: "access-point",   cls: "bg-cyan-900/60 text-cyan-300 border-cyan-700/60",       hint: "Wireless access point; bridge between wireless and wired" },
  { name: "switch",         cls: "bg-slate-700/60 text-slate-300 border-slate-600/60",    hint: "Layer-2 switch; managed or unmanaged" },
  { name: "container-host", cls: "bg-indigo-900/60 text-indigo-300 border-indigo-700/60", hint: "Docker/Kubernetes node running containerised workloads" },
  { name: "vpn",            cls: "bg-violet-900/60 text-violet-300 border-violet-700/60", hint: "VPN gateway or endpoint; tunnelled traffic" },
  { name: "nas",            cls: "bg-lime-900/60 text-lime-300 border-lime-700/60",       hint: "Network-attached storage; SMB/NFS server" },
  { name: "iot",            cls: "bg-pink-900/60 text-pink-300 border-pink-700/60",       hint: "IoT/embedded device; minimal trust, should be isolated" },
  // Trust zones
  { name: "client",         cls: "bg-gray-700/60 text-gray-300 border-gray-600/60",       hint: "End-user host; may only reach frontend" },
  { name: "admin",          cls: "bg-red-900/60 text-red-300 border-red-700/60",          hint: "Privileged host; can reach everything" },
  { name: "monitor",        cls: "bg-green-900/60 text-green-300 border-green-700/60",    hint: "Monitoring/observability; can poll everything" },
  { name: "internal",       cls: "bg-teal-900/60 text-teal-300 border-teal-700/60",       hint: "Trusted internal host" },
  { name: "external",       cls: "bg-rose-900/60 text-rose-300 border-rose-700/60",       hint: "Untrusted external host; block from internal" },
  { name: "dmz",            cls: "bg-amber-900/60 text-amber-300 border-amber-700/60",    hint: "Demilitarized zone; limited trust" },
];

function tagCls(name: string): string {
  return ROLE_TAGS.find((t) => t.name === name)?.cls
    ?? "bg-surface-700 text-gray-300 border-surface-500";
}

function TagEditor({
  ip,
  tags,
  onChange,
}: {
  ip: string;
  tags: string[];
  onChange: (ip: string, next: string[]) => void;
}) {
  const [popOpen, setPopOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function onOutside(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setPopOpen(false);
    }
    document.addEventListener("mousedown", onOutside);
    return () => document.removeEventListener("mousedown", onOutside);
  }, []);

  const available = ROLE_TAGS.filter((t) => !tags.includes(t.name));

  return (
    <div ref={ref} className="relative flex flex-wrap gap-1 items-center min-w-[80px]">
      {tags.map((tag) => (
        <button
          key={tag}
          onClick={() => onChange(ip, tags.filter((t) => t !== tag))}
          aria-label={`Remove ${tag} tag`}
          className={`inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-xs border transition-opacity hover:opacity-70 ${tagCls(tag)}`}
        >
          {tag}
          <X size={9} aria-hidden="true" />
        </button>
      ))}
      {available.length > 0 && (
        <button
          onClick={() => setPopOpen((o) => !o)}
          aria-label="Add role tag"
          aria-expanded={popOpen}
          aria-haspopup="listbox"
          className="text-gray-600 hover:text-gray-300 transition-colors"
        >
          <Plus size={12} aria-hidden="true" />
        </button>
      )}
      {popOpen && (
        <div role="listbox" aria-label="Available role tags" className="absolute top-full left-0 mt-1 z-20 bg-surface-800 border border-surface-600 rounded-lg shadow-xl p-1.5 w-36">
          {available.map((t) => (
            <button
              key={t.name}
              role="option"
              aria-selected={false}
              title={t.hint}
              onClick={() => { onChange(ip, [...tags, t.name]); setPopOpen(false); }}
              className={`block w-full text-left px-2 py-1 rounded text-xs border mb-0.5 last:mb-0 transition-opacity hover:opacity-80 ${t.cls}`}
            >
              {t.name}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Shared helpers ────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(2)} MB`;
}

function severityColor(s: RiskSeverity): string {
  switch (s) {
    case "critical": return "text-red-400 bg-red-900/30 border-red-700/50";
    case "high":     return "text-orange-400 bg-orange-900/30 border-orange-700/50";
    case "medium":   return "text-yellow-400 bg-yellow-900/30 border-yellow-700/50";
    case "low":      return "text-blue-400 bg-blue-900/30 border-blue-700/50";
    default:         return "text-gray-400 bg-surface-700 border-surface-500";
  }
}

function severityIcon(s: RiskSeverity) {
  switch (s) {
    case "critical":
    case "high":  return <AlertTriangle size={14} />;
    case "medium": return <Zap size={14} />;
    default:       return <Info size={14} />;
  }
}

// ── Nmap sub-components ───────────────────────────────────────────────────────

function PortBadge({ state }: { state: string }) {
  const cls =
    state === "open" ? "badge-open" :
    state === "filtered" ? "badge-filtered" : "badge-closed";
  return <span className={cls}>{state}</span>;
}

function ConfBar({ conf }: { conf: number }) {
  const pct = (conf / 10) * 100;
  const color = conf >= 8 ? "bg-green-500" : conf >= 5 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div
        role="progressbar"
        aria-label={`Confidence ${conf} out of 10`}
        aria-valuenow={conf}
        aria-valuemin={0}
        aria-valuemax={10}
        className="w-16 h-1.5 bg-surface-600 rounded-full overflow-hidden"
      >
        <div className={`h-full ${color} rounded-full`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-gray-400 font-mono" aria-hidden="true">{conf}/10</span>
    </div>
  );
}

function PortRow({ port }: { port: PortResult }) {
  return (
    <tr className="border-t border-surface-600 hover:bg-surface-700/50 transition-colors">
      <td className="py-2 px-3 font-mono text-sm text-gray-200">{port.port}/{port.protocol}</td>
      <td className="py-2 px-3"><PortBadge state={port.state} /></td>
      <td className="py-2 px-3 text-sm text-gray-300">{port.service_name || "—"}</td>
      <td className="py-2 px-3 text-sm text-gray-400">{port.product} {port.version}</td>
      <td className="py-2 px-3"><ConfBar conf={port.conf} /></td>
      <td className="py-2 px-3 text-xs text-gray-500">{port.reason}</td>
    </tr>
  );
}

function NmapHostCard({
  host,
  tags,
  onTagChange,
}: {
  host: HostResult;
  tags: string[];
  onTagChange: (ip: string, next: string[]) => void;
}) {
  const [expanded, setExpanded] = useState(true);
  const openPorts = host.ports.filter((p) => p.state === "open").length;

  return (
    <div className="card mb-3">
      <button
        className="flex items-center gap-3 w-full text-left"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
        aria-label={`${host.ip}${host.hostname ? ` (${host.hostname})` : ""}, ${openPorts} open ports. ${expanded ? "Collapse" : "Expand"} details.`}
      >
        {expanded ? <ChevronDown size={16} aria-hidden="true" className="text-gray-400" /> : <ChevronRight size={16} aria-hidden="true" className="text-gray-400" />}
        <span className="font-mono text-white">{host.ip}</span>
        {host.hostname && <span className="text-gray-400 text-sm">({host.hostname})</span>}
        {/* Role tags inline in the header */}
        <div className="flex flex-wrap gap-1" onClick={(e) => e.stopPropagation()}>
          <TagEditor ip={host.ip} tags={tags} onChange={onTagChange} />
        </div>
        <span className="ml-auto text-xs text-gray-400 shrink-0">
          {openPorts} open / {host.ports.length} total
        </span>
        {openPorts > 0 && <AlertTriangle size={14} aria-hidden="true" className="text-yellow-500 shrink-0" />}
      </button>

      {expanded && host.ports.length > 0 && (
        <div className="mt-3 overflow-x-auto">
          <table aria-label={`Port details for ${host.ip}`} className="w-full text-left text-sm">
            <thead>
              <tr className="text-xs text-gray-500 uppercase tracking-wider">
                <th scope="col" className="py-1.5 px-3">Port/Proto</th>
                <th scope="col" className="py-1.5 px-3">State</th>
                <th scope="col" className="py-1.5 px-3">Service</th>
                <th scope="col" className="py-1.5 px-3">Product</th>
                <th scope="col" className="py-1.5 px-3">Confidence</th>
                <th scope="col" className="py-1.5 px-3">Reason</th>
              </tr>
            </thead>
            <tbody>
              {host.ports.map((p) => (
                <PortRow key={`${p.port}-${p.protocol}`} port={p} />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {expanded && host.ports.length === 0 && (
        <p className="mt-3 text-sm text-gray-500">No ports found.</p>
      )}
    </div>
  );
}

// ── Capture sub-components ────────────────────────────────────────────────────

function StatCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="bg-surface-800 border border-surface-600 rounded-lg p-4">
      <p className="text-xs text-gray-500 mb-1">{label}</p>
      <p className="text-xl font-semibold text-white">{value}</p>
    </div>
  );
}

function ProtocolBar({ counts }: { counts: CaptureResult["protocol_counts"] }) {
  const top = counts.slice(0, 8);
  const total = top.reduce((s, p) => s + p.packets, 0) || 1;
  const COLORS = [
    "bg-brand-500", "bg-cyan-500", "bg-purple-500", "bg-yellow-500",
    "bg-pink-500", "bg-green-500", "bg-orange-500", "bg-indigo-500",
  ];
  return (
    <div className="bg-surface-800 border border-surface-600 rounded-lg p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3">Protocol Breakdown</h3>
      <div role="img" aria-label={`Protocol distribution: ${top.map((p) => `${p.protocol} ${p.packets} packets`).join(", ")}`} className="flex h-5 rounded overflow-hidden gap-0.5 mb-3">
        {top.map((p, i) => (
          <div
            key={p.protocol}
            className={`${COLORS[i % COLORS.length]} transition-all`}
            style={{ width: `${(p.packets / total) * 100}%` }}
            aria-hidden="true"
          />
        ))}
      </div>
      <div className="flex flex-wrap gap-3" aria-hidden="true">
        {top.map((p, i) => (
          <span key={p.protocol} className="flex items-center gap-1.5 text-xs text-gray-400">
            <span className={`inline-block w-2.5 h-2.5 rounded-sm ${COLORS[i % COLORS.length]}`} />
            {p.protocol} ({p.packets.toLocaleString()})
          </span>
        ))}
      </div>
    </div>
  );
}

function FindingsList({ findings }: { findings: CaptureFinding[] }) {
  if (findings.length === 0) {
    return (
      <div className="bg-surface-800 border border-surface-600 rounded-lg p-4">
        <h3 className="text-sm font-semibold text-gray-300 mb-2">Risk Findings</h3>
        <p className="text-xs text-gray-500">No risks detected in this capture.</p>
      </div>
    );
  }
  return (
    <div className="bg-surface-800 border border-surface-600 rounded-lg p-4">
      <h3 className="text-sm font-semibold text-gray-300 mb-3">
        Risk Findings ({findings.length})
      </h3>
      <ul className="space-y-2">
        {findings.map((f, i) => (
          <li
            key={i}
            className={`flex items-start gap-2 text-xs px-3 py-2 rounded border ${severityColor(f.severity)}`}
          >
            <span className="mt-0.5 shrink-0" aria-hidden="true">{severityIcon(f.severity)}</span>
            <span className="uppercase font-bold shrink-0 w-16">{f.severity}</span>
            <span>{f.description}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ── Profile selector (shared) ─────────────────────────────────────────────────

function ProfileSelector({
  profile,
  setProfile,
}: {
  profile: RiskProfile;
  setProfile: (p: RiskProfile) => void;
}) {
  return (
    <div role="radiogroup" aria-label="Risk profile" className="flex items-center gap-1">
      {(["strict", "balanced", "permissive"] as RiskProfile[]).map((p) => (
        <button
          key={p}
          role="radio"
          aria-checked={profile === p}
          onClick={() => setProfile(p)}
          className={`px-2.5 py-1 rounded text-xs font-medium capitalize transition-colors ${
            profile === p
              ? p === "strict"
                ? "bg-red-600/30 text-red-300 border border-red-600/40"
                : p === "balanced"
                ? "bg-brand-600/30 text-brand-300 border border-brand-600/40"
                : "bg-green-600/30 text-green-300 border border-green-600/40"
              : "text-gray-500 hover:text-gray-300 hover:bg-surface-700"
          }`}
        >
          {p}
        </button>
      ))}
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ScanPanel({
  scanResult,
  setScanResult,
  captureResult,
  setCaptureResult,
  hostTags,
  setHostTags,
  addLog,
  opnsenseInterface,
  onRulesGenerated,
}: ScanPanelProps) {
  const [mode, setMode] = useState<ScanMode>("nmap-upload");
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [profile, setProfile] = useState<RiskProfile>("balanced");
  const [nmapTarget, setNmapTarget] = useState("");
  const [useTshark, setUseTshark] = useState(true);

  // Determine if there's a result for the active mode
  const hasResult = mode === "wireshark" ? !!captureResult : !!scanResult;

  // ── Nmap handlers ──────────────────────────────────────────────────────────

  async function handleNmapUpload() {
    let selected: string | string[] | null;
    try {
      selected = await open({
        title: "Select Nmap XML file",
        filters: [{ name: "Nmap XML", extensions: ["xml"] }],
        multiple: false,
      });
    } catch (e) {
      addLog("error", `File dialog failed: ${e}`);
      return;
    }
    if (!selected) return;
    const filePath = typeof selected === "string" ? selected : selected[0];
    setLoading(true);
    addLog("info", `Parsing Nmap XML: ${filePath}`);
    try {
      const result = await invoke<ScanResult>("parse_nmap_xml", { filePath });
      setScanResult(result);
      addLog("success", `Parsed scan: ${result.total_open} open, ${result.total_filtered} filtered, ${result.total_closed} closed across ${result.hosts.length} hosts.`);
      await runNmapEngine(result);
    } catch (e) {
      addLog("error", String(e));
    } finally {
      setLoading(false);
    }
  }

  async function handleLiveScan() {
    if (!nmapTarget.trim()) return;
    setLoading(true);
    addLog("info", `Starting Nmap scan against: ${nmapTarget}`);
    try {
      const result = await invoke<ScanResult>("run_nmap_scan", { target: nmapTarget.trim() });
      setScanResult(result);
      addLog("success", `Live scan complete: ${result.total_open} open ports found.`);
      await runNmapEngine(result);
    } catch (e) {
      addLog("error", String(e));
    } finally {
      setLoading(false);
    }
  }

  async function runNmapEngine(scan: ScanResult) {
    addLog("info", `Generating ${profile} recommendations…`);
    try {
      const recs = await invoke<RecommendationSet>("generate_recommendations", {
        scan,
        profile,
        interface: opnsenseInterface || "wan",
      });
      onRulesGenerated(recs);
      addLog("success", recs.summary);
    } catch (e) {
      addLog("error", `Recommendation engine error: ${e}`);
    }
  }

  // ── Wireshark handlers ─────────────────────────────────────────────────────

  async function handleCaptureOpen() {
    let selected: string | string[] | null;
    try {
      selected = await open({
        title: "Open Capture File",
        filters: [{ name: "Packet Captures", extensions: ["pcap", "pcapng", "cap", "json"] }],
        multiple: false,
        directory: false,
      });
    } catch (e) {
      addLog("error", `File dialog failed: ${e}`);
      return;
    }
    if (!selected) return;
    const filePath = typeof selected === "string" ? selected : selected[0];
    setLoading(true);
    addLog("info", `Loading capture: ${filePath}`);
    try {
      let result: CaptureResult;
      if (useTshark && (filePath.endsWith(".pcap") || filePath.endsWith(".pcapng") || filePath.endsWith(".cap"))) {
        result = await invoke<CaptureResult>("run_tshark_on_capture", { filePath });
        addLog("info", "Parsed via tshark (rich L7 detail)");
      } else {
        result = await invoke<CaptureResult>("parse_capture", { filePath });
        addLog("info", "Parsed via built-in Rust parser");
      }
      setCaptureResult(result);
      addLog("success", `Loaded ${result.source_file}: ${result.total_packets.toLocaleString()} packets, ${result.hosts.length} hosts, ${result.risk_findings.length} findings`);
    } catch (err) {
      addLog("error", `Capture parse failed: ${err}`);
    } finally {
      setLoading(false);
    }
  }

  async function handleGenerateCaptureRules() {
    if (!captureResult) return;
    setGenerating(true);
    addLog("info", `Generating ${profile} firewall rules from capture…`);
    try {
      const recs = await invoke<RecommendationSet>("generate_recommendations_from_capture", {
        capture: captureResult,
        profile,
        interface: opnsenseInterface || "wan",
        hostTags,
      });
      addLog("success", recs.summary);
      onRulesGenerated(recs);
    } catch (e) {
      addLog("error", `Rule generation failed: ${e}`);
    } finally {
      setGenerating(false);
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-full overflow-hidden">
      {/* Header */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-surface-600 bg-surface-800 shrink-0 gap-4 flex-wrap">
        <div className="flex items-center gap-2.5">
          <ShieldCheck size={18} aria-hidden="true" className="text-brand-400" />
          <h1 className="text-base font-semibold text-white">Scan & Ingest</h1>
        </div>

        <div className="flex items-center gap-3 flex-wrap">
          {hasResult && <ProfileSelector profile={profile} setProfile={setProfile} />}

          {/* Wireshark-specific tshark toggle */}
          {mode === "wireshark" && (
            <label className="flex items-center gap-1.5 text-xs text-gray-400 cursor-pointer select-none">
              <input
                type="checkbox"
                checked={useTshark}
                onChange={(e) => setUseTshark(e.target.checked)}
                className="rounded border-surface-500 bg-surface-700 text-brand-500"
              />
              Use tshark (richer L7)
            </label>
          )}

          {/* Generate Rules — for capture mode (nmap auto-generates on load) */}
          {mode === "wireshark" && captureResult && (
            <button
              onClick={handleGenerateCaptureRules}
              disabled={generating || loading}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-green-700 hover:bg-green-600 text-white text-sm font-medium transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Zap size={14} aria-hidden="true" />
              {generating ? "Generating…" : "Generate Rules →"}
            </button>
          )}
        </div>
      </header>

      {/* Body */}
      <div className="flex-1 overflow-y-auto p-6 space-y-5">

        {/* Source mode selector */}
        <div className="bg-surface-800 border border-surface-600 rounded-xl p-4">
          <p className="text-xs text-gray-500 uppercase tracking-wider font-medium mb-3">Data source</p>
          <div role="radiogroup" aria-label="Data source" className="flex gap-2 flex-wrap">
            {[
              { id: "nmap-upload" as ScanMode, label: "Nmap XML", icon: Upload, hint: "Upload a saved Nmap XML report" },
              { id: "nmap-live" as ScanMode, label: "Live Nmap Scan", icon: Terminal, hint: "Run Nmap directly against a target" },
              { id: "wireshark" as ScanMode, label: "Wireshark / pcap", icon: Activity, hint: "Load a .pcap, .pcapng, or tshark JSON file" },
            ].map(({ id, label, icon: Icon, hint }) => (
              <button
                key={id}
                role="radio"
                aria-checked={mode === id}
                onClick={() => setMode(id)}
                title={hint}
                className={`flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-colors border ${
                  mode === id
                    ? "bg-brand-600/20 text-brand-300 border-brand-600/40"
                    : "text-gray-400 hover:text-gray-200 hover:bg-surface-700 border-transparent"
                }`}
              >
                <Icon size={14} aria-hidden="true" />
                {label}
              </button>
            ))}
          </div>

          {/* Source-specific input */}
          <div className="mt-4">
            {mode === "nmap-upload" && (
              <button
                onClick={handleNmapUpload}
                disabled={loading}
                className="btn-primary flex items-center gap-2"
              >
                <RefreshCw size={14} aria-hidden="true" className={loading ? "animate-spin" : "hidden"} />
                <Upload size={14} aria-hidden="true" className={loading ? "hidden" : ""} />
                {loading ? "Parsing…" : "Select Nmap XML"}
              </button>
            )}

            {mode === "nmap-live" && (
              <div className="flex gap-3">
                <label htmlFor="nmap-target" className="sr-only">Scan target (IP, CIDR range, or hostname)</label>
                <input
                  id="nmap-target"
                  className="input"
                  placeholder="Target (e.g. 192.168.1.0/24 or hostname)"
                  value={nmapTarget}
                  onChange={(e) => setNmapTarget(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleLiveScan()}
                />
                <button
                  onClick={handleLiveScan}
                  disabled={loading || !nmapTarget.trim()}
                  className="btn-primary flex items-center gap-2 whitespace-nowrap"
                >
                  <RefreshCw size={14} aria-hidden="true" className={loading ? "animate-spin" : "hidden"} />
                  <Terminal size={14} aria-hidden="true" className={loading ? "hidden" : ""} />
                  {loading ? "Scanning…" : "Run Scan"}
                </button>
              </div>
            )}

            {mode === "wireshark" && (
              <button
                onClick={handleCaptureOpen}
                disabled={loading}
                className="btn-primary flex items-center gap-2"
              >
                <RefreshCw size={14} aria-hidden="true" className={loading ? "animate-spin" : "hidden"} />
                <Upload size={14} aria-hidden="true" className={loading ? "hidden" : ""} />
                {loading ? "Parsing…" : "Open Capture File"}
              </button>
            )}
          </div>
        </div>

        {/* ── Nmap results ─────────────────────────────────────────────────── */}
        {(mode === "nmap-upload" || mode === "nmap-live") && (
          <>
            {scanResult ? (
              <>
                {/* Stats */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <StatCard label="Hosts" value={scanResult.hosts.length} />
                  <StatCard label="Open Ports" value={scanResult.total_open} />
                  <StatCard label="Filtered" value={scanResult.total_filtered} />
                  <StatCard label="Closed" value={scanResult.total_closed} />
                </div>
                {/* Hosts */}
                {scanResult.hosts.length > 0 ? (
                  <div>
                    <h2 className="text-sm font-semibold text-gray-400 uppercase tracking-wider mb-3">
                      Hosts ({scanResult.hosts.length})
                    </h2>
                    {scanResult.hosts.map((h) => (
                      <NmapHostCard
                        key={h.ip}
                        host={h}
                        tags={hostTags[h.ip] ?? []}
                        onTagChange={(ip, next) => setHostTags({ ...hostTags, [ip]: next })}
                      />
                    ))}
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-20">
                    <Circle size={48} aria-hidden="true" className="text-surface-600 mb-4" />
                    <p className="text-gray-400">Scan complete — no hosts found.</p>
                  </div>
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center py-20 text-center gap-4">
                <FileSearch size={48} aria-hidden="true" className="text-surface-500" />
                <div>
                  <p className="text-gray-400 font-medium">No Nmap data loaded</p>
                  <p className="text-xs text-gray-600 mt-1">Upload an Nmap XML report or run a live scan above.</p>
                </div>
              </div>
            )}
          </>
        )}

        {/* ── Wireshark / capture results ───────────────────────────────────── */}
        {mode === "wireshark" && (
          <>
            {captureResult ? (
              <>
                {/* Stats */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <StatCard label="Total Packets" value={captureResult.total_packets.toLocaleString()} />
                  <StatCard label="Total Traffic" value={formatBytes(captureResult.total_bytes)} />
                  <StatCard label="Unique Hosts" value={captureResult.hosts.length} />
                  <StatCard label="Conversations" value={captureResult.conversations.length} />
                </div>

                {/* Source file info */}
                <div className="bg-surface-800 border border-surface-600 rounded-lg px-4 py-3 flex items-center gap-2 text-xs text-gray-400">
                  <Activity size={13} aria-hidden="true" className="text-brand-400" />
                  <span className="font-mono">{captureResult.source_file}</span>
                  <span className="text-gray-600">·</span>
                  <span>{captureResult.format}</span>
                </div>

                {/* Protocol breakdown */}
                {captureResult.protocol_counts.length > 0 && (
                  <ProtocolBar counts={captureResult.protocol_counts} />
                )}

                {/* Risk findings */}
                <FindingsList findings={captureResult.risk_findings} />

                {/* Host table with tags */}
                <div className="bg-surface-800 border border-surface-600 rounded-lg overflow-hidden">
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-surface-600">
                    <Wifi size={14} aria-hidden="true" className="text-brand-400" />
                    <h3 className="text-sm font-semibold text-gray-300">
                      Hosts ({captureResult.hosts.length})
                    </h3>
                  </div>
                  <div className="overflow-x-auto">
                    <table aria-label="Capture hosts" className="w-full text-xs">
                      <thead>
                        <tr className="border-b border-surface-600 text-gray-500">
                          <th scope="col" className="px-4 py-2 text-left font-medium">IP Address</th>
                          <th scope="col" className="px-4 py-2 text-right font-medium">Pkts Sent</th>
                          <th scope="col" className="px-4 py-2 text-right font-medium">Pkts Recv</th>
                          <th scope="col" className="px-4 py-2 text-right font-medium">Bytes Out</th>
                          <th scope="col" className="px-4 py-2 text-right font-medium">Bytes In</th>
                          <th scope="col" className="px-4 py-2 text-left font-medium">Protocols</th>
                          <th scope="col" className="px-4 py-2 text-left font-medium">Open Ports</th>
                          <th scope="col" className="px-4 py-2 text-left font-medium">
                            <span className="flex items-center gap-1"><Tag size={11} aria-hidden="true" /> Role Tags</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {captureResult.hosts.map((h) => (
                          <tr
                            key={h.ip}
                            className="border-b border-surface-700/50 hover:bg-surface-700/30 transition-colors"
                          >
                            <td className="px-4 py-2 font-mono text-gray-200">{h.ip}</td>
                            <td className="px-4 py-2 text-right text-gray-400">{h.packets_sent.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right text-gray-400">{h.packets_recv.toLocaleString()}</td>
                            <td className="px-4 py-2 text-right text-gray-400">{formatBytes(h.bytes_sent)}</td>
                            <td className="px-4 py-2 text-right text-gray-400">{formatBytes(h.bytes_recv)}</td>
                            <td className="px-4 py-2 text-gray-400">
                              {h.protocols.slice(0, 4).join(", ")}
                              {h.protocols.length > 4 ? ` +${h.protocols.length - 4}` : ""}
                            </td>
                            <td className="px-4 py-2 font-mono text-gray-400">
                              {h.listening_ports.length > 0
                                ? h.listening_ports.slice(0, 6).join(", ") + (h.listening_ports.length > 6 ? " …" : "")
                                : "—"}
                            </td>
                            <td className="px-4 py-2">
                              <TagEditor
                                ip={h.ip}
                                tags={hostTags[h.ip] ?? []}
                                onChange={(ip, next) => setHostTags({ ...hostTags, [ip]: next })}
                              />
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* Conversation table */}
                {captureResult.conversations.length > 0 && (
                  <div className="bg-surface-800 border border-surface-600 rounded-lg overflow-hidden">
                    <div className="flex items-center gap-2 px-4 py-3 border-b border-surface-600">
                      <Activity size={14} aria-hidden="true" className="text-brand-400" />
                      <h3 className="text-sm font-semibold text-gray-300">
                        Top Conversations (showing {Math.min(captureResult.conversations.length, 100)} of {captureResult.conversations.length})
                      </h3>
                    </div>
                    <div className="overflow-x-auto">
                      <table aria-label="Top network conversations" className="w-full text-xs">
                        <thead>
                          <tr className="border-b border-surface-600 text-gray-500">
                            <th scope="col" className="px-4 py-2 text-left font-medium">Source</th>
                            <th scope="col" className="px-4 py-2 text-left font-medium">Destination</th>
                            <th scope="col" className="px-4 py-2 text-left font-medium">Proto</th>
                            <th scope="col" className="px-4 py-2 text-right font-medium">Packets</th>
                            <th scope="col" className="px-4 py-2 text-right font-medium">Bytes</th>
                          </tr>
                        </thead>
                        <tbody>
                          {captureResult.conversations.slice(0, 100).map((c, i) => (
                            <tr
                              key={i}
                              className="border-b border-surface-700/50 hover:bg-surface-700/30 transition-colors"
                            >
                              <td className="px-4 py-2 font-mono text-gray-300">{c.src_ip}</td>
                              <td className="px-4 py-2 font-mono text-gray-300">
                                {c.dst_ip}{c.dst_port != null ? `:${c.dst_port}` : ""}
                              </td>
                              <td className="px-4 py-2 text-gray-400 uppercase">{c.protocol}</td>
                              <td className="px-4 py-2 text-right text-gray-400">{c.packets.toLocaleString()}</td>
                              <td className="px-4 py-2 text-right text-gray-400">{formatBytes(c.bytes)}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <div className="flex flex-col items-center justify-center py-20 text-center gap-4">
                <FileSearch size={48} aria-hidden="true" className="text-surface-500" />
                <div>
                  <p className="text-gray-400 font-medium">No capture loaded</p>
                  <p className="text-xs text-gray-600 mt-1">
                    Open a .pcap, .pcapng, or tshark JSON file above.
                  </p>
                </div>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
