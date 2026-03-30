import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  ChevronRight,
  FileSearch,
  Layers,
  Network,
  ShieldCheck,
  Wifi,
  Zap,
} from "lucide-react";
import { AppView, CaptureResult, RecommendationSet, ScanResult } from "../types";

interface DashboardProps {
  scanResult: ScanResult | null;
  captureResult: CaptureResult | null;
  recommendations: RecommendationSet | null;
  setView: (v: AppView) => void;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(2)} MB`;
}

function OverviewCard({
  icon: Icon,
  label,
  value,
  sub,
  color,
  onClick,
}: {
  icon: React.ElementType;
  label: string;
  value: string | number;
  sub?: string;
  color: string;
  onClick?: () => void;
}) {
  return (
    <button
      onClick={onClick}
      disabled={!onClick}
      aria-label={`${label}: ${value}${sub ? `, ${sub}` : ""}`}
      className={`bg-surface-800 border border-surface-600 rounded-xl p-5 text-left transition-colors ${
        onClick ? "hover:bg-surface-700 hover:border-surface-500 cursor-pointer" : "cursor-default"
      }`}
    >
      <div className="flex items-center gap-2 mb-3">
        <Icon size={16} aria-hidden="true" className={color} />
        <span className="text-xs text-gray-500 uppercase tracking-wider font-medium">{label}</span>
      </div>
      <p className={`text-2xl font-bold font-mono ${color}`}>{value}</p>
      {sub && <p className="text-xs text-gray-500 mt-1 truncate">{sub}</p>}
    </button>
  );
}

function SourceCard({
  title,
  icon: Icon,
  loaded,
  filename,
  details,
  actionLabel,
  onAction,
}: {
  title: string;
  icon: React.ElementType;
  loaded: boolean;
  filename?: string;
  details: { label: string; value: string | number }[];
  actionLabel: string;
  onAction: () => void;
}) {
  return (
    <div className="bg-surface-800 border border-surface-600 rounded-xl p-5">
      <div className="flex items-start justify-between mb-4">
        <div className="flex items-center gap-2.5">
          <div className={`p-2 rounded-lg ${loaded ? "bg-brand-600/20" : "bg-surface-700"}`}>
            <Icon size={16} className={loaded ? "text-brand-400" : "text-gray-500"} />
          </div>
          <div>
            <h3 className="text-sm font-semibold text-white">{title}</h3>
            {loaded && filename ? (
              <p className="text-xs text-gray-500 mt-0.5 font-mono truncate max-w-[200px]">{filename}</p>
            ) : (
              <p className="text-xs text-gray-600 mt-0.5">No data loaded</p>
            )}
          </div>
        </div>
        {loaded ? (
          <CheckCircle2 size={16} aria-label="Data loaded" className="text-green-500 shrink-0" />
        ) : (
          <div aria-label="No data loaded" className="w-4 h-4 rounded-full border-2 border-surface-500 shrink-0" />
        )}
      </div>

      {loaded && details.length > 0 && (
        <div className="grid grid-cols-2 gap-2 mb-4">
          {details.map(({ label, value }) => (
            <div key={label} className="bg-surface-700/50 rounded-lg px-3 py-2">
              <p className="text-xs text-gray-500">{label}</p>
              <p className="text-sm font-semibold text-white font-mono">{value}</p>
            </div>
          ))}
        </div>
      )}

      <button
        onClick={onAction}
        className="flex items-center gap-1.5 text-xs text-brand-400 hover:text-brand-300 font-medium transition-colors"
      >
        {actionLabel}
        <ChevronRight size={12} aria-hidden="true" />
      </button>
    </div>
  );
}

function RiskRow({ severity, count }: { severity: string; count: number }) {
  const colors: Record<string, string> = {
    critical: "text-red-400 bg-red-900/30 border-red-700/40",
    high: "text-orange-400 bg-orange-900/30 border-orange-700/40",
    medium: "text-yellow-400 bg-yellow-900/30 border-yellow-700/40",
    low: "text-blue-400 bg-blue-900/30 border-blue-700/40",
    info: "text-gray-400 bg-surface-700 border-surface-500",
  };
  const bar: Record<string, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-yellow-500",
    low: "bg-blue-500",
    info: "bg-gray-500",
  };
  const cls = colors[severity] ?? colors.info;
  const barCls = bar[severity] ?? bar.info;
  return (
    <div className={`flex items-center gap-3 px-3 py-2 rounded-lg border ${cls}`}>
      <span className="capitalize text-xs font-bold w-16">{severity}</span>
      <div
        role="progressbar"
        aria-label={`${severity} risk findings`}
        aria-valuenow={count}
        aria-valuemin={0}
        aria-valuemax={10}
        className="flex-1 h-1.5 bg-black/20 rounded-full overflow-hidden"
      >
        <div className={`h-full ${barCls} rounded-full`} style={{ width: `${Math.min(count * 10, 100)}%` }} />
      </div>
      <span className="text-xs font-mono font-semibold w-6 text-right" aria-hidden="true">{count}</span>
    </div>
  );
}

export default function Dashboard({
  scanResult,
  captureResult,
  recommendations,
  setView,
}: DashboardProps) {
  const pendingRules = recommendations?.recommendations.length ?? 0;

  // Risk summary from capture findings
  const riskCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  captureResult?.risk_findings.forEach((f) => {
    riskCounts[f.severity] = (riskCounts[f.severity] ?? 0) + 1;
  });
  const totalRisks = Object.values(riskCounts).reduce((s, n) => s + n, 0);

  // Nmap open-port risk rough count
  const nmapHighRisk = scanResult?.hosts.reduce((sum, h) => {
    const DANGEROUS = [23, 21, 69, 139, 445, 512, 513, 514, 3389, 5900, 6379, 27017, 9200, 2375, 2376];
    return sum + h.ports.filter((p) => p.state === "open" && DANGEROUS.includes(p.port)).length;
  }, 0) ?? 0;

  const hasAnyData = !!(scanResult || captureResult);

  return (
    <div className="flex flex-col gap-6 p-6 overflow-y-auto h-full">
      {/* Header */}
      <div>
        <h1 className="text-xl font-semibold text-white">Overview</h1>
        <p className="text-sm text-gray-400 mt-0.5">
          Summary of all loaded scan and capture data, with quick access to each section.
        </p>
      </div>

      {/* Summary stat cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <OverviewCard
          icon={Network}
          label="Nmap Hosts"
          value={scanResult?.hosts.length ?? "—"}
          sub={scanResult ? `${scanResult.total_open} open ports` : "No scan loaded"}
          color={scanResult ? "text-brand-400" : "text-gray-600"}
          onClick={scanResult ? () => setView("capture") : undefined}
        />
        <OverviewCard
          icon={Wifi}
          label="Capture Hosts"
          value={captureResult?.hosts.length ?? "—"}
          sub={captureResult ? formatBytes(captureResult.total_bytes) : "No capture loaded"}
          color={captureResult ? "text-cyan-400" : "text-gray-600"}
          onClick={captureResult ? () => setView("capture") : undefined}
        />
        <OverviewCard
          icon={Zap}
          label="Pending Rules"
          value={pendingRules > 0 ? pendingRules : "—"}
          sub={pendingRules > 0 ? "Click to review" : "No rules staged"}
          color={pendingRules > 0 ? "text-green-400" : "text-gray-600"}
          onClick={pendingRules > 0 ? () => setView("staging") : undefined}
        />
        <OverviewCard
          icon={AlertTriangle}
          label="Risk Findings"
          value={totalRisks + nmapHighRisk > 0 ? totalRisks + nmapHighRisk : "—"}
          sub={
            totalRisks + nmapHighRisk > 0
              ? `${nmapHighRisk} nmap · ${totalRisks} capture`
              : "No risks detected"
          }
          color={totalRisks + nmapHighRisk > 0 ? "text-red-400" : "text-gray-600"}
        />
      </div>

      {/* Data source status */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <SourceCard
          title="Nmap Scan"
          icon={ShieldCheck}
          loaded={!!scanResult}
          filename={undefined}
          details={
            scanResult
              ? [
                  { label: "Hosts", value: scanResult.hosts.length },
                  { label: "Open Ports", value: scanResult.total_open },
                  { label: "Filtered", value: scanResult.total_filtered },
                  { label: "Closed", value: scanResult.total_closed },
                ]
              : []
          }
          actionLabel={scanResult ? "View scan results" : "Load an Nmap scan"}
          onAction={() => setView("capture")}
        />
        <SourceCard
          title="Wireshark / Capture"
          icon={Activity}
          loaded={!!captureResult}
          filename={captureResult?.source_file}
          details={
            captureResult
              ? [
                  { label: "Packets", value: captureResult.total_packets.toLocaleString() },
                  { label: "Traffic", value: formatBytes(captureResult.total_bytes) },
                  { label: "Hosts", value: captureResult.hosts.length },
                  { label: "Findings", value: captureResult.risk_findings.length },
                ]
              : []
          }
          actionLabel={captureResult ? "View capture results" : "Load a capture file"}
          onAction={() => setView("capture")}
        />
      </div>

      {/* Risk breakdown */}
      {totalRisks > 0 && (
        <div className="bg-surface-800 border border-surface-600 rounded-xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle size={14} aria-hidden="true" className="text-red-400" />
            <h3 className="text-sm font-semibold text-gray-300">Capture Risk Breakdown</h3>
          </div>
          <div className="flex flex-col gap-1.5">
            {(["critical", "high", "medium", "low", "info"] as const)
              .filter((s) => riskCounts[s] > 0)
              .map((s) => (
                <RiskRow key={s} severity={s} count={riskCounts[s]} />
              ))}
          </div>
        </div>
      )}

      {/* Quick actions */}
      <div className="bg-surface-800 border border-surface-600 rounded-xl p-5">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">Quick Actions</h3>
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setView("capture")}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-brand-600 hover:bg-brand-500 text-white text-sm font-medium transition-colors"
          >
            <FileSearch size={14} aria-hidden="true" />
            {hasAnyData ? "Load Another Scan" : "Get Started"}
          </button>
          {pendingRules > 0 && (
            <button
              onClick={() => setView("staging")}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-green-700 hover:bg-green-600 text-white text-sm font-medium transition-colors"
            >
              <Layers size={14} aria-hidden="true" />
              Review {pendingRules} Pending {pendingRules === 1 ? "Rule" : "Rules"}
            </button>
          )}
          <button
            onClick={() => setView("logs")}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-surface-700 hover:bg-surface-600 text-gray-300 text-sm font-medium transition-colors"
          >
            <Activity size={14} aria-hidden="true" />
            View Logs
          </button>
        </div>
      </div>

      {/* Empty state */}
      {!hasAnyData && (
        <div className="flex flex-col items-center justify-center flex-1 text-center py-10">
          <ShieldCheck size={48} aria-hidden="true" className="text-surface-600 mb-4" />
          <p className="text-gray-400 font-medium">Nothing loaded yet</p>
          <p className="text-gray-600 text-sm mt-1">
            Head to <strong className="text-gray-400">Scan & Ingest</strong> to load an Nmap report or Wireshark capture.
          </p>
        </div>
      )}
    </div>
  );
}
