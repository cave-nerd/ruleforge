import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import {
  Shield,
  ShieldOff,
  Eye,
  Play,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Info,
  ArrowRight,
} from "lucide-react";
import {
  ApplyResult,
  LogEntry,
  OPNsenseRuleRow,
  Recommendation,
  RecommendationSet,
  ScanResult,
  ValidationResult,
} from "../types";

interface StagingAreaProps {
  recommendations: RecommendationSet | null;
  scanResult: ScanResult | null;
  addLog: (level: LogEntry["level"], msg: string) => void;
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls =
    severity === "critical"
      ? "badge-critical"
      : severity === "high"
      ? "badge-high"
      : severity === "medium"
      ? "badge-medium"
      : severity === "low"
      ? "badge-low"
      : "badge-info";
  return <span className={cls}>{severity}</span>;
}

function ActionIcon({ action }: { action: string }) {
  if (action === "pass")
    return <Shield size={14} aria-hidden="true" className="text-green-400 shrink-0" />;
  if (action === "block")
    return <ShieldOff size={14} aria-hidden="true" className="text-red-400 shrink-0" />;
  return <Eye size={14} aria-hidden="true" className="text-yellow-400 shrink-0" />;
}

function RuleCard({
  rec,
  selected,
  onToggle,
}: {
  rec: Recommendation;
  selected: boolean;
  onToggle: () => void;
}) {
  const { rule, rationale, severity } = rec;
  return (
    <div
      className={`card mb-2 cursor-pointer transition-all ${
        selected ? "border-brand-500/60 bg-brand-600/5" : "opacity-80 hover:opacity-100"
      }`}
      onClick={onToggle}
    >
      <div className="flex items-start gap-3">
        <input
          type="checkbox"
          checked={selected}
          onChange={onToggle}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select rule: ${rec.rule.description}`}
          className="mt-1 accent-brand-500"
        />
        <ActionIcon action={rule.action} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-sm text-white">{rule.description}</span>
            <SeverityBadge severity={severity} />
          </div>
          <div className="flex gap-4 mt-1 text-xs text-gray-400 font-mono flex-wrap">
            <span>
              {rule.protocol} {rule.destination_port}
            </span>
            <span>{rule.source_net} → {rule.destination_net}</span>
            <span>iface: {rule.interface}</span>
            {rule.log && (
              <span className="text-yellow-500">log-only</span>
            )}
          </div>
          <p className="mt-1.5 text-xs text-gray-400">{rationale}</p>
        </div>
      </div>
    </div>
  );
}

function ExistingRuleRow({ row }: { row: OPNsenseRuleRow }) {
  return (
    <tr className="border-t border-surface-600 hover:bg-surface-700/50 text-sm">
      <td className="py-2 px-3 font-mono text-gray-300">{row.action ?? "—"}</td>
      <td className="py-2 px-3 font-mono text-gray-300">{row.destination_port ?? "any"}</td>
      <td className="py-2 px-3 text-gray-400">{row.interface ?? "—"}</td>
      <td className="py-2 px-3 text-gray-400">{row.description ?? "—"}</td>
      <td className="py-2 px-3">
        <span
          className={
            row.enabled === "1" ? "badge-low" : "badge-info"
          }
        >
          {row.enabled === "1" ? "enabled" : "disabled"}
        </span>
      </td>
    </tr>
  );
}

function ValidationPanel({ result }: { result: ValidationResult }) {
  return (
    <div className="card mt-4" aria-live="polite" aria-atomic="true">
      <h3 className="font-semibold text-white mb-3 flex items-center gap-2">
        <CheckCircle2 size={16} aria-hidden="true" className="text-green-400" />
        Validation Scan — {result.target}
      </h3>
      <div className="grid grid-cols-3 gap-4 text-center">
        <div>
          <div className="text-2xl font-bold font-mono text-gray-300">
            {result.previously_open.length}
          </div>
          <div className="text-xs text-gray-500 mt-0.5">Previously Open</div>
        </div>
        <div>
          <div className="text-2xl font-bold font-mono text-green-400">
            {result.now_filtered.length}
          </div>
          <div className="text-xs text-gray-500 mt-0.5">Now Filtered</div>
        </div>
        <div>
          <div
            className={`text-2xl font-bold font-mono ${
              result.still_open.length > 0 ? "text-red-400" : "text-gray-400"
            }`}
          >
            {result.still_open.length}
          </div>
          <div className="text-xs text-gray-500 mt-0.5">Still Open</div>
        </div>
      </div>
      {result.still_open.length > 0 && (
        <div className="mt-3 p-3 bg-red-500/10 border border-red-500/30 rounded-lg">
          <p className="text-sm text-red-400 flex items-center gap-2">
            <AlertTriangle size={14} aria-hidden="true" />
            Ports still open: {result.still_open.join(", ")}
          </p>
        </div>
      )}
      {result.still_open.length === 0 && result.previously_open.length > 0 && (
        <div className="mt-3 p-3 bg-green-500/10 border border-green-500/30 rounded-lg">
          <p className="text-sm text-green-400 flex items-center gap-2">
            <CheckCircle2 size={14} aria-hidden="true" />
            All targeted ports are now filtered.
          </p>
        </div>
      )}
    </div>
  );
}

export default function StagingArea({
  recommendations,
  scanResult,
  addLog,
}: StagingAreaProps) {
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [existingRules, setExistingRules] = useState<OPNsenseRuleRow[]>([]);
  const [loadingExisting, setLoadingExisting] = useState(false);
  const [deploying, setDeploying] = useState(false);
  const [validating, setValidating] = useState(false);
  const [applyResult, setApplyResult] = useState<ApplyResult | null>(null);
  const [validationResult, setValidationResult] =
    useState<ValidationResult | null>(null);
  const [activeTab, setActiveTab] = useState<"proposed" | "existing">(
    "proposed"
  );

  const recs = recommendations?.recommendations ?? [];

  function toggleAll() {
    if (selected.size === recs.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(recs.map((_, i) => i)));
    }
  }

  function toggle(i: number) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(i)) next.delete(i);
      else next.add(i);
      return next;
    });
  }

  async function loadExistingRules() {
    setLoadingExisting(true);
    addLog("info", "Fetching existing OPNsense firewall rules…");
    try {
      // No config param — Rust reads from AppState
      const rows = await invoke<OPNsenseRuleRow[]>("get_existing_rules");
      setExistingRules(rows);
      addLog("success", `Loaded ${rows.length} existing rules.`);
    } catch (e) {
      addLog("error", String(e));
    } finally {
      setLoadingExisting(false);
    }
  }

  async function deploy() {
    const rulesToDeploy = recs
      .filter((_, i) => selected.has(i))
      .map((r) => r.rule);

    if (rulesToDeploy.length === 0) {
      addLog("warn", "No rules selected for deployment.");
      return;
    }

    setDeploying(true);
    addLog("info", `Backing up OPNsense config and deploying ${rulesToDeploy.length} rules…`);
    try {
      // No config param — Rust reads from AppState
      const result = await invoke<ApplyResult>("apply_firewall_rules", {
        rules: rulesToDeploy,
      });
      setApplyResult(result);
      addLog(
        "success",
        `Deployment complete: ${result.rules_added} rules added, backup taken: ${result.backup_taken}.`
      );
    } catch (e) {
      addLog("error", String(e));
    } finally {
      setDeploying(false);
    }
  }

  async function validate() {
    if (!scanResult) return;

    const openPorts = scanResult.hosts
      .flatMap((h) => h.ports)
      .filter((p) => p.state === "open")
      .map((p) => p.port);

    const target = scanResult.hosts[0]?.ip ?? "";

    setValidating(true);
    addLog("info", `Running validation scan against ${target}…`);
    try {
      const result = await invoke<ValidationResult>("validate_scan", {
        target,
        previouslyOpen: openPorts,
      });
      setValidationResult(result);
      addLog(
        result.still_open.length === 0 ? "success" : "warn",
        `Validation: ${result.now_filtered.length} filtered, ${result.still_open.length} still open.`
      );
    } catch (e) {
      addLog("error", String(e));
    } finally {
      setValidating(false);
    }
  }

  return (
    <div className="flex flex-col gap-4 p-6 overflow-y-auto h-full">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Staging Area</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Review proposed rules before deployment to OPNsense.
          </p>
        </div>

        <div className="flex gap-2">
          <button
            onClick={deploy}
            disabled={deploying || selected.size === 0}
            className="btn-primary flex items-center gap-2"
          >
            <RefreshCw size={14} aria-hidden="true" className={deploying ? "animate-spin" : "hidden"} />
            <Play size={14} aria-hidden="true" className={deploying ? "hidden" : ""} />
            {deploying ? "Deploying…" : `Deploy (${selected.size})`}
          </button>

          {applyResult && (
            <button
              onClick={validate}
              disabled={validating}
              className="btn-ghost flex items-center gap-2"
            >
              {validating ? (
                <RefreshCw size={14} aria-hidden="true" className="animate-spin" />
              ) : (
                <CheckCircle2 size={14} aria-hidden="true" />
              )}
              {validating ? "Validating…" : "Validate"}
            </button>
          )}
        </div>
      </div>

      {/* Summary banner */}
      {recommendations && (
        <div className="flex items-center gap-3 p-3 bg-brand-600/10 border border-brand-600/30 rounded-xl text-sm text-brand-300">
          <Info size={16} aria-hidden="true" />
          {recommendations.summary}
        </div>
      )}

      {/* Tabs */}
      <div role="tablist" aria-label="Rule view" className="flex gap-1 border-b border-surface-600 pb-0">
        {(["proposed", "existing"] as const).map((tab) => (
          <button
            key={tab}
            role="tab"
            aria-selected={activeTab === tab}
            onClick={() => {
              setActiveTab(tab);
              if (tab === "existing" && existingRules.length === 0) {
                loadExistingRules();
              }
            }}
            className={`px-4 py-2 text-sm font-medium capitalize border-b-2 transition-colors ${
              activeTab === tab
                ? "border-brand-400 text-brand-300"
                : "border-transparent text-gray-400 hover:text-gray-200"
            }`}
          >
            {tab === "proposed" ? (
              <span className="flex items-center gap-1.5">
                Proposed
                {recs.length > 0 && (
                  <span aria-label={`${recs.length} proposed rules`} className="bg-brand-600 text-white text-xs rounded-full px-1.5">
                    {recs.length}
                  </span>
                )}
              </span>
            ) : (
              <span className="flex items-center gap-1.5">
                Existing
                {existingRules.length > 0 && (
                  <span aria-label={`${existingRules.length} existing rules`} className="bg-surface-500 text-gray-300 text-xs rounded-full px-1.5">
                    {existingRules.length}
                  </span>
                )}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Proposed rules */}
      {activeTab === "proposed" && (
        <>
          {recs.length > 0 ? (
            <>
              <div className="flex items-center gap-3">
                <button
                  onClick={toggleAll}
                  aria-label={selected.size === recs.length ? "Deselect all rules" : "Select all rules"}
                  className="text-xs text-brand-400 hover:text-brand-300 transition-colors"
                >
                  {selected.size === recs.length ? "Deselect all" : "Select all"}
                </button>
                <span className="text-xs text-gray-500">
                  {selected.size} / {recs.length} selected
                </span>
              </div>
              {recs.map((rec, i) => (
                <RuleCard
                  key={i}
                  rec={rec}
                  selected={selected.has(i)}
                  onToggle={() => toggle(i)}
                />
              ))}
            </>
          ) : (
            <div className="flex flex-col items-center justify-center flex-1 py-20 text-center">
              <ArrowRight size={40} className="text-surface-600 mb-3" />
              <p className="text-gray-400">No recommendations generated yet.</p>
              <p className="text-gray-500 text-sm mt-1">
                Load a scan from the Dashboard first.
              </p>
            </div>
          )}
        </>
      )}

      {/* Existing rules */}
      {activeTab === "existing" && (
        <>
          {loadingExisting ? (
            <div className="flex items-center justify-center py-20" aria-live="polite" aria-label="Loading existing rules">
              <RefreshCw size={24} aria-hidden="true" className="animate-spin text-brand-400" />
            </div>
          ) : existingRules.length > 0 ? (
            <div className="card overflow-x-auto">
              <table aria-label="Existing firewall rules" className="w-full text-left">
                <thead>
                  <tr className="text-xs text-gray-500 uppercase tracking-wider">
                    <th scope="col" className="py-2 px-3">Action</th>
                    <th scope="col" className="py-2 px-3">Port</th>
                    <th scope="col" className="py-2 px-3">Interface</th>
                    <th scope="col" className="py-2 px-3">Description</th>
                    <th scope="col" className="py-2 px-3">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {existingRules.map((row, i) => (
                    <ExistingRuleRow key={i} row={row} />
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center py-20 text-center">
              <XCircle size={40} className="text-surface-600 mb-3" />
              <p className="text-gray-400">No rules loaded.</p>
              <button
                onClick={loadExistingRules}
                className="btn-ghost mt-3 text-sm"
              >
                Reload
              </button>
            </div>
          )}
        </>
      )}

      {/* Validation result */}
      {validationResult && <ValidationPanel result={validationResult} />}

      {/* Deploy result */}
      {applyResult && (
        <div aria-live="polite" aria-atomic="true" className="p-3 bg-green-500/10 border border-green-500/30 rounded-xl text-sm text-green-300 flex items-center gap-2">
          <CheckCircle2 size={16} aria-hidden="true" />
          {applyResult.rules_added} rules deployed. Config backup taken:{" "}
          {applyResult.backup_taken ? "yes" : "no"}.
        </div>
      )}
    </div>
  );
}
