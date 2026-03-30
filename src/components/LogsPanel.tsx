import { Trash2, CheckCircle2, AlertTriangle, XCircle, Info } from "lucide-react";
import { LogEntry } from "../types";

interface LogsPanelProps {
  logs: LogEntry[];
  clearLogs: () => void;
}

function LevelIcon({ level }: { level: LogEntry["level"] }) {
  switch (level) {
    case "success":
      return <CheckCircle2 size={13} aria-hidden="true" className="text-green-400 shrink-0" />;
    case "warn":
      return <AlertTriangle size={13} aria-hidden="true" className="text-yellow-400 shrink-0" />;
    case "error":
      return <XCircle size={13} aria-hidden="true" className="text-red-400 shrink-0" />;
    default:
      return <Info size={13} aria-hidden="true" className="text-brand-400 shrink-0" />;
  }
}

function levelColor(level: LogEntry["level"]) {
  switch (level) {
    case "success":
      return "text-green-300";
    case "warn":
      return "text-yellow-300";
    case "error":
      return "text-red-300";
    default:
      return "text-gray-300";
  }
}

export default function LogsPanel({ logs, clearLogs }: LogsPanelProps) {
  return (
    <div className="flex flex-col h-full p-6 gap-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-white">Activity Log</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Real-time feedback from Nmap invocations and OPNsense API calls.
          </p>
        </div>
        <button
          onClick={clearLogs}
          className="btn-ghost flex items-center gap-2 text-sm"
          disabled={logs.length === 0}
          aria-label={logs.length === 0 ? "Clear logs (no logs to clear)" : "Clear all logs"}
        >
          <Trash2 size={14} aria-hidden="true" />
          Clear
        </button>
      </div>

      {logs.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center text-center" aria-live="polite">
          <Info size={40} aria-hidden="true" className="text-surface-600 mb-3" />
          <p className="text-gray-400">No activity yet.</p>
          <p className="text-gray-500 text-sm mt-1">
            Events will appear here as you interact with the application.
          </p>
        </div>
      ) : (
        <ul aria-live="polite" aria-label="Activity log entries" className="flex-1 overflow-y-auto font-mono text-xs space-y-1 list-none">
          {logs.map((log) => (
            <li
              key={log.id}
              className="flex items-start gap-2.5 p-2.5 rounded-lg hover:bg-surface-700/40 transition-colors"
            >
              <LevelIcon level={log.level} />
              <time
                dateTime={new Date(log.timestamp).toISOString()}
                className="text-gray-500 shrink-0 tabular-nums"
              >
                {new Date(log.timestamp).toLocaleTimeString()}
              </time>
              <span className={`flex-1 break-all ${levelColor(log.level)}`}>
                <span className="sr-only">{log.level}: </span>
                {log.message}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
