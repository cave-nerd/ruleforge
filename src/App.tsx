import { useState } from "react";
import { useTheme } from "./hooks/useTheme";
import { useLogs } from "./hooks/useLogs";
import Sidebar from "./components/Sidebar";
import Dashboard from "./components/Dashboard";
import ScanPanel from "./components/ScanPanel";
import StagingArea from "./components/StagingArea";
import LogsPanel from "./components/LogsPanel";
import Settings from "./components/Settings";
import { AppView, CaptureResult, RecommendationSet, ScanResult } from "./types";

export default function App() {
  const { mode, accent, changeMode, changeAccent } = useTheme();
  const { logs, addLog, clearLogs } = useLogs();

  const [view, setView] = useState<AppView>("dashboard");
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [captureResult, setCaptureResult] = useState<CaptureResult | null>(null);
  const [hostTags, setHostTags] = useState<Record<string, string[]>>({});
  const [recommendations, setRecommendations] = useState<RecommendationSet | null>(null);
  const [opnsenseInterface, setOpnsenseInterface] = useState("wan");

  const pendingCount = recommendations?.recommendations.length ?? 0;

  function handleRulesGenerated(recs: RecommendationSet) {
    setRecommendations(recs);
    setView("staging");
  }

  return (
    <div className="flex h-screen overflow-hidden bg-surface-900 text-gray-800 dark:text-gray-100">
      <Sidebar
        view={view}
        setView={setView}
        pendingCount={pendingCount}
      />

      <main className="flex-1 overflow-hidden">
        {view === "dashboard" && (
          <Dashboard
            scanResult={scanResult}
            captureResult={captureResult}
            recommendations={recommendations}
            setView={setView}
          />
        )}
        {view === "capture" && (
          <ScanPanel
            scanResult={scanResult}
            setScanResult={setScanResult}
            captureResult={captureResult}
            setCaptureResult={setCaptureResult}
            hostTags={hostTags}
            setHostTags={setHostTags}
            addLog={addLog}
            opnsenseInterface={opnsenseInterface}
            onRulesGenerated={handleRulesGenerated}
          />
        )}
        {view === "staging" && (
          <StagingArea
            recommendations={recommendations}
            scanResult={scanResult}
            addLog={addLog}
          />
        )}
        {view === "logs" && (
          <LogsPanel logs={logs} clearLogs={clearLogs} />
        )}
        {view === "settings" && (
          <Settings
            opnsenseInterface={opnsenseInterface}
            setOpnsenseInterface={setOpnsenseInterface}
            addLog={addLog}
            themeMode={mode}
            changeMode={changeMode}
            accent={accent}
            changeAccent={changeAccent}
          />
        )}
      </main>
    </div>
  );
}
