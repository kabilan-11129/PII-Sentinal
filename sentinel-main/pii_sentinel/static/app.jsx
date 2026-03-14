/**
 * app.jsx — PII Sentinel React Frontend
 *
 * Component tree:
 *   App
 *   ├── BgParticles
 *   ├── ScanOverlay
 *   ├── ToastContainer
 *   ├── Navbar
 *   ├── HeroSection
 *   ├── StatCards
 *   ├── UploadPanel  (left col)
 *   ├── ChartsPanel  (left col)
 *   ├── ActivityTimeline (left col)
 *   ├── DpdpaCard    (left col)
 *   ├── ResultsSection OR EmptyState (right col)
 *   ├── FileDetailModal
 *   ├── ScrollTopButton
 *   └── Footer
 */

const { useState, useEffect, useRef, useCallback } = React;

/* ═══════════════════════════════════════════════════════
   CONSTANTS & HELPERS
   ═══════════════════════════════════════════════════════ */

const ALLOWED_EXTS  = [
  "txt", "log", "md",
  "csv", "xlsx", "xls", "ods",
  "pdf", "docx", "pptx", "rtf", "odt",
  "json", "xml",
  "html", "htm",
  "eml", "msg",
  "zip", "tar", "gz", "tgz",
];
const MAX_SIZE_MB   = 64;

const CHART_FONT    = "'Inter', sans-serif";
const CHART_GRID    = "rgba(255,255,255,0.03)";
const CHART_TEXT    = "#8892b0";
const CHART_TIP     = {
  backgroundColor : "rgba(6,8,20,0.95)",
  borderColor     : "rgba(56,189,248,0.2)",
  borderWidth     : 1,
  titleColor      : "#e2e8f0",
  bodyColor       : "#94a3b8",
  titleFont       : { family: CHART_FONT, weight: "700" },
  bodyFont        : { family: CHART_FONT },
  padding         : 12,
  cornerRadius    : 8,
};

const PII_ICONS = {
  Email      : "bi-envelope-fill",
  Phone      : "bi-phone-fill",
  PAN        : "bi-credit-card-2-front-fill",
  Aadhaar    : "bi-fingerprint",
  Card       : "bi-credit-card-fill",
  DOB        : "bi-calendar-event-fill",
  Name       : "bi-person-badge-fill",
  Passport   : "bi-passport-fill",
  IFSC       : "bi-bank2",
  BankAccount: "bi-piggy-bank-fill",
  Vehicle    : "bi-car-front-fill",
  HealthData : "bi-heart-pulse-fill",
  IPAddress  : "bi-router-fill",
};

const RISK_CLASS = {
  LOW     : "risk-low",
  MEDIUM  : "risk-medium",
  HIGH    : "risk-high",
  CRITICAL: "risk-critical",
};

const RISK_DOT = {
  LOW     : "success",
  MEDIUM  : "warning",
  HIGH    : "danger",
  CRITICAL: "danger",
};

const SECURITY_COLORS = {
  PUBLIC       : "#22c55e",
  INTERNAL     : "#06b6d4",
  RESTRICTED   : "#f59e0b",
  CONFIDENTIAL : "#ef4444",
  "TOP SECRET" : "#dc2626",
};
const SECURITY_ICONS = {
  PUBLIC       : "bi-globe2",
  INTERNAL     : "bi-building",
  RESTRICTED   : "bi-exclamation-triangle-fill",
  CONFIDENTIAL : "bi-shield-lock-fill",
  "TOP SECRET" : "bi-lock-fill",
};
const ROLE_COLORS = {
  Employee: "#38bdf8",
  Manager : "#a78bfa",
  HR      : "#ec4899",
  Finance : "#fbbf24",
  Admin   : "#ef4444",
};

function fmtRisk(r) {
  const map = { LOW: "success", MEDIUM: "warning", HIGH: "danger", CRITICAL: "danger" };
  return map[r] || "secondary";
}

function sensitivityClass(s) {
  if (s === "HIGH")   return "chip-high";
  if (s === "MEDIUM") return "chip-medium";
  return "chip-safe";
}

function destroyChart(ref) {
  if (ref.current) { ref.current.destroy(); ref.current = null; }
}


/* ═══════════════════════════════════════════════════════
   ROOT APP
   ═══════════════════════════════════════════════════════ */

function App() {
  const [files,        setFiles]        = useState([]);
  const [summary,      setSummary]      = useState(null);
  const [activity,     setActivity]     = useState([]);
  const [trackerSummary, setTrackerSummary] = useState(null);
  const [trackerEvents,  setTrackerEvents]  = useState([]);
  const [trackerAlerts,  setTrackerAlerts]  = useState([]);
  const [trackerLoading, setTrackerLoading] = useState(false);
  const [scanning,     setScanning]     = useState(false);
  const [scanStep,     setScanStep]     = useState(-1);
  const [toasts,       setToasts]       = useState([]);
  const [modalFile,    setModalFile]    = useState(null);
  const [filterRisk,   setFilterRisk]   = useState("all");
  const [chartsKey,    setChartsKey]    = useState(0);
  const [scrollTop,    setScrollTop]    = useState(false);
  const [history,      setHistory]      = useState(() => {
    try { return JSON.parse(localStorage.getItem("pii_sentinel_history") || "[]"); }
    catch { return []; }
  });
  const [showHistory,  setShowHistory]  = useState(false);

  /* ── History helpers ────────────────────────── */
  const saveToHistory = useCallback((freshFiles) => {
    if (!freshFiles || freshFiles.length === 0) return;
    setHistory(prev => {
      const existingKeys = new Set(prev.map(h => h.filename + "|" + h.scan_time));
      const newEntries = freshFiles
        .filter(f => !existingKeys.has(f.filename + "|" + f.scan_time))
        .map(f => ({
          id:           Date.now() + Math.random(),
          filename:     f.filename,
          scan_time:    f.scan_time,
          pii_total:    f.pii_total,
          risk_level:   f.risk_level,
          pii_counts:   f.pii_counts,
          risk_reason:  f.risk_reason,
          data_source:  f.data_source,
          file_size:    f.file_size,
          data_owner:   f.data_owner,
        }));
      if (newEntries.length === 0) return prev;
      const updated = [...newEntries, ...prev].slice(0, 200);
      localStorage.setItem("pii_sentinel_history", JSON.stringify(updated));
      return updated;
    });
  }, []);

  const clearHistory = () => {
    setHistory([]);
    localStorage.removeItem("pii_sentinel_history");
  };

  /* ── Data fetching ────────────────────────── */
  const fetchAll = useCallback(async () => {
    try {
      const [rRes, sRes, aRes] = await Promise.all([
        fetch("/api/results"),
        fetch("/api/summary"),
        fetch("/api/activity"),
      ]);
      const r = await rRes.json();
      const s = await sRes.json();
      const a = await aRes.json();
      const freshFiles = r.files || [];
      setFiles(freshFiles);
      setSummary(s);
      setActivity(a);
      return freshFiles;
    } catch (e) {
      addToast("Failed to load data: " + e.message, "error");
      return [];
    }
  }, []);

  const fetchTracker = useCallback(async () => {
    setTrackerLoading(true);
    try {
      const [sumRes, eventsRes, alertsRes] = await Promise.all([
        fetch("/api/file-tracker-summary"),
        fetch("/api/file-events?limit=80"),
        fetch("/api/file-alerts?limit=40"),
      ]);

      const sumData = sumRes.ok ? await sumRes.json() : { success: false, summary: {} };
      const eventsData = eventsRes.ok ? await eventsRes.json() : { success: false, events: [] };
      const alertsData = alertsRes.ok ? await alertsRes.json() : { success: false, alerts: [] };

      setTrackerSummary(sumData.summary || null);
      setTrackerEvents(Array.isArray(eventsData.events) ? eventsData.events : []);
      setTrackerAlerts(Array.isArray(alertsData.alerts) ? alertsData.alerts : []);
    } catch {
      setTrackerSummary(null);
      setTrackerEvents([]);
      setTrackerAlerts([]);
    } finally {
      setTrackerLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAll();
    fetchTracker();
  }, []);

  useEffect(() => {
    const t = setInterval(() => {
      fetchTracker();
    }, 15000);
    return () => clearInterval(t);
  }, [fetchTracker]);

  useEffect(() => {
    fetchTracker();
  }, [files.length, activity.length]);

  /* ── Scroll-to-top ────────────────────────── */
  useEffect(() => {
    const onScroll = () => setScrollTop(window.scrollY > 300);
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  /* ── Toast helpers ────────────────────────── */
  const addToast = (msg, type = "success") => {
    const id = Date.now() + Math.random();
    setToasts(prev => [...prev, { id, msg, type }]);
    setTimeout(() => setToasts(prev => prev.filter(t => t.id !== id)), 4500);
  };
  const closeToast = (id) => setToasts(prev => prev.filter(t => t.id !== id));

  /* ── Upload handler ───────────────────────── */
  const handleUpload = async (formData) => {
    setScanning(true);
    setScanStep(0);

    // Cycle overlay steps
    const timers = [1, 2, 3].map((step, i) =>
      setTimeout(() => setScanStep(step), (i + 1) * 900)
    );

    try {
      const res  = await fetch("/api/upload", { method: "POST", body: formData });
      const data = await res.json();

      if (data.success) {
        addToast(`✅ ${data.message}`, "success");
        if (data.skipped?.length) {
          addToast(`⚠️ Skipped: ${data.skipped.join(", ")}`, "warning");
        }
        const freshFiles = await fetchAll();
        saveToHistory(freshFiles);
        setChartsKey(k => k + 1);
        // scroll to results
        setTimeout(() => {
          document.getElementById("results-top")?.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 300);
      } else {
        addToast("❌ " + (data.message || "Upload failed"), "error");
      }
    } catch (e) {
      addToast("❌ Network error: " + e.message, "error");
    } finally {
      timers.forEach(clearTimeout);
      setTimeout(() => { setScanning(false); setScanStep(-1); }, 800);
    }
  };

  /* ── Clear handler ────────────────────────── */
  const handleClear = async () => {
    if (!confirm("Clear all scan data? This cannot be undone.")) return;
    try {
      await fetch("/api/clear-data", { method: "POST" });
      setFiles([]);
      setSummary(null);
      setActivity([]);
      setChartsKey(k => k + 1);
      addToast("🗑️ All data cleared.", "info");
    } catch (e) {
      addToast("Clear failed: " + e.message, "error");
    }
  };

  /* ── Folder scan handler ──────────────────── */
  const handleFolderScan = async (payload) => {
    setScanning(true);
    setScanStep(0);
    const timers = [1, 2, 3].map((s, i) => setTimeout(() => setScanStep(s), (i + 1) * 900));
    try {
      const res  = await fetch("/api/scan-folder", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (data.success) {
        addToast(`✅ ${data.message}`, "success");
        if (data.unsupported > 0)
          addToast(`⚠️ ${data.unsupported} unsupported file(s) skipped.`, "warning");
        if (data.errors > 0)
          addToast(`⚠️ ${data.errors} file(s) had errors.`, "warning");
        const freshFiles = await fetchAll();
        saveToHistory(freshFiles);
        setChartsKey(k => k + 1);
        setTimeout(() => document.getElementById("results-top")?.scrollIntoView({ behavior: "smooth" }), 300);
      } else {
        addToast("❌ " + data.message, "error");
      }
      return data;
    } catch (e) {
      addToast("❌ Network error: " + e.message, "error");
    } finally {
      timers.forEach(clearTimeout);
      setTimeout(() => { setScanning(false); setScanStep(-1); }, 800);
    }
  };

  /* ── Database scan handler ─────────────────── */
  const handleDatabaseScan = async (payload) => {
    setScanning(true);
    setScanStep(0);
    const timers = [1, 2, 3].map((s, i) => setTimeout(() => setScanStep(s), (i + 1) * 900));
    try {
      const res  = await fetch("/api/scan-database", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (data.success) {
        addToast(`✅ ${data.message}`, "success");
        if (data.errors > 0) addToast(`⚠️ ${data.errors} table(s) had errors.`, "warning");
        const freshFiles = await fetchAll();
        saveToHistory(freshFiles);
        setChartsKey(k => k + 1);
        setTimeout(() => document.getElementById("results-top")?.scrollIntoView({ behavior: "smooth" }), 300);
      } else {
        addToast("❌ " + data.message, "error");
      }
      return data;
    } catch (e) {
      addToast("❌ Network error: " + e.message, "error");
    } finally {
      timers.forEach(clearTimeout);
      setTimeout(() => { setScanning(false); setScanStep(-1); }, 800);
    }
  };

  /* ── Cloud storage scan handler ───────────────── */
  const handleCloudScan = async (payload) => {
    setScanning(true);
    setScanStep(0);
    const timers = [1, 2, 3].map((s, i) => setTimeout(() => setScanStep(s), (i + 1) * 1100));
    try {
      const res  = await fetch("/api/scan-cloud", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (data.success) {
        addToast(`✅ ${data.message}`, "success");
        if (data.errors > 0) addToast(`⚠️ ${data.errors} file(s) had errors.`, "warning");
        const freshFiles = await fetchAll();
        saveToHistory(freshFiles);
        setChartsKey(k => k + 1);
        setTimeout(() => document.getElementById("results-top")?.scrollIntoView({ behavior: "smooth" }), 300);
      } else {
        addToast("❌ " + data.message, "error");
      }
      return data;
    } catch (e) {
      addToast("❌ Network error: " + e.message, "error");
    } finally {
      timers.forEach(clearTimeout);
      setTimeout(() => { setScanning(false); setScanStep(-1); }, 800);
    }
  };

  /* ── IMAP email scan handler ───────────────────── */
  const handleImapScan = async (payload) => {
    setScanning(true);
    setScanStep(0);
    const timers = [1, 2, 3].map((s, i) => setTimeout(() => setScanStep(s), (i + 1) * 1200));
    try {
      const res  = await fetch("/api/scan-imap", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (data.success) {
        addToast(`✅ ${data.message}`, "success");
        const freshFiles = await fetchAll();
        saveToHistory(freshFiles);
        setChartsKey(k => k + 1);
        setTimeout(() => document.getElementById("results-top")?.scrollIntoView({ behavior: "smooth" }), 300);
      } else {
        addToast("❌ " + data.message, "error");
      }
      return data;
    } catch (e) {
      addToast("❌ Network error: " + e.message, "error");
    } finally {
      timers.forEach(clearTimeout);
      setTimeout(() => { setScanning(false); setScanStep(-1); }, 800);
    }
  };

  /* ── Real-time monitor update callback ────────── */
  const handleRealtimeUpdate = useCallback(async () => {
    const freshFiles = await fetchAll();
    saveToHistory(freshFiles);
    setChartsKey(k => k + 1);
  }, [fetchAll, saveToHistory]);

  /* ── Auto-discover handler ─────────────────── */
  const handleAutoDiscover = async (payload) => {
    setScanning(true);
    setScanStep(0);
    const timers = [1, 2, 3].map((s, i) => setTimeout(() => setScanStep(s), (i + 1) * 900));
    try {
      const res  = await fetch("/api/auto-discover", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (data.success) {
        addToast(`✅ ${data.message}`, "success");
        if (data.errors > 0) addToast(`⚠️ ${data.errors} file(s) had errors.`, "warning");
        const freshFiles = await fetchAll();
        saveToHistory(freshFiles);
        setChartsKey(k => k + 1);
        setTimeout(() => document.getElementById("results-top")?.scrollIntoView({ behavior: "smooth" }), 300);
      } else {
        addToast("❌ " + data.message, "error");
      }
      return data;
    } catch (e) {
      addToast("❌ Network error: " + e.message, "error");
    } finally {
      timers.forEach(clearTimeout);
      setTimeout(() => { setScanning(false); setScanStep(-1); }, 800);
    }
  };

  /* ── Organization-wide scan handler ─────────── */
  const handleOrgScan = async (payload) => {
    setScanning(true);
    setScanStep(0);
    const timers = [1, 2, 3].map((s, i) => setTimeout(() => setScanStep(s), (i + 1) * 1500));
    try {
      const res  = await fetch("/api/org-scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (data.success) {
        addToast(`✅ ${data.message}`, "success");
        // Show per-source feedback
        const sr = data.scan_results || {};
        if (sr.auto_discover?.success) addToast(`📂 Auto-discover: ${sr.auto_discover.files_scanned} files, ${sr.auto_discover.total_pii} PII`, "info");
        if (sr.folder?.success) addToast(`📁 Folder: ${sr.folder.files_scanned} files, ${sr.folder.total_pii} PII`, "info");
        if (sr.database?.success) addToast(`🗃️ Database: ${sr.database.tables_scanned} tables, ${sr.database.total_pii} PII`, "info");
        if (sr.cloud?.success) addToast(`☁️ Cloud: ${sr.cloud.files_scanned} files, ${sr.cloud.total_pii} PII`, "info");
        if (sr.email?.success) addToast(`📧 Email: ${sr.email.emails_scanned} emails, ${sr.email.total_pii} PII`, "info");
        // Show errors from failed sources
        Object.entries(sr).forEach(([key, val]) => {
          if (val && !val.success && val.message) addToast(`⚠️ ${key}: ${val.message}`, "warning");
        });
        const freshFiles = await fetchAll();
        saveToHistory(freshFiles);
        setChartsKey(k => k + 1);
        setTimeout(() => document.getElementById("results-top")?.scrollIntoView({ behavior: "smooth" }), 300);
      } else {
        addToast("❌ " + (data.message || "Organization scan failed"), "error");
        if (data.scan_results) {
          Object.entries(data.scan_results).forEach(([key, val]) => {
            if (val && !val.success && val.message) addToast(`⚠️ ${key}: ${val.message}`, "warning");
          });
        }
      }
      return data;
    } catch (e) {
      addToast("❌ Network error: " + e.message, "error");
    } finally {
      timers.forEach(clearTimeout);
      setTimeout(() => { setScanning(false); setScanStep(-1); }, 800);
    }
  };

  /* ── Config upload pipeline completion callback ── */
  const handleConfigUpload = useCallback(async (pipelineResult) => {
    if (pipelineResult?.status === "completed") {
      addToast(`Pipeline complete — ${pipelineResult.files_scanned} files, ${pipelineResult.total_pii_detected} PII items`, "success");
    }
    const freshFiles = await fetchAll();
    saveToHistory(freshFiles);
    setChartsKey(k => k + 1);
    setTimeout(() => document.getElementById("results-top")?.scrollIntoView({ behavior: "smooth" }), 300);
  }, [fetchAll, saveToHistory]);

  return (
    <>
      <BgParticles />
      <ScanOverlay active={scanning} step={scanStep} />
      <ToastContainer toasts={toasts} onClose={closeToast} />

      <Navbar
        fileCount={files.length}
        hasData={files.length > 0}
        onClear={handleClear}
        onShowHistory={() => setShowHistory(true)}
        historyCount={history.length}
      />

      <main style={{ position: "relative", zIndex: 1, padding: "0 16px 40px", maxWidth: 1400, margin: "0 auto" }}>

        <HeroSection />

        <StatCards summary={summary} />

        <div className="row g-4">
          {/* ── Left column ── */}
          <div className="col-lg-5">
            <UploadPanel
              onUpload={handleUpload}
              onOrgScan={handleOrgScan}
              onFolderScan={handleFolderScan}
              onDatabaseScan={handleDatabaseScan}
              onAutoDiscover={handleAutoDiscover}
              onCloudScan={handleCloudScan}
              onImapScan={handleImapScan}
              onRealtimeUpdate={handleRealtimeUpdate}
              onConfigUpload={handleConfigUpload}
              scanning={scanning}
            />
            <ChartsPanel summary={summary} chartsKey={chartsKey} />
            <ActivityTimeline activity={activity} />
            <TrackerSummaryPanel
              summary={trackerSummary}
              events={trackerEvents}
              alerts={trackerAlerts}
              loading={trackerLoading}
              onRefresh={fetchTracker}
            />
            <DpdpaCard />
          </div>

          {/* ── Right column ── */}
          <div className="col-lg-7">
            <div id="results-top" />
            {files.length > 0
              ? <ResultsSection
                  files={files}
                  filterRisk={filterRisk}
                  setFilterRisk={setFilterRisk}
                  onViewDetails={setModalFile}
                  onDownload={() => window.location.href = "/download-report"}
                />
              : <EmptyState />
            }
          </div>
        </div>

        {/* ── Role-Based Access Map (full-width) ── */}
        {files.length > 0 && <AccessMapPanel files={files} />}

        {/* ── Enterprise Data Governance Hub (tabbed navigation) ── */}
        {files.length > 0 && <EnterpriseGovernanceHub />}
      </main>

      <Footer />

      {modalFile && (
        <FileDetailModal file={modalFile} onClose={() => setModalFile(null)} />
      )}

      {showHistory && (
        <HistoryModal
          history={history}
          onClearHistory={clearHistory}
          onClose={() => setShowHistory(false)}
        />
      )}

      {scrollTop && (
        <button
          className="scroll-top-btn visible"
          onClick={() => window.scrollTo({ top: 0, behavior: "smooth" })}
          title="Back to top"
        >
          <i className="bi bi-arrow-up" />
        </button>
      )}
    </>
  );
}


/* ═══════════════════════════════════════════════════════
   BG PARTICLES
   ═══════════════════════════════════════════════════════ */

function BgParticles() {
  return <div className="bg-particles" />;
}


/* ═══════════════════════════════════════════════════════
   SCAN OVERLAY
   ═══════════════════════════════════════════════════════ */

const STEPS = [
  { icon: "bi-file-text",              label: "Parsing file"        },
  { icon: "bi-search",                 label: "Detecting PII"       },
  { icon: "bi-tags",                   label: "Classifying data"    },
  { icon: "bi-file-earmark-bar-graph", label: "Generating report"   },
];

function ScanOverlay({ active, step }) {
  return (
    <div className={`scan-overlay ${active ? "active" : ""}`}>
      <div className="scan-overlay-content">
        <div className="scan-overlay-rings">
          <div className="scan-overlay-ring r1" />
          <div className="scan-overlay-ring r2" />
          <div className="scan-overlay-ring r3" />
          <div className="scan-overlay-icon">
            <i className="bi bi-shield-check" />
          </div>
        </div>
        <div className="scan-overlay-title">Scanning for PII</div>
        <div className="scan-overlay-sub">
          Analyzing file contents · Detecting sensitive data
        </div>
        <div className="scan-overlay-steps">
          {STEPS.map((s, i) => {
            const cls = i < step ? "done" : i === step ? "active" : "";
            const icon = i < step ? "bi-check-circle-fill" : s.icon;
            return (
              <div key={i} className={`scan-step ${cls}`}>
                <i className={`bi ${icon}`} />
                {s.label}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   TOAST CONTAINER
   ═══════════════════════════════════════════════════════ */

function ToastContainer({ toasts, onClose }) {
  if (!toasts.length) return null;
  return (
    <div style={{ position: "fixed", top: 80, right: 20, zIndex: 9000, display: "flex", flexDirection: "column", gap: 8 }}>
      {toasts.map(t => <Toast key={t.id} toast={t} onClose={onClose} />)}
    </div>
  );
}

function Toast({ toast, onClose }) {
  const colors = {
    success : { bg: "rgba(34,197,94,0.12)",  border: "rgba(34,197,94,0.25)",  color: "#86efac" },
    error   : { bg: "rgba(239,68,68,0.12)",  border: "rgba(239,68,68,0.25)",  color: "#fca5a5" },
    warning : { bg: "rgba(245,158,11,0.12)", border: "rgba(245,158,11,0.25)", color: "#fcd34d" },
    info    : { bg: "rgba(56,189,248,0.12)", border: "rgba(56,189,248,0.25)", color: "#7dd3fc" },
  };
  const c = colors[toast.type] || colors.info;
  return (
    <div style={{
      background: c.bg, border: `1px solid ${c.border}`, color: c.color,
      padding: "10px 16px", borderRadius: 10, fontSize: "0.84rem", fontWeight: 500,
      backdropFilter: "blur(12px)", display: "flex", alignItems: "center", gap: 10,
      maxWidth: 340, animation: "fadeInUp 0.3s ease",
    }}>
      <span style={{ flex: 1 }}>{toast.msg}</span>
      <button
        onClick={() => onClose(toast.id)}
        style={{ background: "none", border: "none", color: c.color, cursor: "pointer", padding: "0 2px", opacity: 0.7 }}
      >
        <i className="bi bi-x-lg" />
      </button>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   NAVBAR
   ═══════════════════════════════════════════════════════ */

function Navbar({ fileCount, hasData, onClear, onShowHistory, historyCount }) {
  return (
    <nav className="navbar navbar-expand-lg sticky-top" style={{ marginBottom: 0 }}>
      <div className="container-fluid px-4" style={{ maxWidth: 1400, margin: "0 auto" }}>
        <a className="navbar-brand d-flex align-items-center" href="/">
          <div className="brand-shield"><i className="bi bi-shield-shaded" /></div>
          <div>
            <span className="brand-name">PII Sentinel</span>
            <span className="nav-subtitle">Enterprise-Wide Personal Data Discovery · DPDPA 2023</span>
          </div>
        </a>

        <div className="d-flex align-items-center gap-2">
          {/* Live pulse */}
          <div className={`status-pulse ${hasData ? "active" : ""} d-none d-md-flex`}>
            <div className="pulse-dot" />
            <span className="pulse-label">{hasData ? "Monitoring" : "Standby"}</span>
          </div>

          {/* History button — always visible */}
          <button onClick={onShowHistory} className="btn-outline-accent d-none d-sm-inline-flex" style={{ position:"relative" }}>
            <i className="bi bi-clock-history" /> History
            {historyCount > 0 && <span className="history-badge">{historyCount}</span>}
          </button>

          {hasData && (
            <>
              <a href="/download-report" className="btn-outline-accent d-none d-sm-inline-flex">
                <i className="bi bi-download" /> Report
              </a>
              <button onClick={onClear} className="btn btn-outline-danger btn-sm d-none d-sm-inline-flex align-items-center gap-1">
                <i className="bi bi-trash3" /> Clear
              </button>
            </>
          )}
        </div>
      </div>
    </nav>
  );
}


/* ═══════════════════════════════════════════════════════
   HERO SECTION
   ═══════════════════════════════════════════════════════ */

function HeroSection() {
  return (
    <div className="hero-section animate-in mt-3">
      <div className="hero-content">
        <div className="hero-badge">PROBLEM STATEMENT 3 &nbsp;·&nbsp; DPDPA 2023 ALIGNED</div>
        <h1><i className="bi bi-shield-shaded" /> PII Sentinel</h1>
        <p>
          Enterprise-Wide Personal Data Discovery &amp; Classification (DPDPA-Aligned).
          Automatically discover data sources across on-premises and cloud environments.
          Scans emails, files, databases, and archives to detect, classify, and protect
          personal data — structured, semi-structured, and unstructured.
        </p>
        <div className="hero-stats">
          <span><i className="bi bi-shield-check" /> 13 PII Patterns</span>
          <span><i className="bi bi-file-earmark-text" /> 19 File Formats</span>
          <span><i className="bi bi-graph-up" /> Risk Scoring</span>
          <span><i className="bi bi-cloud" /> Cloud + Local Scan</span>
          <span><i className="bi bi-pin-map-fill" /> Ownership Mapping</span>
          <span><i className="bi bi-file-earmark-bar-graph" /> DPDPA Reports</span>
        </div>
      </div>
      <div className="hero-graphic d-none d-lg-block">
        <div className="scanner-ring ring-1" />
        <div className="scanner-ring ring-2" />
        <div className="scanner-ring ring-3" />
        <div className="scanner-center"><i className="bi bi-shield-lock-fill" /></div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   STAT CARDS
   ═══════════════════════════════════════════════════════ */

function StatCards({ summary }) {
  const s = summary || {};
  const cards = [
    { label: "Data Sources Scanned", value: s.total_files       || 0, icon: "bi-database",           cls: "",            bar: "accent",  pct: Math.min((s.total_files||0)*20,100) },
    { label: "PII Detections",        value: s.total_pii         || 0, icon: "bi-exclamation-triangle",cls: "text-warning",bar: "warning", pct: Math.min((s.total_pii||0)*5,100)   },
    { label: "High-Risk Sources",     value: s.high_risk_files   || 0, icon: "bi-shield-exclamation", cls: "text-danger", bar: "danger",  pct: Math.min((s.high_risk_files||0)*25,100) },
    { label: "PII Categories Found",  value: Object.keys(s.pii_type_counts||{}).length, icon: "bi-tags", cls: "text-info", bar: "info", pct: Object.keys(s.pii_type_counts||{}).length * 16 },
  ];

  return (
    <div className="row g-3 mb-4">
      {cards.map((c, i) => (
        <div key={i} className={`col-6 col-lg-3 animate-in delay-${i+1}`}>
          <StatCard {...c} />
        </div>
      ))}
    </div>
  );
}

function StatCard({ label, value, icon, cls, bar, pct }) {
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    if (value === 0) { setDisplay(0); return; }
    const dur = 1200, start = performance.now();
    const ease = t => 1 - Math.pow(1 - t, 4);
    const tick = (now) => {
      const p = Math.min((now - start) / dur, 1);
      setDisplay(Math.round(ease(p) * value));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [value]);

  return (
    <div className="stat-card">
      <div className={`stat-icon-wrap ${cls}`}><i className={`bi ${icon}`} /></div>
      <div className="stat-value counter">{display}</div>
      <div className="stat-label">{label}</div>
      <div className={`stat-bar ${bar}`} style={{ "--bar-width": `${pct}%` }} />
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   UPLOAD PANEL  (3 tabs: File Upload | Folder Scan | DB Scan)
   ═══════════════════════════════════════════════════════ */

function UploadPanel({ onUpload, onOrgScan, onFolderScan, onDatabaseScan, onAutoDiscover, onCloudScan, onImapScan, onRealtimeUpdate, scanning, onConfigUpload }) {
  const [activeTab, setActiveTab] = useState("config");

  const TABS = [
    { id: "config",   icon: "bi-gear-wide-connected", label: "Config Upload", desc: "Upload a single configuration file to auto-scan all enterprise data sources" },
    { id: "file",     icon: "bi-cloud-upload",  label: "Upload",   desc: "Scan uploaded files (19 formats) for PII" },
    { id: "folder",   icon: "bi-folder2-open",  label: "Folder",   desc: "Recursively scan a local directory" },
    { id: "db",       icon: "bi-database",      label: "Database", desc: "Scan SQLite database tables for PII" },
    { id: "discover", icon: "bi-search",        label: "Discover", desc: "Auto-discover data sources on this machine" },
    { id: "cloud",    icon: "bi-cloud",         label: "Cloud",    desc: "Scan AWS S3, Google Drive, Azure, Dropbox" },
    { id: "email",    icon: "bi-envelope-fill", label: "Email",    desc: "Scan Gmail / IMAP inbox for PII in emails & attachments" },
  ];

  const active = TABS.find(t => t.id === activeTab);

  return (
    <div className="section-card animate-in mb-4">
      <div className="section-header mb-3">
        <h4><i className="bi bi-radar" /> Data Source Scanner</h4>
        <span className="section-badge">PII PIPELINE</span>
      </div>

      {/* Tab switcher */}
      <div className="scan-tabs mb-3">
        {TABS.map(t => (
          <button
            key={t.id}
            className={`scan-tab-btn ${activeTab === t.id ? "active" : ""}`}
            onClick={() => setActiveTab(t.id)}
            title={t.desc}
          >
            <i className={`bi ${t.icon}`} /> {t.label}
          </button>
        ))}
      </div>

      {/* Tab description */}
      <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: 16, display: "flex", alignItems: "center", gap: 6 }}>
        <i className="bi bi-info-circle" style={{ color: "var(--accent-primary)", flexShrink: 0 }} />
        {active?.desc}
      </p>

      {activeTab === "config"   && <ConfigUploadTab   onConfigUpload={onConfigUpload} scanning={scanning} />}
      {activeTab === "file"     && <FileUploadTab   onUpload={onUpload}               scanning={scanning} />}
      {activeTab === "folder"   && <FolderScanTab   onFolderScan={onFolderScan}       scanning={scanning} />}
      {activeTab === "db"       && <DatabaseScanTab onDatabaseScan={onDatabaseScan}   scanning={scanning} />}
      {activeTab === "discover" && <AutoDiscoverTab onAutoDiscover={onAutoDiscover}   scanning={scanning} />}
      {activeTab === "cloud"    && <CloudStorageTab onCloudScan={onCloudScan}         scanning={scanning} />}
      {activeTab === "email"    && <ImapScanTab     onImapScan={onImapScan} onRealtimeUpdate={onRealtimeUpdate} scanning={scanning} />}
    </div>
  );
}
/* ═══════════════════════════════════════════════════════
   CONFIG UPLOAD TAB — Single config file for automated pipeline
   ═══════════════════════════════════════════════════════ */

function ConfigUploadTab({ onConfigUpload, scanning }) {
  const [configFile, setConfigFile] = useState(null);
  const [dataOwner, setDataOwner] = useState("");
  const [pipelineStatus, setPipelineStatus] = useState(null);
  const [pollActive, setPollActive] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);

  const pollRef = useRef(null);

  const handleFileDrop = (e) => {
    e.preventDefault();
    const f = e.dataTransfer?.files?.[0];
    if (f && /\.(csv|xlsx|pdf)$/i.test(f.name)) setConfigFile(f);
  };

  const handleFileSelect = (e) => {
    const f = e.target.files?.[0];
    if (f) setConfigFile(f);
  };

  const startPolling = () => {
    setPollActive(true);
    const poll = async () => {
      try {
        const res = await fetch("/api/scan-status");
        const data = await res.json();
        setPipelineStatus(data);
        if (data.status === "completed" || data.status === "failed") {
          setPollActive(false);
          if (pollRef.current) clearInterval(pollRef.current);
          if (onConfigUpload) onConfigUpload(data);
        }
      } catch (e) { /* ignore poll errors */ }
    };
    poll();
    pollRef.current = setInterval(poll, 2000);
  };

  useEffect(() => {
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!configFile) return;

    const fd = new FormData();
    fd.append("config", configFile);
    if (dataOwner.trim()) fd.append("data_owner", dataOwner.trim());

    try {
      const res = await fetch("/api/upload-config", { method: "POST", body: fd });
      const data = await res.json();
      setUploadResult(data);
      if (data.success) {
        startPolling();
      }
    } catch (err) {
      setUploadResult({ success: false, message: "Network error: " + err.message });
    }
  };

  const PIPELINE_STAGES = [
    { key: "config_parsed",       icon: "bi-file-earmark-check", label: "Config Parsed" },
    { key: "sources_identified",  icon: "bi-diagram-3",          label: "Sources Identified" },
    { key: "scanning_emails",     icon: "bi-envelope",           label: "Scanning Emails" },
    { key: "scanning_cloud",      icon: "bi-cloud",              label: "Scanning Cloud" },
    { key: "scanning_folders",    icon: "bi-folder",             label: "Scanning Folders" },
    { key: "scanning_databases",  icon: "bi-database",           label: "Scanning Databases" },
    { key: "pii_detection",       icon: "bi-search",             label: "PII Detection" },
    { key: "classification",      icon: "bi-tags",               label: "Classification" },
    { key: "segregation",         icon: "bi-box-arrow-in-right", label: "Segregation" },
    { key: "lineage_tracking",    icon: "bi-diagram-3-fill",     label: "Lineage Tracking" },
    { key: "completed",           icon: "bi-check-circle-fill",  label: "Complete" },
  ];

  const stagesCompleted = pipelineStatus?.stages_completed || [];

  return (
    <div>
      {/* Upload form */}
      {!uploadResult?.success && (
        <form onSubmit={handleSubmit}>
          <div
            className="config-upload-zone"
            onDrop={handleFileDrop}
            onDragOver={e => e.preventDefault()}
            onClick={() => document.getElementById("config-file-input")?.click()}
            style={{
              border: "2px dashed rgba(56,189,248,0.3)", borderRadius: 14,
              padding: "32px 20px", textAlign: "center", cursor: "pointer",
              background: configFile ? "rgba(56,189,248,0.06)" : "rgba(56,189,248,0.02)",
              transition: "all 0.3s ease",
            }}
          >
            <input
              id="config-file-input" type="file" accept=".csv,.xlsx,.pdf"
              onChange={handleFileSelect} style={{ display: "none" }}
            />
            <i className="bi bi-gear-wide-connected" style={{ fontSize: "2.2rem", color: "var(--accent-primary)", display: "block", marginBottom: 10 }} />
            {configFile ? (
              <div>
                <span style={{ color: "#34d399", fontWeight: 700 }}>{configFile.name}</span>
                <span style={{ color: "var(--text-muted)", fontSize: "0.75rem", display: "block", marginTop: 4 }}>
                  {(configFile.size / 1024).toFixed(1)} KB — Click to change
                </span>
              </div>
            ) : (
              <div>
                <span style={{ color: "var(--text-primary)", fontWeight: 600 }}>Upload Enterprise Scan Configuration</span>
                <span style={{ color: "var(--text-muted)", fontSize: "0.75rem", display: "block", marginTop: 6 }}>
                  Drop or click — accepts CSV, XLSX, or PDF
                </span>
                <span style={{ color: "var(--text-muted)", fontSize: "0.7rem", display: "block", marginTop: 4, opacity: 0.7 }}>
                  Columns: SourceType, Identifier, Credential, PathOrBucket
                </span>
              </div>
            )}
          </div>

          <div style={{ display: "flex", gap: 10, marginTop: 14, alignItems: "center" }}>
            <input
              type="text" className="form-control form-control-sm"
              placeholder="Data owner (optional)"
              value={dataOwner} onChange={e => setDataOwner(e.target.value)}
              style={{ flex: 1, background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.1)", color: "#fff", borderRadius: 8, fontSize: "0.8rem" }}
            />
            <button
              type="submit" className="btn btn-sm px-3"
              disabled={!configFile || scanning || pollActive}
              style={{
                background: "var(--accent-gradient)", color: "#fff", fontWeight: 700,
                border: "none", borderRadius: 8, fontSize: "0.8rem",
                opacity: (!configFile || scanning || pollActive) ? 0.5 : 1,
              }}
            >
              <i className="bi bi-play-fill" /> Launch Pipeline
            </button>
          </div>
        </form>
      )}

      {/* Pipeline Progress */}
      {(uploadResult?.success || pipelineStatus) && (
        <div className="pipeline-progress" style={{ marginTop: 18 }}>
          {/* Source detection summary */}
          {uploadResult?.sources_detected && (
            <div style={{ marginBottom: 16, padding: "12px 16px", background: "rgba(56,189,248,0.06)", borderRadius: 10, border: "1px solid rgba(56,189,248,0.15)" }}>
              <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "var(--accent-primary)", marginBottom: 8 }}>
                <i className="bi bi-diagram-3" /> Detected {uploadResult.total_sources} Data Source(s)
              </div>
              <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
                {Object.entries(uploadResult.sources_detected).map(([src, count]) => (
                  <span key={src} style={{
                    padding: "3px 10px", borderRadius: 8, fontSize: "0.72rem", fontWeight: 600,
                    background: "rgba(56,189,248,0.12)", color: "#7dd3fc",
                  }}>
                    {src}: {count}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Pipeline stage progress */}
          <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
            {PIPELINE_STAGES.map((stage, i) => {
              const done = stagesCompleted.includes(stage.key);
              const isCurrent = pipelineStatus?.current_stage === stage.key && !done;
              return (
                <div key={stage.key} style={{
                  display: "flex", alignItems: "center", gap: 10, padding: "6px 10px",
                  borderRadius: 8, fontSize: "0.75rem",
                  background: done ? "rgba(52,211,153,0.06)" : isCurrent ? "rgba(56,189,248,0.08)" : "transparent",
                  opacity: done || isCurrent ? 1 : 0.4,
                  transition: "all 0.3s ease",
                }}>
                  <i className={`bi ${done ? "bi-check-circle-fill" : isCurrent ? stage.icon : "bi-circle"}`} style={{
                    color: done ? "#34d399" : isCurrent ? "#38bdf8" : "var(--text-muted)",
                    fontSize: "0.85rem",
                  }} />
                  <span style={{ color: done ? "#34d399" : isCurrent ? "#38bdf8" : "var(--text-muted)", fontWeight: done || isCurrent ? 600 : 400 }}>
                    {stage.label}
                  </span>
                  {isCurrent && <span className="pipeline-spinner" />}
                </div>
              );
            })}
          </div>

          {/* Live stats */}
          {pipelineStatus && (pipelineStatus.status === "running" || pipelineStatus.status === "completed") && (
            <div style={{ marginTop: 14, display: "flex", gap: 12, flexWrap: "wrap" }}>
              <div className="pipeline-stat" style={{ background: "rgba(56,189,248,0.08)" }}>
                <span style={{ fontSize: "1.1rem", fontWeight: 800, color: "#38bdf8" }}>{pipelineStatus.files_scanned}</span>
                <span style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Files Scanned</span>
              </div>
              <div className="pipeline-stat" style={{ background: "rgba(239,68,68,0.08)" }}>
                <span style={{ fontSize: "1.1rem", fontWeight: 800, color: "#ef4444" }}>{pipelineStatus.total_pii_detected}</span>
                <span style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>PII Detected</span>
              </div>
              <div className="pipeline-stat" style={{ background: "rgba(52,211,153,0.08)" }}>
                <span style={{ fontSize: "1.1rem", fontWeight: 800, color: "#34d399" }}>{pipelineStatus.sources_processed}/{pipelineStatus.total_sources}</span>
                <span style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Sources Done</span>
              </div>
            </div>
          )}

          {/* Completion message */}
          {pipelineStatus?.status === "completed" && (
            <div style={{
              marginTop: 14, padding: "10px 14px", borderRadius: 10,
              background: "rgba(52,211,153,0.08)", border: "1px solid rgba(52,211,153,0.2)",
              fontSize: "0.78rem", color: "#34d399", fontWeight: 600,
            }}>
              <i className="bi bi-check-circle-fill" /> {pipelineStatus.message}
            </div>
          )}

          {/* Progress log */}
          {pipelineStatus?.progress_log?.length > 0 && (
            <div style={{ marginTop: 12, maxHeight: 160, overflow: "auto", fontSize: "0.7rem" }}>
              {pipelineStatus.progress_log.slice(-8).map((log, i) => (
                <div key={i} style={{ padding: "3px 0", color: "var(--text-muted)", borderBottom: "1px solid rgba(255,255,255,0.03)" }}>
                  <span style={{ color: "rgba(56,189,248,0.6)", marginRight: 8 }}>{log.time?.split(" ")[1] || ""}</span>
                  {log.message}
                </div>
              ))}
            </div>
          )}

          {/* Errors */}
          {pipelineStatus?.errors?.length > 0 && (
            <div style={{ marginTop: 10 }}>
              {pipelineStatus.errors.map((err, i) => (
                <div key={i} style={{ padding: "4px 10px", fontSize: "0.72rem", color: "#fbbf24", background: "rgba(251,191,36,0.06)", borderRadius: 6, marginBottom: 4 }}>
                  <i className="bi bi-exclamation-triangle" /> {err}
                </div>
              ))}
            </div>
          )}

          {/* Reset button */}
          {pipelineStatus?.status === "completed" && (
            <button
              onClick={() => { setUploadResult(null); setPipelineStatus(null); setConfigFile(null); }}
              className="btn btn-sm mt-3"
              style={{ background: "rgba(255,255,255,0.06)", color: "var(--text-muted)", border: "1px solid rgba(255,255,255,0.1)", borderRadius: 8, fontSize: "0.75rem" }}
            >
              <i className="bi bi-arrow-repeat" /> New Configuration
            </button>
          )}
        </div>
      )}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   ORGANIZATION CONNECT TAB — Auto-scan all data sources
   ═══════════════════════════════════════════════════════ */

function OrgConnectTab({ onOrgScan, scanning }) {
  const [orgName,   setOrgName]   = useState("");
  const [dataOwner, setDataOwner] = useState("");
  const [result,    setResult]    = useState(null);

  /* Which sources are enabled */
  const [enableAutoDiscover, setEnableAutoDiscover] = useState(true);
  const [enableFolder,       setEnableFolder]       = useState(false);
  const [enableDatabase,     setEnableDatabase]     = useState(false);
  const [enableCloud,        setEnableCloud]        = useState(false);
  const [enableEmail,        setEnableEmail]        = useState(false);

  /* Source-specific config */
  const [folderPath,    setFolderPath]    = useState("");
  const [folderRecur,   setFolderRecur]   = useState(true);
  const [folderMax,     setFolderMax]     = useState(100);

  const [dbPath,        setDbPath]        = useState("");
  const [dbRowLimit,    setDbRowLimit]    = useState(5000);

  const [cloudProvider, setCloudProvider] = useState("s3");
  const [cloudCreds,    setCloudCreds]    = useState({});
  const [cloudMax,      setCloudMax]      = useState(100);

  const [emailAddr,     setEmailAddr]     = useState("");
  const [emailPwd,      setEmailPwd]      = useState("");
  const [emailHost,     setEmailHost]     = useState("imap.gmail.com");
  const [emailMax,      setEmailMax]      = useState(50);
  const [emailFolder,   setEmailFolder]   = useState("INBOX");
  const [showPwd,       setShowPwd]       = useState(false);

  const [adMax,         setAdMax]         = useState(50);
  const [adRecursive,   setAdRecursive]   = useState(false);
  const [adCustomPaths, setAdCustomPaths] = useState("");

  const CLOUD_PROVIDERS = [
    { id: "s3",      label: "AWS S3",       icon: "bi-cloud-fill" },
    { id: "gdrive",  label: "Google Drive", icon: "bi-google" },
    { id: "azure",   label: "Azure Blob",   icon: "bi-microsoft" },
    { id: "dropbox", label: "Dropbox",      icon: "bi-dropbox" },
  ];

  const CLOUD_FIELDS = {
    s3: [
      { key: "aws_access_key", label: "Access Key ID",       type: "text",     ph: "AKIAIOSFODNN7EXAMPLE" },
      { key: "aws_secret_key", label: "Secret Access Key",   type: "password", ph: "Your AWS secret key" },
      { key: "bucket_name",    label: "Bucket Name",         type: "text",     ph: "my-data-bucket" },
      { key: "aws_region",     label: "Region (opt.)",       type: "text",     ph: "us-east-1" },
      { key: "prefix",         label: "Prefix/Folder (opt.)", type: "text",    ph: "data/hr/" },
    ],
    gdrive: [
      { key: "service_account_json", label: "Service Account JSON", type: "textarea", ph: '{"type":"service_account",...}' },
      { key: "folder_id",            label: "Folder ID (opt.)",     type: "text",     ph: "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs" },
    ],
    azure: [
      { key: "connection_string", label: "Connection String",   type: "password", ph: "DefaultEndpointsProtocol=https;..." },
      { key: "container_name",    label: "Container Name",     type: "text",     ph: "my-container" },
      { key: "prefix",            label: "Blob Prefix (opt.)", type: "text",     ph: "hr-documents/" },
    ],
    dropbox: [
      { key: "access_token", label: "Access Token",       type: "password", ph: "sl.Abcdef..." },
      { key: "folder_path",  label: "Folder Path (opt.)", type: "text",     ph: "/HR/Documents" },
    ],
  };

  const EMAIL_PROVIDERS = {
    "imap.gmail.com":          "Gmail",
    "outlook.office365.com":   "Outlook / 365",
    "imap.mail.yahoo.com":     "Yahoo",
  };

  const updateCloudCred = (key, val) => setCloudCreds(prev => ({ ...prev, [key]: val }));

  const enabledCount = [enableAutoDiscover, enableFolder, enableDatabase, enableCloud, enableEmail].filter(Boolean).length;

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!orgName.trim()) return;
    setResult(null);

    const sources = {};

    if (enableAutoDiscover) {
      const extraPaths = adCustomPaths.split("\n").map(p => p.trim()).filter(Boolean);
      sources.auto_discover = { enabled: true, max_files: adMax, recursive: adRecursive, custom_paths: extraPaths };
    }
    if (enableFolder && folderPath.trim()) {
      sources.folder = { enabled: true, folder_path: folderPath.trim(), recursive: folderRecur, max_files: folderMax };
    }
    if (enableDatabase && dbPath.trim()) {
      sources.database = { enabled: true, db_path: dbPath.trim(), row_limit: dbRowLimit };
    }
    if (enableCloud) {
      sources.cloud = { enabled: true, provider: cloudProvider, credentials: cloudCreds, max_files: cloudMax };
    }
    if (enableEmail && emailAddr.trim() && emailPwd.trim()) {
      sources.email = { enabled: true, email: emailAddr.trim(), password: emailPwd.trim(), imap_host: emailHost, max_emails: emailMax, folder: emailFolder };
    }

    const data = await onOrgScan({ org_name: orgName.trim(), data_owner: dataOwner.trim() || orgName.trim(), sources });
    if (data) setResult(data);
  };

  /* Reusable section toggle */
  const SourceToggle = ({ label, icon, enabled, onToggle, children, color }) => (
    <div className="org-source-section" style={{ borderColor: enabled ? (color || "var(--accent-primary)") + "40" : "var(--border-subtle)" }}>
      <div className="org-source-header" onClick={onToggle} style={{ cursor: "pointer" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <i className={`bi ${icon}`} style={{ color: enabled ? (color || "var(--accent-primary)") : "var(--text-muted)", fontSize: "1.05rem" }} />
          <span style={{ fontWeight: 600, fontSize: "0.85rem", color: enabled ? "var(--text-primary)" : "var(--text-muted)" }}>{label}</span>
        </div>
        <div className="form-check form-switch" style={{ marginBottom: 0 }}>
          <input className="form-check-input" type="checkbox" checked={enabled} onChange={onToggle}
            style={{ cursor: "pointer" }} onClick={e => e.stopPropagation()} />
        </div>
      </div>
      {enabled && <div className="org-source-body">{children}</div>}
    </div>
  );

  return (
    <div className="org-connect-tab">
      {/* Hero banner */}
      <div className="org-banner mb-3">
        <div className="org-banner-icon"><i className="bi bi-building-gear" /></div>
        <div>
          <div className="org-banner-title">Organization-Wide Auto Scan</div>
          <div className="org-banner-sub">
            Connect your organization's data sources — local files, folders, databases, cloud storage, and email — and automatically scan all of them for PII in one click.
          </div>
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        {/* Organization identity */}
        <div className="row g-2 mb-3">
          <div className="col-sm-6">
            <label className="custom-label mb-1"><i className="bi bi-building me-1" /> Organization Name <span className="text-danger">*</span></label>
            <input type="text" className="form-control custom-input" placeholder="e.g. Acme Corp" value={orgName} onChange={e => setOrgName(e.target.value)} />
          </div>
          <div className="col-sm-6">
            <label className="custom-label mb-1"><i className="bi bi-person-badge me-1" /> Data Owner / Dept</label>
            <input type="text" className="form-control custom-input" placeholder="e.g. IT Security Team" value={dataOwner} onChange={e => setDataOwner(e.target.value)} />
          </div>
        </div>

        {/* Enabled sources counter */}
        <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
          <i className="bi bi-lightning-charge" style={{ color: "#f59e0b" }} />
          <span><strong style={{ color: "var(--text-secondary)" }}>{enabledCount}</strong> data source{enabledCount !== 1 ? "s" : ""} enabled — toggle each section to configure</span>
        </div>

        {/* ══ Auto-Discover ══ */}
        <SourceToggle label="Auto-Discover (Local Machine)" icon="bi-search" enabled={enableAutoDiscover}
          onToggle={() => setEnableAutoDiscover(v => !v)} color="#06b6d4">
          <p style={{ fontSize: "0.75rem", color: "var(--text-muted)", margin: "0 0 8px" }}>
            Scans Documents, Downloads, Desktop and custom paths automatically.
          </p>
          <div className="row g-2">
            <div className="col-6">
              <label className="form-label-sm">Max Files</label>
              <input type="number" className="form-control form-control-sm dark-input" min={5} max={200} value={adMax} onChange={e => setAdMax(+e.target.value || 50)} />
            </div>
            <div className="col-6 d-flex align-items-end">
              <div className="form-check">
                <input className="form-check-input" type="checkbox" checked={adRecursive} onChange={e => setAdRecursive(e.target.checked)} id="ad-recur" />
                <label className="form-check-label" htmlFor="ad-recur" style={{ fontSize: "0.78rem", color: "var(--text-secondary)" }}>Recursive</label>
              </div>
            </div>
          </div>
          <div className="mt-2">
            <label className="form-label-sm">Custom Paths (one per line, optional)</label>
            <textarea className="form-control form-control-sm dark-input" rows={2} placeholder={"C:\\OrgData\\Shared\n/mnt/network/hr"} value={adCustomPaths} onChange={e => setAdCustomPaths(e.target.value)} style={{ fontFamily: "monospace", fontSize: "0.76rem" }} />
          </div>
        </SourceToggle>

        {/* ══ Folder Scan ══ */}
        <SourceToggle label="Organization Folder / Shared Drive" icon="bi-folder2-open" enabled={enableFolder}
          onToggle={() => setEnableFolder(v => !v)} color="#8b5cf6">
          <div className="mb-2">
            <label className="form-label-sm">Folder Path <span className="text-danger">*</span></label>
            <input type="text" className="form-control form-control-sm dark-input" placeholder="e.g. C:\OrgData or /mnt/shared" value={folderPath} onChange={e => setFolderPath(e.target.value)} />
          </div>
          <div className="row g-2">
            <div className="col-6">
              <label className="form-label-sm">Max Files</label>
              <input type="number" className="form-control form-control-sm dark-input" min={10} max={500} value={folderMax} onChange={e => setFolderMax(+e.target.value || 100)} />
            </div>
            <div className="col-6 d-flex align-items-end">
              <div className="form-check">
                <input className="form-check-input" type="checkbox" checked={folderRecur} onChange={e => setFolderRecur(e.target.checked)} id="folder-recur" />
                <label className="form-check-label" htmlFor="folder-recur" style={{ fontSize: "0.78rem", color: "var(--text-secondary)" }}>Recursive scan</label>
              </div>
            </div>
          </div>
        </SourceToggle>

        {/* ══ Database ══ */}
        <SourceToggle label="SQLite Database" icon="bi-database" enabled={enableDatabase}
          onToggle={() => setEnableDatabase(v => !v)} color="#f59e0b">
          <div className="mb-2">
            <label className="form-label-sm">Database File Path <span className="text-danger">*</span></label>
            <input type="text" className="form-control form-control-sm dark-input" placeholder="e.g. C:\data\app.db" value={dbPath} onChange={e => setDbPath(e.target.value)} />
            <small style={{ color: "var(--text-muted)", fontSize: "0.7rem" }}>Supports .db, .sqlite, .sqlite3</small>
          </div>
          <div>
            <label className="form-label-sm">Row Limit per Table</label>
            <input type="number" className="form-control form-control-sm dark-input" min={100} max={50000} step={500} value={dbRowLimit} onChange={e => setDbRowLimit(+e.target.value || 5000)} />
          </div>
        </SourceToggle>

        {/* ══ Cloud Storage ══ */}
        <SourceToggle label="Cloud Storage" icon="bi-cloud" enabled={enableCloud}
          onToggle={() => setEnableCloud(v => !v)} color="#22c55e">
          <div className="mb-2">
            <label className="form-label-sm">Provider</label>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {CLOUD_PROVIDERS.map(p => (
                <button key={p.id} type="button" onClick={() => { setCloudProvider(p.id); setCloudCreds({}); }}
                  style={{
                    display: "flex", alignItems: "center", gap: 5, padding: "4px 10px",
                    borderRadius: "var(--radius-sm)", fontSize: "0.76rem",
                    border: cloudProvider === p.id ? "1.5px solid var(--accent-primary)" : "1px solid rgba(255,255,255,0.08)",
                    background: cloudProvider === p.id ? "rgba(56,189,248,0.12)" : "transparent",
                    color: cloudProvider === p.id ? "var(--accent-primary)" : "var(--text-muted)",
                    cursor: "pointer", fontWeight: cloudProvider === p.id ? 600 : 400,
                  }}>
                  <i className={`bi ${p.icon}`} /> {p.label}
                </button>
              ))}
            </div>
          </div>
          {(CLOUD_FIELDS[cloudProvider] || []).map(f => (
            <div className="mb-2" key={f.key}>
              <label className="form-label-sm">{f.label}</label>
              {f.type === "textarea"
                ? <textarea className="form-control form-control-sm dark-input" rows={3} placeholder={f.ph}
                    value={cloudCreds[f.key] || ""} onChange={e => updateCloudCred(f.key, e.target.value)}
                    style={{ fontFamily: "monospace", fontSize: "0.74rem" }} />
                : <input type={f.type} className="form-control form-control-sm dark-input" placeholder={f.ph}
                    value={cloudCreds[f.key] || ""} onChange={e => updateCloudCred(f.key, e.target.value)} autoComplete="off" />
              }
            </div>
          ))}
          <div>
            <label className="form-label-sm">Max Files</label>
            <input type="number" className="form-control form-control-sm dark-input" min={1} max={500} value={cloudMax} onChange={e => setCloudMax(+e.target.value || 100)} />
          </div>
        </SourceToggle>

        {/* ══ Email (IMAP) ══ */}
        <SourceToggle label="Email (IMAP)" icon="bi-envelope-fill" enabled={enableEmail}
          onToggle={() => setEnableEmail(v => !v)} color="#ef4444">
          <div className="mb-2">
            <label className="form-label-sm">IMAP Server</label>
            <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
              {Object.entries(EMAIL_PROVIDERS).map(([host, name]) => (
                <button key={host} type="button" onClick={() => setEmailHost(host)}
                  style={{
                    padding: "4px 10px", borderRadius: "var(--radius-sm)", fontSize: "0.76rem",
                    border: emailHost === host ? "1.5px solid var(--accent-primary)" : "1px solid rgba(255,255,255,0.08)",
                    background: emailHost === host ? "rgba(56,189,248,0.12)" : "transparent",
                    color: emailHost === host ? "var(--accent-primary)" : "var(--text-muted)",
                    cursor: "pointer", fontWeight: emailHost === host ? 600 : 400,
                  }}>
                  {name}
                </button>
              ))}
            </div>
          </div>
          <div className="row g-2 mb-2">
            <div className="col-12">
              <label className="form-label-sm">Email Address <span className="text-danger">*</span></label>
              <input type="email" className="form-control form-control-sm dark-input" placeholder="you@company.com" value={emailAddr} onChange={e => setEmailAddr(e.target.value)} autoComplete="off" />
            </div>
            <div className="col-12">
              <label className="form-label-sm">App Password <span className="text-danger">*</span></label>
              <div className="input-group input-group-sm">
                <input type={showPwd ? "text" : "password"} className="form-control dark-input" placeholder="App password" value={emailPwd} onChange={e => setEmailPwd(e.target.value)} autoComplete="new-password" />
                <button type="button" className="btn btn-outline-secondary btn-sm" onClick={() => setShowPwd(v => !v)}
                  style={{ borderColor: "var(--border-subtle)", color: "var(--text-muted)" }}>
                  <i className={`bi ${showPwd ? "bi-eye-slash" : "bi-eye"}`} />
                </button>
              </div>
            </div>
          </div>
          <div className="row g-2">
            <div className="col-6">
              <label className="form-label-sm">Max Emails</label>
              <input type="number" className="form-control form-control-sm dark-input" min={5} max={100} value={emailMax} onChange={e => setEmailMax(+e.target.value || 50)} />
            </div>
            <div className="col-6">
              <label className="form-label-sm">Folder</label>
              <input type="text" className="form-control form-control-sm dark-input" value={emailFolder} onChange={e => setEmailFolder(e.target.value)} placeholder="INBOX" />
            </div>
          </div>
        </SourceToggle>

        {/* Security notice */}
        <div style={{ fontSize: "0.74rem", color: "var(--text-muted)", margin: "12px 0", display: "flex", alignItems: "center", gap: 6 }}>
          <i className="bi bi-shield-lock-fill" style={{ color: "#22c55e" }} />
          All credentials are used <strong style={{ color: "var(--text-secondary)" }}>only for this scan</strong> and are never stored on the server.
        </div>

        {/* Submit */}
        <button type="submit" className="btn-accent w-100 org-scan-btn" disabled={scanning || !orgName.trim() || enabledCount === 0}>
          {scanning
            ? <><span className="spinner-border spinner-border-sm me-2" />Scanning {enabledCount} source{enabledCount !== 1 ? "s" : ""}...</>
            : <><i className="bi bi-lightning-charge-fill me-2" />Scan {enabledCount} Data Source{enabledCount !== 1 ? "s" : ""} for {orgName.trim() || "Organization"}</>
          }
        </button>
      </form>

      {/* ── Results Summary ── */}
      {result && result.success && (
        <div className="org-results-summary mt-3">
          <div className="org-results-header">
            <i className="bi bi-check-circle-fill" style={{ color: "#22c55e" }} />
            <span>Organization Scan Complete — <strong>{result.org_name}</strong></span>
          </div>

          <div className="org-results-totals">
            <div className="org-total-item">
              <span className="org-total-num">{result.totals?.sources_scanned || 0}</span>
              <span className="org-total-label">Sources</span>
            </div>
            <div className="org-total-item">
              <span className="org-total-num">{result.totals?.total_files || 0}</span>
              <span className="org-total-label">Items Scanned</span>
            </div>
            <div className="org-total-item" style={{ color: "#f59e0b" }}>
              <span className="org-total-num">{result.totals?.total_pii || 0}</span>
              <span className="org-total-label">PII Found</span>
            </div>
            {(result.totals?.total_errors || 0) > 0 && (
              <div className="org-total-item" style={{ color: "var(--danger)" }}>
                <span className="org-total-num">{result.totals.total_errors}</span>
                <span className="org-total-label">Errors</span>
              </div>
            )}
          </div>

          {/* Per-source breakdown */}
          <div className="org-source-results">
            {Object.entries(result.scan_results || {}).map(([key, val]) => (
              <div key={key} className="org-source-result-row">
                <span className="org-src-name">
                  <i className={`bi ${val.success ? "bi-check-circle" : "bi-x-circle"} me-1`}
                    style={{ color: val.success ? "#22c55e" : "var(--danger)" }} />
                  {key.replace("_", " ").replace(/\b\w/g, c => c.toUpperCase())}
                </span>
                {val.success ? (
                  <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                    {val.files_scanned ?? val.tables_scanned ?? val.emails_scanned ?? 0} scanned
                    {" · "}
                    <strong style={{ color: "#f59e0b" }}>{val.total_pii || 0}</strong> PII
                  </span>
                ) : (
                  <span style={{ fontSize: "0.75rem", color: "var(--danger)" }}>{val.message || "Failed"}</span>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {result && !result.success && (
        <div className="file-error-msg mt-3">
          <i className="bi bi-exclamation-triangle-fill" /> {result.message || "Organization scan failed."}
        </div>
      )}
    </div>
  );
}


/* ── File Upload Tab ──────────────────────────────────── */
function FileUploadTab({ onUpload, scanning }) {
  const [dragOver,      setDragOver]  = useState(false);
  const [fileList,      setFileList]  = useState([]);
  const [owner,         setOwner]     = useState("");
  const [storage,       setStorage]   = useState("");
  const [validationErr, setValidErr]  = useState("");
  const inputRef = useRef(null);

  const iconMap  = {
    txt:  "bi-file-text-fill",
    log:  "bi-terminal-fill",
    md:   "bi-markdown-fill",
    csv:  "bi-filetype-csv",
    pdf:  "bi-file-earmark-pdf-fill",
    docx: "bi-file-earmark-word-fill",
    xlsx: "bi-file-earmark-spreadsheet-fill",
    xls:  "bi-file-earmark-spreadsheet-fill",
    pptx: "bi-file-earmark-slides-fill",
    rtf:  "bi-file-earmark-richtext-fill",
    json: "bi-filetype-json",
    xml:  "bi-filetype-xml",
    html: "bi-filetype-html",
    htm:  "bi-filetype-html",
    eml:  "bi-envelope-fill",
    msg:  "bi-envelope-at-fill",
    odt:  "bi-file-earmark-text-fill",
    ods:  "bi-file-earmark-spreadsheet-fill",
    zip:  "bi-file-zip-fill",
    tar:  "bi-archive-fill",
    gz:   "bi-archive-fill",
    tgz:  "bi-archive-fill",
  };
  const colorMap = {
    txt:  "#38bdf8",
    log:  "#64748b",
    md:   "#0ea5e9",
    csv:  "#22c55e",
    pdf:  "#ef4444",
    docx: "#3b82f6",
    xlsx: "#16a34a",
    xls:  "#15803d",
    ods:  "#166534",
    pptx: "#f97316",
    rtf:  "#a855f7",
    odt:  "#2563eb",
    json: "#f59e0b",
    xml:  "#06b6d4",
    html: "#e11d48",
    htm:  "#e11d48",
    eml:  "#f59e0b",
    msg:  "#d97706",
    zip:  "#8b5cf6",
    tar:  "#8b5cf6",
    gz:   "#8b5cf6",
    tgz:  "#8b5cf6",
  };

  const processFiles = (files) => {
    const arr = Array.from(files);
    setFileList(arr);
    setValidErr("");
    const invalid = arr.filter(f => {
      const ext = f.name.split(".").pop().toLowerCase();
      return !ALLOWED_EXTS.includes(ext) || f.size / (1024*1024) > MAX_SIZE_MB;
    });
    if (invalid.length) setValidErr(`${invalid.length} file(s) invalid (unsupported type or >${MAX_SIZE_MB} MB) — will be skipped.`);
  };

  const handleDrop = (e) => {
    e.preventDefault(); setDragOver(false);
    processFiles(e.dataTransfer.files);
  };

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!fileList.length) { setValidErr("Please select at least one file."); return; }
    const fd = new FormData();
    fileList.forEach(f => fd.append("files", f));
    fd.append("data_owner", owner);
    fd.append("storage_location", storage);
    onUpload(fd);
    // Reset
    setFileList([]);
    setOwner("");
    setStorage("");
    if (inputRef.current) inputRef.current.value = "";
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        {/* Drop zone */}
        <div
          id="upload-zone"
          className={`upload-zone mb-3 ${dragOver ? "drag-over" : ""}`}
          onClick={() => inputRef.current?.click()}
          onDragEnter={e => { e.preventDefault(); setDragOver(true); }}
          onDragOver={e => { e.preventDefault(); setDragOver(true); }}
          onDragLeave={() => setDragOver(false)}
          onDrop={handleDrop}
        >
          <input
            ref={inputRef}
            type="file"
            multiple
            accept=".txt,.log,.md,.csv,.xlsx,.xls,.ods,.pdf,.docx,.pptx,.rtf,.odt,.json,.xml,.html,.htm,.eml,.msg,.zip,.tar,.gz,.tgz"
            style={{ display: "none" }}
            onChange={e => processFiles(e.target.files)}
          />
          <div className="upload-icon-wrap"><i className="bi bi-cloud-upload-fill" /></div>
          <p className="upload-title">
            {dragOver ? "Release to scan files" : "Drag & drop files here or click to browse"}
          </p>
          <div className="file-types">
            {["TXT","LOG","MD","CSV","XLSX","XLS","ODS","PDF","DOCX","PPTX","RTF","ODT","JSON","XML","HTML","EML","MSG","ZIP","TAR"].map(t => <span key={t} className="file-badge">{t}</span>)}
            <span className="file-size-note">· max 64 MB</span>
          </div>
        </div>

        {/* File preview chips */}
        {fileList.length > 0 && (
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 12 }}>
            {fileList.map((f, i) => {
              const ext   = f.name.split(".").pop().toLowerCase();
              const icon  = iconMap[ext]  || "bi-file-earmark-fill";
              const color = colorMap[ext] || "var(--accent-primary)";
              const size  = f.size < 1048576 ? (f.size/1024).toFixed(1)+" KB" : (f.size/1048576).toFixed(1)+" MB";
              return (
                <div key={i} className="pii-chip" style={{ borderColor: color + "40" }}>
                  <i className={`bi ${icon}`} style={{ color }} />
                  <span>{f.name}</span>
                  <span style={{ color: "var(--text-muted)", fontSize: "0.68rem" }}>({size})</span>
                </div>
              );
            })}
          </div>
        )}

        {/* Validation error */}
        {validationErr && (
          <div className="file-error-msg mb-3">
            <i className="bi bi-exclamation-triangle-fill" /> {validationErr}
          </div>
        )}

        {/* Metadata fields */}
        <div className="row g-2 mb-3">
          <div className="col-sm-6">
            <label className="custom-label mb-1"><i className="bi bi-person" /> Data Owner</label>
            <input
              type="text"
              className="form-control custom-input"
              placeholder="e.g. HR Department"
              value={owner}
              onChange={e => setOwner(e.target.value)}
            />
          </div>
          <div className="col-sm-6">
            <label className="custom-label mb-1"><i className="bi bi-hdd-network" /> Storage Location</label>
            <input
              type="text"
              className="form-control custom-input"
              placeholder="e.g. On-Premises / Cloud"
              value={storage}
              onChange={e => setStorage(e.target.value)}
            />
          </div>
        </div>

        <button
          type="submit"
          id="btn-scan"
          className="btn-accent w-100"
          disabled={scanning || fileList.length === 0}
        >
          {scanning
            ? <><span className="spinner-border spinner-border-sm me-2" role="status" />Scanning...</>
            : <><i className="bi bi-shield-shaded me-2" />Scan for PII</>
          }
        </button>
      </form>
    </div>
  );
}


/* ── Folder Scan Tab ─────────────────────────────────── */
function FolderScanTab({ onFolderScan, scanning }) {
  const [folderPath, setFolderPath] = useState("");
  const [recursive,  setRecursive]  = useState(true);
  const [owner,      setOwner]      = useState("");
  const [maxFiles,   setMaxFiles]   = useState(50);
  const [error,      setError]      = useState("");
  const [result,     setResult]     = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!folderPath.trim()) { setError("Please enter a folder path."); return; }
    setError("");
    setResult(null);
    const data = await onFolderScan({
      folder_path: folderPath.trim(),
      recursive,
      data_owner: owner.trim() || "Unassigned",
      max_files: maxFiles,
    });
    if (data) setResult(data);
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <div className="mb-3">
          <label className="custom-label mb-1"><i className="bi bi-folder2-open" /> Folder Path</label>
          <input
            type="text"
            className="form-control custom-input"
            placeholder="e.g. C:\Users\user\Documents  or  /home/user/docs"
            value={folderPath}
            onChange={e => setFolderPath(e.target.value)}
          />
        </div>

        <div className="row mb-3">
          <div className="col-6">
            <label className="custom-label mb-1">
              <i className="bi bi-file-earmark-text" /> Max Files
            </label>
            <select
              className="form-select custom-input"
              value={maxFiles}
              onChange={e => setMaxFiles(parseInt(e.target.value))}
            >
              <option value={10}>10 files (fastest)</option>
              <option value={25}>25 files</option>
              <option value={50}>50 files</option>
              <option value={100}>100 files</option>
              <option value={200}>200 files</option>
            </select>
          </div>
          <div className="col-6">
            <label className="custom-label mb-1">
              <i className="bi bi-diagram-3" /> Scan Mode
            </label>
            <div className="form-check form-switch mt-2">
              <input
                className="form-check-input"
                type="checkbox"
                id="recursive-toggle"
                checked={recursive}
                onChange={e => setRecursive(e.target.checked)}
              />
              <label className="form-check-label" htmlFor="recursive-toggle" style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                Include subfolders
              </label>
            </div>
          </div>
        </div>

        <div className="mb-3">
          <label className="custom-label mb-1">
            <i className="bi bi-person" /> Data Owner
            <span style={{ color: "var(--text-muted)", fontWeight: 400, marginLeft: 4 }}>(optional)</span>
          </label>
          <input
            type="text"
            className="form-control custom-input"
            placeholder="e.g. IT Department"
            value={owner}
            onChange={e => setOwner(e.target.value)}
          />
        </div>

        {error && (
          <div className="file-error-msg mb-3">
            <i className="bi bi-exclamation-triangle-fill" /> {error}
          </div>
        )}

        <button
          type="submit"
          className="btn-accent w-100"
          disabled={scanning || !folderPath.trim()}
        >
          {scanning
            ? <><span className="spinner-border spinner-border-sm me-2" role="status" />Scanning folder...</>
            : <><i className="bi bi-folder2-open me-2" />Scan Folder</>
          }
        </button>
      </form>

      {result && result.success && (
        <div className="scan-summary-box mt-3">
          <div className="scan-summary-row">
            <i className="bi bi-folder-check" style={{ color: "var(--accent-primary)" }} />
            <span><strong>{result.scanned}</strong> of {result.supported_files} file(s) scanned</span>
          </div>
          <div className="scan-summary-row">
            <i className="bi bi-exclamation-diamond" style={{ color: "var(--accent-warn, #f59e0b)" }} />
            <span><strong>{result.total_pii}</strong> PII items detected</span>
          </div>
          {result.unsupported > 0 && (
            <div className="scan-summary-row">
              <i className="bi bi-file-earmark-x" style={{ color: "var(--text-muted)" }} />
              <span>{result.unsupported} unsupported file(s) skipped</span>
            </div>
          )}
          {(result.skipped_large || 0) > 0 && (
            <div className="scan-summary-row">
              <i className="bi bi-file-earmark-arrow-up" style={{ color: "var(--text-muted)" }} />
              <span>{result.skipped_large} large file(s) skipped (&gt;1 MB)</span>
            </div>
          )}
          {(result.skipped_timeout || 0) > 0 && (
            <div className="scan-summary-row">
              <i className="bi bi-clock" style={{ color: "var(--text-muted)" }} />
              <span>{result.skipped_timeout} file(s) timed out</span>
            </div>
          )}
          {result.limit_reached && (
            <div className="scan-summary-row">
              <i className="bi bi-info-circle" style={{ color: "var(--accent-primary)" }} />
              <span>File limit reached — increase Max Files to scan more</span>
            </div>
          )}
          {result.errors > 0 && (
            <div className="scan-summary-row">
              <i className="bi bi-bug" style={{ color: "var(--danger)" }} />
              <span>{result.errors} file(s) had errors</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}


/* ── Database Scan Tab ───────────────────────────────── */
function DatabaseScanTab({ onDatabaseScan, scanning }) {
  const [dbPath,   setDbPath]   = useState("");
  const [rowLimit, setRowLimit] = useState(5000);
  const [owner,    setOwner]    = useState("");
  const [error,    setError]    = useState("");
  const [result,   setResult]   = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!dbPath.trim()) { setError("Please enter a database file path."); return; }
    const ext = dbPath.trim().split(".").pop().toLowerCase();
    if (!["db", "sqlite", "sqlite3"].includes(ext)) {
      setError("Only SQLite files (.db, .sqlite, .sqlite3) are supported.");
      return;
    }
    setError("");
    setResult(null);
    const data = await onDatabaseScan({ db_path: dbPath.trim(), data_owner: owner.trim() || "Unassigned", row_limit: rowLimit });
    if (data) setResult(data);
  };

  const riskColor = { LOW: "#22c55e", MEDIUM: "#f59e0b", HIGH: "#ef4444", CRITICAL: "#dc2626" };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <div className="mb-3">
          <label className="custom-label mb-1"><i className="bi bi-database" /> Database File Path</label>
          <input
            type="text"
            className="form-control custom-input"
            placeholder="e.g. C:\data\myapp.db  or  /var/app/data.sqlite"
            value={dbPath}
            onChange={e => setDbPath(e.target.value)}
          />
          <small style={{ color: "var(--text-muted)", fontSize: "0.75rem", marginTop: 4, display: "block" }}>
            Supports .db, .sqlite, .sqlite3 formats
          </small>
        </div>

        <div className="row g-2 mb-3">
          <div className="col-sm-6">
            <label className="custom-label mb-1">
              <i className="bi bi-person" /> Data Owner
              <span style={{ color: "var(--text-muted)", fontWeight: 400, marginLeft: 4 }}>(optional)</span>
            </label>
            <input
              type="text"
              className="form-control custom-input"
              placeholder="e.g. Database Team"
              value={owner}
              onChange={e => setOwner(e.target.value)}
            />
          </div>
          <div className="col-sm-6">
            <label className="custom-label mb-1"><i className="bi bi-list-ol" /> Row Limit per Table</label>
            <input
              type="number"
              className="form-control custom-input"
              min={100}
              max={50000}
              step={500}
              value={rowLimit}
              onChange={e => setRowLimit(parseInt(e.target.value) || 5000)}
            />
          </div>
        </div>

        {error && (
          <div className="file-error-msg mb-3">
            <i className="bi bi-exclamation-triangle-fill" /> {error}
          </div>
        )}

        <button
          type="submit"
          className="btn-accent w-100"
          disabled={scanning || !dbPath.trim()}
        >
          {scanning
            ? <><span className="spinner-border spinner-border-sm me-2" role="status" />Scanning database...</>
            : <><i className="bi bi-database me-2" />Scan Database</>
          }
        </button>
      </form>

      {result && result.success && (
        <div className="scan-summary-box mt-3">
          <div className="scan-summary-row">
            <i className="bi bi-table" style={{ color: "var(--accent-primary)" }} />
            <span><strong>{result.tables_scanned}</strong> of {result.tables_found} table(s) scanned</span>
          </div>
          <div className="scan-summary-row">
            <i className="bi bi-exclamation-diamond" style={{ color: "var(--accent-warn, #f59e0b)" }} />
            <span><strong>{result.total_pii}</strong> PII items detected</span>
          </div>
          {result.errors > 0 && (
            <div className="scan-summary-row">
              <i className="bi bi-bug" style={{ color: "var(--danger)" }} />
              <span>{result.errors} table(s) had errors</span>
            </div>
          )}
          {result.table_results?.length > 0 && (
            <div className="mt-2">
              <div style={{ fontSize: "0.73rem", color: "var(--text-muted)", marginBottom: 6, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                Table Breakdown
              </div>
              {result.table_results.map((t, i) => (
                <div key={i} className="db-table-row">
                  <span className="db-table-name">
                    <i className="bi bi-table me-1" style={{ opacity: 0.5 }} />{t.table}
                  </span>
                  <span style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>{t.rows} rows</span>
                  <span style={{ color: "#f59e0b", fontSize: "0.75rem", marginLeft: "auto" }}>{t.pii_total} PII</span>
                  <span className="pii-chip" style={{ padding: "2px 8px", fontSize: "0.7rem", borderColor: (riskColor[t.risk] || "#38bdf8") + "40", color: riskColor[t.risk] || "var(--accent-primary)" }}>
                    {t.risk}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


/* ── Auto Discover Tab ───────────────────────────────── */
function AutoDiscoverTab({ onAutoDiscover, scanning }) {
  const [owner,       setOwner]       = useState("");
  const [customPaths, setCustomPaths] = useState("");
  const [maxFiles,    setMaxFiles]    = useState(10);
  const [recursive,   setRecursive]   = useState(false);
  const [result,      setResult]      = useState(null);
  const [error,       setError]       = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setResult(null);
    const extraPaths = customPaths.split("\n").map(p => p.trim()).filter(Boolean);
    const data = await onAutoDiscover({
      data_owner  : owner.trim() || "Auto-Discovered",
      custom_paths: extraPaths,
      max_files   : maxFiles,
      recursive   : recursive,
    });
    if (data) setResult(data);
  };

  const defaultPaths = [
    "~/Documents",
    "~/Downloads",
    "~/Desktop",
    "~/OneDrive/Documents",
  ];

  return (
    <div>
      {/* Info header */}
      <div className="auto-discover-banner mb-3">
        <div className="adb-icon"><i className="bi bi-search" /></div>
        <div>
          <div className="adb-title">Automatic Data Source Discovery</div>
          <div className="adb-sub">
            Scans your local system for files containing personal data across
            Documents, Downloads, Desktop, and any custom paths you add.
          </div>
        </div>
      </div>

      {/* Default paths display */}
      <div className="mb-3">
        <label className="custom-label mb-2">
          <i className="bi bi-folder-symlink me-1" /> Default Discovery Paths
        </label>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
          {defaultPaths.map((p, i) => (
            <span key={i} className="pii-chip" style={{ borderColor: "rgba(56,189,248,0.3)", fontSize: "0.74rem" }}>
              <i className="bi bi-folder2" style={{ color: "var(--accent-primary)" }} />
              {p}
            </span>
          ))}
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        {/* Scan options row */}
        <div className="row mb-3">
          <div className="col-6">
            <label className="custom-label mb-1">
              <i className="bi bi-file-earmark-text" /> Max Files
            </label>
            <select
              className="form-select custom-input"
              value={maxFiles}
              onChange={e => setMaxFiles(parseInt(e.target.value))}
            >
              <option value={5}>5 files (fastest)</option>
              <option value={10}>10 files</option>
              <option value={20}>20 files</option>
              <option value={50}>50 files</option>
              <option value={100}>100 files</option>
            </select>
          </div>
          <div className="col-6">
            <label className="custom-label mb-1">
              <i className="bi bi-diagram-3" /> Scan Mode
            </label>
            <div className="form-check mt-2">
              <input
                type="checkbox"
                className="form-check-input"
                id="recursiveCheck"
                checked={recursive}
                onChange={e => setRecursive(e.target.checked)}
              />
              <label className="form-check-label" htmlFor="recursiveCheck" style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                Recursive (include subfolders)
              </label>
            </div>
          </div>
        </div>

        {/* Extra custom paths */}
        <div className="mb-3">
          <label className="custom-label mb-1">
            <i className="bi bi-plus-circle" /> Additional Paths
            <span style={{ color: "var(--text-muted)", fontWeight: 400, marginLeft: 4 }}>(one per line, optional)</span>
          </label>
          <textarea
            className="form-control custom-input"
            rows={2}
            placeholder={"e.g.\nC:\\Projects\\HRData\n/var/app/uploads"}
            value={customPaths}
            onChange={e => setCustomPaths(e.target.value)}
            style={{ resize: "vertical", fontFamily: "monospace", fontSize: "0.8rem" }}
          />
        </div>

        <div className="mb-3">
          <label className="custom-label mb-1">
            <i className="bi bi-person" /> Data Owner
            <span style={{ color: "var(--text-muted)", fontWeight: 400, marginLeft: 4 }}>(optional)</span>
          </label>
          <input
            type="text"
            className="form-control custom-input"
            placeholder="e.g. Enterprise IT"
            value={owner}
            onChange={e => setOwner(e.target.value)}
          />
        </div>

        {/* Supported formats note */}
        <div style={{ fontSize: "0.76rem", color: "var(--text-muted)", marginBottom: 12 }}>
          <i className="bi bi-info-circle me-1" />
          Discovers: TXT, LOG, MD, CSV, XLSX, XLS, ODS, PDF, DOCX, PPTX, RTF, ODT, JSON, XML, HTML, EML, MSG, ZIP, TAR
        </div>

        {error && (
          <div className="file-error-msg mb-3">
            <i className="bi bi-exclamation-triangle-fill" /> {error}
          </div>
        )}

        <button
          type="submit"
          className="btn-accent w-100"
          disabled={scanning}
        >
          {scanning
            ? <><span className="spinner-border spinner-border-sm me-2" role="status" />Discovering data sources...</>
            : <><i className="bi bi-search me-2" />Start Auto-Discovery</>
          }
        </button>
      </form>

      {result && result.success && (
        <div className="scan-summary-box mt-3">
          {result.limit_reached && (
            <div className="scan-summary-row" style={{ color: "var(--accent-warning)" }}>
              <i className="bi bi-exclamation-circle" />
              <span>File limit reached ({result.max_files}). Increase limit for more files.</span>
            </div>
          )}
          <div className="scan-summary-row">
            <i className="bi bi-hdd-network" style={{ color: "var(--accent-primary)" }} />
            <span><strong>{result.paths_scanned?.length || 0}</strong> path(s) scanned</span>
          </div>
          <div className="scan-summary-row">
            <i className="bi bi-file-earmark-text" style={{ color: "var(--accent-primary)" }} />
            <span><strong>{result.files_found}</strong> supported file(s) discovered</span>
          </div>
          <div className="scan-summary-row">
            <i className="bi bi-shield-check" style={{ color: "#22c55e" }} />
            <span><strong>{result.files_scanned}</strong> file(s) scanned for PII</span>
          </div>
          <div className="scan-summary-row">
            <i className="bi bi-exclamation-diamond" style={{ color: "var(--accent-warn, #f59e0b)" }} />
            <span><strong>{result.total_pii}</strong> PII items detected</span>
          </div>
          {result.errors > 0 && (
            <div className="scan-summary-row">
              <i className="bi bi-bug" style={{ color: "var(--danger)" }} />
              <span>{result.errors} file(s) had errors</span>
            </div>
          )}
          {result.paths_scanned?.length > 0 && (
            <div className="mt-2">
              <div style={{ fontSize: "0.73rem", color: "var(--text-muted)", marginBottom: 6, fontWeight: 600, textTransform: "uppercase", letterSpacing: "0.06em" }}>
                Paths Scanned
              </div>
              {result.paths_scanned.map((p, i) => (
                <div key={i} className="db-table-row">
                  <i className="bi bi-folder-check" style={{ color: "var(--accent-primary)", opacity: 0.7 }} />
                  <span className="db-table-name" style={{ fontSize: "0.75rem" }}>{p}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {result && !result.success && (
        <div className="file-error-msg mt-3">
          <i className="bi bi-exclamation-triangle-fill" /> {result.message}
        </div>
      )}
    </div>
  );
}


/* ── Cloud Storage Tab ─────────────────────────────────── */
function CloudStorageTab({ onCloudScan, scanning }) {
  const [provider,  setProvider]  = useState("s3");
  const [creds,     setCreds]     = useState({});
  const [owner,     setOwner]     = useState("");
  const [maxFiles,  setMaxFiles]  = useState(100);
  const [result,    setResult]    = useState(null);

  const PROVIDERS = [
    { id: "s3",      label: "AWS S3",       icon: "bi-cloud-fill"   },
    { id: "gdrive",  label: "Google Drive", icon: "bi-google"       },
    { id: "azure",   label: "Azure Blob",   icon: "bi-microsoft"    },
    { id: "dropbox", label: "Dropbox",      icon: "bi-dropbox"      },
  ];

  const CRED_FIELDS = {
    s3: [
      { key: "aws_access_key", label: "Access Key ID",   type: "text",     ph: "AKIAIOSFODNN7EXAMPLE" },
      { key: "aws_secret_key", label: "Secret Access Key", type: "password", ph: "Your AWS secret key" },
      { key: "bucket_name",    label: "Bucket Name",     type: "text",     ph: "my-data-bucket" },
      { key: "aws_region",     label: "Region (opt.)",   type: "text",     ph: "us-east-1" },
      { key: "prefix",         label: "Prefix/Folder (opt.)", type: "text", ph: "data/hr/" },
    ],
    gdrive: [
      { key: "service_account_json", label: "Service Account JSON", type: "textarea", ph: '{"type":"service_account",...}' },
      { key: "folder_id",            label: "Folder ID (opt.)",     type: "text",     ph: "1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs" },
    ],
    azure: [
      { key: "connection_string", label: "Connection String", type: "password", ph: "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net" },
      { key: "container_name",    label: "Container Name",   type: "text",     ph: "my-container" },
      { key: "prefix",            label: "Blob Prefix (opt.)", type: "text",   ph: "hr-documents/" },
    ],
    dropbox: [
      { key: "access_token", label: "Access Token",      type: "password", ph: "sl.Abcdef..." },
      { key: "folder_path",  label: "Folder Path (opt.)", type: "text",    ph: "/HR/Documents" },
    ],
  };

  const updateCred  = (key, val) => setCreds(prev => ({ ...prev, [key]: val }));
  const changeProvider = (p) => { setProvider(p); setCreds({}); setResult(null); };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setResult(null);
    const data = await onCloudScan({
      provider   : provider,
      credentials: creds,
      data_owner : owner.trim() || "Cloud-Scanned",
      max_files  : parseInt(maxFiles) || 100,
    });
    if (data) setResult(data);
  };

  const currentProvider = PROVIDERS.find(p => p.id === provider);

  return (
    <div>
      {/* Info banner */}
      <div className="auto-discover-banner mb-3">
        <div className="adb-icon"><i className="bi bi-cloud" /></div>
        <div>
          <div className="adb-title">Cloud Storage Scanner</div>
          <div className="adb-sub">
            Scan AWS S3, Google Drive, Azure Blob, or Dropbox for PII.
            Credentials are used only during this request and never stored.
          </div>
        </div>
      </div>

      {/* Provider pills */}
      <div className="mb-3">
        <label className="custom-label mb-2"><i className="bi bi-cloud me-1" /> Provider</label>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {PROVIDERS.map(p => (
            <button
              key={p.id}
              type="button"
              onClick={() => changeProvider(p.id)}
              style={{
                display: "flex", alignItems: "center", gap: 6,
                padding: "6px 14px", borderRadius: "var(--radius-sm)",
                border: provider === p.id ? "1.5px solid var(--accent-primary)" : "1px solid rgba(255,255,255,0.1)",
                background: provider === p.id ? "rgba(56,189,248,0.15)" : "rgba(255,255,255,0.03)",
                color: provider === p.id ? "var(--accent-primary)" : "var(--text-secondary)",
                fontSize: "0.82rem", fontWeight: provider === p.id ? 600 : 400,
                cursor: "pointer", transition: "all 0.2s",
              }}
            >
              <i className={`bi ${p.icon}`} style={{ fontSize: "1rem" }} />
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <form onSubmit={handleSubmit}>
        {(CRED_FIELDS[provider] || []).map(f => (
          <div className="mb-3" key={f.key}>
            <label className="custom-label mb-1">{f.label}</label>
            {f.type === "textarea"
              ? <textarea
                  className="form-control custom-input"
                  rows={4}
                  placeholder={f.ph}
                  value={creds[f.key] || ""}
                  onChange={e => updateCred(f.key, e.target.value)}
                  style={{ fontFamily: "monospace", fontSize: "0.78rem", resize: "vertical" }}
                />
              : <input
                  type={f.type}
                  className="form-control custom-input"
                  placeholder={f.ph}
                  value={creds[f.key] || ""}
                  onChange={e => updateCred(f.key, e.target.value)}
                  autoComplete="off"
                />
            }
          </div>
        ))}

        <div className="row g-3 mb-3">
          <div className="col-8">
            <label className="custom-label mb-1">
              <i className="bi bi-person" /> Data Owner
              <span style={{ color: "var(--text-muted)", fontWeight: 400, marginLeft: 4 }}>(optional)</span>
            </label>
            <input
              type="text" className="form-control custom-input"
              placeholder="e.g. Cloud Ops"
              value={owner} onChange={e => setOwner(e.target.value)}
            />
          </div>
          <div className="col-4">
            <label className="custom-label mb-1"><i className="bi bi-hash" /> Max Files</label>
            <input
              type="number" className="form-control custom-input"
              min={1} max={500}
              value={maxFiles} onChange={e => setMaxFiles(e.target.value)}
            />
          </div>
        </div>

        <div style={{ fontSize: "0.74rem", color: "var(--text-muted)", marginBottom: 12, display: "flex", alignItems: "center", gap: 6 }}>
          <i className="bi bi-shield-lock" style={{ color: "#22c55e" }} />
          Credentials are never stored — used only for this scan request.
        </div>

        <button type="submit" className="btn-accent w-100" disabled={scanning}>
          {scanning
            ? <><span className="spinner-border spinner-border-sm me-2" role="status" />Scanning {currentProvider?.label}...</>
            : <><i className="bi bi-cloud-download me-2" />Scan {currentProvider?.label}</>
          }
        </button>
      </form>

      {result && result.success && (
        <div className="scan-summary-box mt-3">
          <div className="scan-summary-row">
            <i className="bi bi-cloud-check" style={{ color: "#22c55e" }} />
            <span>Provider: <strong>{(result.provider || "").toUpperCase()}</strong></span>
          </div>
          <div className="scan-summary-row">
            <i className="bi bi-file-earmark" style={{ color: "var(--accent-primary)" }} />
            <span><strong>{result.files_found}</strong> supported file(s) found in cloud</span>
          </div>
          <div className="scan-summary-row">
            <i className="bi bi-shield-check" style={{ color: "#22c55e" }} />
            <span><strong>{result.files_scanned}</strong> file(s) scanned for PII</span>
          </div>
          <div className="scan-summary-row">
            <i className="bi bi-exclamation-diamond" style={{ color: "#f59e0b" }} />
            <span><strong>{result.total_pii}</strong> PII items detected</span>
          </div>
          {result.errors > 0 && (
            <div className="scan-summary-row">
              <i className="bi bi-bug" style={{ color: "var(--danger)" }} />
              <span>{result.errors} file(s) had errors</span>
            </div>
          )}
        </div>
      )}

      {result && !result.success && (
        <div className="file-error-msg mt-3">
          <i className="bi bi-exclamation-triangle-fill" /> {result.message}
        </div>
      )}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   IMAP EMAIL SCAN TAB
   ═══════════════════════════════════════════════════════ */

const IMAP_HOSTS = {
  "Gmail":          "imap.gmail.com",
  "Outlook / 365":  "outlook.office365.com",
  "Yahoo Mail":     "imap.mail.yahoo.com",
  "iCloud":         "imap.mail.me.com",
  "Zoho Mail":      "imap.zoho.com",
};

function ImapScanTab({ onImapScan, onRealtimeUpdate, scanning }) {
  /* ── Shared credentials / options ─────────────────────────────────────── */
  const [email,         setEmail]         = useState("");
  const [password,      setPassword]      = useState("");
  const [showPwd,       setShowPwd]       = useState(false);
  const [provider,      setProvider]      = useState("Gmail");
  const [customHost,    setCustomHost]    = useState("");
  const [maxEmails,     setMaxEmails]     = useState(20);
  const [folder,        setFolder]        = useState("INBOX");
  const [pollInterval,  setPollInterval]  = useState(10);

  /* ── Realtime state ─────────────────────────────────────────────────────── */
  const [rtActive,  setRtActive]  = useState(false);
  const [rtEvents,  setRtEvents]  = useState([]);
  const [rtStats,   setRtStats]   = useState({ scanned: 0, pii_found: 0, clean: 0, errors: 0 });
  const [rtStatus,  setRtStatus]  = useState("");
  const [loading,   setLoading]   = useState(false);
  const esRef = useRef(null);

  const imapHost = provider === "Custom" ? customHost : (IMAP_HOSTS[provider] || "imap.gmail.com");

  /* ── Check if monitor is already running on mount ─────────────────────── */
  useEffect(() => {
    fetch("/api/realtime/status")
      .then(r => r.json())
      .then(d => {
        if (d.active) {
          setRtActive(true);
          if (d.config?.email) setEmail(d.config.email);
          setRtStats(d.stats || rtStats);
          setRtStatus("Monitor running — reconnecting to live stream…");
          _connectSSE();
        }
      })
      .catch(() => {});
    // Cleanup SSE on unmount
    return () => esRef.current?.close();
  }, []);

  /* ── SSE connection helper ─────────────────────────────────────────────── */
  const _connectSSE = () => {
    if (esRef.current) esRef.current.close();
    const es = new EventSource("/api/realtime/stream");
    es.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data);
        if (ev.type === "new_email") {
          setRtEvents(prev => [ev, ...prev].slice(0, 60));
          setRtStats({
            scanned:   (ev.stats?.scanned   || 0),
            pii_found: (ev.stats?.pii_found || 0),
            clean:     (ev.stats?.clean     || 0),
            errors:    (ev.stats?.errors    || 0),
          });
          onRealtimeUpdate?.();   // refresh dashboard charts/stats
        } else if (ev.type === "connected") {
          setRtStatus(`Watching ${ev.folder} on ${ev.host} · polling every ${ev.interval}s`);
        } else if (ev.type === "stopped") {
          setRtActive(false);
          setRtStatus("Monitor stopped.");
          es.close();
        } else if (ev.type === "error") {
          setRtStatus(`⚠️ ${ev.message}`);
        }
      } catch (_) {}
    };
    es.onerror = () => setRtStatus("Stream connection lost — retrying…");
    esRef.current = es;
  };

  /* ── Batch scan ────────────────────────────────────────────────────────── */
  const handleBatchScan = async () => {
    if (!email.trim() || !password.trim()) return;
    setLoading(true);
    try {
      await onImapScan({
        email:      email.trim(),
        password:   password.trim(),
        imap_host:  imapHost,
        imap_port:  993,
        max_emails: maxEmails,
        folder:     folder.trim() || "INBOX",
      });
    } finally {
      setLoading(false);
    }
  };

  /* ── Start / stop realtime monitor ────────────────────────────────────── */
  const handleStartMonitor = async () => {
    if (!email.trim() || !password.trim()) return;
    const res  = await fetch("/api/realtime/start", {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        email:         email.trim(),
        password:      password.trim(),
        imap_host:     imapHost,
        imap_port:     993,
        folder:        folder.trim() || "INBOX",
        poll_interval: pollInterval,
      }),
    });
    const d = await res.json();
    if (d.success) {
      setRtActive(true);
      setRtEvents([]);
      setRtStats({ scanned: 0, pii_found: 0, clean: 0, errors: 0 });
      setRtStatus("Connecting…");
      _connectSSE();
    } else {
      setRtStatus(`❌ ${d.message}`);
    }
  };

  const handleStopMonitor = async () => {
    esRef.current?.close();
    esRef.current = null;
    await fetch("/api/realtime/stop", { method: "POST" });
    setRtActive(false);
    setRtStatus("Monitor stopped.");
  };

  const isReady = email.trim() && password.trim() && !scanning;

  return (
    <div className="imap-scan-tab">

      {/* Security notice */}
      <div className="imap-notice mb-3">
        <i className="bi bi-shield-check-fill me-2" style={{ color: "#22c55e" }} />
        <span>
          Credentials are used <strong>only for this scan</strong> and never stored.
          Use a <strong>Gmail App Password</strong> — not your account password.
        </span>
      </div>

      {/* Provider selector */}
      <div className="mb-3">
        <label className="form-label-sm">Email Provider</label>
        <div className="imap-provider-row">
          {[...Object.keys(IMAP_HOSTS), "Custom"].map(p => (
            <button key={p} type="button"
              className={`imap-provider-btn ${provider === p ? "active" : ""}`}
              onClick={() => setProvider(p)}>{p}</button>
          ))}
        </div>
      </div>

      {provider === "Custom" && (
        <div className="mb-3">
          <label className="form-label-sm">IMAP Host</label>
          <input type="text" className="form-control form-control-sm dark-input"
            placeholder="mail.yourcompany.com" value={customHost}
            onChange={e => setCustomHost(e.target.value)} />
        </div>
      )}

      {/* Credentials */}
      <div className="row g-2 mb-3">
        <div className="col-12">
          <label className="form-label-sm">Email Address</label>
          <input type="email" className="form-control form-control-sm dark-input"
            placeholder="yourname@gmail.com" value={email}
            onChange={e => setEmail(e.target.value)} autoComplete="off" />
        </div>
        <div className="col-12">
          <label className="form-label-sm">
            App Password
            {provider === "Gmail" && (
              <span className="ms-2" style={{ fontSize: "0.65rem", color: "var(--text-muted)", fontWeight: 400 }}>
                Google Account → Security → App Passwords
              </span>
            )}
          </label>
          <div className="input-group input-group-sm">
            <input type={showPwd ? "text" : "password"} className="form-control dark-input"
              placeholder="App password (16 chars)" value={password}
              onChange={e => setPassword(e.target.value)} autoComplete="new-password" />
            <button type="button" className="btn btn-outline-secondary btn-sm"
              style={{ borderColor: "var(--border-subtle)", color: "var(--text-muted)" }}
              onClick={() => setShowPwd(v => !v)} title={showPwd ? "Hide" : "Show"}>
              <i className={`bi ${showPwd ? "bi-eye-slash" : "bi-eye"}`} />
            </button>
          </div>
        </div>
      </div>

      {/* Options row */}
      <div className="row g-2 mb-3">
        <div className="col-4">
          <label className="form-label-sm">
            Emails &nbsp;<span className="badge" style={{ background:"var(--accent-gradient)", fontSize:"0.6rem" }}>{maxEmails}</span>
          </label>
          <input type="range" className="form-range" min={5} max={100} step={5}
            value={maxEmails} onChange={e => setMaxEmails(+e.target.value)}
            style={{ accentColor: "var(--accent-primary)" }} />
        </div>
        <div className="col-4">
          <label className="form-label-sm">Folder</label>
          <input type="text" className="form-control form-control-sm dark-input"
            value={folder} onChange={e => setFolder(e.target.value)} placeholder="INBOX" />
        </div>
        <div className="col-4">
          <label className="form-label-sm">
            Poll &nbsp;<span className="badge" style={{ background:"rgba(34,197,94,0.15)", color:"#22c55e", fontSize:"0.6rem" }}>{pollInterval}s</span>
          </label>
          <input type="range" className="form-range" min={5} max={60} step={5}
            value={pollInterval} onChange={e => setPollInterval(+e.target.value)}
            style={{ accentColor: "#22c55e" }} />
        </div>
      </div>

      {/* IMAP host display */}
      <div className="imap-host-display mb-3">
        <i className="bi bi-hdd-network me-1" style={{ color: "var(--accent-primary)" }} />
        <span style={{ color: "var(--text-muted)", fontSize: "0.74rem" }}>
          <strong style={{ color: "var(--text-secondary)" }}>{imapHost}</strong>:993 (SSL)
        </span>
      </div>

      {/* ── Action buttons ─────────────────────────────────────────────────── */}
      <div className="imap-actions-row mb-3">
        {/* Batch scan */}
        <button className="btn-accent imap-btn-scan"
          onClick={handleBatchScan} disabled={!isReady || loading}
          style={{ opacity: (isReady && !loading) ? 1 : 0.5 }}>
          {loading || scanning
            ? <><span className="spinner-border spinner-border-sm me-1" /> Scanning…</>
            : <><i className="bi bi-envelope-open-fill me-1" /> Scan {maxEmails} Emails</>
          }
        </button>

        {/* Real-time monitor toggle */}
        {rtActive
          ? (
            <button className="imap-btn-stop" onClick={handleStopMonitor}>
              <i className="bi bi-stop-fill me-1" /> Stop Monitor
            </button>
          ) : (
            <button className="imap-btn-live" onClick={handleStartMonitor}
              disabled={!email.trim() || !password.trim()}>
              <i className="bi bi-broadcast me-1" /> Go Live
            </button>
          )
        }
      </div>

      {/* ── Real-time feed ─────────────────────────────────────────────────── */}
      {(rtActive || rtStatus) && (
        <RealtimeFeed
          active={rtActive}
          events={rtEvents}
          stats={rtStats}
          status={rtStatus}
        />
      )}
    </div>
  );
}

/* ═══════════════════════════════════════════════════════
   REALTIME FEED
   ═══════════════════════════════════════════════════════ */

function RealtimeFeed({ active, events, stats, status }) {
  return (
    <div className="rt-feed">
      <div className="rt-header">
        <div className="d-flex align-items-center gap-2">
          {active
            ? <span className="rt-live-badge"><i className="bi bi-dot" />LIVE</span>
            : <span className="rt-idle-badge"><i className="bi bi-pause-circle me-1" />IDLE</span>
          }
          <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>Real-Time Monitor</span>
        </div>
        <div className="rt-stats-chips">
          <span className="rt-stat-chip" title="Scanned"><i className="bi bi-envelope-check" style={{ color: "var(--accent-primary)" }} />{stats.scanned}</span>
          <span className="rt-stat-chip" title="PII"><i className="bi bi-exclamation-triangle-fill" style={{ color: "#f59e0b" }} />{stats.pii_found}</span>
          <span className="rt-stat-chip" title="Clean"><i className="bi bi-check-circle-fill" style={{ color: "#22c55e" }} />{stats.clean}</span>
          {stats.errors > 0 && <span className="rt-stat-chip"><i className="bi bi-x-circle-fill" style={{ color: "#ef4444" }} />{stats.errors}</span>}
        </div>
      </div>
      {status && (
        <div className="rt-status-line">
          <i className="bi bi-info-circle me-1" style={{ color: "var(--accent-primary)", fontSize: "0.75rem" }} />
          <span>{status}</span>
        </div>
      )}
      <div className="rt-events">
        {events.length === 0
          ? (
            <div className="rt-empty">
              <i className="bi bi-hourglass-split" style={{ fontSize: "1.4rem", opacity: 0.4 }} />
              <div>Waiting for new emails…</div>
              <div style={{ fontSize: "0.7rem", opacity: 0.5 }}>New emails appear here in real-time</div>
            </div>
          )
          : events.map((ev, i) => <RtEventCard key={i} event={ev} fresh={i === 0} />)
        }
      </div>
    </div>
  );
}

function RtEventCard({ event, fresh }) {
  const BG = { CRITICAL:"rgba(239,68,68,0.07)", HIGH:"rgba(245,158,11,0.07)", MEDIUM:"rgba(234,179,8,0.07)", LOW:"rgba(34,197,94,0.06)", NONE:"rgba(255,255,255,0.03)" };
  const BD = { CRITICAL:"rgba(239,68,68,0.25)",  HIGH:"rgba(245,158,11,0.25)", MEDIUM:"rgba(234,179,8,0.2)",  LOW:"rgba(34,197,94,0.2)",  NONE:"var(--border-subtle)" };
  return (
    <div className={`rt-event-card${fresh ? " rt-event-fresh" : ""}`}
      style={{ background: BG[event.risk_level]||BG.NONE, borderColor: BD[event.risk_level]||BD.NONE }}>
      <div className="rt-event-top">
        <span className="rt-event-icon">{event.risk_icon}</span>
        <span className="rt-event-subject" title={event.subject}>
          {event.subject.length > 44 ? event.subject.slice(0, 41)+"…" : event.subject}
        </span>
        {event.risk_level !== "NONE" && (
          <span className={`rt-risk-badge risk-${event.risk_level.toLowerCase()}`}>{event.risk_level}</span>
        )}
      </div>
      <div className="rt-event-meta">
        <span><i className="bi bi-person me-1" style={{ opacity:0.5 }} />{event.from_addr.length > 34 ? event.from_addr.slice(0,31)+"…" : event.from_addr}</span>
        <span style={{ flexShrink:0 }}><i className="bi bi-clock me-1" style={{ opacity:0.5 }} />{event.scan_time?.slice(11,19)}</span>
      </div>
      {event.pii_types?.length > 0 && (
        <div className="rt-pii-chips">
          {event.pii_types.map(t => (
            <span key={t} className="rt-pii-chip"><i className={`bi ${PII_ICONS[t]||"bi-tag"} me-1`}/>{t}</span>
          ))}
          <span className="rt-pii-count">{event.pii_total} match{event.pii_total !== 1 ? "es" : ""}</span>
        </div>
      )}
    </div>
  );
}


function ChartsPanel({ summary, chartsKey }) {
  const donutRef  = useRef(null);
  const riskRef   = useRef(null);
  const scaleRef  = useRef(null);
  const donutInst = useRef(null);
  const riskInst  = useRef(null);
  const scaleInst = useRef(null);

  useEffect(() => {
    if (!summary) return;
    destroyChart(donutInst);
    destroyChart(riskInst);
    destroyChart(scaleInst);

    const pii  = summary.pii_type_counts  || {};
    const risk = summary.risk_counts      || {};

    // PII Donut
    if (donutRef.current && Object.keys(pii).length) {
      const labels = Object.keys(pii);
      const colors = ["#38bdf8","#a855f7","#ec4899","#f97316","#06b6d4","#22c55e"];
      donutInst.current = new Chart(donutRef.current, {
        type: "doughnut",
        data: {
          labels,
          datasets: [{ data: Object.values(pii), backgroundColor: colors.slice(0,labels.length), borderColor: "#0d1025", borderWidth: 3, hoverOffset: 12 }],
        },
        options: {
          responsive: true, maintainAspectRatio: false, cutout: "68%",
          plugins: {
            legend: { position: "bottom", labels: { color: CHART_TEXT, font: { family: CHART_FONT, size: 11 }, padding: 14, usePointStyle: true } },
            title:  { display: true, text: "PII Type Distribution", color: "#e2e8f0", font: { family: CHART_FONT, size: 13, weight: "700" }, padding: { bottom: 12 } },
            tooltip: { ...CHART_TIP },
          },
          animation: { duration: 900, easing: "easeOutQuart" },
        },
      });
    }

    // Risk Bar
    if (riskRef.current && Object.keys(risk).length) {
      const order  = ["LOW","MEDIUM","HIGH","CRITICAL"].filter(l => l in risk);
      const cMap   = { LOW:"#22c55e", MEDIUM:"#f59e0b", HIGH:"#ef4444", CRITICAL:"#dc2626" };
      const colors = order.map(l => cMap[l]);
      riskInst.current = new Chart(riskRef.current, {
        type: "bar",
        data: {
          labels: order,
          datasets: [{ label:"Files", data: order.map(l=>risk[l]), backgroundColor: colors.map(c=>c+"28"), borderColor: colors, borderWidth:2, borderRadius:10, barPercentage:0.55 }],
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          scales: {
            x: { ticks:{ color:CHART_TEXT, font:{family:CHART_FONT,weight:"600",size:11} }, grid:{display:false} },
            y: { beginAtZero:true, ticks:{ color:CHART_TEXT, font:{family:CHART_FONT,size:11}, stepSize:1 }, grid:{ color:CHART_GRID } },
          },
          plugins: {
            legend: { display:false },
            title:  { display:true, text:"File Risk Distribution", color:"#e2e8f0", font:{family:CHART_FONT,size:13,weight:"700"}, padding:{bottom:12} },
            tooltip: { ...CHART_TIP },
          },
          animation: { duration:900, easing:"easeOutQuart" },
        },
      });
    }

    // Data Volume/Scaling Metrics (Horizontal Bar)
    if (scaleRef.current && summary.total_files > 0) {
      const metrics = [
        { label: "Files Scanned",     value: summary.total_files       || 0, color: "#38bdf8" },
        { label: "PII Items Found",   value: summary.total_pii         || 0, color: "#a855f7" },
        { label: "High-Risk Files",   value: summary.high_risk_files   || 0, color: "#ef4444" },
        { label: "PII Categories",    value: Object.keys(pii).length   || 0, color: "#06b6d4" },
      ];
      scaleInst.current = new Chart(scaleRef.current, {
        type: "bar",
        data: {
          labels: metrics.map(m => m.label),
          datasets: [{
            label: "Count",
            data: metrics.map(m => m.value),
            backgroundColor: metrics.map(m => m.color + "28"),
            borderColor: metrics.map(m => m.color),
            borderWidth: 2,
            borderRadius: 10,
            barPercentage: 0.6,
          }],
        },
        options: {
          responsive: true, maintainAspectRatio: false, indexAxis: "y",
          scales: {
            x: { beginAtZero: true, ticks: { color: CHART_TEXT, font: { family: CHART_FONT, size: 11 }, stepSize: 1 }, grid: { color: CHART_GRID } },
            y: { ticks: { color: CHART_TEXT, font: { family: CHART_FONT, weight: "600", size: 11 } }, grid: { display: false } },
          },
          plugins: {
            legend: { display: false },
            title: { display: true, text: "Data Volume & Scaling", color: "#e2e8f0", font: { family: CHART_FONT, size: 13, weight: "700" }, padding: { bottom: 12 } },
            tooltip: { ...CHART_TIP },
          },
          animation: { duration: 900, easing: "easeOutQuart" },
        },
      });
    }

    return () => { destroyChart(donutInst); destroyChart(riskInst); destroyChart(scaleInst); };
  }, [summary, chartsKey]);

  const empty = (icon, txt) => (
    <div style={{ display:"flex",flexDirection:"column",alignItems:"center",justifyContent:"center",height:"100%",minHeight:180,color:"var(--text-muted)",gap:10 }}>
      <i className={`bi ${icon}`} style={{ fontSize:"2rem",opacity:0.2,color:"var(--accent-primary)" }} />
      <span style={{ fontSize:"0.8rem" }}>{txt}</span>
    </div>
  );

  const hasPii   = summary && Object.keys(summary.pii_type_counts||{}).length > 0;
  const hasRisk  = summary && Object.keys(summary.risk_counts||{}).length > 0;
  const hasScale = summary && summary.total_files > 0;

  return (
    <div className="section-card animate-in delay-1 mb-4">
      <div className="section-header">
        <h4><i className="bi bi-bar-chart-line" /> Analytics</h4>
        <span className="section-badge">CHARTS</span>
      </div>

      <div className="chart-container mb-4">
        {hasPii  ? <canvas ref={donutRef} /> : empty("bi-pie-chart","No PII data yet")}
      </div>
      <div className="chart-container mb-4">
        {hasRisk ? <canvas ref={riskRef}  /> : empty("bi-bar-chart","No risk data yet")}
      </div>
      <div className="chart-container">
        {hasScale ? <canvas ref={scaleRef}  /> : empty("bi-gear-wide-connected","No data scanned yet")}
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   ACTIVITY TIMELINE
   ═══════════════════════════════════════════════════════ */

function ActivityTimeline({ activity }) {
  const recent = [...(activity||[])].reverse().slice(0, 8);
  return (
    <div className="section-card animate-in delay-2 mb-4">
      <div className="section-header">
        <h4><i className="bi bi-activity" /> Scan Activity</h4>
        <span className="results-count">{activity.length} events</span>
      </div>

      {recent.length === 0 ? (
        <div style={{ textAlign:"center",padding:"24px 0",color:"var(--text-muted)",fontSize:"0.85rem" }}>
          <i className="bi bi-clock-history" style={{ fontSize:"1.8rem",opacity:0.25,display:"block",marginBottom:8 }} />
          No scans yet
        </div>
      ) : (
        <div className="activity-timeline">
          {recent.map((a, i) => (
            <div key={i} className="activity-item">
              <div className={`activity-dot ${RISK_DOT[a.risk_level] || "success"}`} />
              <div>
                <div className="activity-text">{a.action}</div>
                <div className="activity-time">{a.time}</div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   TRACKER SUMMARY PANEL
   ═══════════════════════════════════════════════════════ */

function TrackerSummaryPanel({ summary, events, alerts, loading, onRefresh }) {
  const s = summary || { tracked_files: 0, events: 0, alerts: 0, by_system: [] };
  const recentEvents = (events || []).slice(0, 6);
  const recentAlerts = (alerts || []).slice(0, 4);

  const sevClass = (level) => {
    const l = String(level || "").toUpperCase();
    if (l === "CRITICAL") return "badge text-bg-danger";
    if (l === "HIGH") return "badge text-bg-warning";
    return "badge text-bg-info";
  };

  return (
    <div className="section-card animate-in delay-2 mb-4">
      <div className="section-header d-flex justify-content-between align-items-center">
        <h4><i className="bi bi-diagram-3-fill" /> Tracker Summary</h4>
        <div className="d-flex align-items-center gap-2">
          <span className="section-badge">LINEAGE</span>
          <button
            className="btn btn-sm btn-outline-info"
            onClick={onRefresh}
            disabled={loading}
            title="Refresh tracker metrics"
          >
            <i className={`bi ${loading ? "bi-arrow-repeat spin-icon" : "bi-arrow-clockwise"}`} />
          </button>
        </div>
      </div>

      <div className="row g-2 mb-3">
        <div className="col-4">
          <div className="metric-card" style={{ minHeight: 92 }}>
            <div className="metric-label">Tracked Files</div>
            <div className="metric-value">{s.tracked_files || 0}</div>
          </div>
        </div>
        <div className="col-4">
          <div className="metric-card" style={{ minHeight: 92 }}>
            <div className="metric-label">Event Log</div>
            <div className="metric-value">{s.events || 0}</div>
          </div>
        </div>
        <div className="col-4">
          <div className="metric-card" style={{ minHeight: 92 }}>
            <div className="metric-label">Breach Alerts</div>
            <div className="metric-value" style={{ color: (s.alerts || 0) > 0 ? "#fca5a5" : undefined }}>
              {s.alerts || 0}
            </div>
          </div>
        </div>
      </div>

      <div className="mb-3">
        <div className="section-subtitle mb-2"><i className="bi bi-hdd-network" /> Events By System</div>
        {(s.by_system || []).length === 0 ? (
          <div className="text-muted" style={{ fontSize: ".82rem" }}>No tracker events yet.</div>
        ) : (
          <div className="d-flex flex-wrap gap-2">
            {s.by_system.slice(0, 8).map((it, idx) => (
              <span key={idx} className="badge rounded-pill text-bg-dark" style={{ border: "1px solid rgba(56,189,248,.3)" }}>
                {it.system}: {it.events}
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="mb-3">
        <div className="section-subtitle mb-2"><i className="bi bi-exclamation-octagon-fill" /> Recent Alerts</div>
        {recentAlerts.length === 0 ? (
          <div className="text-muted" style={{ fontSize: ".82rem" }}>No breach alerts.</div>
        ) : (
          <div className="d-flex flex-column gap-2">
            {recentAlerts.map((a, i) => (
              <div key={i} style={{ border: "1px solid rgba(255,255,255,.08)", borderRadius: 10, padding: "8px 10px" }}>
                <div className="d-flex align-items-center justify-content-between gap-2 mb-1">
                  <strong style={{ fontSize: ".84rem" }}>{a.alert_type || "ALERT"}</strong>
                  <span className={sevClass(a.severity)}>{a.severity || "INFO"}</span>
                </div>
                <div style={{ fontSize: ".8rem", color: "var(--text-secondary)" }}>{a.message || ""}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      <div>
        <div className="section-subtitle mb-2"><i className="bi bi-clock-history" /> Recent Tracker Events</div>
        {recentEvents.length === 0 ? (
          <div className="text-muted" style={{ fontSize: ".82rem" }}>No movement events recorded yet.</div>
        ) : (
          <div className="table-responsive" style={{ maxHeight: 220 }}>
            <table className="table table-dark table-sm align-middle mb-0">
              <thead>
                <tr>
                  <th style={{ fontSize: ".74rem" }}>Time</th>
                  <th style={{ fontSize: ".74rem" }}>Event</th>
                  <th style={{ fontSize: ".74rem" }}>File</th>
                </tr>
              </thead>
              <tbody>
                {recentEvents.map((e, i) => (
                  <tr key={i}>
                    <td style={{ fontSize: ".73rem", whiteSpace: "nowrap" }}>{e.timestamp || ""}</td>
                    <td style={{ fontSize: ".73rem" }}>{e.event_type || ""}</td>
                    <td style={{ fontSize: ".73rem" }} title={e.filename || ""}>{e.filename || ""}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="mt-3 d-flex gap-2 flex-wrap">
        <a className="btn btn-sm btn-outline-accent" href="/tracker-summary">
          <i className="bi bi-box-arrow-up-right" /> Open Full Tracker View
        </a>
        <a className="btn btn-sm btn-outline-accent" href="/api/file-tracker-summary" target="_blank" rel="noreferrer">
          <i className="bi bi-filetype-json" /> Tracker JSON
        </a>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   DPDPA CARD
   ═══════════════════════════════════════════════════════ */

const DPDPA_SECTIONS = [
  { sec: "§ 4",   desc: "Grounds for processing personal data" },
  { sec: "§ 5",   desc: "Notice requirement before data collection" },
  { sec: "§ 6",   desc: "Consent — freely given, specific & informed" },
  { sec: "§ 8",   desc: "Obligations of data fiduciary & security" },
  { sec: "§ 9",   desc: "Processing children's data — age verification" },
];

function DpdpaCard() {
  return (
    <div className="dpdpa-card animate-in delay-3">
      <div className="dpdpa-header">
        <i className="bi bi-book-half" />
        <h5>DPDPA 2023 — Compliance Reference</h5>
      </div>
      <div className="dpdpa-sections">
        {DPDPA_SECTIONS.map((s, i) => (
          <div key={i} className="dpdpa-item">
            <span className="dpdpa-section">{s.sec}</span>
            <span>{s.desc}</span>
          </div>
        ))}
      </div>
      <div className="dpdpa-footer">
        <i className="bi bi-info-circle-fill" />
        All detected personal data is mapped to the relevant DPDPA section
        with actionable remediation guidance in the compliance report.
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   RESULTS SECTION
   ═══════════════════════════════════════════════════════ */

function ResultsSection({ files, filterRisk, setFilterRisk, onViewDetails, onDownload }) {
  const [viewMode, setViewMode] = useState("cards"); // "cards" or "timeline"

  const filtered = filterRisk === "all"
    ? files
    : files.filter(f => f.risk_level === filterRisk);

  const risks = ["all", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const riskCounts = risks.reduce((acc, r) => {
    acc[r] = r === "all" ? files.length : files.filter(f => f.risk_level === r).length;
    return acc;
  }, {});
  const riskColors = { LOW: "#22c55e", MEDIUM: "#f59e0b", HIGH: "#ef4444", CRITICAL: "#dc2626" };

  return (
    <div>
      {/* Section header */}
      <div className="section-card mb-3">
        <div className="section-header mb-3">
          <h4><i className="bi bi-folder2-open" /> Scan Results</h4>
          <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
            {/* View mode toggle */}
            <div className="view-toggle-group">
              <button
                className={`view-toggle-btn ${viewMode === "cards" ? "active" : ""}`}
                onClick={() => setViewMode("cards")}
                title="Card View"
              >
                <i className="bi bi-grid-3x2-gap" />
              </button>
              <button
                className={`view-toggle-btn ${viewMode === "timeline" ? "active" : ""}`}
                onClick={() => setViewMode("timeline")}
                title="Timeline View"
              >
                <i className="bi bi-clock-history" />
              </button>
            </div>
            <span className="results-count">{files.length} source(s) scanned</span>
          </div>
        </div>

        {/* Risk filter pills */}
        <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginBottom:4 }}>
          {risks.map(r => {
            const cnt = riskCounts[r];
            if (r !== "all" && cnt === 0) return null;
            const isActive = filterRisk === r;
            const color = riskColors[r] || "var(--accent-primary)";
            return (
              <button
                key={r}
                onClick={() => setFilterRisk(r)}
                style={{
                  display: "inline-flex", alignItems: "center", gap: 6,
                  padding: "5px 14px",
                  borderRadius: 20,
                  border: isActive
                    ? `1px solid ${r === "all" ? "var(--accent-primary)" : color}`
                    : "1px solid var(--border-subtle)",
                  background: isActive
                    ? r === "all" ? "rgba(56,189,248,0.15)" : `${color}18`
                    : "transparent",
                  color: isActive
                    ? r === "all" ? "var(--accent-primary)" : color
                    : "var(--text-muted)",
                  cursor: "pointer",
                  fontSize: "0.73rem",
                  fontWeight: 600,
                  textTransform: "uppercase",
                  letterSpacing: "0.5px",
                  transition: "all 0.2s",
                }}
              >
                {r === "all" ? "All" : r}
                <span style={{
                  background: isActive ? (r === "all" ? "rgba(56,189,248,0.25)" : `${color}30`) : "rgba(255,255,255,0.06)",
                  borderRadius: 10, padding: "0 6px", fontSize: "0.68rem", fontWeight: 700,
                }}>
                  {cnt}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* File results - Cards or Timeline view */}
      {filtered.length === 0 ? (
        <div className="section-card" style={{ textAlign:"center",padding:"32px 20px",color:"var(--text-muted)" }}>
          <i className="bi bi-funnel" style={{ fontSize:"2rem",opacity:0.3,display:"block",marginBottom:8 }} />
          No files match the selected filter.
        </div>
      ) : viewMode === "timeline" ? (
        <div className="section-card mb-3">
          <ScanTimeline files={filtered} onViewDetails={onViewDetails} />
        </div>
      ) : (
        <div className="section-card mb-3">
          {filtered.map((fd, i) => (
            <FileResultCard key={i} fd={fd} onViewDetails={onViewDetails} />
          ))}
        </div>
      )}

      {/* Compliance report table */}
      <ComplianceTable files={files} onDownload={onDownload} />

      {/* DPDPA Retention Warning - shows expired records from MySQL */}
      <RetentionWarningPanel />
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   PII VALUE MASKING — never show raw sensitive data on UI
   ═══════════════════════════════════════════════════════ */

function maskPiiValue(value, category) {
  if (!value) return "—";
  const v = String(value);
  const cat = (category || "").toLowerCase();

  if (cat.includes("email")) {
    const at = v.indexOf("@");
    if (at > 1) return v[0] + "***@" + v.slice(at + 1);
    return "***@***.com";
  }
  if (cat.includes("phone")) return "XXXXX" + v.slice(-4);
  if (cat.includes("aadhaar")) return "XXXX XXXX " + v.replace(/[^0-9]/g, "").slice(-4);
  if (cat.includes("pan")) return v.slice(0, 2) + "XXXXX" + v.slice(-2);
  if (cat.includes("card") || cat.includes("bank")) return "XXXXXXXX" + v.replace(/[^0-9]/g, "").slice(-4);
  if (cat.includes("passport")) return v[0] + "XXXXXX" + v.slice(-1);
  if (cat.includes("name")) return v; // Names are OK to show
  if (cat.includes("ifsc")) return v.slice(0, 4) + "XXXXXXX";
  if (cat.includes("health") || cat.includes("biometric")) return "[REDACTED]";
  // Default: show first 2 chars + mask
  if (v.length > 4) return v.slice(0, 2) + "***" + v.slice(-2);
  return "***";
}


/* ═══════════════════════════════════════════════════════
   DPDPA RETENTION WARNING PANEL (Yellow alerts for >3yr records)
   ═══════════════════════════════════════════════════════ */

function RetentionWarningPanel() {
  const [expired, setExpired] = useState([]);
  const [allRecords, setAllRecords] = useState([]);
  const [show, setShow] = useState(true);

  useEffect(() => {
    fetch("/api/db-records?expired=1&years=3")
      .then(r => r.json())
      .then(d => { if (d.success) setExpired(d.records || []); })
      .catch(() => {});
    fetch("/api/db-records")
      .then(r => r.json())
      .then(d => { if (d.success) setAllRecords(d.records || []); })
      .catch(() => {});
  }, []);

  if (expired.length === 0) return null;

  const typeColors = { PII: "#38bdf8", SPII: "#ef4444" };

  return (
    <div className="section-card" style={{
      marginTop: 16,
      border: "1px solid rgba(251,191,36,0.3)",
      background: "linear-gradient(135deg, rgba(251,191,36,0.06) 0%, rgba(251,191,36,0.02) 100%)",
    }}>
      {/* Header */}
      <div style={{
        display: "flex", justifyContent: "space-between", alignItems: "center",
        marginBottom: 14, paddingBottom: 12,
        borderBottom: "1px solid rgba(251,191,36,0.15)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: "rgba(251,191,36,0.15)", display: "flex",
            alignItems: "center", justifyContent: "center",
          }}>
            <i className="bi bi-exclamation-triangle-fill" style={{ color: "#fbbf24", fontSize: "1.1rem" }} />
          </div>
          <div>
            <h5 style={{ margin: 0, fontSize: "0.95rem", fontWeight: 800, color: "#fbbf24" }}>
              DPDPA Retention Warning
            </h5>
            <small style={{ color: "#fcd34d", fontSize: "0.7rem" }}>
              Section 8 — Storage Limitation &middot; Records older than 3 years detected
            </small>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <span style={{
            background: "rgba(251,191,36,0.2)", color: "#fbbf24",
            border: "1px solid rgba(251,191,36,0.4)",
            padding: "4px 12px", borderRadius: 8,
            fontSize: "0.75rem", fontWeight: 800,
          }}>
            {expired.length} expired of {allRecords.length} total
          </span>
          <button onClick={() => setShow(s => !s)} style={{
            padding: "4px 10px", borderRadius: 6, fontSize: "0.7rem",
            border: "1px solid rgba(251,191,36,0.3)", background: "rgba(251,191,36,0.1)",
            color: "#fbbf24", cursor: "pointer",
          }}>
            <i className={`bi bi-chevron-${show ? "up" : "down"}`} />
          </button>
        </div>
      </div>

      {/* Warning message */}
      <div style={{
        padding: "10px 14px", borderRadius: 8, marginBottom: show ? 14 : 0,
        background: "rgba(251,191,36,0.08)", border: "1px solid rgba(251,191,36,0.2)",
        fontSize: "0.76rem", color: "#fcd34d", lineHeight: 1.5,
      }}>
        <i className="bi bi-info-circle-fill" style={{ marginRight: 6 }} />
        Under <strong>DPDPA 2023 Section 8</strong>, personal data shall not be retained beyond the period necessary for the purpose for which it was collected.
        The following <strong>{expired.length} records</strong> were uploaded more than <strong>3 years ago</strong> and should be reviewed for deletion.
      </div>

      {/* Expired records table */}
      {show && (
        <div style={{ overflowX: "auto", borderRadius: 10, border: "1px solid rgba(251,191,36,0.15)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.74rem" }}>
            <thead>
              <tr style={{ background: "rgba(251,191,36,0.1)" }}>
                {["#", "User ID", "Type", "Category", "Value", "Uploaded", "Age"].map(h => (
                  <th key={h} style={{
                    padding: "10px 14px", textAlign: "left", fontWeight: 700, fontSize: "0.68rem",
                    color: "#fbbf24", textTransform: "uppercase", letterSpacing: "0.5px",
                    borderBottom: "1px solid rgba(251,191,36,0.15)",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {expired.slice(0, 30).map((rec, idx) => {
                const uploaded = new Date(rec.uploaded_at);
                const now = new Date();
                const ageYears = ((now - uploaded) / (365.25 * 24 * 60 * 60 * 1000)).toFixed(1);
                return (
                  <tr key={rec.record_id || idx} style={{
                    borderBottom: "1px solid rgba(251,191,36,0.08)",
                    background: idx % 2 === 0 ? "rgba(251,191,36,0.04)" : "rgba(251,191,36,0.02)",
                    borderLeft: "3px solid #fbbf24",
                  }}>
                    <td style={{ padding: "8px 14px", color: "#fcd34d", fontFamily: "monospace", fontSize: "0.7rem" }}>
                      {rec.record_id}
                    </td>
                    <td style={{ padding: "8px 14px", fontWeight: 600, color: "var(--text-primary)" }}>
                      {rec.user_id}
                    </td>
                    <td style={{ padding: "8px 14px" }}>
                      <span style={{
                        padding: "2px 8px", borderRadius: 6, fontSize: "0.64rem", fontWeight: 700,
                        background: `${typeColors[rec.data_type] || "#999"}15`,
                        color: typeColors[rec.data_type] || "#999",
                        border: `1px solid ${typeColors[rec.data_type] || "#999"}30`,
                      }}>
                        {rec.data_type}
                      </span>
                    </td>
                    <td style={{ padding: "8px 14px", color: "#a78bfa", fontWeight: 600 }}>
                      {rec.data_category}
                    </td>
                    <td style={{ padding: "8px 14px", color: "var(--text-secondary)", fontFamily: "monospace", fontSize: "0.7rem" }}>
                      {maskPiiValue(rec.data_value, rec.data_category)}
                    </td>
                    <td style={{ padding: "8px 14px", color: "#fbbf24", fontWeight: 700, fontSize: "0.7rem" }}>
                      {rec.uploaded_at}
                    </td>
                    <td style={{ padding: "8px 14px" }}>
                      <span style={{
                        padding: "3px 8px", borderRadius: 6, fontSize: "0.64rem", fontWeight: 700,
                        background: "rgba(239,68,68,0.15)", color: "#ef4444",
                        border: "1px solid rgba(239,68,68,0.3)",
                      }}>
                        {ageYears} yrs
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {show && expired.length > 30 && (
        <div style={{ textAlign: "center", padding: "8px 0", fontSize: "0.7rem", color: "#fcd34d" }}>
          Showing 30 of {expired.length} expired records. View all in Enterprise Governance → DB Records tab.
        </div>
      )}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   FILE RESULT CARD
   ═══════════════════════════════════════════════════════ */

function FileResultCard({ fd, onViewDetails }) {
  const [expanded, setExpanded] = useState(false);

  const riskLower = (fd.risk_level || "low").toLowerCase();
  const filteredCounts = Object.entries(fd.pii_counts || {}).filter(([, v]) => v > 0);

  return (
    <div className="file-result-card" data-risk={riskLower} style={{ marginBottom: 10 }}>
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:12 }}>
        <div style={{ flex:1, minWidth:0 }}>
          <div className="file-name">
            <i className="bi bi-file-earmark-text" />
            {fd.filename}
            <span className="file-size-chip">{fd.file_size}</span>
          </div>
          <div className="file-meta mt-1">
            <i className="bi bi-tag" /> {fd.data_source}
            <span className="meta-dot">·</span>
            <i className="bi bi-hdd-network" /> {fd.storage_location || "Local"}
            <span className="meta-dot">·</span>
            <i className="bi bi-person" /> {fd.data_owner}
            <span className="meta-dot">·</span>
            <i className="bi bi-clock" /> {fd.scan_time}
          </div>
        </div>
        <div className="d-flex align-items-center gap-2 flex-shrink-0">
          <span className={`risk-badge ${RISK_CLASS[fd.risk_level] || "risk-low"}`}>
            {fd.risk_level}
          </span>
          <button
            className="btn-outline-accent"
            style={{ padding:"4px 10px", fontSize:"0.75rem" }}
            onClick={() => onViewDetails(fd)}
            title="View full PII breakdown"
          >
            <i className="bi bi-eye" />
          </button>
        </div>
      </div>

      {/* PII chips */}
      {filteredCounts.length > 0 && (
        <div style={{ display:"flex", flexWrap:"wrap", gap:6, margin:"10px 0 6px" }}>
          {filteredCounts.map(([type, count]) => (
            <span key={type} className="pii-chip">
              <i className={`bi ${PII_ICONS[type] || "bi-dot"}`} />
              {type}
              <span className="chip-count">{count}</span>
            </span>
          ))}
          {fd.pii_total === 0 && (
            <span className="pii-chip chip-safe"><i className="bi bi-check-circle" /> No PII found</span>
          )}
        </div>
      )}

      {/* Risk reason */}
      <div className="risk-reason mt-1">
        <i className="bi bi-info-circle" /> {fd.risk_reason}
      </div>

      {/* Collapsible detail table */}
      {filteredCounts.length > 0 && (
        <div style={{ marginTop:10 }}>
          <button
            className="btn-outline-accent"
            style={{ padding:"4px 12px", fontSize:"0.74rem" }}
            onClick={() => setExpanded(e => !e)}
          >
            <i className={`bi bi-chevron-${expanded ? "up" : "down"}`} />
            {expanded ? " Hide" : " Show"} PII details
          </button>

          {expanded && (
            <div className="table-responsive mt-2">
              <table className="table table-sm table-dark-custom">
                <thead>
                  <tr>
                    <th>PII Type</th>
                    <th>Sensitivity</th>
                    <th>Count</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredCounts.map(([type, count]) => (
                    <tr key={type}>
                      <td><i className={`bi ${PII_ICONS[type] || "bi-dot"} pii-type-icon`} />{type}</td>
                      <td>
                        <span className={`risk-badge ${RISK_CLASS[(fd.classifications||{})[type]] || "risk-low"}`} style={{ fontSize:"0.65rem" }}>
                          {(fd.classifications||{})[type] || "LOW"}
                        </span>
                      </td>
                      <td>
                        <span style={{
                          padding: "2px 10px", borderRadius: 6, fontSize: "0.72rem", fontWeight: 700,
                          background: "rgba(56,189,248,0.1)", color: "#7dd3fc",
                        }}>
                          {count} found
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   SCAN TIMELINE
   ═══════════════════════════════════════════════════════ */

function ScanTimeline({ files, onViewDetails }) {
  // Sort files by scan_time (newest first)
  const sortedFiles = [...files].sort((a, b) => {
    const timeA = new Date(a.scan_time || 0);
    const timeB = new Date(b.scan_time || 0);
    return timeB - timeA;
  });

  // Group files by date
  const groupedByDate = sortedFiles.reduce((acc, file) => {
    const date = file.scan_time ? file.scan_time.split(" ")[0] : "Unknown";
    if (!acc[date]) acc[date] = [];
    acc[date].push(file);
    return acc;
  }, {});

  const riskColors = {
    LOW: "#22c55e",
    MEDIUM: "#f59e0b",
    HIGH: "#ef4444",
    CRITICAL: "#dc2626",
    NONE: "#64748b"
  };

  return (
    <div className="scan-timeline-container">
      {Object.entries(groupedByDate).map(([date, dateFiles]) => (
        <div key={date} className="timeline-date-group">
          <div className="timeline-date-header">
            <i className="bi bi-calendar3" />
            <span>{date}</span>
            <span className="timeline-date-count">{dateFiles.length} file(s)</span>
          </div>
          <div className="timeline-items">
            {dateFiles.map((fd, i) => {
              const riskColor = riskColors[fd.risk_level] || riskColors.NONE;
              const time = fd.scan_time ? fd.scan_time.split(" ")[1] : "--:--:--";
              return (
                <div key={i} className="timeline-item" style={{ "--risk-color": riskColor }}>
                  <div className="timeline-connector">
                    <div className="timeline-dot" style={{ background: riskColor }} />
                    {i < dateFiles.length - 1 && <div className="timeline-line" />}
                  </div>
                  <div className="timeline-content">
                    <div className="timeline-time">
                      <i className="bi bi-clock" /> {time}
                    </div>
                    <div className="timeline-card" onClick={() => onViewDetails(fd)}>
                      <div className="timeline-card-header">
                        <div className="timeline-filename">
                          <i className="bi bi-file-earmark-text" />
                          {fd.filename}
                        </div>
                        <span
                          className="timeline-risk-badge"
                          style={{ background: `${riskColor}20`, color: riskColor, borderColor: riskColor }}
                        >
                          {fd.risk_level || "NONE"}
                        </span>
                      </div>
                      <div className="timeline-card-meta">
                        <span><i className="bi bi-tag" /> {fd.data_source}</span>
                        <span><i className="bi bi-hdd" /> {fd.storage_location || "Local"}</span>
                        <span><i className="bi bi-shield-exclamation" /> {fd.pii_total || 0} PII</span>
                      </div>
                      {fd.pii_counts && Object.keys(fd.pii_counts).filter(k => fd.pii_counts[k] > 0).length > 0 && (
                        <div className="timeline-pii-chips">
                          {Object.entries(fd.pii_counts).filter(([, v]) => v > 0).slice(0, 4).map(([type, count]) => (
                            <span key={type} className="timeline-pii-chip">
                              <i className={`bi ${PII_ICONS[type] || "bi-dot"}`} />
                              {type}: {count}
                            </span>
                          ))}
                          {Object.keys(fd.pii_counts).filter(k => fd.pii_counts[k] > 0).length > 4 && (
                            <span className="timeline-pii-chip more">
                              +{Object.keys(fd.pii_counts).filter(k => fd.pii_counts[k] > 0).length - 4} more
                            </span>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   COMPLIANCE TABLE
   ═══════════════════════════════════════════════════════ */

function ComplianceTable({ files, onDownload }) {
  const [copied, setCopied] = useState(null);
  const [search, setSearch] = useState("");

  // Flatten all rows from all files
  const allRows = files.flatMap(fd =>
    Object.entries(fd.pii_counts || {})
      .filter(([, v]) => v > 0)
      .map(([type]) => ({
        file_name   : fd.filename,
        pii_type    : type,
        sensitivity : (fd.classifications||{})[type] || "LOW",
        risk_level  : fd.risk_level,
        risk_reason : fd.risk_reason,
        data_owner  : fd.data_owner,
        scan_time   : fd.scan_time,
      }))
  );

  const filtered = search
    ? allRows.filter(r =>
        r.file_name.toLowerCase().includes(search.toLowerCase()) ||
        r.pii_type.toLowerCase().includes(search.toLowerCase())
      )
    : allRows;

  const copyVal = (val) => {
    navigator.clipboard.writeText(val).catch(() => {});
    setCopied(val);
    setTimeout(() => setCopied(null), 1800);
  };

  if (allRows.length === 0) return null;

  return (
    <div className="section-card" id="report-section">
      <div className="section-header mb-3">
        <h4><i className="bi bi-table" /> Compliance Report</h4>
        <button className="btn-accent" style={{ padding: "7px 18px", fontSize: "0.82rem" }} onClick={onDownload}>
          <i className="bi bi-download me-2" /> Export CSV
        </button>
      </div>

      {/* Search bar */}
      <div style={{ position:"relative", marginBottom:12 }}>
        <i className="bi bi-search" style={{ position:"absolute", left:12, top:"50%", transform:"translateY(-50%)", color:"var(--text-muted)", fontSize:"0.85rem" }} />
        <input
          type="text"
          className="form-control custom-input"
          placeholder="Search by filename or PII type..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ paddingLeft:34 }}
        />
      </div>

      <div className="table-responsive" style={{ maxHeight:400, overflowY:"auto" }}>
        <table className="table table-dark-custom" id="compliance-table">
          <thead>
            <tr>
              <th>File</th>
              <th>PII Type</th>
              <th>Risk</th>
              <th>Owner</th>
              <th>Scanned</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((r, i) => (
              <tr key={i}>
                <td style={{ maxWidth:160, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                  <i className="bi bi-file-earmark me-1" style={{ opacity:0.5 }} />
                  <span title={r.file_name}>{r.file_name}</span>
                </td>
                <td>
                  <i className={`bi ${PII_ICONS[r.pii_type] || "bi-dot"} me-1`} style={{ opacity:0.7 }} />
                  {r.pii_type}
                </td>
                <td>
                  <span className={`risk-badge ${RISK_CLASS[r.risk_level]||"risk-low"}`} style={{ fontSize:"0.65rem" }}>
                    {r.risk_level}
                  </span>
                </td>
                <td>
                  <button className="copy-btn" style={{ opacity:1 }} onClick={() => copyVal(r.data_owner)} title="Copy">
                    <i className={`bi ${copied === r.data_owner ? "bi-check-lg" : "bi-person"}`} style={{ marginRight:4 }} />
                  </button>
                  {r.data_owner}
                </td>
                <td className="text-muted-xs">{r.scan_time}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {filtered.length === 0 && search && (
        <div style={{ textAlign:"center",padding:"16px 0",color:"var(--text-muted)",fontSize:"0.85rem" }}>
          No rows match "<strong>{search}</strong>"
        </div>
      )}

      <div style={{ marginTop:8, fontSize:"0.74rem", color:"var(--text-muted)" }}>
        Showing {filtered.length} of {allRows.length} entries
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   EMPTY STATE
   ═══════════════════════════════════════════════════════ */

const HOW_STEPS = [
  { n:"1", title:"Choose a source",   desc:"Upload files, scan a folder, connect a database, or auto-discover" },
  { n:"2", title:"Auto scan",         desc:"Detects 13 PII types: Email, Phone, PAN, Aadhaar, Health, Name…"   },
  { n:"3", title:"View results",      desc:"Risk score, sensitivity classification & DPDPA remediation guidance" },
  { n:"4", title:"Export report",     desc:"Download a DPDPA-aligned CSV compliance report"                     },
];

const CLASSIFICATION_ROWS = [
  { type:"Email Address",    icon:"bi-envelope-fill",            sens:"MEDIUM", ref:"§4,5 — consent for contact data"              },
  { type:"Phone Number",     icon:"bi-phone-fill",               sens:"MEDIUM", ref:"§4,5 — consent for contact data"              },
  { type:"Date of Birth",    icon:"bi-calendar-event-fill",      sens:"MEDIUM", ref:"§9 — age-related data restrictions"           },
  { type:"Full Name",        icon:"bi-person-badge-fill",        sens:"LOW",    ref:"§4,5 — lawful basis for personal data"        },
  { type:"IFSC Code",        icon:"bi-bank2",                    sens:"MEDIUM", ref:"§8 — financial routing data safeguards"       },
  { type:"Bank Account",     icon:"bi-piggy-bank-fill",          sens:"HIGH",   ref:"§8 — financial account data; RBI guidelines" },
  { type:"PAN Number",       icon:"bi-credit-card-2-front-fill", sens:"HIGH",   ref:"§8 — financial ID, strict safeguards"         },
  { type:"Aadhaar Number",   icon:"bi-fingerprint",              sens:"HIGH",   ref:"§8 — government ID safeguards"                },
  { type:"Card Number",      icon:"bi-credit-card-fill",         sens:"HIGH",   ref:"§8 — PCI-DSS financial data compliance"       },
  { type:"Passport Number",  icon:"bi-passport-fill",            sens:"HIGH",   ref:"§8 — govt ID; strict access & encrypt"        },
  { type:"Health Data",      icon:"bi-heart-pulse-fill",         sens:"HIGH",   ref:"§8 — sensitive personal data; explicit consent"},
  { type:"Vehicle Reg",      icon:"bi-car-front-fill",           sens:"LOW",    ref:"§4 — personal identifier; lawful basis"       },
  { type:"IP Address",       icon:"bi-router-fill",              sens:"LOW",    ref:"§4 — network identifier; re-ID risk"          },
];

const FEATURE_CARDS = [
  { icon:"bi-file-earmark-text-fill",     title:"19 File Formats",         desc:"TXT, CSV, XLS, XLSX, ODS, PDF, DOCX, PPTX, RTF, ODT, JSON, XML, HTML, EML, MSG, ZIP/TAR, LOG, MD + more" },
  { icon:"bi-fingerprint",                title:"13 PII Patterns",         desc:"Names, Aadhaar, PAN, phone, financial, health & network identifiers"  },
  { icon:"bi-cloud-fill",                 title:"Cloud Storage Scan",      desc:"AWS S3, Google Drive, Azure Blob, Dropbox — on-premises & cloud"      },
  { icon:"bi-pin-map-fill",               title:"Ownership & Location Map", desc:"Maps data owner, storage location, and source type per data item"     },
  { icon:"bi-shield-lock-fill",           title:"Risk Classification",     desc:"Structured, semi-structured & unstructured data sensitivity scoring"   },
  { icon:"bi-file-earmark-bar-graph-fill",title:"DPDPA Reports",           desc:"Compliance-ready exports with DPDPA section references"                },
];

function EmptyState() {
  return (
    <div className="section-card animate-in">
      {/* Icon + title */}
      <div className="empty-state">
        <div className="empty-icon-wrap">
          <div className="empty-ring" />
          <i className="bi bi-shield-lock" />
        </div>
        <h5>No Data Sources Scanned Yet</h5>
        <p>Upload files to begin enterprise-wide personal data discovery &amp; classification.</p>
      </div>

      {/* How it works */}
      <div className="how-it-works mt-2 mb-4">
        <div className="hiw-title"><i className="bi bi-lightning-charge-fill" /> How it works</div>
        <div className="hiw-steps">
          {HOW_STEPS.map((s, i) => (
            <React.Fragment key={i}>
              <div className="hiw-step">
                <div className="hiw-num">{s.n}</div>
                <div className="hiw-body">
                  <div className="hiw-step-title">{s.title}</div>
                  <div className="hiw-step-desc">{s.desc}</div>
                </div>
              </div>
              {i < HOW_STEPS.length - 1 && <div className="hiw-connector" />}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Classification reference */}
      <h6 className="section-subtitle"><i className="bi bi-book" /> Data Sensitivity Classification</h6>
      <div className="table-responsive mb-4">
        <table className="table table-sm table-dark-custom">
          <thead>
            <tr><th>Identifier</th><th>Sensitivity</th><th>DPDPA Relevance</th></tr>
          </thead>
          <tbody>
            {CLASSIFICATION_ROWS.map((r, i) => (
              <tr key={i}>
                <td><i className={`bi ${r.icon} me-2`} style={{ color: r.sens === "HIGH" ? "var(--danger)" : "var(--info)" }} />{r.type}</td>
                <td><span className={`risk-badge ${RISK_CLASS[r.sens]}`}>{r.sens}</span></td>
                <td className="text-muted-sm">{r.ref}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Feature grid */}
      <div className="features-grid">
        {FEATURE_CARDS.map((f, i) => (
          <div key={i} className="feature-card">
            <i className={`bi ${f.icon}`} />
            <h6>{f.title}</h6>
            <p>{f.desc}</p>
          </div>
        ))}
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   FILE DETAIL MODAL
   ═══════════════════════════════════════════════════════ */

function FileDetailModal({ file: fd, onClose }) {
  // Close on Escape key
  useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", h);
    document.body.style.overflow = "hidden";
    return () => { document.removeEventListener("keydown", h); document.body.style.overflow = ""; };
  }, []);

  const allPii = Object.entries(fd.pii_results || {}).filter(([, v]) => v.length > 0);

  return (
    <div
      style={{
        position:"fixed", inset:0, zIndex:8000,
        background:"rgba(6,8,26,0.85)", backdropFilter:"blur(8px)",
        display:"flex", alignItems:"center", justifyContent:"center",
        padding:16, animation:"fadeInUp 0.25s ease",
      }}
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      <div style={{
        background:"var(--bg-card-solid)", border:"1px solid var(--border-accent)",
        borderRadius: "var(--radius-xl)", padding:28, width:"100%", maxWidth:640,
        maxHeight:"85vh", overflowY:"auto",
        boxShadow:"0 24px 80px rgba(0,0,0,0.5)",
      }}>
        {/* Modal header */}
        <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", marginBottom:20 }}>
          <div>
            <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
              <i className="bi bi-file-earmark-text" style={{ color:"var(--accent-primary)" }} />
              <span style={{ fontWeight:800, fontSize:"1rem" }}>{fd.filename}</span>
              <span className="file-size-chip">{fd.file_size}</span>
            </div>
            <div className="file-meta">
              <i className="bi bi-tag" />{fd.data_source}
              <span className="meta-dot">·</span>
              <i className="bi bi-person" />{fd.data_owner}
              <span className="meta-dot">·</span>
              <i className="bi bi-clock" />{fd.scan_time}
            </div>
          </div>
          <button onClick={onClose} style={{ background:"none",border:"1px solid var(--border-subtle)",borderRadius:8,color:"var(--text-muted)",cursor:"pointer",padding:"4px 8px",fontSize:"1rem" }}>
            <i className="bi bi-x-lg" />
          </button>
        </div>

        {/* Risk + total */}
        <div style={{ display:"flex", gap:12, marginBottom:20 }}>
          <div style={{ flex:1, background:"rgba(56,189,248,0.06)", border:"1px solid var(--border-subtle)", borderRadius:10, padding:"12px 16px", textAlign:"center" }}>
            <div style={{ fontSize:"0.68rem", textTransform:"uppercase", letterSpacing:"1px", color:"var(--text-muted)", marginBottom:4 }}>Risk Level</div>
            <span className={`risk-badge ${RISK_CLASS[fd.risk_level]}`}>{fd.risk_level}</span>
          </div>
          <div style={{ flex:1, background:"rgba(56,189,248,0.06)", border:"1px solid var(--border-subtle)", borderRadius:10, padding:"12px 16px", textAlign:"center" }}>
            <div style={{ fontSize:"0.68rem", textTransform:"uppercase", letterSpacing:"1px", color:"var(--text-muted)", marginBottom:4 }}>Total PII</div>
            <div style={{ fontWeight:800, fontSize:"1.4rem", color:"var(--text-primary)" }}>{fd.pii_total}</div>
          </div>
          <div style={{ flex:2, background:"rgba(56,189,248,0.06)", border:"1px solid var(--border-subtle)", borderRadius:10, padding:"12px 16px" }}>
            <div style={{ fontSize:"0.68rem", textTransform:"uppercase", letterSpacing:"1px", color:"var(--text-muted)", marginBottom:4 }}>Risk Reason</div>
            <div style={{ fontSize:"0.82rem", color:"var(--text-secondary)" }}>{fd.risk_reason}</div>
          </div>
        </div>

        {/* PII breakdown */}
        {allPii.length === 0 ? (
          <div style={{ textAlign:"center", padding:"24px 0", color:"var(--text-muted)" }}>
            <i className="bi bi-check-circle" style={{ fontSize:"2rem", color:"var(--success)", display:"block", marginBottom:8 }} />
            No personal data detected in this file.
          </div>
        ) : (
          allPii.map(([type, values]) => (
            <div key={type} style={{ marginBottom:16 }}>
              <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:8 }}>
                <i className={`bi ${PII_ICONS[type] || "bi-dot"}`} style={{ color:"var(--accent-primary)" }} />
                <span style={{ fontWeight:700, fontSize:"0.9rem" }}>{type}</span>
                <span className={`risk-badge ${RISK_CLASS[(fd.classifications||{})[type]]||"risk-low"}`} style={{ fontSize:"0.62rem" }}>
                  {(fd.classifications||{})[type] || "LOW"}
                </span>
                <span style={{ marginLeft:"auto", fontSize:"0.72rem", color:"var(--text-muted)" }}>{values.length} found</span>
              </div>
              <div style={{ display:"flex", flexWrap:"wrap", gap:6 }}>
                {values.map((v, i) => (
                  <code key={i} style={{ fontSize:"0.8rem" }}>{maskPiiValue(v, type)}</code>
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   HISTORY MODAL
   ═══════════════════════════════════════════════════════ */

function HistoryModal({ history, onClearHistory, onClose }) {
  useEffect(() => {
    const h = (e) => { if (e.key === "Escape") onClose(); };
    document.addEventListener("keydown", h);
    document.body.style.overflow = "hidden";
    return () => { document.removeEventListener("keydown", h); document.body.style.overflow = ""; };
  }, []);

  // Group history entries by date
  const grouped = {};
  history.forEach(entry => {
    const date = (entry.scan_time || "").split(" ")[0] || "Unknown";
    if (!grouped[date]) grouped[date] = [];
    grouped[date].push(entry);
  });
  const dateKeys = Object.keys(grouped).sort().reverse();

  return (
    <div
      style={{
        position:"fixed", inset:0, zIndex:8000,
        background:"rgba(6,8,26,0.85)", backdropFilter:"blur(8px)",
        display:"flex", alignItems:"center", justifyContent:"center",
        padding:16, animation:"fadeInUp 0.25s ease",
      }}
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      <div style={{
        background:"var(--bg-card-solid)", border:"1px solid var(--border-accent)",
        borderRadius: "var(--radius-xl)", padding:28, width:"100%", maxWidth:680,
        maxHeight:"85vh", overflowY:"auto",
        boxShadow:"0 24px 80px rgba(0,0,0,0.5)",
      }}>
        {/* Header */}
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:20 }}>
          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <i className="bi bi-clock-history" style={{ fontSize:"1.3rem", color:"var(--accent-primary)" }} />
            <span style={{ fontWeight:800, fontSize:"1.1rem" }}>Scan History</span>
            <span style={{
              background:"rgba(56,189,248,0.15)", color:"var(--accent-primary)",
              fontSize:"0.7rem", fontWeight:700, padding:"2px 8px", borderRadius:8,
            }}>{history.length} entries</span>
          </div>
          <div style={{ display:"flex", gap:8 }}>
            {history.length > 0 && (
              <button
                onClick={() => { if (confirm("Clear all scan history?")) onClearHistory(); }}
                className="btn btn-outline-danger btn-sm"
                style={{ fontSize:"0.72rem", padding:"4px 10px" }}
              >
                <i className="bi bi-trash3" /> Clear History
              </button>
            )}
            <button onClick={onClose} style={{ background:"none",border:"1px solid var(--border-subtle)",borderRadius:8,color:"var(--text-muted)",cursor:"pointer",padding:"4px 8px",fontSize:"1rem" }}>
              <i className="bi bi-x-lg" />
            </button>
          </div>
        </div>

        {/* Body */}
        {history.length === 0 ? (
          <div style={{ textAlign:"center", padding:"40px 0", color:"var(--text-muted)" }}>
            <i className="bi bi-clock" style={{ fontSize:"2.5rem", display:"block", marginBottom:12, opacity:0.4 }} />
            <div style={{ fontWeight:600, marginBottom:4 }}>No scan history yet</div>
            <div style={{ fontSize:"0.82rem" }}>Scan some files and they will appear here.</div>
          </div>
        ) : (
          dateKeys.map(date => (
            <div key={date} style={{ marginBottom:18 }}>
              <div style={{
                fontSize:"0.7rem", fontWeight:700, textTransform:"uppercase", letterSpacing:"1px",
                color:"var(--text-muted)", marginBottom:8, paddingBottom:4,
                borderBottom:"1px solid var(--border-subtle)",
              }}>
                {date}
              </div>
              {grouped[date].map((entry, i) => {
                const filteredCounts = Object.entries(entry.pii_counts || {}).filter(([, v]) => v > 0);
                return (
                  <div key={entry.id || i} style={{
                    background:"rgba(56,189,248,0.04)", border:"1px solid var(--border-subtle)",
                    borderRadius:10, padding:"12px 16px", marginBottom:8,
                  }}>
                    <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between", gap:10 }}>
                      <div style={{ flex:1, minWidth:0 }}>
                        <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                          <i className="bi bi-file-earmark-text" style={{ color:"var(--accent-primary)", fontSize:"0.9rem" }} />
                          <span style={{ fontWeight:700, fontSize:"0.88rem" }}>{entry.filename}</span>
                          <span className="file-size-chip">{entry.file_size}</span>
                        </div>
                        <div className="file-meta">
                          <i className="bi bi-tag" /> {entry.data_source}
                          <span className="meta-dot">·</span>
                          <i className="bi bi-person" /> {entry.data_owner}
                          <span className="meta-dot">·</span>
                          <i className="bi bi-clock" /> {entry.scan_time}
                        </div>
                      </div>
                      <div style={{ display:"flex", alignItems:"center", gap:8, flexShrink:0 }}>
                        <span style={{
                          fontWeight:800, fontSize:"1.1rem",
                          color: entry.pii_total > 0 ? "var(--accent-primary)" : "var(--success)",
                        }}>
                          {entry.pii_total}
                        </span>
                        <span style={{ fontSize:"0.65rem", color:"var(--text-muted)" }}>PII</span>
                        <span className={`risk-badge ${RISK_CLASS[entry.risk_level] || "risk-low"}`}>
                          {entry.risk_level}
                        </span>
                      </div>
                    </div>
                    {/* PII chips */}
                    {filteredCounts.length > 0 && (
                      <div style={{ display:"flex", flexWrap:"wrap", gap:5, marginTop:8 }}>
                        {filteredCounts.map(([type, count]) => (
                          <span key={type} className="pii-chip" style={{ fontSize:"0.68rem", padding:"2px 7px" }}>
                            <i className={`bi ${PII_ICONS[type] || "bi-dot"}`} />
                            {type}
                            <span className="chip-count">{count}</span>
                          </span>
                        ))}
                      </div>
                    )}
                    {/* Risk reason */}
                    <div className="risk-reason" style={{ marginTop:6, fontSize:"0.72rem" }}>
                      <i className="bi bi-info-circle" /> {entry.risk_reason}
                    </div>
                  </div>
                );
              })}
            </div>
          ))
        )}
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   ACCESS LEVEL CHART — doughnut
   ═══════════════════════════════════════════════════════ */

function AccessLevelChart({ byLevel }) {
  const ref = useRef(null);
  const chartRef = useRef(null);

  useEffect(() => {
    if (!ref.current) return;
    if (chartRef.current) chartRef.current.destroy();

    const labels = Object.keys(byLevel);
    const data   = Object.values(byLevel);
    const colors = labels.map(l => SECURITY_COLORS[l] || "#6b7280");

    chartRef.current = new Chart(ref.current, {
      type: "doughnut",
      data: {
        labels,
        datasets: [{ data, backgroundColor: colors, borderWidth: 2, borderColor: "rgba(6,8,26,0.8)", hoverOffset: 6 }],
      },
      options: {
        cutout: "65%",
        plugins: {
          legend: { position: "right", labels: { color: CHART_TEXT, font: { family: CHART_FONT, size: 11 }, padding: 12, boxWidth: 12 } },
          tooltip: { ...CHART_TIP, callbacks: { label: ctx => ` ${ctx.label}: ${ctx.raw} file(s)` } },
        },
      },
    });
    return () => chartRef.current?.destroy();
  }, [byLevel]);

  return <canvas ref={ref} style={{ maxHeight: 200 }} />;
}


/* ═══════════════════════════════════════════════════════
   ROLE ACCESS CHART — horizontal bar
   ═══════════════════════════════════════════════════════ */

function RoleAccessChart({ byRole }) {
  const ref = useRef(null);
  const chartRef = useRef(null);

  useEffect(() => {
    if (!ref.current) return;
    if (chartRef.current) chartRef.current.destroy();

    const labels = Object.keys(byRole);
    const data   = Object.values(byRole);
    const colors = labels.map(r => ROLE_COLORS[r] || "#6b7280");

    chartRef.current = new Chart(ref.current, {
      type: "bar",
      data: {
        labels,
        datasets: [{ label: "Accessible Files", data, backgroundColor: colors, borderRadius: 4, borderSkipped: false }],
      },
      options: {
        indexAxis: "y",
        plugins: {
          legend: { display: false },
          tooltip: { ...CHART_TIP, callbacks: { label: ctx => ` ${ctx.raw} file(s) accessible` } },
        },
        scales: {
          x: { grid: { color: CHART_GRID }, ticks: { color: CHART_TEXT, font: { family: CHART_FONT, size: 10 } } },
          y: { grid: { display: false }, ticks: { color: CHART_TEXT, font: { family: CHART_FONT, size: 11, weight: "600" } } },
        },
      },
    });
    return () => chartRef.current?.destroy();
  }, [byRole]);

  return <canvas ref={ref} style={{ maxHeight: 200 }} />;
}


/* ═══════════════════════════════════════════════════════
   ACCESS MAP PANEL
   ═══════════════════════════════════════════════════════ */

function AccessMapPanel({ files }) {
  const [data,       setData]       = useState(null);
  const [levelFilter, setLevelFilter] = useState("ALL");
  const [roleFilter,  setRoleFilter]  = useState("ALL");
  const [search,      setSearch]      = useState("");

  useEffect(() => {
    if (!files.length) return;
    fetch("/api/access-map")
      .then(r => r.json())
      .then(setData)
      .catch(() => {});
  }, [files.length]);

  if (!data) return null;

  const { access_map: rawMap, summary, roles, level_meta, level_access } = data;
  const levels = ["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL", "TOP SECRET"];

  /* filter */
  const filtered = rawMap.filter(e => {
    if (levelFilter !== "ALL" && e.security_level !== levelFilter) return false;
    if (roleFilter  !== "ALL" && !e.allowed_roles.includes(roleFilter)) return false;
    if (search) {
      const q = search.toLowerCase();
      if (!e.file_name.toLowerCase().includes(q) && !e.pii_type.toLowerCase().includes(q)) return false;
    }
    return true;
  });

  const levelOrder = { "TOP SECRET": 0, CONFIDENTIAL: 1, RESTRICTED: 2, INTERNAL: 3, PUBLIC: 4 };

  return (
    <div className="access-map-panel mt-4">
      {/* Header */}
      <div className="section-header mb-3 d-flex align-items-center justify-content-between flex-wrap gap-2">
        <div className="d-flex align-items-center gap-2">
          <i className="bi bi-shield-lock-fill" style={{ color: "var(--accent-primary)", fontSize: "1.1rem" }} />
          <span style={{ fontWeight: 700, fontSize: "1rem", color: "var(--text-primary)" }}>
            Role-Based Data Access Control
          </span>
          <span className="badge ms-1" style={{ background: "var(--accent-gradient)", fontSize: "0.6rem", letterSpacing: 1 }}>
            RBAC
          </span>
        </div>
        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
          {rawMap.length} record(s) · {summary.total} file(s)
        </span>
      </div>

      {/* Summary chips */}
      <div className="access-summary-row mb-3">
        {levels.map(lv => {
          const meta = level_meta[lv];
          const cnt  = summary.by_level[lv] || 0;
          return (
            <div
              key={lv}
              className={`access-stat-chip ${levelFilter === lv ? "active" : ""}`}
              style={{ "--chip-color": meta.color }}
              onClick={() => setLevelFilter(levelFilter === lv ? "ALL" : lv)}
              title={`Filter to ${lv}`}
            >
              <i className={`bi ${meta.icon}`} style={{ color: meta.color }} />
              <span className="chip-label">{lv}</span>
              <span className="chip-count">{cnt}</span>
            </div>
          );
        })}
      </div>

      {/* Charts row */}
      <div className="access-charts-row mb-3">
        <div className="access-chart-box">
          <div className="access-chart-title">Files by Security Level</div>
          <AccessLevelChart byLevel={summary.by_level} />
        </div>
        <div className="access-chart-box">
          <div className="access-chart-title">Files Accessible per Role</div>
          <RoleAccessChart byRole={summary.by_role} />
        </div>
      </div>

      {/* Filters */}
      <div className="access-filters mb-3 d-flex flex-wrap gap-2 align-items-center">
        <div className="input-group input-group-sm" style={{ maxWidth: 260 }}>
          <span className="input-group-text" style={{ background: "var(--card-bg)", border: "1px solid var(--border-subtle)", color: "var(--text-muted)" }}>
            <i className="bi bi-search" />
          </span>
          <input
            type="text"
            className="form-control"
            placeholder="Search file or PII type…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ background: "var(--card-bg)", border: "1px solid var(--border-subtle)", color: "var(--text-primary)" }}
          />
        </div>

        <div className="d-flex gap-1 flex-wrap">
          {["ALL", ...levels].map(lv => (
            <button
              key={lv}
              className={`access-filter-btn ${levelFilter === lv ? "active" : ""}`}
              style={lv !== "ALL" ? { "--btn-color": SECURITY_COLORS[lv] } : {}}
              onClick={() => setLevelFilter(lv)}
            >
              {lv === "ALL" ? "All Levels" : lv}
            </button>
          ))}
        </div>

        <div className="d-flex gap-1 flex-wrap">
          {["ALL", ...roles].map(r => (
            <button
              key={r}
              className={`access-filter-btn ${roleFilter === r ? "active" : ""}`}
              style={r !== "ALL" ? { "--btn-color": ROLE_COLORS[r] } : {}}
              onClick={() => setRoleFilter(r)}
            >
              {r === "ALL" ? "All Roles" : r}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="access-table-wrap">
        <table className="access-table">
          <thead>
            <tr>
              <th>File</th>
              <th>PII Type</th>
              <th>Count</th>
              <th>Security Level</th>
              <th>Allowed Roles</th>
              <th>Denied Roles</th>
              <th>Owner</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: "center", color: "var(--text-muted)", padding: "24px 0" }}>No records match the current filters.</td></tr>
            )}
            {filtered.map((e, i) => {
              const meta  = level_meta[e.security_level] || {};
              const order = levelOrder[e.security_level] ?? 99;
              return (
                <tr key={i} data-level-order={order}>
                  <td>
                    <span className="access-file-name" title={e.file_name}>
                      <i className="bi bi-file-earmark-text me-1" style={{ color: "var(--accent-primary)", fontSize: "0.8rem" }} />
                      {e.file_name.length > 28 ? e.file_name.slice(0, 25) + "…" : e.file_name}
                    </span>
                    {e.source_type && (
                      <span className="access-source-badge ms-1">{e.source_type}</span>
                    )}
                  </td>
                  <td>
                    <i className={`bi ${PII_ICONS[e.pii_type] || "bi-tag"} me-1`} style={{ color: "var(--text-muted)", fontSize: "0.8rem" }} />
                    {e.pii_type}
                  </td>
                  <td>
                    <span className="access-count-badge">{e.pii_count}</span>
                  </td>
                  <td>
                    <span className="security-level-badge" style={{ "--level-color": meta.color || "#6b7280" }}>
                      <i className={`bi ${meta.icon || "bi-circle"} me-1`} />
                      <span className="security-level-num">{e.security_level_num || meta.level || "?"}</span>
                      <span className="security-level-divider">/</span>
                      <span className="security-level-max">5</span>
                      <span className="security-level-name ms-1">— {e.security_level}</span>
                    </span>
                  </td>
                  <td>
                    <div className="role-chips-row">
                      {e.allowed_roles.map(r => (
                        <span key={r} className="role-chip role-allowed" style={{ "--role-color": ROLE_COLORS[r] || "#6b7280" }} title={`${r} — ALLOWED`}>
                          {r}
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    <div className="role-chips-row">
                      {e.denied_roles.length === 0
                        ? <span style={{ color: "var(--text-muted)", fontSize: "0.7rem" }}>—</span>
                        : e.denied_roles.map(r => (
                          <span key={r} className="role-chip role-denied" title={`${r} — DENIED`}>
                            {r}
                          </span>
                        ))
                      }
                    </div>
                  </td>
                  <td style={{ color: "var(--text-muted)", fontSize: "0.78rem" }}>
                    {e.data_owner || "—"}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   ENTERPRISE GOVERNANCE HUB (Tabbed Navigation)
   ═══════════════════════════════════════════════════════ */

const GOV_TABS = [
  { id: "lineage",      icon: "bi-diagram-3-fill",            label: "Data Lineage"          },
  { id: "security",     icon: "bi-pie-chart-fill",            label: "Security Distribution" },
  { id: "access",       icon: "bi-shield-lock-fill",          label: "Access Control"        },
  { id: "segregation",  icon: "bi-folder2-open",              label: "File Segregation"      },
  { id: "inventory",    icon: "bi-journal-text",              label: "Data Inventory"        },
  { id: "dpdpa",        icon: "bi-patch-check-fill",          label: "DPDPA Compliance"      },
  { id: "dbrecords",    icon: "bi-database-fill",             label: "DB Records"            },
];

function EnterpriseGovernanceHub() {
  const [activeTab, setActiveTab] = useState("lineage");

  return (
    <div style={{ marginTop: 28 }}>
      {/* ── Section heading ── */}
      <div style={{ marginBottom: 16, display: "flex", alignItems: "center", gap: 10 }}>
        <i className="bi bi-building-gear" style={{ color: "var(--accent-primary)", fontSize: "1.2rem", filter: "drop-shadow(0 0 8px rgba(56,189,248,0.4))" }} />
        <h5 style={{ margin: 0, fontWeight: 800, letterSpacing: "-0.02em", fontSize: "1.05rem" }}>
          Enterprise Data Governance
        </h5>
        <span style={{
          background: "var(--accent-gradient)", color: "#fff",
          fontSize: "0.58rem", fontWeight: 800, padding: "2px 8px",
          borderRadius: 10, letterSpacing: "0.5px", textTransform: "uppercase",
        }}>
          LIVE
        </span>
      </div>

      {/* ── Navigation tabs ── */}
      <div className="enterprise-nav">
        {GOV_TABS.map(tab => (
          <button
            key={tab.id}
            className={`enterprise-nav-btn ${activeTab === tab.id ? "active" : ""}`}
            onClick={() => setActiveTab(tab.id)}
          >
            <i className={`bi ${tab.icon}`} />
            {tab.label}
          </button>
        ))}
      </div>

      {/* ── Active panel ── */}
      <div style={{ animation: "fadeInUp 0.3s ease" }} key={activeTab}>
        {activeTab === "lineage"     && <DataLineagePanel />}
        {activeTab === "security"    && <SecurityDistributionPanel />}
        {activeTab === "access"      && <UnauthorizedAccessPanel />}
        {activeTab === "segregation" && <FileSegregationPanel />}
        {activeTab === "inventory"   && <DataInventoryPanel />}
        {activeTab === "dpdpa"       && <DpdpaCompliancePanel />}
        {activeTab === "dbrecords"   && <DbRecordsPanel />}
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   DATA LINEAGE TRACKING PANEL
   ═══════════════════════════════════════════════════════ */

function DataLineagePanel() {
  const [lineage, setLineage]     = useState([]);
  const [summary, setSummary]     = useState(null);
  const [loading, setLoading]     = useState(false);
  const [expanded, setExpanded]   = useState(null);

  const fetchLineage = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/data-lineage");
      const data = await res.json();
      setLineage(data.lineage || []);
      setSummary(data.summary || null);
    } catch (e) { console.error("Lineage fetch error:", e); }
    setLoading(false);
  };

  useEffect(() => { fetchLineage(); }, []);

  if (!lineage.length && !loading) return null;

  return (
    <div className="section-card governance-panel">
      <div className="section-card-header">
        <div>
          <h5 className="section-title" style={{ margin: 0 }}>
            <i className="bi bi-diagram-3-fill me-2" style={{ color: "var(--accent-primary)" }} />
            Data Lineage Tracking
          </h5>
          <small style={{ color: "var(--text-muted)" }}>
            Track the complete lifecycle of files containing sensitive data
          </small>
        </div>
        <button className="btn btn-sm btn-outline-primary" onClick={fetchLineage} disabled={loading}>
          <i className={`bi ${loading ? "bi-arrow-repeat spin-icon" : "bi-arrow-clockwise"} me-1`} />
          Refresh
        </button>
      </div>

      {summary && (
        <div className="lineage-stats-row">
          <div className="lineage-stat-card">
            <div className="lineage-stat-num">{summary.total_tracked_files}</div>
            <div className="lineage-stat-label">Tracked Files</div>
          </div>
          <div className="lineage-stat-card">
            <div className="lineage-stat-num">{summary.total_movements}</div>
            <div className="lineage-stat-label">Total Movements</div>
          </div>
          <div className="lineage-stat-card">
            <div className="lineage-stat-num">{summary.total_access_attempts}</div>
            <div className="lineage-stat-label">Access Attempts</div>
          </div>
          <div className="lineage-stat-card" style={{ borderColor: "var(--danger-glow)" }}>
            <div className="lineage-stat-num" style={{ color: "#ef4444" }}>{summary.total_unauthorized}</div>
            <div className="lineage-stat-label">Unauthorized</div>
          </div>
        </div>
      )}

      <div className="lineage-table-wrap">
        <table className="compliance-table">
          <thead>
            <tr>
              <th>File Name</th>
              <th>Origin Source</th>
              <th>Security Level</th>
              <th>Detected PII</th>
              <th>Authorized Roles</th>
              <th>Sharing Path</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {lineage.length === 0 && (
              <tr><td colSpan={7} style={{ textAlign: "center", color: "var(--text-muted)", padding: 24 }}>No lineage records yet. Scan files to start tracking.</td></tr>
            )}
            {lineage.map((rec, i) => {
              const levelColor = SECURITY_COLORS[rec.security_level] || "#6b7280";
              const isExpanded = expanded === i;
              return (
                <React.Fragment key={i}>
                  <tr>
                    <td>
                      <span className="access-file-name" title={rec.file_name}>
                        <i className="bi bi-file-earmark-text me-1" style={{ color: "var(--accent-primary)" }} />
                        {rec.file_name.length > 25 ? rec.file_name.slice(0, 22) + "..." : rec.file_name}
                      </span>
                    </td>
                    <td>
                      <span className="lineage-origin-badge">{rec.origin_source}</span>
                    </td>
                    <td>
                      <span className="security-level-badge" style={{ "--level-color": levelColor }}>
                        <i className={`bi ${SECURITY_ICONS[rec.security_level] || "bi-circle"} me-1`} />
                        {rec.security_level}
                      </span>
                    </td>
                    <td>
                      <div className="role-chips-row">
                        {(rec.detected_pii || []).map(p => (
                          <span key={p} className="pii-chip-sm">{p}</span>
                        ))}
                        {(!rec.detected_pii || rec.detected_pii.length === 0) && <span style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>None</span>}
                      </div>
                    </td>
                    <td>
                      <div className="role-chips-row">
                        {(rec.authorized_roles || []).map(r => (
                          <span key={r} className="role-chip role-allowed" style={{ "--role-color": ROLE_COLORS[r] || "#6b7280" }}>{r}</span>
                        ))}
                      </div>
                    </td>
                    <td>
                      <div className="role-chips-row">
                        {(rec.sharing_path || []).map(s => (
                          <span key={s} className="sharing-path-chip">{s}</span>
                        ))}
                        {(!rec.sharing_path || rec.sharing_path.length === 0) && <span style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>—</span>}
                      </div>
                    </td>
                    <td>
                      <button className="btn btn-sm btn-outline-secondary" onClick={() => setExpanded(isExpanded ? null : i)} title="View Movement History">
                        <i className={`bi ${isExpanded ? "bi-chevron-up" : "bi-chevron-down"}`} />
                      </button>
                    </td>
                  </tr>
                  {isExpanded && (
                    <tr className="lineage-expanded-row">
                      <td colSpan={7}>
                        <div className="lineage-detail-panel">
                          <div className="lineage-detail-section">
                            <h6><i className="bi bi-arrow-left-right me-1" />File Movement History</h6>
                            <div className="lineage-timeline">
                              {(rec.movement_history || []).map((m, mi) => (
                                <div key={mi} className="lineage-timeline-item">
                                  <div className="lineage-timeline-dot" />
                                  <div className="lineage-timeline-content">
                                    <div className="lineage-timeline-action">{m.action.toUpperCase()}</div>
                                    <div className="lineage-timeline-details">{m.details}</div>
                                    <div className="lineage-timeline-time">{m.timestamp}</div>
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                          {rec.access_history && rec.access_history.length > 0 && (
                            <div className="lineage-detail-section">
                              <h6><i className="bi bi-person-check me-1" />Access History</h6>
                              <div className="lineage-access-list">
                                {rec.access_history.map((a, ai) => (
                                  <div key={ai} className={`lineage-access-entry ${a.status === "DENIED" ? "access-denied" : "access-granted"}`}>
                                    <i className={`bi ${a.status === "DENIED" ? "bi-x-circle-fill" : "bi-check-circle-fill"} me-1`} />
                                    <strong>{a.user}</strong> ({a.role}) — <span className={a.status === "DENIED" ? "text-danger" : "text-success"}>{a.status}</span>
                                    <span className="lineage-timeline-time ms-2">{a.timestamp}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          <div className="lineage-detail-meta">
                            <span><strong>Original:</strong> {rec.original_path}</span>
                            <span><strong>Current:</strong> {rec.current_path}</span>
                            <span><strong>Created:</strong> {rec.created_at}</span>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   SECURITY LEVEL DISTRIBUTION PANEL
   ═══════════════════════════════════════════════════════ */

function SecurityDistributionPanel() {
  const [data, setData] = useState(null);
  const chartRef = useRef(null);
  const canvasRef = useRef(null);

  const fetchData = async () => {
    try {
      const res = await fetch("/api/data-lineage");
      const d = await res.json();
      setData(d.summary || null);
    } catch (e) { console.error(e); }
  };

  useEffect(() => { fetchData(); }, []);

  useEffect(() => {
    if (!data || !canvasRef.current) return;
    if (chartRef.current) chartRef.current.destroy();

    const levels = Object.keys(data.by_security_level || {});
    const counts = levels.map(l => data.by_security_level[l]);
    const colors = levels.map(l => SECURITY_COLORS[l] || "#6b7280");

    chartRef.current = new Chart(canvasRef.current, {
      type: "doughnut",
      data: {
        labels: levels,
        datasets: [{ data: counts, backgroundColor: colors, borderWidth: 0 }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "right", labels: { color: CHART_TEXT, font: { family: CHART_FONT, size: 11 }, padding: 12 } },
          tooltip: CHART_TIP,
        },
      },
    });

    return () => { if (chartRef.current) chartRef.current.destroy(); };
  }, [data]);

  if (!data || !data.by_security_level || Object.keys(data.by_security_level).length === 0) return null;

  return (
    <div className="section-card governance-panel">
      <div className="section-card-header">
        <h5 className="section-title" style={{ margin: 0 }}>
          <i className="bi bi-pie-chart-fill me-2" style={{ color: "#f59e0b" }} />
          Security Level Distribution
        </h5>
      </div>
      <div style={{ display: "flex", gap: 24, flexWrap: "wrap", alignItems: "center" }}>
        <div style={{ width: 280, height: 200 }}>
          <canvas ref={canvasRef} />
        </div>
        <div className="security-dist-cards">
          {Object.entries(data.by_security_level).map(([level, count]) => (
            <div key={level} className="security-dist-item" style={{ borderLeftColor: SECURITY_COLORS[level] || "#6b7280" }}>
              <i className={`bi ${SECURITY_ICONS[level] || "bi-circle"}`} style={{ color: SECURITY_COLORS[level], fontSize: "1.1rem" }} />
              <div>
                <div className="security-dist-level">{level}</div>
                <div className="security-dist-count">{count} file{count !== 1 ? "s" : ""}</div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   UNAUTHORIZED ACCESS ATTEMPTS PANEL
   ═══════════════════════════════════════════════════════ */

function UnauthorizedAccessPanel() {
  const [logs, setLogs]       = useState([]);
  const [unauthorized, setUnauthorized] = useState([]);
  const [loading, setLoading] = useState(false);

  // --- Access check form state ---
  const [checkRole, setCheckRole]   = useState("Employee");
  const [checkLevel, setCheckLevel] = useState("CONFIDENTIAL");
  const [checkUser, setCheckUser]   = useState("");
  const [checkFile, setCheckFile]   = useState("");
  const [checkResult, setCheckResult] = useState(null);

  const fetchLogs = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/access-logs");
      const data = await res.json();
      setLogs(data.logs || []);
      setUnauthorized(data.unauthorized_attempts || []);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { fetchLogs(); }, []);

  const handleCheckAccess = async () => {
    try {
      const res = await fetch("/api/check-access", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          user_role: checkRole,
          security_level: checkLevel,
          user: checkUser || "test_user",
          file_name: checkFile || "",
        }),
      });
      const data = await res.json();
      setCheckResult(data);
      // Refresh logs after access check
      fetchLogs();
    } catch (e) { console.error(e); }
  };

  return (
    <div className="section-card governance-panel">
      <div className="section-card-header">
        <div>
          <h5 className="section-title" style={{ margin: 0 }}>
            <i className="bi bi-shield-exclamation me-2" style={{ color: "#ef4444" }} />
            Role-Based Access Control & Access Logs
          </h5>
          <small style={{ color: "var(--text-muted)" }}>
            Check access permissions and track unauthorized attempts
          </small>
        </div>
        <button className="btn btn-sm btn-outline-primary" onClick={fetchLogs} disabled={loading}>
          <i className={`bi ${loading ? "bi-arrow-repeat spin-icon" : "bi-arrow-clockwise"} me-1`} />
          Refresh
        </button>
      </div>

      {/* Access Check Form */}
      <div className="access-check-form">
        <h6 style={{ color: "var(--text-primary)", marginBottom: 12 }}>
          <i className="bi bi-key-fill me-1" style={{ color: "var(--accent-primary)" }} />
          Check Access Permission
        </h6>
        <div className="access-check-grid">
          <div className="form-group-sm">
            <label>User Role</label>
            <select className="form-select form-select-sm dark-select" value={checkRole} onChange={e => setCheckRole(e.target.value)}>
              {["Employee", "Manager", "HR", "Finance", "Admin"].map(r => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
          </div>
          <div className="form-group-sm">
            <label>Security Level</label>
            <select className="form-select form-select-sm dark-select" value={checkLevel} onChange={e => setCheckLevel(e.target.value)}>
              {["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL", "TOP SECRET"].map(l => (
                <option key={l} value={l}>{l}</option>
              ))}
            </select>
          </div>
          <div className="form-group-sm">
            <label>Username (optional)</label>
            <input className="form-control form-control-sm dark-input" placeholder="e.g. employee_15" value={checkUser} onChange={e => setCheckUser(e.target.value)} />
          </div>
          <div className="form-group-sm">
            <label>File Name (optional)</label>
            <input className="form-control form-control-sm dark-input" placeholder="e.g. report.xlsx" value={checkFile} onChange={e => setCheckFile(e.target.value)} />
          </div>
          <div className="form-group-sm" style={{ alignSelf: "end" }}>
            <button className="btn btn-sm btn-primary" onClick={handleCheckAccess}>
              <i className="bi bi-shield-check me-1" />Check Access
            </button>
          </div>
        </div>
        {checkResult && (
          <div className={`access-check-result ${checkResult.authorized ? "access-granted" : "access-denied"}`}>
            <i className={`bi ${checkResult.authorized ? "bi-check-circle-fill" : "bi-x-circle-fill"} me-2`} />
            <strong>{checkResult.message}</strong> — {checkResult.reason}
          </div>
        )}
      </div>

      {/* RBAC Policy Table */}
      <div style={{ marginTop: 16 }}>
        <h6 style={{ color: "var(--text-primary)", marginBottom: 8 }}>
          <i className="bi bi-table me-1" />Access Policy Matrix
        </h6>
        <div className="table-responsive">
          <table className="compliance-table" style={{ fontSize: "0.8rem" }}>
            <thead>
              <tr>
                <th>Role</th>
                <th style={{ textAlign: "center" }}>PUBLIC</th>
                <th style={{ textAlign: "center" }}>INTERNAL</th>
                <th style={{ textAlign: "center" }}>RESTRICTED</th>
                <th style={{ textAlign: "center" }}>CONFIDENTIAL</th>
                <th style={{ textAlign: "center" }}>TOP SECRET</th>
              </tr>
            </thead>
            <tbody>
              {["Employee", "Manager", "HR", "Finance", "Admin"].map(role => (
                <tr key={role}>
                  <td><span className="role-chip role-allowed" style={{ "--role-color": ROLE_COLORS[role] || "#6b7280" }}>{role}</span></td>
                  {["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL", "TOP SECRET"].map(level => {
                    const allowed = ({
                      Employee: ["PUBLIC", "INTERNAL"],
                      Manager: ["PUBLIC", "INTERNAL", "RESTRICTED"],
                      HR: ["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL"],
                      Finance: ["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL"],
                      Admin: ["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL", "TOP SECRET"],
                    })[role] || [];
                    const ok = allowed.includes(level);
                    return (
                      <td key={level} style={{ textAlign: "center" }}>
                        <i className={`bi ${ok ? "bi-check-circle-fill text-success" : "bi-x-circle-fill text-danger"}`} style={{ fontSize: "1rem" }} />
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Unauthorized Attempts */}
      {unauthorized.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <h6 style={{ color: "#ef4444", marginBottom: 8 }}>
            <i className="bi bi-exclamation-triangle-fill me-1" />
            Unauthorized Access Attempts ({unauthorized.length})
          </h6>
          <div className="unauthorized-list">
            {unauthorized.slice(0, 20).map((u, i) => (
              <div key={i} className="unauthorized-entry">
                <i className="bi bi-x-circle-fill text-danger me-2" />
                <strong>{u.user}</strong> ({u.role}) tried to access <strong>{u.file_name}</strong>
                <span className="lineage-timeline-time ms-2">{u.timestamp}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Access Logs */}
      {logs.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <h6 style={{ color: "var(--text-primary)", marginBottom: 8 }}>
            <i className="bi bi-clock-history me-1" />
            Recent Access Logs ({logs.length})
          </h6>
          <div className="access-logs-list">
            {logs.slice(-20).reverse().map((log, i) => (
              <div key={i} className={`access-log-entry ${log.status === "DENIED" ? "log-denied" : "log-granted"}`}>
                <i className={`bi ${log.status === "DENIED" ? "bi-x-circle-fill text-danger" : "bi-check-circle-fill text-success"} me-1`} />
                <span className="log-user">{log.user}</span>
                <span className="log-role">({log.role})</span>
                <span className="log-arrow">→</span>
                <span className="log-file">{log.file_name}</span>
                <span className={`log-status ${log.status === "DENIED" ? "text-danger" : "text-success"}`}>{log.status}</span>
                <span className="log-time">{log.timestamp}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   FILE SEGREGATION STATUS PANEL
   ═══════════════════════════════════════════════════════ */

function FileSegregationPanel() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/segregation-status");
      const d = await res.json();
      setData(d);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { fetchData(); }, []);

  if (!data) return null;

  const levels = ["PUBLIC", "INTERNAL", "RESTRICTED", "CONFIDENTIAL"];

  return (
    <div className="section-card governance-panel">
      <div className="section-card-header">
        <div>
          <h5 className="section-title" style={{ margin: 0 }}>
            <i className="bi bi-folder2-open me-2" style={{ color: "#22c55e" }} />
            Automated File Segregation
          </h5>
          <small style={{ color: "var(--text-muted)" }}>
            Files automatically organized by security classification level
          </small>
        </div>
        <button className="btn btn-sm btn-outline-primary" onClick={fetchData} disabled={loading}>
          <i className={`bi ${loading ? "bi-arrow-repeat spin-icon" : "bi-arrow-clockwise"} me-1`} />
          Refresh
        </button>
      </div>

      <div className="segregation-folder-grid">
        {levels.map(level => {
          const files = (data.files_by_level || {})[level] || [];
          const byLevel = (data.summary?.by_level || {})[level] || 0;
          return (
            <div key={level} className="segregation-folder-card" style={{ borderTopColor: SECURITY_COLORS[level] || "#6b7280" }}>
              <div className="segregation-folder-header">
                <i className={`bi ${SECURITY_ICONS[level] || "bi-folder"}`} style={{ color: SECURITY_COLORS[level], fontSize: "1.3rem" }} />
                <div>
                  <div className="segregation-folder-name">{level.toLowerCase()}/</div>
                  <div className="segregation-folder-count">{files.length} file{files.length !== 1 ? "s" : ""}</div>
                </div>
              </div>
              <div className="segregation-file-list">
                {files.length === 0 && <span style={{ color: "var(--text-muted)", fontSize: "0.75rem" }}>Empty</span>}
                {files.slice(0, 5).map((f, i) => (
                  <div key={i} className="segregation-file-item">
                    <i className="bi bi-file-earmark-text me-1" style={{ fontSize: "0.7rem", color: "var(--text-muted)" }} />
                    <span title={f}>{f.length > 20 ? f.slice(0, 17) + "..." : f}</span>
                  </div>
                ))}
                {files.length > 5 && (
                  <div style={{ color: "var(--text-muted)", fontSize: "0.72rem", marginTop: 2 }}>
                    +{files.length - 5} more
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {data.log && data.log.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <h6 style={{ color: "var(--text-primary)", fontSize: "0.85rem", marginBottom: 8 }}>
            <i className="bi bi-arrow-left-right me-1" />Recent Segregation Events
          </h6>
          <div className="segregation-log-list">
            {data.log.slice(-10).reverse().map((entry, i) => (
              <div key={i} className="segregation-log-entry">
                <span className="security-level-badge" style={{ "--level-color": SECURITY_COLORS[entry.security_level] || "#6b7280", fontSize: "0.7rem" }}>
                  {entry.security_level}
                </span>
                <span className="seg-log-file">{entry.file_name}</span>
                <span className="seg-log-action">{entry.action}</span>
                <span className="seg-log-time">{entry.timestamp}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   PERSONAL DATA INVENTORY PANEL (DPDPA)
   ═══════════════════════════════════════════════════════ */

function DataInventoryPanel() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchData = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/data-inventory");
      const d = await res.json();
      setData(d);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { fetchData(); }, []);

  if (!data) return null;

  const summary = data.summary || {};
  const records = data.inventory || [];

  const CONSENT_COLORS = {
    verified: "#34d399",
    notice_based: "#38bdf8",
    pending: "#fbbf24",
    requires_verification: "#ef4444",
    not_applicable: "var(--text-muted)",
  };

  const SUBJECT_ICONS = {
    employee: "bi-person-badge",
    citizen: "bi-people",
    customer: "bi-person-lines-fill",
    patient: "bi-heart-pulse",
    user: "bi-person-circle",
  };

  return (
    <div className="section-card governance-panel">
      <div className="section-card-header">
        <div>
          <h5 className="section-title" style={{ margin: 0 }}>
            <i className="bi bi-journal-text" style={{ color: "var(--accent-primary)" }} /> Personal Data Inventory
          </h5>
          <small style={{ color: "var(--text-muted)" }}>DPDPA Section 4 — Central catalog of personal data processing activities</small>
        </div>
        <button onClick={fetchData} className="btn btn-sm" style={{ background: "rgba(56,189,248,0.1)", color: "#7dd3fc", border: "1px solid rgba(56,189,248,0.2)", borderRadius: 8, fontSize: "0.72rem" }}>
          <i className="bi bi-arrow-clockwise" /> Refresh
        </button>
      </div>

      {/* Summary cards */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))", gap: 10, margin: "16px 0" }}>
        <div className="pipeline-stat" style={{ background: "rgba(56,189,248,0.06)", padding: "12px" }}>
          <span style={{ fontSize: "1.3rem", fontWeight: 800, color: "#38bdf8" }}>{summary.total_files_cataloged || 0}</span>
          <span style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Files Cataloged</span>
        </div>
        <div className="pipeline-stat" style={{ background: "rgba(239,68,68,0.06)", padding: "12px" }}>
          <span style={{ fontSize: "1.3rem", fontWeight: 800, color: "#ef4444" }}>{summary.files_with_personal_data || 0}</span>
          <span style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>With Personal Data</span>
        </div>
        <div className="pipeline-stat" style={{ background: "rgba(251,191,36,0.06)", padding: "12px" }}>
          <span style={{ fontSize: "1.3rem", fontWeight: 800, color: "#fbbf24" }}>{summary.files_needing_consent || 0}</span>
          <span style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Need Consent</span>
        </div>
        <div className="pipeline-stat" style={{ background: "rgba(52,211,153,0.06)", padding: "12px" }}>
          <span style={{ fontSize: "1.3rem", fontWeight: 800, color: "#34d399" }}>{summary.average_compliance_score || 0}%</span>
          <span style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>Avg Compliance</span>
        </div>
      </div>

      {/* Data subject distribution */}
      {summary.by_data_subject_type && Object.keys(summary.by_data_subject_type).length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: 8 }}>Data Subject Types</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {Object.entries(summary.by_data_subject_type).map(([subj, count]) => (
              <span key={subj} style={{
                padding: "4px 12px", borderRadius: 8, fontSize: "0.72rem", fontWeight: 600,
                background: "rgba(167,139,250,0.1)", color: "#a78bfa", display: "flex", alignItems: "center", gap: 5,
              }}>
                <i className={`bi ${SUBJECT_ICONS[subj] || "bi-person"}`} /> {subj}: {count}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Consent status distribution */}
      {summary.by_consent_status && Object.keys(summary.by_consent_status).length > 0 && (
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: "0.75rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: 8 }}>Consent Status</div>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 8 }}>
            {Object.entries(summary.by_consent_status).map(([status, count]) => (
              <span key={status} style={{
                padding: "4px 12px", borderRadius: 8, fontSize: "0.72rem", fontWeight: 600,
                background: `${CONSENT_COLORS[status] || "#999"}15`, color: CONSENT_COLORS[status] || "#999",
              }}>
                {status.replace(/_/g, " ")}: {count}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* File inventory list */}
      {records.length > 0 && (
        <div style={{ maxHeight: 350, overflow: "auto" }}>
          {records.slice(0, 30).map((rec, i) => (
            <div key={i} style={{
              padding: "10px 14px", marginBottom: 6, borderRadius: 10,
              background: "rgba(255,255,255,0.02)", border: "1px solid rgba(255,255,255,0.05)",
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 6 }}>
                <span style={{ fontWeight: 700, fontSize: "0.78rem", color: "var(--text-primary)" }}>
                  <i className="bi bi-file-earmark-text" style={{ color: "var(--accent-primary)", marginRight: 6 }} />
                  {rec.file_name}
                </span>
                <span style={{
                  fontSize: "0.65rem", fontWeight: 700, padding: "2px 8px", borderRadius: 6,
                  background: `${CONSENT_COLORS[rec.consent_status] || "#999"}15`,
                  color: CONSENT_COLORS[rec.consent_status] || "#999",
                }}>
                  {(rec.consent_status || "").replace(/_/g, " ")}
                </span>
              </div>
              <div style={{ display: "flex", gap: 14, fontSize: "0.7rem", color: "var(--text-muted)", flexWrap: "wrap" }}>
                <span><i className="bi bi-shield-lock" /> {rec.security_level}</span>
                <span><i className="bi bi-person" /> {rec.data_subject_type?.join(", ")}</span>
                <span><i className="bi bi-speedometer2" /> {rec.compliance_score}%</span>
              </div>
              {rec.detected_personal_data_types?.length > 0 && (
                <div style={{ marginTop: 6, display: "flex", gap: 4, flexWrap: "wrap" }}>
                  {rec.detected_personal_data_types.map((pt, j) => (
                    <span key={j} style={{ fontSize: "0.62rem", padding: "1px 6px", borderRadius: 4, background: "rgba(56,189,248,0.1)", color: "#7dd3fc" }}>
                      {pt}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   DPDPA COMPLIANCE PANEL
   ═══════════════════════════════════════════════════════ */

function DpdpaCompliancePanel() {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchReport = async () => {
    setLoading(true);
    try {
      const res = await fetch("/api/dpdpa-report");
      const d = await res.json();
      setReport(d);
    } catch (e) { console.error(e); }
    setLoading(false);
  };

  useEffect(() => { fetchReport(); }, []);

  if (!report) return null;

  const summary = report.summary || {};
  const rating = summary.compliance_rating || "LOW";
  const ratingColors = { HIGH: "#34d399", MEDIUM: "#fbbf24", LOW: "#ef4444" };

  return (
    <div className="section-card governance-panel">
      <div className="section-card-header">
        <div>
          <h5 className="section-title" style={{ margin: 0 }}>
            <i className="bi bi-patch-check-fill" style={{ color: "#34d399" }} /> DPDPA Compliance Assessment
          </h5>
          <small style={{ color: "var(--text-muted)" }}>Digital Personal Data Protection Act 2023 — Compliance readiness report</small>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <a href="/api/dpdpa-report/csv" className="btn btn-sm" style={{
            background: "rgba(52,211,153,0.1)", color: "#34d399", border: "1px solid rgba(52,211,153,0.2)",
            borderRadius: 8, fontSize: "0.72rem", textDecoration: "none",
          }}>
            <i className="bi bi-download" /> Export CSV
          </a>
          <button onClick={fetchReport} className="btn btn-sm" style={{
            background: "rgba(56,189,248,0.1)", color: "#7dd3fc", border: "1px solid rgba(56,189,248,0.2)",
            borderRadius: 8, fontSize: "0.72rem",
          }}>
            <i className="bi bi-arrow-clockwise" /> Refresh
          </button>
        </div>
      </div>

      {/* Compliance score hero */}
      <div style={{
        display: "flex", alignItems: "center", gap: 20, margin: "16px 0",
        padding: "16px 20px", borderRadius: 12,
        background: `${ratingColors[rating]}08`, border: `1px solid ${ratingColors[rating]}25`,
      }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: "2.2rem", fontWeight: 900, color: ratingColors[rating], lineHeight: 1 }}>
            {summary.average_compliance_score || 0}
          </div>
          <div style={{ fontSize: "0.65rem", color: "var(--text-muted)", fontWeight: 600, marginTop: 2 }}>out of 100</div>
        </div>
        <div>
          <div style={{ fontWeight: 800, fontSize: "0.9rem", color: ratingColors[rating] }}>
            Compliance Rating: {rating}
          </div>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: 4 }}>
            {summary.total_files_cataloged || 0} files cataloged &middot; {summary.files_with_personal_data || 0} contain personal data &middot; {summary.files_needing_consent || 0} need consent verification
          </div>
        </div>
      </div>

      {/* Summary grid */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 10, marginBottom: 16 }}>
        {summary.by_security_level && Object.entries(summary.by_security_level).map(([level, count]) => {
          const colors = { PUBLIC: "#22c55e", INTERNAL: "#06b6d4", RESTRICTED: "#f59e0b", CONFIDENTIAL: "#ef4444", "TOP SECRET": "#dc2626" };
          return (
            <div key={level} style={{
              padding: "10px 14px", borderRadius: 10,
              background: `${colors[level] || "#999"}0a`, border: `1px solid ${colors[level] || "#999"}20`,
            }}>
              <div style={{ fontSize: "1.1rem", fontWeight: 800, color: colors[level] || "#999" }}>{count}</div>
              <div style={{ fontSize: "0.65rem", color: "var(--text-muted)" }}>{level}</div>
            </div>
          );
        })}
      </div>

      {/* Recommendations */}
      {report.recommendations?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: 10 }}>
            <i className="bi bi-lightbulb" style={{ color: "#fbbf24" }} /> Recommendations
          </div>
          {report.recommendations.map((rec, i) => (
            <div key={i} style={{
              padding: "8px 14px", marginBottom: 6, borderRadius: 8,
              background: "rgba(251,191,36,0.04)", borderLeft: "3px solid rgba(251,191,36,0.4)",
              fontSize: "0.73rem", color: "var(--text-secondary)",
            }}>
              {rec}
            </div>
          ))}
        </div>
      )}

      {/* DPDPA Obligations */}
      {report.applicable_obligations?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "var(--text-primary)", marginBottom: 10 }}>
            <i className="bi bi-list-check" style={{ color: "#38bdf8" }} /> Applicable DPDPA Obligations
          </div>
          <div style={{ maxHeight: 200, overflow: "auto" }}>
            {report.applicable_obligations.map((obl, i) => (
              <div key={i} style={{
                padding: "6px 12px", marginBottom: 4, borderRadius: 6,
                background: "rgba(56,189,248,0.04)", fontSize: "0.72rem", color: "var(--text-muted)",
                display: "flex", alignItems: "center", gap: 8,
              }}>
                <i className="bi bi-check2-square" style={{ color: "#38bdf8", flexShrink: 0 }} />
                {obl}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Consent gaps */}
      {report.consent_gaps?.length > 0 && (
        <div style={{ marginBottom: 16 }}>
          <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "#ef4444", marginBottom: 10 }}>
            <i className="bi bi-exclamation-triangle-fill" /> Consent Gaps ({report.consent_gaps.length})
          </div>
          {report.consent_gaps.slice(0, 10).map((gap, i) => (
            <div key={i} style={{
              padding: "8px 12px", marginBottom: 4, borderRadius: 8,
              background: "rgba(239,68,68,0.04)", border: "1px solid rgba(239,68,68,0.1)",
              fontSize: "0.72rem",
            }}>
              <span style={{ fontWeight: 600, color: "#ef4444" }}>{gap.file_name}</span>
              <span style={{ color: "var(--text-muted)", marginLeft: 8 }}>
                Status: {gap.consent_status?.replace(/_/g, " ")} &middot; PII: {gap.pii_types?.join(", ")}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* High risk files */}
      {report.high_risk_files?.length > 0 && (
        <div>
          <div style={{ fontSize: "0.78rem", fontWeight: 700, color: "#ef4444", marginBottom: 10 }}>
            <i className="bi bi-shield-exclamation" /> High-Risk Files ({report.high_risk_files.length})
          </div>
          {report.high_risk_files.slice(0, 10).map((hrf, i) => (
            <div key={i} style={{
              padding: "8px 12px", marginBottom: 4, borderRadius: 8,
              background: "rgba(239,68,68,0.04)", border: "1px solid rgba(239,68,68,0.08)",
              fontSize: "0.72rem", display: "flex", justifyContent: "space-between", alignItems: "center",
            }}>
              <span style={{ fontWeight: 600, color: "var(--text-primary)" }}>{hrf.file_name}</span>
              <span style={{
                fontSize: "0.62rem", padding: "2px 8px", borderRadius: 6, fontWeight: 700,
                background: "rgba(239,68,68,0.12)", color: "#ef4444",
              }}>
                {hrf.security_level} &middot; Score: {hrf.compliance_score}%
              </span>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: 14, fontSize: "0.68rem", color: "var(--text-muted)", textAlign: "center", opacity: 0.6 }}>
        Report generated: {report.generated_at}
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   DATABASE RECORDS PANEL
   ═══════════════════════════════════════════════════════ */

function DbRecordsPanel() {
  const [records, setRecords] = useState([]);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState("ALL");
  const [totalCount, setTotalCount] = useState(0);
  const [page, setPage] = useState(1);
  const perPage = 20;

  const fetchRecords = async (type) => {
    setLoading(true);
    setPage(1);
    try {
      let url = "/api/db-records";
      if (type === "PII" || type === "SPII") url += `?type=${type}`;
      else if (type === "EXPIRED") url += "?expired=1&years=3";
      const res = await fetch(url);
      const d = await res.json();
      if (d.success) {
        setRecords(d.records || []);
        setTotalCount(d.count || 0);
      } else {
        setRecords([]);
        setTotalCount(0);
      }
    } catch (e) {
      console.error("[DB Records]", e);
      setRecords([]);
    }
    setLoading(false);
  };

  useEffect(() => { fetchRecords(filter); }, [filter]);

  // Check if a record is older than 3 years
  const isExpired = (uploadedAt) => {
    if (!uploadedAt) return false;
    const uploaded = new Date(uploadedAt);
    const threeYearsAgo = new Date();
    threeYearsAgo.setFullYear(threeYearsAgo.getFullYear() - 3);
    return uploaded < threeYearsAgo;
  };

  const expiredCount = records.filter(r => isExpired(r.uploaded_at)).length;

  // Sort: expired records first, then newest first
  const sorted = [...records].sort((a, b) => {
    const aExp = isExpired(a.uploaded_at);
    const bExp = isExpired(b.uploaded_at);
    if (aExp && !bExp) return -1;
    if (!aExp && bExp) return 1;
    return (b.record_id || 0) - (a.record_id || 0);
  });

  const totalPages = Math.ceil(sorted.length / perPage);
  const pageRecords = sorted.slice((page - 1) * perPage, page * perPage);

  const typeColors  = { PII: "#38bdf8", SPII: "#ef4444" };
  const filterBtns  = [
    { key: "ALL",     label: "All Records",  icon: "bi-database"           },
    { key: "PII",     label: "PII Only",     icon: "bi-person"             },
    { key: "SPII",    label: "SPII Only",    icon: "bi-shield-exclamation" },
    { key: "EXPIRED", label: "Expired (3yr)", icon: "bi-clock-history"     },
  ];

  return (
    <div className="section-card governance-panel">
      <div className="section-card-header">
        <div>
          <h5 className="section-title" style={{ margin: 0 }}>
            <i className="bi bi-database-fill" style={{ color: "#38bdf8" }} /> MySQL Database Records
          </h5>
          <small style={{ color: "var(--text-muted)" }}>
            Live data from <code style={{ color: "#a78bfa", fontSize: "0.72rem" }}>personal_data_records</code> table
          </small>
        </div>
        <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
          <span style={{
            background: "rgba(56,189,248,0.1)", color: "#7dd3fc", border: "1px solid rgba(56,189,248,0.2)",
            borderRadius: 8, fontSize: "0.7rem", fontWeight: 700, padding: "4px 10px",
          }}>
            {totalCount} records
          </span>
          {expiredCount > 0 && (
            <span style={{
              background: "rgba(251,191,36,0.15)", color: "#fbbf24", border: "1px solid rgba(251,191,36,0.3)",
              borderRadius: 8, fontSize: "0.7rem", fontWeight: 700, padding: "4px 10px",
              display: "flex", alignItems: "center", gap: 4,
            }}>
              <i className="bi bi-exclamation-triangle-fill" /> {expiredCount} expired
            </span>
          )}
          <button onClick={() => fetchRecords(filter)} className="btn btn-sm" style={{
            background: "rgba(56,189,248,0.1)", color: "#7dd3fc", border: "1px solid rgba(56,189,248,0.2)",
            borderRadius: 8, fontSize: "0.72rem",
          }}>
            <i className="bi bi-arrow-clockwise" /> Refresh
          </button>
        </div>
      </div>

      {/* Filter buttons */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {filterBtns.map(fb => (
          <button key={fb.key} onClick={() => setFilter(fb.key)} style={{
            padding: "6px 14px", borderRadius: 8, fontSize: "0.72rem", fontWeight: 600, cursor: "pointer",
            border: filter === fb.key ? "1px solid rgba(56,189,248,0.5)" : "1px solid rgba(255,255,255,0.06)",
            background: filter === fb.key ? "rgba(56,189,248,0.15)" : "rgba(255,255,255,0.03)",
            color: filter === fb.key ? "#7dd3fc" : "var(--text-muted)",
            transition: "all 0.2s",
          }}>
            <i className={`bi ${fb.icon}`} style={{ marginRight: 4 }} />{fb.label}
          </button>
        ))}
      </div>

      {/* Loading state */}
      {loading && (
        <div style={{ textAlign: "center", padding: "30px 0", color: "var(--text-muted)" }}>
          <div className="pipeline-spinner" style={{ width: 28, height: 28, margin: "0 auto 10px" }} />
          Fetching records from MySQL...
        </div>
      )}

      {/* No records */}
      {!loading && records.length === 0 && (
        <div style={{
          textAlign: "center", padding: "40px 20px", color: "var(--text-muted)",
          background: "rgba(255,255,255,0.02)", borderRadius: 12, border: "1px dashed rgba(255,255,255,0.06)",
        }}>
          <i className="bi bi-database-x" style={{ fontSize: "2rem", opacity: 0.4, display: "block", marginBottom: 10 }} />
          <div style={{ fontSize: "0.82rem", fontWeight: 600 }}>No records found</div>
          <div style={{ fontSize: "0.72rem", marginTop: 4 }}>
            {filter === "EXPIRED"
              ? "No records older than 3 years — retention policy is being followed."
              : "Scan files to auto-populate the database, or check MySQL connection."}
          </div>
        </div>
      )}

      {/* Records table */}
      {!loading && records.length > 0 && (
        <div style={{ overflowX: "auto", borderRadius: 10, border: "1px solid rgba(255,255,255,0.06)" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.74rem" }}>
            <thead>
              <tr style={{ background: "rgba(56,189,248,0.06)" }}>
                {["Record ID", "User ID", "Data Type", "Category", "Value", "Uploaded Date", "Status"].map(h => (
                  <th key={h} style={{
                    padding: "10px 14px", textAlign: "left", fontWeight: 700, fontSize: "0.68rem",
                    color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.5px",
                    borderBottom: "1px solid rgba(255,255,255,0.06)",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pageRecords.map((rec, idx) => {
                const expired = isExpired(rec.uploaded_at);
                return (
                <tr key={rec.record_id || idx} style={{
                  borderBottom: "1px solid rgba(255,255,255,0.03)",
                  background: expired
                    ? "rgba(251,191,36,0.08)"
                    : idx % 2 === 0 ? "transparent" : "rgba(255,255,255,0.015)",
                  borderLeft: expired ? "3px solid #fbbf24" : "3px solid transparent",
                }}>
                  <td style={{ padding: "9px 14px", color: "var(--text-muted)", fontFamily: "monospace", fontSize: "0.7rem" }}>
                    #{rec.record_id}
                  </td>
                  <td style={{ padding: "9px 14px", fontWeight: 600, color: "var(--text-primary)" }}>
                    {rec.user_id}
                  </td>
                  <td style={{ padding: "9px 14px" }}>
                    <span style={{
                      padding: "2px 8px", borderRadius: 6, fontSize: "0.64rem", fontWeight: 700,
                      background: `${typeColors[rec.data_type] || "#999"}15`,
                      color: typeColors[rec.data_type] || "#999",
                      border: `1px solid ${typeColors[rec.data_type] || "#999"}30`,
                    }}>
                      {rec.data_type}
                    </span>
                  </td>
                  <td style={{ padding: "9px 14px", color: "#a78bfa", fontWeight: 600 }}>
                    {rec.data_category}
                  </td>
                  <td style={{ padding: "9px 14px", color: "var(--text-secondary)", fontFamily: "monospace", fontSize: "0.7rem" }}>
                    {maskPiiValue(rec.data_value, rec.data_category)}
                  </td>
                  <td style={{ padding: "9px 14px", color: expired ? "#fbbf24" : "var(--text-muted)", fontSize: "0.7rem", fontWeight: expired ? 700 : 400 }}>
                    {rec.uploaded_at}
                  </td>
                  <td style={{ padding: "9px 14px", textAlign: "center" }}>
                    {expired ? (
                      <span style={{
                        display: "inline-flex", alignItems: "center", gap: 4,
                        padding: "3px 10px", borderRadius: 6, fontSize: "0.64rem", fontWeight: 700,
                        background: "rgba(251,191,36,0.15)", color: "#fbbf24",
                        border: "1px solid rgba(251,191,36,0.3)",
                      }}>
                        <i className="bi bi-exclamation-triangle-fill" /> Expired
                      </span>
                    ) : (
                      <span style={{
                        display: "inline-flex", alignItems: "center", gap: 4,
                        padding: "3px 10px", borderRadius: 6, fontSize: "0.64rem", fontWeight: 600,
                        background: "rgba(52,211,153,0.1)", color: "#34d399",
                        border: "1px solid rgba(52,211,153,0.2)",
                      }}>
                        <i className="bi bi-check-circle-fill" /> Active
                      </span>
                    )}
                  </td>
                </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Retention warning for expired records */}
      {expiredCount > 0 && (
        <div style={{
          marginTop: 14, padding: "12px 16px", borderRadius: 10,
          background: "rgba(251,191,36,0.06)", border: "1px solid rgba(251,191,36,0.2)",
          fontSize: "0.74rem", color: "#fcd34d",
        }}>
          <i className="bi bi-exclamation-triangle-fill" style={{ color: "#fbbf24", marginRight: 6 }} />
          <strong>{expiredCount} records</strong> exceed the 3-year retention period under DPDPA Section 8 (Storage Limitation).
          These are highlighted in yellow and sorted to the top. Review and purge if their processing purpose has been fulfilled.
        </div>
      )}

      {/* Pagination */}
      {!loading && totalPages > 1 && (
        <div style={{ display: "flex", justifyContent: "center", alignItems: "center", gap: 6, marginTop: 14 }}>
          <button onClick={() => setPage(1)} disabled={page === 1} style={{
            padding: "5px 10px", borderRadius: 6, fontSize: "0.7rem", cursor: page === 1 ? "default" : "pointer",
            border: "1px solid rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.03)",
            color: page === 1 ? "rgba(255,255,255,0.2)" : "var(--text-muted)", opacity: page === 1 ? 0.5 : 1,
          }}><i className="bi bi-chevron-double-left" /></button>
          <button onClick={() => setPage(p => Math.max(1, p - 1))} disabled={page === 1} style={{
            padding: "5px 10px", borderRadius: 6, fontSize: "0.7rem", cursor: page === 1 ? "default" : "pointer",
            border: "1px solid rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.03)",
            color: page === 1 ? "rgba(255,255,255,0.2)" : "var(--text-muted)", opacity: page === 1 ? 0.5 : 1,
          }}><i className="bi bi-chevron-left" /></button>
          <span style={{ fontSize: "0.72rem", color: "var(--text-muted)", padding: "0 8px", fontWeight: 600 }}>
            Page {page} of {totalPages}
          </span>
          <button onClick={() => setPage(p => Math.min(totalPages, p + 1))} disabled={page === totalPages} style={{
            padding: "5px 10px", borderRadius: 6, fontSize: "0.7rem", cursor: page === totalPages ? "default" : "pointer",
            border: "1px solid rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.03)",
            color: page === totalPages ? "rgba(255,255,255,0.2)" : "var(--text-muted)", opacity: page === totalPages ? 0.5 : 1,
          }}><i className="bi bi-chevron-right" /></button>
          <button onClick={() => setPage(totalPages)} disabled={page === totalPages} style={{
            padding: "5px 10px", borderRadius: 6, fontSize: "0.7rem", cursor: page === totalPages ? "default" : "pointer",
            border: "1px solid rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.03)",
            color: page === totalPages ? "rgba(255,255,255,0.2)" : "var(--text-muted)", opacity: page === totalPages ? 0.5 : 1,
          }}><i className="bi bi-chevron-double-right" /></button>
        </div>
      )}

      <div style={{ marginTop: 12, fontSize: "0.66rem", color: "var(--text-muted)", textAlign: "center", opacity: 0.5 }}>
        Source: MySQL &middot; <code>db.personal_data_records</code> &middot; Showing {perPage} per page &middot; DPDPA-aligned retention tracking
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   FOOTER
   ═══════════════════════════════════════════════════════ */

function Footer() {
  return (
    <div className="footer" style={{ position:"relative", zIndex:1 }}>
      <div className="footer-content">
        <div className="footer-brand">
          <i className="bi bi-shield-shaded me-2" />PII Sentinel v2.0
        </div>
        <div className="footer-text">
          Enterprise-Wide Personal Data Discovery &amp; Classification (DPDPA-Aligned) · Problem Statement 3
        </div>
        <div className="footer-links">
          Built with React · Flask · DPDPA Aligned &nbsp;·&nbsp;
          <span className="text-danger"><i className="bi bi-heart-fill" /></span>
        </div>
      </div>
    </div>
  );
}


/* ═══════════════════════════════════════════════════════
   MOUNT
   ═══════════════════════════════════════════════════════ */

const root = ReactDOM.createRoot(document.getElementById("root"));
root.render(<App />);
