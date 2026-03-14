/**
 * script.js — PII Sentinel frontend interactions
 *
 * Handles:
 *  • Scan loading overlay with animated step progress
 *  • Drag-and-drop with full-page drag detection
 *  • Client-side file validation (type + size)
 *  • File list preview before upload
 *  • Chart.js visualizations (PII donut, Risk bar, Sensitivity chart)
 *  • Counter animations for stat cards
 *  • Scroll-to-top button
 *  • Copy-to-clipboard for masked PII values
 *  • Bootstrap tooltip initialization
 *  • Auto-scroll to results after scan
 *  • Auto-dismiss flash messages
 */

const MAX_FILE_SIZE_MB = 16;
const ALLOWED_TYPES = ["txt", "csv", "pdf", "docx"];

document.addEventListener("DOMContentLoaded", () => {

  // ────────────────────────────────────────────
  // Bootstrap tooltips
  // ────────────────────────────────────────────
  const tooltipEls = document.querySelectorAll('[data-bs-toggle="tooltip"]');
  tooltipEls.forEach((el) => new bootstrap.Tooltip(el, { trigger: "hover" }));

  // ────────────────────────────────────────────
  // Drag & drop — upload zone + page-level
  // ────────────────────────────────────────────
  const uploadZone = document.getElementById("upload-zone");
  const fileInput  = document.getElementById("file-input");
  const fileList   = document.getElementById("file-list-preview");
  const scanBtn    = document.getElementById("btn-scan");

  if (uploadZone && fileInput) {

    // Zone-level drag styling
    ["dragenter", "dragover"].forEach((evt) => {
      uploadZone.addEventListener(evt, (e) => {
        e.preventDefault();
        uploadZone.classList.add("drag-over");
      });
    });

    ["dragleave", "drop"].forEach((evt) => {
      uploadZone.addEventListener(evt, () => uploadZone.classList.remove("drag-over"));
    });

    uploadZone.addEventListener("drop", (e) => {
      e.preventDefault();
      fileInput.files = e.dataTransfer.files;
      showFilePreview(fileInput.files);
    });

    fileInput.addEventListener("change", () => showFilePreview(fileInput.files));
  }

  // Page-level drag-over highlight
  let dragCounter = 0;
  document.addEventListener("dragenter", () => {
    dragCounter++;
    document.body.classList.add("page-drag-over");
  });
  document.addEventListener("dragleave", () => {
    dragCounter--;
    if (dragCounter === 0) document.body.classList.remove("page-drag-over");
  });
  document.addEventListener("drop", () => {
    dragCounter = 0;
    document.body.classList.remove("page-drag-over");
  });

  /**
   * Validate files and show preview chips with name, size, and type icon.
   * Shows an inline error if a file fails validation.
   */
  function showFilePreview(files) {
    if (!fileList) return;
    fileList.innerHTML = "";
    if (!files || files.length === 0) return;

    const iconMap = {
      txt:  "bi-file-text-fill",
      csv:  "bi-filetype-csv",
      pdf:  "bi-file-earmark-pdf-fill",
      docx: "bi-file-earmark-word-fill",
    };

    const colorMap = {
      txt:  "#6366f1",
      csv:  "#22c55e",
      pdf:  "#ef4444",
      docx: "#3b82f6",
    };

    const container = document.createElement("div");
    container.style.cssText = "display:flex;flex-wrap:wrap;gap:8px;";

    let hasError = false;

    for (const f of files) {
      const ext  = f.name.split(".").pop().toLowerCase();
      const icon = iconMap[ext] || "bi-file-earmark-fill";
      const color = colorMap[ext] || "var(--accent-primary)";
      const sizeMB = f.size / (1024 * 1024);
      const sizeStr = sizeMB < 1
        ? (f.size / 1024).toFixed(1) + " KB"
        : sizeMB.toFixed(1) + " MB";

      const invalid = !ALLOWED_TYPES.includes(ext) || sizeMB > MAX_FILE_SIZE_MB;

      const chip = document.createElement("div");
      chip.className = "pii-chip" + (invalid ? " chip-high" : "");
      chip.style.cssText = invalid ? "" : `border-color: ${color}30;`;
      chip.innerHTML = `
        <i class="bi ${icon}" style="color:${invalid ? "var(--danger)" : color}"></i>
        <span>${f.name}</span>
        <span style="color:var(--text-muted);font-size:0.68rem;">(${sizeStr})</span>
        ${invalid ? '<i class="bi bi-exclamation-circle-fill" style="color:var(--danger);margin-left:2px;" title="Invalid file"></i>' : ""}
      `;
      container.appendChild(chip);

      if (invalid) hasError = true;
    }

    fileList.appendChild(container);

    // Show error message if any file is invalid
    const existing = document.getElementById("file-error-msg");
    if (existing) existing.remove();

    if (hasError) {
      const msg = document.createElement("div");
      msg.id = "file-error-msg";
      msg.className = "file-error-msg";
      msg.innerHTML = `<i class="bi bi-exclamation-triangle-fill"></i>
        Some files are invalid (unsupported type or &gt;16 MB). They will be skipped.`;
      fileList.appendChild(msg);
    }

    // Enable/disable scan button
    const anyValid = Array.from(files).some((f) => {
      const ext = f.name.split(".").pop().toLowerCase();
      return ALLOWED_TYPES.includes(ext) && f.size / (1024 * 1024) <= MAX_FILE_SIZE_MB;
    });
    if (scanBtn) scanBtn.disabled = !anyValid;
  }

  // ────────────────────────────────────────────
  // Scan loading overlay & step animation
  // ────────────────────────────────────────────
  const uploadForm = document.getElementById("upload-form");
  const overlay    = document.getElementById("scan-overlay");
  const steps      = ["ovl-step-1", "ovl-step-2", "ovl-step-3", "ovl-step-4"];
  let   stepIndex  = 0;
  let   stepTimer  = null;

  if (uploadForm && scanBtn && overlay) {
    uploadForm.addEventListener("submit", (e) => {
      // Basic validation: at least one file selected
      if (!fileInput || !fileInput.files || fileInput.files.length === 0) {
        e.preventDefault();
        if (uploadZone) {
          uploadZone.style.borderColor = "var(--danger)";
          setTimeout(() => (uploadZone.style.borderColor = ""), 2000);
        }
        return;
      }

      // Show overlay
      overlay.classList.add("active");
      scanBtn.disabled = true;
      scanBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Scanning...';

      // Cycle through steps
      const stepEls = steps.map((id) => document.getElementById(id));
      stepIndex = 0;
      if (stepEls[0]) stepEls[0].classList.add("active");

      stepTimer = setInterval(() => {
        if (stepEls[stepIndex]) stepEls[stepIndex].classList.replace("active", "done");
        stepIndex++;
        if (stepIndex < stepEls.length) {
          if (stepEls[stepIndex]) stepEls[stepIndex].classList.add("active");
        } else {
          clearInterval(stepTimer);
        }
      }, 1200);
    });
  }

  // ────────────────────────────────────────────
  // Auto-scroll to results after scan
  // ────────────────────────────────────────────
  const resultsAnchor = document.getElementById("results-anchor");
  const hasResults    = document.getElementById("results-section");
  if (resultsAnchor && hasResults) {
    // If we just came back from a scan (flash alert is visible), scroll to results
    const flashAlert = document.getElementById("flash-alert");
    if (flashAlert) {
      setTimeout(() => {
        resultsAnchor.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 400);
    }
  }

  // ────────────────────────────────────────────
  // Counter animation for stat cards
  // ────────────────────────────────────────────
  animateCounters();

  // ────────────────────────────────────────────
  // Charts
  // ────────────────────────────────────────────
  renderCharts();

  // ────────────────────────────────────────────
  // Scroll-to-top button
  // ────────────────────────────────────────────
  const scrollTopBtn = document.getElementById("scrollTopBtn");
  if (scrollTopBtn) {
    window.addEventListener("scroll", () => {
      if (window.scrollY > 300) {
        scrollTopBtn.classList.add("visible");
      } else {
        scrollTopBtn.classList.remove("visible");
      }
    }, { passive: true });

    scrollTopBtn.addEventListener("click", () => {
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  // ────────────────────────────────────────────
  // Auto-dismiss flash messages after 6s
  // ────────────────────────────────────────────
  document.querySelectorAll(".alert").forEach((alert) => {
    setTimeout(() => {
      const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
      if (bsAlert) bsAlert.close();
    }, 6000);
  });

});


// ── Global: Copy to clipboard ─────────────────────────
/**
 * Called from inline onclick in the compliance table.
 * Copies the given value to clipboard and shows a toast.
 */
function copyValue(value) {
  if (!value || value === "—") return;

  navigator.clipboard.writeText(value).then(() => {
    const toast = document.getElementById("copyToast");
    if (!toast) return;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 2200);
  }).catch(() => {
    // Fallback for older browsers
    const ta = document.createElement("textarea");
    ta.value = value;
    ta.style.cssText = "position:fixed;opacity:0;";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);

    const toast = document.getElementById("copyToast");
    if (toast) {
      toast.classList.add("show");
      setTimeout(() => toast.classList.remove("show"), 2200);
    }
  });
}


// ── Counter animation ──────────────────────────────────
/**
 * Animates stat card number values from 0 to target using easeOutQuart.
 */
function animateCounters() {
  document.querySelectorAll(".counter").forEach((counter) => {
    const target = parseInt(counter.getAttribute("data-target")) || 0;
    if (target === 0) return;

    const duration = 1400;
    const startTime = performance.now();

    function easeOutQuart(t) {
      return 1 - Math.pow(1 - t, 4);
    }

    function tick(now) {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const value = Math.round(easeOutQuart(progress) * target);
      counter.textContent = value;
      if (progress < 1) requestAnimationFrame(tick);
    }

    requestAnimationFrame(tick);
  });
}


// ── Chart rendering ────────────────────────────────────
/**
 * Fetch summary data from the API and render all three charts.
 */
function renderCharts() {
  fetch("/api/summary")
    .then((res) => res.json())
    .then((data) => {
      drawPiiDonut(data.pii_type_counts || {});
      drawRiskBar(data.risk_counts || {});
      drawSensitivityChart(data.sensitivity_counts || {});
    })
    .catch((err) => console.log("Chart data unavailable:", err));
}


// ── Shared chart config ────────────────────────────────
const chartFont  = "'Inter', sans-serif";
const chartGrid  = "rgba(255, 255, 255, 0.03)";
const chartText  = "#8892b0";
const chartTip   = {
  backgroundColor: "rgba(13, 16, 37, 0.95)",
  borderColor: "rgba(99, 102, 241, 0.2)",
  borderWidth: 1,
  titleColor: "#e2e8f0",
  bodyColor: "#94a3b8",
  titleFont: { family: chartFont, weight: "700" },
  bodyFont: { family: chartFont },
  padding: 12,
  cornerRadius: 8,
};

function chartEmptyState(canvas, icon, text) {
  canvas.parentElement.innerHTML = `
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;
                height:100%;min-height:200px;color:var(--text-muted);gap:10px;">
      <i class="bi ${icon}" style="font-size:2.2rem;opacity:0.25;color:var(--accent-primary)"></i>
      <span style="font-size:0.82rem;">${text}</span>
    </div>`;
}


/**
 * PII Type Distribution — Doughnut chart
 */
function drawPiiDonut(piiCounts) {
  const canvas = document.getElementById("piiDonutChart");
  if (!canvas) return;

  const labels = Object.keys(piiCounts);
  const values = Object.values(piiCounts);

  if (labels.length === 0) {
    chartEmptyState(canvas, "bi-pie-chart", "No PII data yet");
    return;
  }

  const colors = ["#6366f1", "#a855f7", "#ec4899", "#f97316", "#06b6d4", "#22c55e"];

  new Chart(canvas, {
    type: "doughnut",
    data: {
      labels,
      datasets: [{
        data: values,
        backgroundColor: colors.slice(0, labels.length),
        borderColor: "#0d1025",
        borderWidth: 3,
        hoverOffset: 12,
        hoverBorderWidth: 0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: "68%",
      plugins: {
        legend: {
          position: "bottom",
          labels: {
            color: chartText,
            font: { family: chartFont, size: 11, weight: "500" },
            padding: 16,
            usePointStyle: true,
            pointStyleWidth: 10,
          },
        },
        title: {
          display: true,
          text: "PII Type Distribution",
          color: "#e2e8f0",
          font: { family: chartFont, size: 13, weight: "700" },
          padding: { bottom: 14 },
        },
        tooltip: { ...chartTip, displayColors: true, boxPadding: 4 },
      },
      animation: { animateRotate: true, animateScale: true, duration: 900, easing: "easeOutQuart" },
    },
  });
}


/**
 * Risk Level Distribution — Vertical bar chart
 */
function drawRiskBar(riskCounts) {
  const canvas = document.getElementById("riskBarChart");
  if (!canvas) return;

  const order  = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
  const labels = order.filter((l) => l in riskCounts);
  const values = labels.map((l) => riskCounts[l]);

  if (labels.length === 0) {
    chartEmptyState(canvas, "bi-bar-chart", "No risk data yet");
    return;
  }

  const colorMap = { LOW: "#22c55e", MEDIUM: "#f59e0b", HIGH: "#ef4444", CRITICAL: "#dc2626" };
  const colors   = labels.map((l) => colorMap[l] || "#6366f1");

  new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "Files",
        data: values,
        backgroundColor: colors.map((c) => c + "28"),
        borderColor: colors,
        borderWidth: 2,
        borderRadius: 10,
        barPercentage: 0.55,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          ticks: { color: chartText, font: { family: chartFont, weight: "600", size: 11 } },
          grid: { display: false },
          border: { color: "rgba(255,255,255,0.04)" },
        },
        y: {
          beginAtZero: true,
          ticks: { color: chartText, font: { family: chartFont, size: 11 }, stepSize: 1 },
          grid: { color: chartGrid },
          border: { display: false },
        },
      },
      plugins: {
        legend: { display: false },
        title: {
          display: true,
          text: "File Risk Distribution",
          color: "#e2e8f0",
          font: { family: chartFont, size: 13, weight: "700" },
          padding: { bottom: 14 },
        },
        tooltip: chartTip,
      },
      animation: { duration: 900, easing: "easeOutQuart" },
    },
  });
}


/**
 * Sensitivity Distribution — Horizontal bar chart
 */
function drawSensitivityChart(sensitivityCounts) {
  const canvas = document.getElementById("sensitivityChart");
  if (!canvas) return;

  const order  = ["LOW", "MEDIUM", "HIGH"];
  const labels = order.filter((l) => l in sensitivityCounts);
  const values = labels.map((l) => sensitivityCounts[l]);

  if (labels.length === 0) {
    chartEmptyState(canvas, "bi-shield", "No sensitivity data yet");
    return;
  }

  const colorMap = { LOW: "#22c55e", MEDIUM: "#f59e0b", HIGH: "#ef4444" };
  const colors   = labels.map((l) => colorMap[l] || "#6366f1");

  new Chart(canvas, {
    type: "bar",
    data: {
      labels,
      datasets: [{
        label: "PII Items",
        data: values,
        backgroundColor: colors.map((c) => c + "28"),
        borderColor: colors,
        borderWidth: 2,
        borderRadius: 10,
        barPercentage: 0.55,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: "y",
      scales: {
        x: {
          beginAtZero: true,
          ticks: { color: chartText, font: { family: chartFont, size: 11 }, stepSize: 1 },
          grid: { color: chartGrid },
          border: { display: false },
        },
        y: {
          ticks: { color: chartText, font: { family: chartFont, weight: "600", size: 11 } },
          grid: { display: false },
          border: { color: "rgba(255,255,255,0.04)" },
        },
      },
      plugins: {
        legend: { display: false },
        title: {
          display: true,
          text: "Sensitivity Level Distribution",
          color: "#e2e8f0",
          font: { family: chartFont, size: 13, weight: "700" },
          padding: { bottom: 14 },
        },
        tooltip: chartTip,
      },
      animation: { duration: 900, easing: "easeOutQuart" },
    },
  });
}
