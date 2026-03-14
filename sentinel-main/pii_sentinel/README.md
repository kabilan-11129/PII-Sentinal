# 🛡️ PII Sentinel

**Enterprise-Wide Personal Data Discovery & Classification (DPDPA-Aligned)**

PII Sentinel scans uploaded documents to discover and classify **Personally Identifiable Information (PII)**, helping organizations comply with India's **Digital Personal Data Protection Act (DPDPA), 2023**.

---

## ✨ Features

| Feature | Description |
|---|---|
| **File Upload** | Upload TXT, CSV, PDF, DOCX files (drag & drop supported) |
| **PII Detection** | Regex-based detection of Email, Phone, PAN, Aadhaar |
| **Classification** | Automatic sensitivity levels (LOW / MEDIUM / HIGH) |
| **Risk Scoring** | File-level risk assessment based on detected PII |
| **Dashboard** | Interactive metrics, charts, and detailed results |
| **Compliance Report** | Downloadable CSV report for audit / regulatory review |
| **DPDPA Reference** | Quick reference to relevant DPDPA sections |
| **File Lineage Tracking** | SHA-256 fingerprinted lifecycle tracking across systems |
| **Breach Alerts** | Rule-based alerts for external sharing, mass downloads, unexpected propagation |

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10+
- pip

### Installation & Run

```bash
cd pii_sentinel
pip install -r requirements.txt
python app.py
```

Open your browser at **http://localhost:5000**

### Local Monitoring Agent (optional)

```bash
python scanner/local_monitor_agent.py --path "C:/Users/you/Documents" --collector "http://localhost:5000/api/file-events" --user employee1 --system laptop --recursive
```

The agent uses `watchdog` to capture filesystem events and sends them to the central collector.

---

## File Lineage & Movement APIs

- `POST /api/file-events` — append one lifecycle event (CREATE/READ/COPY/MOVE/DOWNLOAD/SHARE/MODIFY/DELETE)
- `GET /api/file-events` — fetch event log (append-only)
- `GET /api/file-timeline/<file_hash>` — full lifecycle timeline for one file fingerprint
- `GET /api/file-lineage-graph` — nodes and edges for lineage visualization
- `GET /api/file-alerts` — breach alerts from detection rules
- `GET /api/file-tracker-summary` — aggregate tracking metrics
- `POST /api/file-events/email` — email attachment movement connector
- `POST /api/file-events/cloud` — cloud storage movement connector

---

## 📁 Project Structure

```
pii_sentinel/
├── app.py                       # Flask application (routes, upload, dashboard)
├── requirements.txt             # Python dependencies
├── sample_data.txt              # Sample file for testing
│
├── scanner/                     # PII scanning engine
│   ├── __init__.py
│   ├── file_parser.py           # Text extraction (TXT, CSV, PDF, DOCX)
│   ├── pii_detector.py          # Regex-based PII detection
│   └── classifier.py            # Sensitivity classification & risk scoring
│
├── reports/                     # Report generation
│   ├── __init__.py
│   └── report_generator.py      # CSV compliance report builder
│
├── templates/
│   └── index.html               # Dashboard HTML (Bootstrap 5 + Chart.js)
│
├── static/
│   ├── style.css                # Custom dark theme CSS
│   └── script.js                # Frontend JS (drag-drop, charts)
│
└── uploads/                     # Uploaded files storage
```

---

## 🔍 Detectable PII Types

| PII Type | Pattern | Sensitivity |
|---|---|---|
| **Email** | `user@domain.com` | 🟡 MEDIUM |
| **Phone** | Indian 10-digit mobile (6-9 start) | 🟡 MEDIUM |
| **PAN** | `ABCDE1234F` format | 🔴 HIGH |
| **Aadhaar** | 12-digit number (space/dash separated OK) | 🔴 HIGH |

---

## 📊 Risk Assessment

| Risk Level | Condition |
|---|---|
| 🔴 **HIGH** | PAN or Aadhaar detected |
| 🟡 **MEDIUM** | Phone number detected (no HIGH) |
| 🟢 **LOW** | Only email or no PII |

---

## 🏛️ DPDPA Alignment

| Section | Obligation |
|---|---|
| **Section 4** | Lawful processing of personal data |
| **Section 5** | Data principal's right to information |
| **Section 6** | Consent requirements |
| **Section 8** | Security safeguards by data fiduciaries |
| **Section 9** | Children's data protections |

---

## 🛠️ Tech Stack

- **Python 3** + **Flask** — Backend
- **HTML / CSS / JavaScript / Bootstrap 5** — Frontend
- **Regex** + **Pandas** — PII detection & data processing
- **pdfminer.six** — PDF text extraction
- **python-docx** — DOCX text extraction
- **Chart.js** — Interactive visualizations
