# 🚀 CyberSentinel — D2 Threat Intelligence Assistant

> An AI-powered defensive threat intelligence assistant for alert correlation, prioritisation, MITRE ATT&CK mapping, and investigation support.

---

## 👥 Team

| Field | Value |
|---|---|
| **Team Name** | CyberSentinel |
| **Track** | AI |
| **Team Lead** | Nayan Prakashbhai Dungrani — npdpatel203@gmail.com |
| **Members** | Nayan Prakashbhai Dungrani, Shashvat Bharatbhai Sutariya, Ridham Jayantibhai Katrodiya, Vraj Kantilal Koringa |

---

## 🎯 Problem Statement

Defence and security analysts can receive large volumes of alerts from SIEM systems, cyber sensors, satellite feeds, and intelligence reports in different formats. Manually reviewing and correlating these alerts makes it difficult to identify genuine threats quickly while false positives consume valuable investigation time.

---

## 💡 Solution

CyberSentinel is an AI-powered threat intelligence assistant that processes synthetic multi-source alerts, normalizes and correlates them, identifies likely genuine threats and false positives, and prioritizes incidents using weighted scoring. It also maps identified threats to MITRE ATT&CK techniques and provides investigation-focused BLUF summaries.

---

## ✨ Key Features

- **Multi-source Alert Ingestion:** Ingests synthetic alerts representing different threat intelligence sources.
- **Alert Correlation:** Normalizes and correlates related alerts to identify meaningful incidents.
- **Threat Prioritisation:** Uses weighted scoring to classify incidents into risk levels.
- **MITRE ATT&CK Mapping:** Maps identified threat activity to relevant MITRE ATT&CK techniques.
- **Investigation & BLUF:** Provides an investigation view with concise BLUF summaries for analysts.

---

## 🛠️ Tech Stack

| Category | Technologies |
|---|---|
| **Languages** | Python, JavaScript |
| **Frameworks** | FastAPI, React, Vite, Tailwind CSS |
| **IBM Technologies** | IBM Bob |
| **Databases** | SQLite |
| **Other** | Docker, GitHub Actions, Chart.js, Synthetic JSON/CSV data |

---

## 📁 Repository Structure

```text
├── src/
│   ├── backend/           # FastAPI backend and threat analysis pipeline
│   └── frontend/          # React frontend dashboard
├── docs/                  # Written documentation
│   ├── problem-statement.md
│   ├── solution-overview.md
│   ├── architecture.md
│   └── setup-guide.md
├── demo/                  # Demo artifacts
│   ├── screenshots/
│   ├── demo-video-link.txt
│   └── live-demo-url.txt
├── presentation/          # Slide deck
└── submission.yaml        # Structured submission metadata

## ⚡ How to Run

### Backend

```bash
cd src/backend
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload

### Frontend

```bash
cd src/frontend
npm.cmd install
npm.cmd run dev

## 🖥️ Demo

| Artifact | Link |
|---|---|
| 📹 Demo Video | [See demo/demo-video-link.txt](demo/demo-video-link.txt) |
| 🌐 Live Demo | [See demo/live-demo-url.txt](demo/live-demo-url.txt) |
| 🖼️ Screenshots | [See demo/screenshots/](demo/screenshots/) |
| 📊 Presentation | [See presentation/](presentation/) |

---

## ⚠️ Known Limitations

- The current MVP uses synthetic threat-alert data rather than live defence or government data sources.
- Alert correlation, false-positive detection, and prioritisation currently use local rules, heuristics, and weighted scoring.
- MITRE ATT&CK mapping is based on local/sample mapping data.
- The project is a hackathon prototype and is not intended for direct use with production defence systems.

---

## 🏅 What We're Most Proud Of

We are most proud of creating an end-to-end defensive threat intelligence workflow that transforms large volumes of synthetic alerts into correlated, prioritized, and investigation-ready incidents. The combination of alert analysis, MITRE ATT&CK mapping, investigation views, and BLUF summaries demonstrates how IBM Bob can accelerate the development of a practical AI-powered cybersecurity solution.

---