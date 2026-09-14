# Architecture

## 1. System Architecture

```mermaid
flowchart TD
    A[Synthetic Multi-Source Alerts] --> B[Alert Ingestion]
    B --> C[Alert Normalization]
    C --> D[Alert Correlation]
    D --> E[False-Positive Detection]
    E --> F[Threat Prioritisation]
    F --> G[MITRE ATT&CK Mapping]
    G --> H[Investigation View]
    H --> I[BLUF Summary]

    J[React + Vite Frontend] --> K[FastAPI Backend]
    K --> B
    K --> H
    
    ## 2. Main Components

| Component | Technology | Purpose |
|---|---|---|
| Frontend | React + Vite + Tailwind CSS | Analyst dashboard and investigation interface |
| Backend | Python + FastAPI | API layer and application logic |
| Database | SQLite | Local application data storage |
| Alert Pipeline | Python | Normalization, correlation, classification, and prioritisation |
| MITRE Mapping | Local JSON/sample data | Maps threat activity to MITRE ATT&CK techniques |
| Charts | Chart.js | Dashboard visualisation |
| Data | Synthetic JSON/CSV | Controlled hackathon threat-alert dataset |

## 3. End-to-End Data Flow

1. Synthetic alerts are loaded into the application.
2. The backend ingests the alerts.
3. Alerts are normalized into a consistent structure.
4. Related alerts are correlated into potential incidents.
5. Heuristic logic identifies likely false positives.
6. Weighted scoring determines incident priority.
7. Relevant MITRE ATT&CK techniques are mapped.
8. The investigation interface presents incident evidence and analysis.
9. A concise BLUF summary supports rapid understanding.

## 4. Frontend Architecture

The React frontend provides:

- Dashboard
- Alert list
- Alert ingestion controls
- Incident list
- Investigation view
- Priority information
- MITRE ATT&CK information
- BLUF summaries

The frontend communicates with the FastAPI backend through API requests.

## 5. Backend Architecture

The FastAPI backend provides API endpoints for:

- Dashboard information
- Alert ingestion
- Alert data
- Incident information
- Investigation data

The backend connects the API layer with the threat-analysis pipeline and SQLite database.

## 6. Threat Analysis Pipeline

The threat analysis pipeline consists of the following stages:

```text
Input Alerts
    ↓
Normalization
    ↓
Correlation
    ↓
False-Positive Classification
    ↓
Weighted Prioritisation
    ↓
MITRE ATT&CK Mapping
    ↓
Investigation / BLUF

## 7. Security Considerations

The hackathon implementation uses synthetic data and does not connect to real defence or government systems.

The prototype avoids storing real credentials or production threat intelligence.

Environment-specific secrets should be kept outside the repository and should not be committed to Git.

## 8. Scalability Considerations

The current implementation is designed as a lightweight hackathon MVP.

Future versions could improve scalability by:

- Replacing SQLite with a production database.
- Adding scalable message or event processing.
- Connecting to live threat-intelligence feeds.
- Improving correlation with advanced AI/ML techniques.
- Adding authentication and role-based access control.
- Deploying backend and frontend as

## 9. IBM Bob in the Architecture Workflow

IBM Bob supported the devlopment lifecycle by helping with architecture planning, implementation, code review, testig,
and debugging.

The resulting application remains a conventional React + FastAPI application with the the threat-analysis logic 
implemented within the project source code.
