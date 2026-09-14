# Solution Overview

## 1. Solution

CyberSentinel is an AI-powered defensive threat intelligence assistant designed to help security analysts process and investigate large volumes of threat alerts.

The system converts synthetic multi-source alerts into normalized, correlated, prioritized, and investigation-ready incidents.

## 2. Core Mechanism

The solution follows this workflow:

```text
Synthetic Threat Sources
        ↓
Alert Ingestion
        ↓
Alert Normalization
        ↓
Alert Correlation
        ↓
False-Positive Detection
        ↓
Threat Prioritisation
        ↓
MITRE ATT&CK Mapping
        ↓
Investigation View
        ↓
BLUF Summary

## 3. Key Capabilities

### Alert Ingestion

CyberSentinel accepts synthetic alerts representing multiple threat intelligence sources.

### Alert Normalization

Alerts are converted into a consistent structure so that information from different sources can be processed together.

### Alert Correlation

Related alerts are grouped using rule-based correlation logic to identify meaningful incident patterns.

### False-Positive Detection

Heuristic rules help identify alerts that are more likely to be false positives, reducing unnecessary investigation effort.

### Threat Prioritisation

A weighted scoring approach assigns risk levels to incidents, helping analysts focus on higher-priority activity first.

### MITRE ATT&CK Mapping

Identified threat activity is mapped to relevant MITRE ATT&CK techniques using local/sample mapping data.

### Investigation and BLUF

Analysts can open an incident to review its evidence, priority, MITRE ATT&CK information, and a concise BLUF investigation summary.

## 4. Design Decisions

The hackathon MVP uses local processing rather than depending on live external threat-intelligence services.

The main analysis components use:

- Rule-based alert correlation
- Heuristic false-positive detection
- Weighted threat scoring
- Local/sample MITRE ATT&CK mappings
- Synthetic alert data

This makes the prototype reproducible and suitable for a controlled hackathon demonstration.

## 5. User Experience

The interface is organized around the analyst workflow:

1. **Dashboard** — provides an overview of alerts and incidents.
2. **Alerts** — displays available synthetic alerts and supports ingestion.
3. **Incidents** — displays correlated and prioritized incidents.
4. **Investigation** — provides detailed incident information, MITRE ATT&CK mapping, and BLUF summaries.

The goal is to reduce the amount of raw alert information an analyst needs to manually process before beginning an investigation.

## 6. Differentiation

CyberSentinel combines multiple defensive analysis steps into a single workflow rather than treating alert review, prioritisation, threat mapping, and investigation summaries as separate tasks.

Its main differentiators are:

- Multi-source alert normalization and correlation.
- Automated prioritisation using weighted scoring.
- Heuristic false-positive identification.
- MITRE ATT&CK mapping within the investigation workflow.
- BLUF summaries designed for rapid analyst understanding.
- End-to-end implementation accelerated with IBM Bob.

## 7. IBM Bob Integration

IBM Bob was used as an AI-powered development partner throughout the implementation process.

It supported the development workflow by helping with:

- Architecture and project planning.
- Backend and frontend implementation.
- Feature development.
- Code organization and review.
- Testing and debugging.
- Development workflow acceleration.

IBM Bob is therefore integrated into the actual software development process rather than being included only as a project description.

## 8. Current Scope

The current implementation is a hackathon MVP using synthetic data and local analysis components.

It demonstrates the complete defensive workflow while leaving room for future integration with live threat-intelligence feeds, production-grade data pipelines, and more advanced AI analysis.