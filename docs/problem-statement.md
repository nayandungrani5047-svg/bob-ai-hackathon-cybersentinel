# Problem Statement

## 1. Target Audience

CyberSentinel is designed for defence and security analysts who need to review and investigate large volumes of threat alerts from multiple sources.

## 2. The Problem

Security analysts may receive large numbers of alerts from SIEM systems, cyber sensors, satellite feeds, and intelligence reports. These alerts can arrive in different formats and may contain overlapping or related information.

Manually reviewing and correlating such alerts can make it difficult to identify genuine threats quickly. At the same time, false positives can consume valuable analyst time and attention.

The key challenge is to transform large volumes of multi-source alerts into a smaller number of meaningful, prioritized incidents that analysts can investigate efficiently.

## 3. Why Existing Workflows Are Challenging

Traditional alert-review workflows can require analysts to:

- Review alerts from multiple sources.
- Understand different alert formats.
- Identify relationships between related alerts.
- Separate likely genuine threats from false positives.
- Determine which incidents require the most attention.
- Map observed activity to relevant MITRE ATT&CK techniques.
- Prepare investigation summaries for decision-making.

These activities can become difficult when alert volume increases.

## 4. What CyberSentinel Addresses

CyberSentinel provides an end-to-end defensive workflow that:

1. Ingests synthetic multi-source threat alerts.
2. Normalizes the alert information.
3. Correlates related alerts.
4. Identifies likely genuine threats and false positives.
5. Prioritizes incidents using weighted scoring.
6. Maps identified activity to MITRE ATT&CK techniques.
7. Provides an investigation view with concise BLUF summaries.

## 5. Scope

The hackathon MVP focuses on demonstrating this workflow using synthetic threat-alert data.

It is designed as a defensive cybersecurity prototype and does not connect to real defence, government, or production security systems.

## 6. Why This Matters

The goal is to help analysts move from large volumes of raw alerts toward a more focused and investigation-ready view of potential threats.

By combining alert processing, correlation, prioritisation, MITRE ATT&CK mapping, and investigation summaries in one workflow, CyberSentinel demonstrates a practical approach to reducing analyst workload and improving threat-triage efficiency.