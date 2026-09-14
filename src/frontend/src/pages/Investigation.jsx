import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { apiClient } from '../api/client.js';
import SeverityBadge from '../components/alerts/SeverityBadge.jsx';
import BlufPanel from '../components/investigation/BlufPanel.jsx';
import MitrePanel from '../components/investigation/MitrePanel.jsx';
import EvidenceList from '../components/investigation/EvidenceList.jsx';
import PriorityReasoningPanel from '../components/investigation/PriorityReasoningPanel.jsx';

/* ─── Helpers ─────────────────────────────────────────────────────────── */

function formatTime(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return ts;
  }
}

function formatDate(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleDateString(undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  } catch {
    return ts;
  }
}

function StatusBadge({ status }) {
  const isOpen = (status ?? '').toLowerCase() === 'open';
  return (
    <span
      className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium uppercase border ${
        isOpen
          ? 'bg-emerald-900 text-emerald-300 border-emerald-700'
          : 'bg-slate-800 text-slate-400 border-slate-600'
      }`}
    >
      {isOpen ? 'Open' : status ?? 'Unknown'}
    </span>
  );
}

function parseTechniques(raw) {
  if (Array.isArray(raw)) return raw;
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw);
    } catch {
      return [];
    }
  }
  return [];
}

/**
 * Builds a dynamic "Recommended Investigation Focus" block from incident data.
 */
function buildFocusSteps(incident, alerts) {
  const sev = (incident.severity ?? '').toLowerCase();

  // Collect unique IPs from alerts
  const sourceIPs = [
    ...new Set(
      (alerts ?? [])
        .filter((a) => a.source_ip && !a.is_false_positive)
        .map((a) => a.source_ip)
    ),
  ].slice(0, 4);

  const destIPs = [
    ...new Set(
      (alerts ?? [])
        .filter((a) => a.dest_ip && !a.is_false_positive)
        .map((a) => a.dest_ip)
    ),
  ].slice(0, 4);

  // Date range
  const timestamps = (alerts ?? [])
    .filter((a) => a.timestamp)
    .map((a) => new Date(a.timestamp).getTime())
    .filter(Boolean);
  const dateRange =
    timestamps.length >= 2
      ? `${formatDate(Math.min(...timestamps))} – ${formatDate(Math.max(...timestamps))}`
      : incident.created_at
      ? formatDate(incident.created_at)
      : 'unknown timeframe';

  const ipStr = sourceIPs.length ? sourceIPs.join(', ') : 'source hosts';
  const destStr = destIPs.length ? destIPs.join(', ') : 'affected systems';

  const escalate =
    sev === 'critical'
      ? 'Incident Response Team immediately — this is P1'
      : sev === 'high'
      ? 'Senior Security Analyst for triage within 1 hour'
      : 'Security team for scheduled review';

  return [
    `Isolate potentially compromised systems: ${destStr}`,
    `Review authentication logs for source addresses: ${ipStr}`,
    `Check affected systems for indicators of compromise (IOCs) matching observed alert signatures`,
    `Review network traffic captured between ${dateRange}`,
    `Escalate to: ${escalate}`,
  ];
}

/* ─── Loading / Error states ─────────────────────────────────────────── */

function FullPageSpinner() {
  return (
    <div className="flex items-center justify-center min-h-[60vh]">
      <div className="flex flex-col items-center gap-4">
        <div className="w-10 h-10 border-4 border-cyan-800 border-t-cyan-400 rounded-full animate-spin" />
        <p className="text-slate-400 text-sm font-mono">Loading investigation…</p>
      </div>
    </div>
  );
}

function ErrorCard({ message }) {
  return (
    <div className="m-6 bg-red-950/30 border border-red-800 rounded-lg p-6 max-w-lg">
      <p className="text-red-400 font-semibold mb-1">Failed to load investigation</p>
      <p className="text-red-300/70 text-sm font-mono">{message}</p>
    </div>
  );
}

/* ─── Main Page ──────────────────────────────────────────────────────── */

export default function Investigation() {
  const { id } = useParams();
  const navigate = useNavigate();

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [incident, setIncident] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [bluf, setBluf] = useState('');

  useEffect(() => {
    if (!id) return;
    setLoading(true);
    setError(null);
    apiClient
      .getInvestigation(id)
      .then((res) => {
        const data = res.data ?? {};
        setIncident(data.incident ?? null);
        setAlerts(data.alerts ?? []);
        setBluf(data.bluf ?? data.incident?.bluf ?? '');
      })
      .catch((err) => {
        setError(err?.response?.data?.detail ?? err?.message ?? 'Unknown error');
      })
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return <FullPageSpinner />;
  if (error) return <ErrorCard message={error} />;
  if (!incident) return <ErrorCard message="Incident not found." />;

  const techniques = parseTechniques(incident.mitre_techniques);

  // sources list
  const sourceList = Array.isArray(incident.sources)
    ? incident.sources
    : typeof incident.sources === 'string' && incident.sources
    ? incident.sources.split(',').map((s) => s.trim())
    : [];

  const focusSteps = buildFocusSteps(incident, alerts);

  return (
    <div className="min-h-screen bg-[#0a0f1a] px-4 py-6 space-y-6 max-w-[1400px] mx-auto">

      {/* ── Section 1: Incident Header ─────────────────────────────────── */}
      <div className="space-y-3">
        {/* Back button */}
        <button
          onClick={() => navigate('/incidents')}
          className="flex items-center gap-1.5 text-xs font-mono text-slate-400 hover:text-white transition-colors"
        >
          <span>←</span>
          <span>Back to Incidents</span>
        </button>

        {/* Title row */}
        <h1 className="text-2xl font-bold text-white leading-tight">
          {incident.title ?? `Incident ${id}`}
        </h1>

        {/* Meta badges row */}
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={incident.severity} />

          {incident.priority_score != null && (
            <span className="text-xs font-mono bg-[#0d1117] border border-[#21262d] text-white px-2.5 py-1 rounded">
              Score{' '}
              <span className="font-bold text-cyan-400">
                {Math.round(incident.priority_score)}
              </span>
              <span className="text-slate-500">/100</span>
            </span>
          )}

          <StatusBadge status={incident.status} />

          <span className="text-xs text-slate-500 font-mono">
            Created: {formatTime(incident.created_at)}
          </span>
        </div>

        {/* Alert count + sources row */}
        <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
          {incident.alert_count != null && (
            <span>
              <span className="text-slate-200 font-semibold">{incident.alert_count}</span>
              {' '}correlated alert{incident.alert_count !== 1 ? 's' : ''}
            </span>
          )}
          {sourceList.length > 0 && (
            <span className="flex items-center gap-1">
              {sourceList.map((s) => (
                <span
                  key={s}
                  className="bg-[#161b22] border border-[#21262d] text-slate-300 px-1.5 py-0.5 rounded font-mono"
                >
                  {s}
                </span>
              ))}
            </span>
          )}
          {incident.correlation_rule && (
            <span className="bg-blue-950 text-blue-300 border border-blue-800 px-2 py-0.5 rounded-full">
              {incident.correlation_rule}
            </span>
          )}
        </div>
      </div>

      {/* ── Section 2: BLUF Panel ──────────────────────────────────────── */}
      <BlufPanel
        bluf={bluf}
        severity={incident.severity}
        priority_score={incident.priority_score}
        title={incident.title}
      />

      {/* ── Section 3: Two-column layout ──────────────────────────────── */}
      <div className="flex flex-col xl:flex-row gap-6">
        {/* Left 60% — Evidence */}
        <div className="flex-[3] min-w-0">
          <EvidenceList alerts={alerts} />
        </div>

        {/* Right 40% — Reasoning + MITRE */}
        <div className="flex-[2] min-w-0 space-y-6">
          <PriorityReasoningPanel
            reasoning={incident.priority_reasoning}
            score={incident.priority_score}
            severity={incident.severity}
          />
          {techniques.length > 0 && (
            <MitrePanel techniques={techniques} />
          )}
        </div>
      </div>

      {/* ── Section 4: Recommended Investigation Focus ─────────────────── */}
      <div className="bg-[#0d1117] border border-[#21262d] rounded-lg overflow-hidden">
        <div className="px-5 py-3 border-b border-[#21262d] flex items-center gap-2">
          <span className="text-xs font-mono font-semibold uppercase tracking-widest text-amber-400">
            Recommended Investigation Focus
          </span>
        </div>
        <div className="px-5 py-4">
          <p className="text-xs text-slate-500 mb-3 font-mono">
            Based on the threat profile for this incident:
          </p>
          <ul className="space-y-2">
            {focusSteps.map((step, i) => (
              <li key={i} className="flex gap-3 text-sm text-slate-200 leading-relaxed">
                <span className="mt-0.5 text-amber-400 font-bold shrink-0">•</span>
                <span>{step}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

    </div>
  );
}
