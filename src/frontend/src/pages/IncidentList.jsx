import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { apiClient } from '../api/client.js';
import IncidentCard from '../components/incidents/IncidentCard.jsx';
import { useApp } from '../contexts/AppContext.jsx';

// ─── Filter options ────────────────────────────────────────────────────────────

const SEVERITY_FILTERS = ['All', 'Critical', 'High', 'Medium', 'Low'];
const STATUS_FILTERS = ['All', 'Open', 'Closed'];

// ─── Skeleton loader ───────────────────────────────────────────────────────────

function SkeletonCard() {
  return (
    <div className="bg-[#0d1117] border border-[#21262d] border-l-4 border-l-slate-700 rounded-lg p-4 flex flex-col gap-3 animate-pulse">
      <div className="flex gap-2 items-center">
        <div className="h-5 w-16 bg-slate-800 rounded-full" />
        <div className="h-5 w-20 bg-slate-800 rounded-full" />
        <div className="h-5 w-12 bg-slate-800 rounded-full" />
        <div className="ml-auto h-4 w-24 bg-slate-800 rounded" />
      </div>
      <div className="h-4 w-2/3 bg-slate-800 rounded" />
      <div className="flex gap-2">
        <div className="h-4 w-24 bg-slate-800 rounded" />
        <div className="h-4 w-20 bg-slate-800 rounded" />
      </div>
      <div className="flex gap-1.5">
        <div className="h-5 w-28 bg-slate-800 rounded-full" />
        <div className="h-5 w-24 bg-slate-800 rounded-full" />
        <div className="h-5 w-20 bg-slate-800 rounded-full" />
      </div>
    </div>
  );
}

// ─── Filter tab button ─────────────────────────────────────────────────────────

function FilterTab({ label, active, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
        active
          ? 'bg-[#21262d] text-white border border-[#30363d]'
          : 'text-slate-400 hover:text-slate-200 hover:bg-[#161b22]'
      }`}
    >
      {label}
    </button>
  );
}

// ─── Stats bar ─────────────────────────────────────────────────────────────────

function StatsBar({ incidents }) {
  const total = incidents.length;
  const critical = incidents.filter(
    (i) => (i.severity ?? '').toLowerCase() === 'critical'
  ).length;
  const high = incidents.filter(
    (i) => (i.severity ?? '').toLowerCase() === 'high'
  ).length;
  const open = incidents.filter(
    (i) => (i.status ?? '').toLowerCase() === 'open'
  ).length;

  return (
    <div className="flex flex-wrap gap-4 text-xs text-slate-400">
      <span>
        Total Incidents:{' '}
        <span className="text-white font-semibold">{total}</span>
      </span>
      <span>
        Critical:{' '}
        <span className="text-red-400 font-semibold">{critical}</span>
      </span>
      <span>
        High:{' '}
        <span className="text-orange-400 font-semibold">{high}</span>
      </span>
      <span>
        Open:{' '}
        <span className="text-emerald-400 font-semibold">{open}</span>
      </span>
    </div>
  );
}

// ─── Page ──────────────────────────────────────────────────────────────────────

export default function IncidentList() {
  const navigate = useNavigate();
  const { lastIngested } = useApp();

  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState('All');
  const [statusFilter, setStatusFilter] = useState('All');

  useEffect(() => {
    setLoading(true);
    setError(null);
    apiClient
      .getIncidents()
      .then(({ data }) => {
        // Normalise: parse mitre_techniques if it's still a JSON string
        const normalised = (Array.isArray(data) ? data : []).map((inc) => {
          if (typeof inc.mitre_techniques === 'string') {
            try {
              inc = { ...inc, mitre_techniques: JSON.parse(inc.mitre_techniques) };
            } catch {
              inc = { ...inc, mitre_techniques: [] };
            }
          }
          return inc;
        });
        setIncidents(normalised);
      })
      .catch((err) => {
        setError(err?.message ?? 'Failed to load incidents.');
      })
      .finally(() => setLoading(false));
  }, [lastIngested]);

  // Apply filters
  const filtered = incidents.filter((inc) => {
    if (
      severityFilter !== 'All' &&
      (inc.severity ?? '').toLowerCase() !== severityFilter.toLowerCase()
    ) {
      return false;
    }
    if (
      statusFilter !== 'All' &&
      (inc.status ?? '').toLowerCase() !== statusFilter.toLowerCase()
    ) {
      return false;
    }
    return true;
  });

  return (
    <div className="p-6 max-w-4xl mx-auto flex flex-col gap-5">
      {/* Page heading */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-2xl font-bold text-white font-mono">Incidents</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            Correlated threat incidents, sorted by priority score.
          </p>
        </div>

        {/* Priority sort indicator */}
        <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#161b22] border border-[#21262d] text-xs text-slate-300">
          <span className="text-brand-cyan">↓</span> Sorted by Threat Priority
        </span>
      </div>

      {/* Stats bar */}
      {!loading && !error && <StatsBar incidents={incidents} />}

      {/* Filter controls */}
      <div className="flex flex-wrap gap-4">
        {/* Severity */}
        <div className="flex items-center gap-1">
          <span className="text-xs text-slate-500 mr-1">Severity:</span>
          {SEVERITY_FILTERS.map((f) => (
            <FilterTab
              key={f}
              label={f}
              active={severityFilter === f}
              onClick={() => setSeverityFilter(f)}
            />
          ))}
        </div>

        {/* Status */}
        <div className="flex items-center gap-1">
          <span className="text-xs text-slate-500 mr-1">Status:</span>
          {STATUS_FILTERS.map((f) => (
            <FilterTab
              key={f}
              label={f}
              active={statusFilter === f}
              onClick={() => setStatusFilter(f)}
            />
          ))}
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-lg bg-red-950 border border-red-800 p-4 text-red-300 text-sm">
          {error}
        </div>
      )}

      {/* Loading skeletons */}
      {loading && (
        <div className="flex flex-col gap-3">
          {Array.from({ length: 5 }).map((_, i) => (
            <SkeletonCard key={i} />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && filtered.length === 0 && (
        <div className="flex flex-col items-center justify-center gap-3 py-16 text-slate-500">
          <svg
            className="w-10 h-10 opacity-40"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={1.5}
              d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"
            />
          </svg>
          <p className="text-sm">
            {incidents.length === 0
              ? "No incidents found. Click 'Ingest Alerts' to run correlation."
              : 'No incidents match the current filters.'}
          </p>
        </div>
      )}

      {/* Incident cards */}
      {!loading && !error && filtered.length > 0 && (
        <div className="flex flex-col gap-3">
          {filtered.map((inc) => (
            <IncidentCard
              key={inc.id}
              incident={inc}
              onClick={() => navigate(`/incidents/${inc.id}`)}
            />
          ))}
        </div>
      )}
    </div>
  );
}
