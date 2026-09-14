import { useState, useMemo } from 'react';
import { useNavigate } from 'react-router-dom';
import SeverityBadge from './SeverityBadge';

const PAGE_SIZE = 20;

const ALERT_TYPE_ABBR = {
  brute_force: 'BRF',
  lateral_movement: 'LAT',
  malware: 'MLW',
  data_exfil: 'EXF',
  recon: 'RCN',
  phishing: 'PHI',
  privilege_escalation: 'PRV',
  scan: 'SCN',
  anomaly: 'ANO',
  intrusion: 'INT',
};

function formatTimestamp(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  if (isNaN(d)) return ts;
  const mm = String(d.getUTCMonth() + 1).padStart(2, '0');
  const dd = String(d.getUTCDate()).padStart(2, '0');
  const hh = String(d.getUTCHours()).padStart(2, '0');
  const min = String(d.getUTCMinutes()).padStart(2, '0');
  return `${mm}/${dd} ${hh}:${min} UTC`;
}

function shortId(id) {
  if (!id) return '—';
  return id.slice(-5).toUpperCase();
}

export default function AlertTable({ alerts = [], loading, onAlertClick }) {
  const navigate = useNavigate();

  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('all');
  const [sourceFilter, setSourceFilter] = useState('all');
  const [classFilter, setClassFilter] = useState('all');
  const [page, setPage] = useState(1);

  // Derive unique sources from data
  const sources = useMemo(() => {
    const set = new Set(alerts.map((a) => a.raw_source).filter(Boolean));
    return Array.from(set).sort();
  }, [alerts]);

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    return alerts.filter((a) => {
      if (q && !(a.description?.toLowerCase().includes(q) || a.source_ip?.toLowerCase().includes(q))) {
        return false;
      }
      if (severityFilter !== 'all') {
        const sev = (a.severity_raw ?? '').toLowerCase();
        if (sev !== severityFilter) return false;
      }
      if (sourceFilter !== 'all' && a.raw_source !== sourceFilter) return false;
      if (classFilter === 'genuine' && a.is_false_positive) return false;
      if (classFilter === 'fp' && !a.is_false_positive) return false;
      return true;
    });
  }, [alerts, search, severityFilter, sourceFilter, classFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, totalPages);
  const pageSlice = filtered.slice((currentPage - 1) * PAGE_SIZE, currentPage * PAGE_SIZE);

  function handleRowClick(alert) {
    if (alert.incident_id) {
      if (onAlertClick) onAlertClick(alert);
      else navigate(`/incidents/${alert.incident_id}`);
    }
  }

  function handleFilterChange(setter) {
    return (e) => {
      setter(e.target.value);
      setPage(1);
    };
  }

  const inputBase =
    'bg-[#0d1117] border border-[#21262d] text-[#c9d1d9] rounded-md px-3 py-1.5 text-sm focus:outline-none focus:border-brand-cyan';

  return (
    <div className="flex flex-col gap-3">
      {/* Filter bar */}
      <div className="bg-[#161b22] border border-[#21262d] rounded-lg p-4 flex flex-wrap gap-3 items-center">
        <input
          type="text"
          placeholder="Search description or source IP…"
          value={search}
          onChange={handleFilterChange(setSearch)}
          className={`${inputBase} min-w-[220px] flex-1`}
        />
        <select value={severityFilter} onChange={handleFilterChange(setSeverityFilter)} className={inputBase}>
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="informational">Informational</option>
        </select>
        <select value={sourceFilter} onChange={handleFilterChange(setSourceFilter)} className={inputBase}>
          <option value="all">All Sources</option>
          {sources.map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        {/* Classification toggle */}
        <div className="flex rounded-md overflow-hidden border border-[#21262d] text-xs font-semibold">
          {[
            { label: 'All', value: 'all' },
            { label: 'Genuine', value: 'genuine' },
            { label: 'False +', value: 'fp' },
          ].map(({ label, value }) => (
            <button
              key={value}
              onClick={() => { setClassFilter(value); setPage(1); }}
              className={`px-3 py-1.5 transition-colors ${
                classFilter === value
                  ? 'bg-brand-cyan text-[#0a0f1a]'
                  : 'bg-[#0d1117] text-[#8b949e] hover:bg-[#161b22]'
              }`}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {/* Count bar */}
      <div className="text-xs text-[#8b949e] px-1">
        Showing <span className="text-white font-mono">{filtered.length}</span> of{' '}
        <span className="text-white font-mono">{alerts.length}</span> alerts
      </div>

      {/* Table */}
      <div className="bg-[#0d1117] border border-[#21262d] rounded-lg overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-16 gap-3 text-[#8b949e]">
            <svg className="animate-spin h-5 w-5 text-brand-cyan" viewBox="0 0 24 24" fill="none">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
            </svg>
            <span className="text-sm">Loading alerts…</span>
          </div>
        ) : pageSlice.length === 0 ? (
          <div className="py-16 text-center text-[#8b949e] text-sm">
            {alerts.length === 0
              ? "No alerts found. Click 'Ingest Alerts' to load demo data."
              : 'No alerts match the current filters.'}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm border-collapse">
              <thead>
                <tr className="text-left text-[#8b949e] text-xs uppercase tracking-wider bg-[#0d1117] border-b border-[#21262d] sticky top-0 z-10">
                  <th className="px-4 py-3 font-semibold">#</th>
                  <th className="px-4 py-3 font-semibold">Timestamp</th>
                  <th className="px-4 py-3 font-semibold">Source</th>
                  <th className="px-4 py-3 font-semibold">Type</th>
                  <th className="px-4 py-3 font-semibold">Source IP</th>
                  <th className="px-4 py-3 font-semibold">Severity</th>
                  <th className="px-4 py-3 font-semibold text-center">FP?</th>
                  <th className="px-4 py-3 font-semibold text-center">Incident</th>
                </tr>
              </thead>
              <tbody>
                {pageSlice.map((alert, idx) => {
                  const isFp = alert.is_false_positive;
                  const hasIncident = Boolean(alert.incident_id);
                  const rowBase =
                    'border-b border-[#21262d] transition-colors duration-100';
                  const rowBg = idx % 2 === 0 ? 'bg-[#0d1117]' : 'bg-[#111720]';
                  const rowFp = isFp ? 'opacity-60' : '';
                  const rowHover = hasIncident
                    ? 'cursor-pointer hover:bg-[#1c2433]'
                    : 'hover:bg-[#161b22]';
                  return (
                    <tr
                      key={alert.id}
                      className={`${rowBase} ${rowBg} ${rowFp} ${rowHover}`}
                      onClick={() => handleRowClick(alert)}
                    >
                      <td className="px-4 py-3 font-mono text-[#8b949e] text-xs">
                        {shortId(alert.id)}
                      </td>
                      <td className="px-4 py-3 font-mono text-[#8b949e] text-xs whitespace-nowrap">
                        {formatTimestamp(alert.timestamp)}
                      </td>
                      <td className="px-4 py-3 text-[#c9d1d9] text-xs whitespace-nowrap">
                        {alert.raw_source ?? '—'}
                      </td>
                      <td className="px-4 py-3 text-xs">
                        <span
                          className="font-mono bg-[#1c2433] text-[#c9d1d9] border border-[#21262d] px-1.5 py-0.5 rounded text-[10px] uppercase"
                          title={alert.alert_type}
                        >
                          {ALERT_TYPE_ABBR[alert.alert_type] ?? alert.alert_type?.slice(0, 4).toUpperCase() ?? '?'}
                        </span>
                      </td>
                      <td className="px-4 py-3 font-mono text-[#79c0ff] text-xs whitespace-nowrap">
                        {alert.source_ip ?? '—'}
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={alert.severity_raw} />
                      </td>
                      <td className="px-4 py-3 text-center">
                        {isFp ? (
                          <span className="text-red-400 text-base" title="False positive">✗</span>
                        ) : (
                          <span className="text-green-400 text-base" title="Genuine threat">✓</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-center">
                        {hasIncident ? (
                          <span
                            className="text-[#79c0ff] text-base"
                            title={`Incident ${alert.incident_id}`}
                          >
                            ↗
                          </span>
                        ) : (
                          <span className="text-[#21262d]">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-end gap-3 text-sm text-[#8b949e]">
          <button
            disabled={currentPage === 1}
            onClick={() => setPage((p) => p - 1)}
            className="px-3 py-1 bg-[#161b22] border border-[#21262d] rounded hover:bg-[#1c2433] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            ← Prev
          </button>
          <span className="font-mono text-xs">
            Page {currentPage} / {totalPages}
          </span>
          <button
            disabled={currentPage === totalPages}
            onClick={() => setPage((p) => p + 1)}
            className="px-3 py-1 bg-[#161b22] border border-[#21262d] rounded hover:bg-[#1c2433] disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  );
}
