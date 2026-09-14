import { useState } from 'react';
import SeverityBadge from '../alerts/SeverityBadge.jsx';

const SEVERITY_DOT_COLOR = {
  critical: '#ff4444',
  high: '#ff8c00',
  medium: '#ffd700',
  low: '#00cc88',
  informational: '#4a9eff',
};

/** Format ISO timestamp to readable short string */
function formatTime(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
    });
  } catch {
    return ts;
  }
}

/** Format extra_data (JSON string or object) into a readable block */
function ExtraDataBlock({ extraData }) {
  if (!extraData) return null;
  let parsed = extraData;
  if (typeof extraData === 'string') {
    try {
      parsed = JSON.parse(extraData);
    } catch {
      return <p className="text-xs text-slate-400 font-mono">{extraData}</p>;
    }
  }
  return (
    <pre className="text-xs text-slate-300 bg-[#0a0f1a] border border-[#21262d] rounded p-3 overflow-x-auto leading-relaxed whitespace-pre-wrap">
      {JSON.stringify(parsed, null, 2)}
    </pre>
  );
}

/** Single expandable alert row */
function AlertRow({ alert, isLast }) {
  const [expanded, setExpanded] = useState(false);

  const {
    id,
    timestamp,
    raw_source,
    alert_type,
    source_ip,
    dest_ip,
    severity_raw,
    description,
    is_false_positive,
    fp_reason,
    confidence,
    extra_data,
  } = alert ?? {};

  const sevKey = (severity_raw ?? 'informational').toLowerCase();
  const dotColor = SEVERITY_DOT_COLOR[sevKey] ?? SEVERITY_DOT_COLOR.informational;
  const isFp = Boolean(is_false_positive);

  return (
    <div className="relative flex gap-4">
      {/* Timeline track */}
      <div className="flex flex-col items-center">
        <div
          className="mt-1 w-3 h-3 rounded-full shrink-0 z-10 ring-2 ring-[#0d1117]"
          style={{ backgroundColor: dotColor }}
        />
        {!isLast && <div className="w-px flex-1 bg-[#21262d] mt-1" />}
      </div>

      {/* Card */}
      <div
        className={`flex-1 mb-4 rounded-lg border transition-colors cursor-pointer select-none ${
          isFp
            ? 'bg-[#0a0f1a] border-[#1a1f27] opacity-60'
            : 'bg-[#0d1117] border-[#21262d] hover:border-[#30363d]'
        }`}
        onClick={() => setExpanded((v) => !v)}
      >
        {/* Collapsed row */}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 px-4 py-3">
          {/* Expand chevron */}
          <span className="text-slate-500 text-xs mr-1 select-none">
            {expanded ? '▾' : '▸'}
          </span>

          {/* Timestamp */}
          <span className="text-xs font-mono text-slate-400 min-w-[120px]">
            {formatTime(timestamp)}
          </span>

          {/* Source */}
          {raw_source && (
            <span className="text-xs bg-[#161b22] border border-[#21262d] text-slate-300 px-2 py-0.5 rounded font-mono">
              {raw_source}
            </span>
          )}

          {/* Alert type */}
          {alert_type && (
            <span className="text-xs text-slate-300 font-medium">{alert_type}</span>
          )}

          {/* Source IP */}
          {source_ip && (
            <span className="text-xs font-mono text-cyan-400">{source_ip}</span>
          )}

          {/* Severity */}
          <SeverityBadge severity={severity_raw} />

          {/* False positive indicator */}
          {isFp && (
            <span className="text-xs font-mono uppercase tracking-wider text-red-500 border border-red-800 px-2 py-0.5 rounded-full ml-auto">
              False Positive
            </span>
          )}
        </div>

        {/* Expanded content */}
        {expanded && (
          <div
            className="px-4 pb-4 space-y-3 border-t border-[#21262d] pt-3"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Description */}
            {description && (
              <p className="text-sm text-slate-300 leading-relaxed">{description}</p>
            )}

            {/* Metadata row */}
            <div className="flex flex-wrap gap-4 text-xs text-slate-400">
              {dest_ip && (
                <span>
                  Destination: <span className="font-mono text-slate-200">{dest_ip}</span>
                </span>
              )}
              {confidence != null && (
                <span>
                  Confidence:{' '}
                  <span className="font-semibold text-slate-200">{(confidence * 100).toFixed(0)}%</span>
                </span>
              )}
              {id && (
                <span className="font-mono text-slate-500 break-all">ID: {id}</span>
              )}
            </div>

            {/* FP reason */}
            {isFp && fp_reason && (
              <div className="text-xs bg-red-950/30 border border-red-900/40 rounded p-2 text-red-300">
                <span className="font-semibold uppercase tracking-wider mr-2">FP Reason:</span>
                {fp_reason}
              </div>
            )}

            {/* Extra data */}
            {extra_data && (
              <div>
                <p className="text-xs font-mono text-slate-500 uppercase tracking-wider mb-1">
                  Extra Data
                </p>
                <ExtraDataBlock extraData={extra_data} />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * EvidenceList — expandable timeline of correlated alerts.
 * Props: { alerts }
 */
export default function EvidenceList({ alerts = [] }) {
  if (!alerts.length) {
    return (
      <div className="bg-[#0d1117] border border-[#21262d] rounded-lg px-5 py-8 text-center text-slate-500 text-sm">
        No correlated alerts found.
      </div>
    );
  }

  // Separate real alerts from FPs
  const realAlerts = alerts.filter((a) => !a.is_false_positive);
  const fpAlerts = alerts.filter((a) => a.is_false_positive);
  const sorted = [...realAlerts, ...fpAlerts];

  return (
    <div className="bg-[#0d1117] border border-[#21262d] rounded-lg overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3 border-b border-[#21262d] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="text-xs font-mono font-semibold uppercase tracking-widest text-cyan-400">
            Evidence
          </span>
          <span className="text-xs text-slate-500">
            {alerts.length} alert{alerts.length !== 1 ? 's' : ''}
          </span>
        </div>
        <div className="flex items-center gap-3 text-xs text-slate-500">
          <span>
            <span className="text-slate-200 font-semibold">{realAlerts.length}</span> real
          </span>
          {fpAlerts.length > 0 && (
            <span>
              <span className="text-red-400 font-semibold">{fpAlerts.length}</span> FP
            </span>
          )}
          <span className="text-slate-600 italic">click row to expand</span>
        </div>
      </div>

      {/* Timeline list */}
      <div className="px-5 pt-4 pb-2">
        {sorted.map((alert, i) => (
          <AlertRow
            key={alert.id ?? i}
            alert={alert}
            isLast={i === sorted.length - 1}
          />
        ))}
      </div>
    </div>
  );
}
