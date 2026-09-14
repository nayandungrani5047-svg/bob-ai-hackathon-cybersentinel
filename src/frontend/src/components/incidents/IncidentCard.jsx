import SeverityBadge from '../alerts/SeverityBadge.jsx';
import MitreTag from './MitreTag.jsx';

/** Left-border + optional glow colour keyed by severity */
const SEVERITY_BORDER = {
  critical: 'border-l-[#ff4444]',
  high: 'border-l-[#ff8c00]',
  medium: 'border-l-[#ffd700]',
  low: 'border-l-[#00cc88]',
};

const SEVERITY_GLOW = {
  critical: 'ring-1 ring-red-700',
  high: '',
  medium: '',
  low: '',
};

/** Human-readable status badge */
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
      {isOpen ? 'Open' : 'Closed'}
    </span>
  );
}

/** Formats an ISO timestamp to a short readable string */
function formatTime(ts) {
  if (!ts) return '—';
  try {
    return new Date(ts).toLocaleString(undefined, {
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  } catch {
    return ts;
  }
}

/**
 * IncidentCard — shows a single incident summary.
 * Props: { incident, onClick }
 */
export default function IncidentCard({ incident, onClick }) {
  const {
    id,
    title,
    severity,
    priority_score,
    status,
    created_at,
    alert_count,
    mitre_techniques,
    sources,
    correlation_rule,
  } = incident ?? {};

  const sevKey = (severity ?? 'low').toLowerCase();
  const borderClass = SEVERITY_BORDER[sevKey] ?? SEVERITY_BORDER.low;
  const glowClass = SEVERITY_GLOW[sevKey] ?? '';

  // mitre_techniques may arrive as a JSON string or already parsed array
  let techniques = [];
  if (Array.isArray(mitre_techniques)) {
    techniques = mitre_techniques;
  } else if (typeof mitre_techniques === 'string') {
    try {
      techniques = JSON.parse(mitre_techniques);
    } catch {
      techniques = [];
    }
  }

  const visibleTechniques = techniques.slice(0, 4);
  const hiddenCount = techniques.length - visibleTechniques.length;

  // sources may be an array or a comma-separated string
  const sourceList = Array.isArray(sources)
    ? sources
    : typeof sources === 'string' && sources
    ? sources.split(',').map((s) => s.trim())
    : [];

  return (
    <div
      className={`
        bg-[#0d1117] border border-[#21262d] border-l-4 ${borderClass} ${glowClass}
        rounded-lg p-4 flex flex-col gap-3
        hover:border-[#30363d] transition-colors cursor-pointer
      `}
      onClick={onClick}
    >
      {/* Header row */}
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={severity} />

        <span className="text-xs font-mono text-slate-400">
          Priority{' '}
          <span className="text-white font-semibold">
            {priority_score != null ? `${Math.round(priority_score)}/100` : '—'}
          </span>
        </span>

        <StatusBadge status={status} />

        <span className="ml-auto text-xs text-slate-500">{formatTime(created_at)}</span>
      </div>

      {/* Title */}
      <p className="text-sm font-bold text-white leading-snug">{title ?? `Incident ${id}`}</p>

      {/* Stats row */}
      <div className="flex flex-wrap items-center gap-3 text-xs text-slate-400">
        {alert_count != null && (
          <span>
            <span className="text-slate-200 font-semibold">{alert_count}</span> correlated alert
            {alert_count !== 1 ? 's' : ''}
          </span>
        )}

        {sourceList.length > 0 && (
          <span className="flex items-center gap-1">
            {sourceList.map((s) => (
              <span
                key={s}
                className="bg-[#161b22] border border-[#21262d] px-1.5 py-0.5 rounded text-slate-300"
              >
                {s}
              </span>
            ))}
          </span>
        )}

        {correlation_rule && (
          <span className="bg-blue-950 text-blue-300 border border-blue-800 px-2 py-0.5 rounded-full">
            {correlation_rule}
          </span>
        )}
      </div>

      {/* MITRE techniques */}
      {techniques.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {visibleTechniques.map((t) => (
            <MitreTag key={t.id ?? t.name} technique={t} />
          ))}
          {hiddenCount > 0 && (
            <span className="inline-flex items-center px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 border border-slate-600 text-xs">
              +{hiddenCount} more
            </span>
          )}
        </div>
      )}

      {/* Footer */}
      <div className="flex justify-end pt-1">
        <button
          className="text-xs text-brand-cyan hover:text-white font-semibold tracking-wide transition-colors"
          onClick={(e) => {
            e.stopPropagation();
            onClick?.();
          }}
        >
          Investigate →
        </button>
      </div>
    </div>
  );
}
