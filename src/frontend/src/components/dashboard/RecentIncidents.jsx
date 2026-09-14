import { useNavigate } from 'react-router-dom';

const SEVERITY_STYLES = {
  Critical: 'bg-red-900/40 text-critical border border-critical/40',
  High: 'bg-orange-900/30 text-high border border-high/40',
  Medium: 'bg-yellow-900/30 text-medium border border-medium/40',
  Low: 'bg-green-900/30 text-low border border-low/40',
};

function SeverityBadge({ severity }) {
  const cls = SEVERITY_STYLES[severity] ?? 'bg-[#21262d] text-[#8b949e] border border-[#21262d]';
  return (
    <span className={`px-2 py-0.5 rounded text-xs font-semibold font-mono uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  );
}

function StatusBadge({ status }) {
  const isOpen = status?.toLowerCase() === 'open';
  return (
    <span
      className={`px-2 py-0.5 rounded text-xs font-mono uppercase tracking-wide ${
        isOpen
          ? 'bg-brand-cyan/10 text-brand-cyan border border-brand-cyan/30'
          : 'bg-[#21262d] text-[#8b949e] border border-[#21262d]'
      }`}
    >
      {status ?? 'unknown'}
    </span>
  );
}

export default function RecentIncidents({ incidents = [] }) {
  const navigate = useNavigate();

  // Top 5 by priority_score descending
  const top5 = [...incidents]
    .sort((a, b) => (b.priority_score ?? 0) - (a.priority_score ?? 0))
    .slice(0, 5);

  if (top5.length === 0) {
    return (
      <div className="text-center text-[#8b949e] text-sm py-8">
        No incidents yet.
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="text-xs text-[#8b949e] uppercase tracking-widest border-b border-[#21262d]">
            <th className="text-left py-2 pr-4 font-semibold">Severity</th>
            <th className="text-left py-2 pr-4 font-semibold">Title</th>
            <th className="text-right py-2 pr-4 font-semibold">Score</th>
            <th className="text-right py-2 pr-4 font-semibold">Alerts</th>
            <th className="text-left py-2 font-semibold">Status</th>
          </tr>
        </thead>
        <tbody>
          {top5.map((inc) => (
            <tr
              key={inc.id}
              onClick={() => navigate(`/incidents/${inc.id}`)}
              className="border-b border-[#21262d]/60 hover:bg-[#161b22] cursor-pointer transition-colors"
            >
              <td className="py-3 pr-4">
                <SeverityBadge severity={inc.severity} />
              </td>
              <td className="py-3 pr-4 text-white font-medium max-w-[280px] truncate">
                {inc.title}
              </td>
              <td className="py-3 pr-4 text-right font-mono text-brand-cyan font-semibold">
                {inc.priority_score != null ? inc.priority_score.toFixed(1) : '—'}
              </td>
              <td className="py-3 pr-4 text-right font-mono text-[#8b949e]">
                {inc.alert_count ?? '—'}
              </td>
              <td className="py-3">
                <StatusBadge status={inc.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
