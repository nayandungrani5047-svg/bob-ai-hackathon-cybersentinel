/** Gauge/progress bar color by severity */
const SEVERITY_COLOR = {
  critical: '#ff4444',
  high: '#ff8c00',
  medium: '#ffd700',
  low: '#00cc88',
  informational: '#4a9eff',
};

/** Human label + background tint for the score bar track */
const SEVERITY_TRACK = {
  critical: 'bg-red-950/40',
  high: 'bg-orange-950/40',
  medium: 'bg-yellow-950/40',
  low: 'bg-green-950/40',
  informational: 'bg-blue-950/40',
};

/**
 * Splits reasoning text into bullet points on ". " boundaries.
 * Returns an array of clean sentences.
 */
function splitReasoning(text) {
  if (!text) return [];
  // Split on ". " or ".\n" while keeping longer sentences together
  const raw = text
    .split(/\.\s+/)
    .map((s) => s.trim().replace(/\.+$/, ''))
    .filter((s) => s.length > 4);
  return raw;
}

/**
 * PriorityReasoningPanel — collapsible panel showing priority score and reasoning.
 * Props: { reasoning, score, severity }
 */
export default function PriorityReasoningPanel({ reasoning, score, severity }) {
  const sevKey = (severity ?? 'informational').toLowerCase();
  const barColor = SEVERITY_COLOR[sevKey] ?? SEVERITY_COLOR.informational;
  const trackClass = SEVERITY_TRACK[sevKey] ?? SEVERITY_TRACK.informational;

  const pct = Math.min(100, Math.max(0, Math.round(score ?? 0)));
  const bullets = splitReasoning(reasoning);

  return (
    <div className="bg-[#0d1117] border border-[#21262d] rounded-lg overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3 border-b border-[#21262d] flex items-center gap-2">
        <span className="text-xs font-mono font-semibold uppercase tracking-widest text-cyan-400">
          Scoring Factors
        </span>
        <span className="text-xs text-slate-500">Priority Reasoning</span>
      </div>

      <div className="px-5 py-4 space-y-4">
        {/* Score gauge */}
        <div className="space-y-1.5">
          <div className="flex items-baseline justify-between">
            <span className="text-xs font-mono text-slate-400 uppercase tracking-wider">
              Priority Score
            </span>
            <span className="font-mono text-lg font-bold" style={{ color: barColor }}>
              {pct}
              <span className="text-slate-500 text-sm font-normal">/100</span>
            </span>
          </div>

          {/* Track */}
          <div className={`h-3 rounded-full w-full ${trackClass} overflow-hidden`}>
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{
                width: `${pct}%`,
                backgroundColor: barColor,
                boxShadow: `0 0 8px ${barColor}88`,
              }}
            />
          </div>

          {/* Scale labels */}
          <div className="flex justify-between text-[10px] text-slate-600 font-mono">
            <span>0</span>
            <span>25</span>
            <span>50</span>
            <span>75</span>
            <span>100</span>
          </div>
        </div>

        {/* Reasoning bullets */}
        {bullets.length > 0 && (
          <div className="space-y-2">
            <p className="text-xs font-mono text-slate-500 uppercase tracking-wider">
              Analysis
            </p>
            <ul className="space-y-1.5">
              {bullets.map((bullet, i) => (
                <li key={i} className="flex gap-2 text-sm text-slate-300 leading-relaxed">
                  <span className="mt-1.5 w-1.5 h-1.5 rounded-full shrink-0" style={{ backgroundColor: barColor }} />
                  <span>{bullet}</span>
                </li>
              ))}
            </ul>
          </div>
        )}

        {!bullets.length && reasoning && (
          <p className="text-sm text-slate-300 leading-relaxed">{reasoning}</p>
        )}
      </div>
    </div>
  );
}
