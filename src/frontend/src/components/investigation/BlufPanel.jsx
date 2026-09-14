import SeverityBadge from '../alerts/SeverityBadge.jsx';

/** Top border color keyed by severity */
const SEVERITY_BORDER_COLOR = {
  critical: '#ff4444',
  high: '#ff8c00',
  medium: '#ffd700',
  low: '#00cc88',
  informational: '#4a9eff',
};

/** Inline highlight colors for severity keywords in the BLUF text */
const KEYWORD_STYLES = {
  CRITICAL: 'text-red-400 font-bold',
  HIGH: 'text-orange-400 font-bold',
  MEDIUM: 'text-yellow-400 font-bold',
  LOW: 'text-green-400 font-bold',
  INFORMATIONAL: 'text-blue-400 font-bold',
};

const KEYWORDS = Object.keys(KEYWORD_STYLES);

/**
 * Splits a string and wraps severity keywords in styled spans.
 * Returns an array of React nodes.
 */
function highlightKeywords(text) {
  if (!text) return text;
  const pattern = new RegExp(`(${KEYWORDS.join('|')})`, 'g');
  const parts = text.split(pattern);
  return parts.map((part, i) => {
    const style = KEYWORD_STYLES[part];
    return style ? (
      <span key={i} className={style}>
        {part}
      </span>
    ) : (
      part
    );
  });
}

/**
 * BlufPanel — Bottom Line Up Front summary panel.
 * Props: { bluf, severity, priority_score, title }
 */
export default function BlufPanel({ bluf, severity, priority_score, title }) {
  const sevKey = (severity ?? 'informational').toLowerCase();
  const borderColor = SEVERITY_BORDER_COLOR[sevKey] ?? SEVERITY_BORDER_COLOR.informational;

  // Split the BLUF text into paragraphs on double newlines
  const paragraphs = (bluf ?? '')
    .split(/\n\n+/)
    .map((p) => p.trim())
    .filter(Boolean);

  return (
    <div
      className="bg-[#0d1117] border border-[#21262d] rounded-lg overflow-hidden"
      style={{ borderTop: `4px solid ${borderColor}` }}
    >
      {/* Header row */}
      <div className="flex items-center justify-between px-5 pt-4 pb-3 border-b border-[#21262d]">
        <div className="flex items-center gap-3">
          {/* Pulsing indicator */}
          <span className="relative flex h-2.5 w-2.5">
            <span
              className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
              style={{ backgroundColor: borderColor }}
            />
            <span
              className="relative inline-flex rounded-full h-2.5 w-2.5"
              style={{ backgroundColor: borderColor }}
            />
          </span>
          <span className="text-xs font-mono font-semibold uppercase tracking-widest text-cyan-400">
            BLUF — Bottom Line Up Front
          </span>
        </div>
        <div className="flex items-center gap-3">
          <SeverityBadge severity={severity} />
          {priority_score != null && (
            <span className="text-xs font-mono bg-[#161b22] border border-[#21262d] text-white px-2.5 py-1 rounded">
              Score:{' '}
              <span className="font-bold" style={{ color: borderColor }}>
                {Math.round(priority_score)}
              </span>
              <span className="text-slate-500">/100</span>
            </span>
          )}
        </div>
      </div>

      {/* BLUF body */}
      <div className="px-5 py-4 space-y-3">
        {paragraphs.length === 0 ? (
          <p className="text-slate-400 text-sm italic">No BLUF available.</p>
        ) : (
          paragraphs.map((para, i) => (
            <div key={i}>
              {i > 0 && <div className="border-t border-[#21262d] mb-3" />}
              <p className="text-[15px] leading-relaxed text-slate-200">
                {highlightKeywords(para)}
              </p>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
