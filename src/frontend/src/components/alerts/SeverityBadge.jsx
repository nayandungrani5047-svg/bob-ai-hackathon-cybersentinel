const SEVERITY_STYLES = {
  critical: 'bg-red-900 text-red-300 border border-red-700',
  high: 'bg-orange-900 text-orange-300 border border-orange-700',
  medium: 'bg-yellow-900 text-yellow-300 border border-yellow-700',
  low: 'bg-green-900 text-green-300 border border-green-700',
  informational: 'bg-slate-800 text-slate-400 border border-slate-600',
};

export default function SeverityBadge({ severity }) {
  const key = (severity ?? 'informational').toLowerCase();
  const styles = SEVERITY_STYLES[key] ?? SEVERITY_STYLES.informational;

  return (
    <span
      className={`inline-block px-2 py-0.5 rounded-full text-xs font-medium uppercase ${styles}`}
    >
      {key}
    </span>
  );
}
