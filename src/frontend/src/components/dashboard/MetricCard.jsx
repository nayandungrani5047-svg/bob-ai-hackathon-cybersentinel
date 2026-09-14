export default function MetricCard({ title, value, subtitle, colorClass, icon }) {
  const borderColorMap = {
    critical: 'border-l-critical',
    high: 'border-l-high',
    medium: 'border-l-medium',
    low: 'border-l-low',
    cyan: 'border-l-brand-cyan',
    blue: 'border-l-blue-500',
  };

  const borderClass = borderColorMap[colorClass] ?? 'border-l-brand-cyan';

  return (
    <div
      className={`bg-bg-card border border-[#21262d] border-l-4 ${borderClass} rounded-lg p-5 flex flex-col gap-2`}
    >
      <div className="flex items-center justify-between">
        <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
          {title}
        </span>
        {icon && <span className="text-2xl opacity-60">{icon}</span>}
      </div>
      <div className="text-4xl font-bold text-white font-mono leading-none">
        {value ?? '—'}
      </div>
      {subtitle && (
        <div className="text-xs text-[#8b949e]">{subtitle}</div>
      )}
    </div>
  );
}
