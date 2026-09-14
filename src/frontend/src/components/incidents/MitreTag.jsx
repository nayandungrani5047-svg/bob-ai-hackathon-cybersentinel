/**
 * MitreTag — pill showing a MITRE ATT&CK technique.
 * Props: { technique: { id, name, tactic } }
 */
export default function MitreTag({ technique }) {
  const { id, name, tactic } = technique ?? {};

  return (
    <span
      title={tactic ?? ''}
      className="
        inline-flex items-center gap-1
        px-2 py-0.5 rounded-full
        bg-indigo-900 text-indigo-300 border border-indigo-700
        text-xs cursor-default select-none
        hover:bg-indigo-800 transition-colors
      "
    >
      <span className="font-mono font-semibold">{id}</span>
      {name && (
        <span className="opacity-80">· {name}</span>
      )}
    </span>
  );
}
