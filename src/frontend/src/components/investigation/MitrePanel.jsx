/** Static short descriptions for known MITRE ATT&CK technique IDs */
const TECHNIQUE_DESCRIPTIONS = {
  T1595: 'Adversary conducts active reconnaissance by scanning the target network',
  T1110: 'Adversary uses brute force techniques to gain access to accounts',
  T1021: 'Adversary uses legitimate remote services to move laterally',
  T1570: 'Adversary transfers tools or files to target systems',
  T1059: 'Adversary uses command and script interpreters to execute commands',
  T1204: 'Adversary relies on user execution to run malicious content',
  T1041: 'Adversary exfiltrates data over the C2 channel',
  T1048: 'Adversary exfiltrates data using an alternative protocol',
  T1566: 'Adversary sends phishing messages to gain initial access',
  T1598: 'Adversary sends phishing messages to gather information',
  T1068: 'Adversary exploits software vulnerability for privilege escalation',
  T1078: 'Adversary uses valid account credentials for privilege escalation',
  T1046: 'Adversary scans the network to discover services and ports',
  T1071: 'Adversary uses application layer protocols for C2 communication',
};

/**
 * Individual MITRE technique card.
 */
function TechniqueCard({ technique }) {
  const { id, name, tactic } = technique ?? {};
  const description = TECHNIQUE_DESCRIPTIONS[id] ?? 'Adversary technique — see MITRE ATT&CK for details';

  return (
    <div className="bg-[#0d1117] border border-indigo-900/50 rounded-lg p-4 flex flex-col gap-2 hover:border-indigo-700 transition-colors">
      {/* Technique ID */}
      <div className="flex items-start justify-between gap-2">
        <span className="font-mono text-xl font-bold text-cyan-400 leading-none">{id}</span>
        {tactic && (
          <span className="inline-block shrink-0 px-2 py-0.5 rounded-full bg-indigo-900 text-indigo-300 border border-indigo-700 text-xs font-medium">
            {tactic}
          </span>
        )}
      </div>

      {/* Technique name */}
      {name && (
        <p className="text-sm font-semibold text-white leading-snug">{name}</p>
      )}

      {/* Description */}
      <p className="text-xs text-slate-400 leading-relaxed">{description}</p>

      {/* External link */}
      <a
        href={`https://attack.mitre.org/techniques/${id}/`}
        target="_blank"
        rel="noopener noreferrer"
        className="mt-auto text-xs text-indigo-400 hover:text-indigo-300 font-mono transition-colors"
      >
        attack.mitre.org ↗
      </a>
    </div>
  );
}

/**
 * MitrePanel — grid of MITRE ATT&CK technique cards.
 * Props: { techniques }  // [{ id, name, tactic }]
 */
export default function MitrePanel({ techniques = [] }) {
  if (!techniques.length) return null;

  return (
    <div className="bg-[#0d1117] border border-[#21262d] rounded-lg overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3 border-b border-[#21262d] flex items-center gap-2">
        <span className="text-xs font-mono font-semibold uppercase tracking-widest text-indigo-400">
          MITRE ATT&CK
        </span>
        <span className="text-xs text-slate-500">
          {techniques.length} technique{techniques.length !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Grid */}
      <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-3">
        {techniques.map((t) => (
          <TechniqueCard key={t.id ?? t.name} technique={t} />
        ))}
      </div>
    </div>
  );
}
