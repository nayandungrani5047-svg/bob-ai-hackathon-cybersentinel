export default function TopBar({
  title,
  onIngest,
  onReset,
  isIngesting,
  alertCount,
  incidentCount,
}) {
  function handleReset() {
    if (window.confirm('Reset all data? This will delete all alerts and incidents.')) {
      onReset();
    }
  }

  return (
    <header className="sticky top-0 z-10 flex items-center justify-between h-14 px-6 bg-[#0d1117] border-b border-[#21262d]">
      {/* Page title */}
      <h1 className="text-base font-semibold text-gray-100 font-mono tracking-wide">
        {title}
      </h1>

      <div className="flex items-center gap-4">
        {/* Status counts */}
        <div className="hidden sm:flex items-center gap-3 text-xs font-mono text-gray-500">
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-cyan-400"></span>
            <span>{alertCount ?? '—'} alerts</span>
          </span>
          <span className="text-gray-700">|</span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-purple-400"></span>
            <span>{incidentCount ?? '—'} incidents</span>
          </span>
        </div>

        {/* Ingest button */}
        <button
          onClick={onIngest}
          disabled={isIngesting}
          className={[
            'flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono font-semibold',
            'border transition-colors duration-150',
            isIngesting
              ? 'border-cyan-800 bg-cyan-950 text-cyan-600 cursor-not-allowed'
              : 'border-cyan-700 bg-cyan-900/40 text-cyan-300 hover:bg-cyan-800/60 hover:text-cyan-100',
          ].join(' ')}
        >
          {isIngesting ? (
            <>
              <Spinner />
              Ingesting…
            </>
          ) : (
            <>
              <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 16.5v2.25A2.25 2.25 0 005.25 21h13.5A2.25 2.25 0 0021 18.75V16.5m-13.5-9L12 3m0 0l4.5 4.5M12 3v13.5" />
              </svg>
              Ingest Alerts
            </>
          )}
        </button>

        {/* Reset button */}
        <button
          onClick={handleReset}
          disabled={isIngesting}
          className={[
            'flex items-center gap-2 px-3 py-1.5 rounded text-xs font-mono font-semibold',
            'border transition-colors duration-150',
            isIngesting
              ? 'border-gray-700 bg-gray-900 text-gray-600 cursor-not-allowed'
              : 'border-gray-600 bg-gray-800/40 text-gray-400 hover:bg-gray-700/60 hover:text-gray-200',
          ].join(' ')}
        >
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0l3.181 3.183a8.25 8.25 0 0013.803-3.7M4.031 9.865a8.25 8.25 0 0113.803-3.7l3.181 3.182m0-4.991v4.99" />
          </svg>
          Reset Data
        </button>
      </div>
    </header>
  );
}

function Spinner() {
  return (
    <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}
