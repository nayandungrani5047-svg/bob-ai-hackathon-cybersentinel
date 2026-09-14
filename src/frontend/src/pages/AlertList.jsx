import { useEffect, useState } from 'react';
import { apiClient } from '../api/client';
import AlertTable from '../components/alerts/AlertTable';
import { useApp } from '../contexts/AppContext';

export default function AlertList() {
  const { lastIngested: contextLastIngested } = useApp();
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [lastIngested, setLastIngested] = useState(null);

  useEffect(() => {
    fetchAlerts();
  }, [contextLastIngested]);

  async function fetchAlerts() {
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.getAlerts();
      const data = res.data ?? [];
      setAlerts(data);
      if (data.length > 0) {
        // Use the latest created_at from the fetched data as "last ingested" time
        const latest = data.reduce((max, a) => {
          const t = a.created_at ?? a.timestamp ?? '';
          return t > max ? t : max;
        }, '');
        if (latest) {
          setLastIngested(new Date(latest).toLocaleString('en-US', { timeZoneName: 'short' }));
        }
      }
    } catch (err) {
      setError('Failed to load alerts. Ensure the backend is running and alerts have been ingested.');
    } finally {
      setLoading(false);
    }
  }

  const genuineCount = alerts.filter((a) => !a.is_false_positive).length;
  const fpCount = alerts.filter((a) => a.is_false_positive).length;

  return (
    <div className="p-6 flex flex-col gap-4 min-h-screen bg-[#0a0f1a]">
      {/* Page header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white font-mono tracking-tight">
            Alert Feed
          </h1>
          <p className="text-xs text-[#8b949e] mt-1">
            Filterable SIEM alert list — click a row with an incident to investigate
          </p>
        </div>

        {/* Info bar */}
        <div className="bg-[#161b22] border border-[#21262d] rounded-lg px-4 py-2 text-xs text-[#8b949e] text-right shrink-0">
          <div className="font-mono text-[#c9d1d9]">80 synthetic alerts · 6 sources</div>
          {lastIngested ? (
            <div className="mt-0.5">Last ingested: {lastIngested}</div>
          ) : (
            <div className="mt-0.5 italic">Not yet ingested</div>
          )}
        </div>
      </div>

      {/* Summary stats bar */}
      <div className="flex gap-3 flex-wrap">
        <StatChip label="Total" value={alerts.length} color="text-white" />
        <StatChip label="Genuine Threats" value={genuineCount} color="text-green-400" />
        <StatChip label="False Positives" value={fpCount} color="text-red-400" />
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-900/30 border border-red-700 text-red-300 rounded-lg px-4 py-3 text-sm">
          {error}
        </div>
      )}

      {/* Alert table */}
      <AlertTable alerts={alerts} loading={loading} />
    </div>
  );
}

function StatChip({ label, value, color }) {
  return (
    <div className="bg-[#161b22] border border-[#21262d] rounded-lg px-4 py-2 flex items-center gap-2">
      <span className="text-xs text-[#8b949e] uppercase tracking-wider">{label}</span>
      <span className={`font-mono font-bold text-lg leading-none ${color}`}>{value}</span>
    </div>
  );
}
