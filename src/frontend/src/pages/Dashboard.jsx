import { useEffect, useRef, useState } from 'react';
import { Chart } from 'chart.js';
import { apiClient } from '../api/client';
import { useApp } from '../contexts/AppContext';
import MetricCard from '../components/dashboard/MetricCard';
import SeverityChart from '../components/dashboard/SeverityChart';
import AlertsBySourceChart from '../components/dashboard/AlertsBySourceChart';
import IncidentTimelineChart from '../components/dashboard/IncidentTimelineChart';
import RecentIncidents from '../components/dashboard/RecentIncidents';

// Global Chart.js defaults — applied once when module loads
Chart.defaults.color = '#8b949e';
Chart.defaults.borderColor = '#21262d';

const REFRESH_INTERVAL_MS = 30_000;

function SectionHeader({ children }) {
  return (
    <h2 className="text-xs font-semibold uppercase tracking-widest text-brand-cyan mb-3">
      {children}
    </h2>
  );
}

function Spinner() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="w-10 h-10 border-4 border-[#21262d] border-t-brand-cyan rounded-full animate-spin" />
    </div>
  );
}

function EmptyState() {
  return (
    <div className="flex flex-col items-center justify-center gap-5 py-24 text-center">
      <div className="text-6xl select-none">🛡️</div>
      <div>
        <p className="text-xl font-bold text-white mb-2">No threat data yet</p>
        <p className="text-[#8b949e] text-sm max-w-sm">
          Click <span className="text-brand-cyan font-semibold">Ingest Alerts</span> in the top bar
          to load demo data and populate the dashboard.
        </p>
      </div>
      <div className="mt-2 px-4 py-2 rounded border border-brand-cyan/30 bg-brand-cyan/5 text-brand-cyan text-xs font-mono tracking-wide">
        80 synthetic alerts · 10 incidents · MITRE ATT&amp;CK mapped
      </div>
    </div>
  );
}

export default function Dashboard() {
  const { lastIngested } = useApp();

  const [metrics, setMetrics] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [hasData, setHasData] = useState(false);

  const timerRef = useRef(null);

  const fetchData = async () => {
    try {
      const [metricsRes, incidentsRes] = await Promise.all([
        apiClient.getDashboardMetrics(),
        apiClient.getIncidents(),
      ]);
      const m = metricsRes.data;
      setMetrics(m);
      setIncidents(incidentsRes.data ?? []);
      setHasData((m?.total_alerts ?? 0) > 0);
    } catch {
      // Backend not ready — stay in empty/loading state
    } finally {
      setLoading(false);
    }
  };

  // Fetch on mount and whenever ingest fires
  useEffect(() => {
    setLoading(true);
    fetchData();
  }, [lastIngested]);

  // Auto-refresh every 30s when data is present
  useEffect(() => {
    if (!hasData) return;
    timerRef.current = setInterval(fetchData, REFRESH_INTERVAL_MS);
    return () => clearInterval(timerRef.current);
  }, [hasData]);

  if (loading) return <Spinner />;
  if (!hasData) return <EmptyState />;

  const severityDist = metrics?.severity_distribution ?? {};
  const alertsBySource = metrics?.alerts_by_source ?? {};
  const incidentsByHour = metrics?.incidents_by_hour ?? [];

  const fpCount = metrics?.false_positives ?? 0;
  const genuineCount = metrics?.genuine_threats ?? 0;

  return (
    <div className="p-6 space-y-8 max-w-[1400px]">

      {/* ── Row 1: KPI Metric Cards ── */}
      <section>
        <SectionHeader>Threat Overview</SectionHeader>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <MetricCard
            title="Total Alerts"
            value={metrics?.total_alerts ?? 0}
            subtitle="Across all sources"
            colorClass="blue"
            icon="📡"
          />
          <MetricCard
            title="Genuine Threats"
            value={genuineCount}
            subtitle={`${metrics?.total_alerts ? ((genuineCount / metrics.total_alerts) * 100).toFixed(0) : 0}% of total`}
            colorClass="cyan"
            icon="⚠️"
          />
          <MetricCard
            title="False Positives"
            value={fpCount}
            subtitle="Filtered by pipeline"
            colorClass="medium"
            icon="✅"
          />
          <MetricCard
            title="Open Incidents"
            value={metrics?.open_incidents ?? 0}
            subtitle="Requiring attention"
            colorClass="critical"
            icon="🔥"
          />
        </div>
      </section>

      {/* ── Row 2: Severity Doughnut + Source Bar ── */}
      <section>
        <SectionHeader>Alert Breakdown</SectionHeader>
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">

          {/* Severity doughnut — 2/5 width */}
          <div className="md:col-span-2 bg-bg-card border border-[#21262d] rounded-lg p-5">
            <p className="text-xs font-semibold uppercase tracking-widest text-[#8b949e] mb-4">
              By Severity
            </p>
            <SeverityChart data={severityDist} />
          </div>

          {/* Source bar — 3/5 width */}
          <div className="md:col-span-3 bg-bg-card border border-[#21262d] rounded-lg p-5">
            <p className="text-xs font-semibold uppercase tracking-widest text-[#8b949e] mb-4">
              Alerts by Source
            </p>
            {Object.keys(alertsBySource).length === 0 ? (
              <div className="flex items-center justify-center h-[180px] text-[#8b949e] text-sm">
                No source data available
              </div>
            ) : (
              <AlertsBySourceChart data={alertsBySource} />
            )}
          </div>

        </div>
      </section>

      {/* ── Row 3: Incident Timeline ── */}
      <section>
        <SectionHeader>Activity Analysis</SectionHeader>
        <div className="bg-bg-card border border-[#21262d] rounded-lg p-5">
          <p className="text-xs font-semibold uppercase tracking-widest text-[#8b949e] mb-4">
            Incident Timeline (by hour)
          </p>
          {incidentsByHour.length === 0 ? (
            <div className="flex items-center justify-center h-[200px] text-[#8b949e] text-sm">
              No timeline data available
            </div>
          ) : (
            <IncidentTimelineChart data={incidentsByHour} />
          )}
        </div>
      </section>

      {/* ── Row 4: Top Incidents Table ── */}
      <section>
        <SectionHeader>Top Incidents by Priority</SectionHeader>
        <div className="bg-bg-card border border-[#21262d] rounded-lg p-5">
          <RecentIncidents incidents={incidents} />
        </div>
      </section>

    </div>
  );
}
