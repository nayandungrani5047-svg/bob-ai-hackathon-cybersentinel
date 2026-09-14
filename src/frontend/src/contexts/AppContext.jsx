import { createContext, useCallback, useContext, useState } from 'react';
import { apiClient } from '../api/client';

export const AppContext = createContext(null);

export function AppProvider({ children }) {
  const [alertCount, setAlertCount] = useState(null);
  const [incidentCount, setIncidentCount] = useState(null);
  const [lastIngested, setLastIngested] = useState(null);
  const [isIngesting, setIsIngesting] = useState(false);

  const ingestAlerts = useCallback(async () => {
    setIsIngesting(true);
    try {
      const res = await apiClient.ingestAlerts();
      const data = res.data;
      // Backend returns { alerts_ingested, incidents_created, ... }
      if (data?.alerts_ingested != null) setAlertCount(data.alerts_ingested);
      if (data?.incidents_created != null) setIncidentCount(data.incidents_created);
      setLastIngested(new Date().toISOString());
      // Refresh counts from metrics endpoint for accuracy
      try {
        const metrics = await apiClient.getDashboardMetrics();
        if (metrics.data?.total_alerts != null) setAlertCount(metrics.data.total_alerts);
        if (metrics.data?.open_incidents != null) setIncidentCount(metrics.data.open_incidents);
      } catch {
        // Non-fatal — counts from ingest response are good enough
      }
    } finally {
      setIsIngesting(false);
    }
  }, []);

  const resetData = useCallback(async () => {
    try {
      await apiClient.resetData();
      setAlertCount(0);
      setIncidentCount(0);
      setLastIngested(null);
    } catch (err) {
      console.error('Reset failed:', err);
    }
  }, []);

  // Load current counts on mount (backend may already have data)
  const refreshCounts = useCallback(async () => {
    try {
      const metrics = await apiClient.getDashboardMetrics();
      if (metrics.data?.total_alerts != null) setAlertCount(metrics.data.total_alerts);
      if (metrics.data?.open_incidents != null) setIncidentCount(metrics.data.open_incidents);
    } catch {
      // Backend not running yet — that's fine
    }
  }, []);

  const value = {
    alertCount,
    incidentCount,
    lastIngested,
    isIngesting,
    ingestAlerts,
    resetData,
    refreshCounts,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
}

/** Convenience hook */
export function useApp() {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
}
