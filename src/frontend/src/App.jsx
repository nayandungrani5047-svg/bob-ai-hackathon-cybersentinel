import { BrowserRouter, Routes, Route, useLocation } from 'react-router-dom';
import { useEffect } from 'react';
import { AppProvider, useApp } from './contexts/AppContext';
import Sidebar from './components/layout/Sidebar';
import TopBar from './components/layout/TopBar';
import Dashboard from './pages/Dashboard';
import AlertList from './pages/AlertList';
import IncidentList from './pages/IncidentList';
import Investigation from './pages/Investigation';

const PAGE_TITLES = {
  '/': 'Dashboard',
  '/alerts': 'Alerts',
  '/incidents': 'Incidents',
};

function getTitle(pathname) {
  if (pathname.startsWith('/incidents/')) return 'Investigation';
  return PAGE_TITLES[pathname] ?? 'D2 TIAC';
}

function AppLayout() {
  const location = useLocation();
  const { alertCount, incidentCount, isIngesting, ingestAlerts, resetData, refreshCounts } =
    useApp();

  // Refresh counts whenever the layout mounts
  useEffect(() => {
    refreshCounts();
  }, [refreshCounts]);

  const title = getTitle(location.pathname);

  return (
    <div className="flex min-h-screen bg-[#0a0f1a]">
      {/* Fixed sidebar */}
      <Sidebar />

      {/* Main area offset by sidebar width */}
      <div className="flex flex-col flex-1 ml-64">
        <TopBar
          title={title}
          onIngest={ingestAlerts}
          onReset={resetData}
          isIngesting={isIngesting}
          alertCount={alertCount}
          incidentCount={incidentCount}
        />
        <main className="flex-1 overflow-y-auto">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/alerts" element={<AlertList />} />
            <Route path="/incidents" element={<IncidentList />} />
            <Route path="/incidents/:id" element={<Investigation />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AppProvider>
        <AppLayout />
      </AppProvider>
    </BrowserRouter>
  );
}
