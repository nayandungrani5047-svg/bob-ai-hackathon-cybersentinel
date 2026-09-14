import axios from 'axios';

const api = axios.create({
  baseURL: '/api', // proxied to http://localhost:8000/api via vite config
  timeout: 30000,
});

export const apiClient = {
  // Ingest / Reset
  ingestAlerts: () => api.post('/ingest'),
  resetData: () => api.delete('/reset'),

  // Dashboard
  getDashboardMetrics: () => api.get('/dashboard/metrics'),

  // Alerts
  getAlerts: (params = {}) => api.get('/alerts', { params }),
  getAlert: (id) => api.get(`/alerts/${id}`),

  // Incidents
  getIncidents: (params = {}) => api.get('/incidents', { params }),
  getIncident: (id) => api.get(`/incidents/${id}`),
  getInvestigation: (id) => api.get(`/incidents/${id}/investigation`),

  // Health
  healthCheck: () => api.get('/health'),
};

export default api;
