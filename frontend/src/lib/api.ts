import axios, { AxiosInstance } from 'axios';

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080';

const api: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token if needed
api.interceptors.request.use(
  (config) => {
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle errors
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      // Handle unauthorized - redirect to login
      if (typeof window !== 'undefined') {
        window.location.href = '/';
      }
    }
    return Promise.reject(error);
  }
);

// Auth endpoints
export const authAPI = {
  login: (password: string) =>
    api.post('/login', { password }),
  logout: () =>
    api.post('/logout'),
};

// Device endpoints
export const deviceAPI = {
  list: () =>
    api.get('/sniffer/devices'),
  select: (deviceName: string) =>
    api.post('/sniffer/devices/select', { device_name: deviceName }),
};

// Filter endpoints
export const filterAPI = {
  getFilters: () =>
    api.get('/sniffer/filters'),
  setFilters: (filters: any) =>
    api.post('/sniffer/filters/set', filters),
};

// Recording endpoints
export const recordingAPI = {
  startPcap: (durationSeconds: number = 0) =>
    api.post('/sniffer/recording/pcap/start', { duration_seconds: durationSeconds }),
  stopPcap: () =>
    api.post('/sniffer/recording/pcap/stop', {}),
  startCsv: (durationSeconds: number = 0) =>
    api.post('/sniffer/recording/csv/start', { duration_seconds: durationSeconds }),
  stopCsv: () =>
    api.post('/sniffer/recording/csv/stop', {}),
  startJson: (durationSeconds: number = 0) =>
    api.post('/sniffer/recording/json/start', { duration_seconds: durationSeconds }),
  stopJson: () =>
    api.post('/sniffer/recording/json/stop', {}),
  getStatus: () =>
    api.get('/sniffer/recording/pcap/status'),
  getStatusPcap: () =>
    api.get('/sniffer/recording/pcap/status'),
  getStatusCsv: () =>
    api.get('/sniffer/recording/csv/status'),
  getStatusJson: () =>
    api.get('/sniffer/recording/json/status'),
};

// Metrics endpoints
export const metricsAPI = {
  startCollection: () =>
    api.post('/sniffer/metrics/start'),
  stopCollection: () =>
    api.post('/sniffer/metrics/stop'),
  getStatus: () =>
    api.get('/sniffer/metrics/status'),
  getMetrics: () =>
    api.get('/metrics'),
  streamMetrics: (onData: (data: any) => void, onError: (error: Error) => void) => {
    const eventSource = new EventSource(`${API_BASE_URL}/sniffer/packets/stream`);

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        onData(data);
      } catch (err) {
        onError(new Error('Failed to parse metrics data'));
      }
    };

    eventSource.onerror = () => {
      eventSource.close();
      onError(new Error('Metrics stream disconnected'));
    };

    return eventSource;
  },
};

// File operations endpoints
export const fileAPI = {
  listFiles: () =>
    api.get('/sniffer/captures'),
  downloadFile: (fileName: string, format: 'pcap' | 'csv' | 'json') =>
    api.get(`/sniffer/captures/download/${format}/${fileName}`, {
      responseType: 'blob',
    }),
};

export default api;
