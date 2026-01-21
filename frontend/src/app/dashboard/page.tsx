'use client';

import { useState, useEffect } from 'react';
import { metricsAPI } from '@/lib/api';

interface MetricsData {
  timestamp: number;
  packets_per_second: number;
  total_packets: number;
  dropped_packets: number;
  drop_rate_percent: number;
  bytes_per_second: number;
  total_bytes: number;
  mbps: number;
  peak_metrics: {
    peak_pps: number;
    peak_mbps: number;
    avg_pps: number;
    avg_mbps: number;
    peak_memory_mb: number;
    peak_goroutines: number;
  };
  active_subscribers: number;
  system_metrics: {
    memory_usage_mb: number;
    memory_alloc_mb: number;
    goroutine_count: number;
    cpu_cores: number;
    gc_pause_ms: number;
  };
  sniffer_status: {
    uptime_seconds: number;
    interface: string;
    is_recording: boolean;
    is_metrics_enabled: boolean;
    consecutive_errors: number;
    filter_active: boolean;
  };
  storage_metrics: {
    capture_file_count: number;
    total_storage_used_mb: number;
    disk_space_free_mb: number;
    disk_usage_percent: number;
    oldest_capture_age_hours: number;
  };
  error_metrics: {
    total_errors: number;
    errors_last_minute: number;
    last_error_time: number;
    capture_errors: number;
    processing_errors: number;
  };
  protocol_stats: Record<string, number>;
}

export default function Dashboard() {
  const [metrics, setMetrics] = useState<MetricsData | null>(null);
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let eventSource: EventSource | null = null;
    let reconnectTimeout: NodeJS.Timeout | null = null;

    const handleMetricsData = (data: MetricsData) => {
      setMetrics(data);
      setError('');
      setLoading(false);
      
      setHistory((prev) => {
        const newHistory = [
          ...prev,
          {
            time: new Date(data.timestamp).toLocaleTimeString(),
            pps: data.packets_per_second,
            mbps: data.mbps,
            memory: data.system_metrics.memory_usage_mb,
          },
        ];
        return newHistory.slice(-30); // Keep last 30 data points
      });
    };

    const handleMetricsError = (err: Error) => {
      // Don't show error if we already have metrics - just show temporary status
      if (metrics) {
        // Connection was closed but we have data, try to reconnect silently
        if (eventSource) {
          eventSource.close();
          eventSource = null;
        }
        // Reconnect after 1 second
        reconnectTimeout = setTimeout(() => {
          connectToMetrics();
        }, 1000);
      } else {
        // If we never got metrics, show the error
        setError('Unable to connect to metrics stream. Retrying...');
        setLoading(false);
        // Retry after 2 seconds
        reconnectTimeout = setTimeout(() => {
          connectToMetrics();
        }, 2000);
      }
    };

    const connectToMetrics = () => {
      try {
        eventSource = metricsAPI.streamMetrics(handleMetricsData, handleMetricsError);
      } catch (err: any) {
        handleMetricsError(new Error(err.message || 'Failed to connect to metrics stream'));
      }
    };

    connectToMetrics();

    return () => {
      if (eventSource) {
        eventSource.close();
      }
      if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
      }
    };
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          <p className="mt-4 text-gray-600">Loading metrics...</p>
        </div>
      </div>
    );
  }

  if (error && !metrics) {
    return (
      <div className="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded">
        Error: {error}
      </div>
    );
  }

  const MetricCard = ({ label, value, unit = '' }: any) => (
    <div className="bg-gradient-to-br from-slate-800 to-slate-900 p-4 rounded-lg border border-slate-700 hover:border-slate-600 transition-colors">
      <p className="text-slate-400 text-xs font-semibold uppercase tracking-wider">{label}</p>
      <div className="flex items-baseline gap-2 mt-2">
        <p className="text-3xl font-bold text-white">{value}</p>
        {unit && <span className="text-sm text-slate-400">{unit}</span>}
      </div>
    </div>
  );

  const SectionTitle = ({ children }: any) => (
    <h2 className="text-xl font-bold text-white mb-4 flex items-center gap-2">
      <div className="w-1 h-6 bg-gradient-to-b from-cyan-500 to-blue-500 rounded-full"></div>
      {children}
    </h2>
  );

  return (
    <div className="min-h-screen bg-slate-950 p-6 space-y-8">
      {/* Current Metrics */}
      <div>
        <SectionTitle>Current Metrics</SectionTitle>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
          <MetricCard label="Packets/Sec" value={metrics?.packets_per_second || 0} unit="pkt/s" />
          <MetricCard label="Bytes/Sec" value={(metrics?.bytes_per_second || 0).toLocaleString()} unit="B/s" />
          <MetricCard label="Throughput" value={metrics?.mbps.toFixed(2) || '0.00'} unit="Mbps" />
          <MetricCard label="Total Packets" value={(metrics?.total_packets || 0).toLocaleString()} />
          <MetricCard label="Total Bytes" value={(metrics?.total_bytes || 0).toLocaleString()} unit="B" />
        </div>
      </div>

      {/* Packet Loss & Buffer */}
      <div>
        <SectionTitle>Packet Loss & Buffer</SectionTitle>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
          <MetricCard label="Dropped Packets" value={metrics?.dropped_packets || 0} />
          <MetricCard label="Drop Rate" value={(metrics?.drop_rate_percent || 0).toFixed(2)} unit="%" />
          <MetricCard label="Active Subscribers" value={metrics?.active_subscribers || 0} />
        </div>
      </div>

      {/* Peak Metrics */}
      {metrics?.peak_metrics && (
        <div>
          <SectionTitle>Peak Metrics</SectionTitle>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            <MetricCard label="Peak PPS" value={metrics.peak_metrics.peak_pps || 0} unit="pkt/s" />
            <MetricCard label="Peak Mbps" value={(metrics.peak_metrics.peak_mbps || 0).toFixed(2)} unit="Mbps" />
            <MetricCard label="Avg PPS" value={metrics.peak_metrics.avg_pps || 0} unit="pkt/s" />
            <MetricCard label="Avg Mbps" value={(metrics.peak_metrics.avg_mbps || 0).toFixed(2)} unit="Mbps" />
            <MetricCard label="Peak Memory" value={metrics.peak_metrics.peak_memory_mb || 0} unit="MB" />
            <MetricCard label="Peak Goroutines" value={metrics.peak_metrics.peak_goroutines || 0} />
          </div>
        </div>
      )}

      {/* System Metrics */}
      {metrics?.system_metrics && (
        <div>
          <SectionTitle>System Metrics</SectionTitle>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            <MetricCard label="Memory Usage" value={metrics.system_metrics.memory_usage_mb || 0} unit="MB" />
            <MetricCard label="Memory Alloc" value={metrics.system_metrics.memory_alloc_mb || 0} unit="MB" />
            <MetricCard label="Goroutines" value={metrics.system_metrics.goroutine_count || 0} />
            <MetricCard label="CPU Cores" value={metrics.system_metrics.cpu_cores || 0} />
            <MetricCard label="GC Pause" value={metrics.system_metrics.gc_pause_ms || 0} unit="ms" />
          </div>
        </div>
      )}

      {/* Sniffer Status */}
      {metrics?.sniffer_status && (
        <div>
          <SectionTitle>Sniffer Status</SectionTitle>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            <MetricCard label="Uptime" value={metrics.sniffer_status.uptime_seconds || 0} unit="s" />
            <MetricCard label="Interface" value={metrics.sniffer_status.interface || 'N/A'} />
            <MetricCard label="Recording" value={metrics.sniffer_status.is_recording ? '● Active' : '○ Inactive'} />
            <MetricCard label="Metrics" value={metrics.sniffer_status.is_metrics_enabled ? '● Enabled' : '○ Disabled'} />
            <MetricCard label="Errors" value={metrics.sniffer_status.consecutive_errors || 0} />
            <MetricCard label="Filter" value={metrics.sniffer_status.filter_active ? '● Active' : '○ Inactive'} />
          </div>
        </div>
      )}

      {/* Storage Metrics */}
      {metrics?.storage_metrics && (
        <div>
          <SectionTitle>Storage Metrics</SectionTitle>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            <MetricCard label="Capture Files" value={metrics.storage_metrics.capture_file_count || 0} />
            <MetricCard label="Storage Used" value={metrics.storage_metrics.total_storage_used_mb || 0} unit="MB" />
            <MetricCard label="Disk Free" value={(metrics.storage_metrics.disk_space_free_mb || 0).toLocaleString()} unit="MB" />
            <MetricCard label="Disk Usage" value={(metrics.storage_metrics.disk_usage_percent || 0).toFixed(2)} unit="%" />
            <MetricCard label="Oldest Capture" value={metrics.storage_metrics.oldest_capture_age_hours || 0} unit="h" />
          </div>
        </div>
      )}

      {/* Error Metrics */}
      {metrics?.error_metrics && (
        <div>
          <SectionTitle>Error Metrics</SectionTitle>
          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-4">
            <MetricCard label="Total Errors" value={metrics.error_metrics.total_errors || 0} />
            <MetricCard label="Last Minute" value={metrics.error_metrics.errors_last_minute || 0} />
            <MetricCard label="Capture Errors" value={metrics.error_metrics.capture_errors || 0} />
            <MetricCard label="Processing Errors" value={metrics.error_metrics.processing_errors || 0} />
          </div>
        </div>
      )}
    </div>
  );
}
