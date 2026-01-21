'use client';

import { useState, useEffect } from 'react';
import { configurationAPI } from '@/lib/api';

interface Device {
  name: string;
  description: string;
}

interface Filters {
  protocols: {
    tcp: boolean;
    udp: boolean;
    icmp: boolean;
    dns: boolean;
  };
  src_ip: string;
  dst_ip: string;
  ports: string;
}

export default function ConfigurationPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [filters, setFilters] = useState<Filters>({
    protocols: {
      tcp: true,
      udp: true,
      icmp: true,
      dns: true,
    },
    src_ip: '',
    dst_ip: '',
    ports: '',
  });
  const [loading, setLoading] = useState(true);
  const [applying, setApplying] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    fetchConfiguration();
  }, []);

  const fetchConfiguration = async () => {
    try {
      setLoading(true);
      const [devicesRes, filtersRes] = await Promise.all([
        configurationAPI.getDevices(),
        configurationAPI.getFilters(),
      ]);

      setDevices(devicesRes.data || []);
      setFilters(filtersRes.data || filters);
      
      // Set the first device as selected if available
      if (devicesRes.data && devicesRes.data.length > 0) {
        setSelectedDevice(devicesRes.data[0].name);
      }
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to fetch configuration');
    } finally {
      setLoading(false);
    }
  };

  const handleProtocolChange = (protocol: keyof Filters['protocols']) => {
    setFilters((prev) => ({
      ...prev,
      protocols: {
        ...prev.protocols,
        [protocol]: !prev.protocols[protocol],
      },
    }));
  };

  const handleInputChange = (field: 'src_ip' | 'dst_ip' | 'ports', value: string) => {
    setFilters((prev) => ({
      ...prev,
      [field]: value,
    }));
  };

  const handleApplyConfiguration = async () => {
    if (!selectedDevice) {
      setError('Please select a device');
      return;
    }

    try {
      setApplying(true);
      setError('');
      await configurationAPI.applyConfiguration({
        device_name: selectedDevice,
        filters,
      });
      setSuccess('Configuration applied successfully. Sniffer is restarting...');
      setTimeout(() => setSuccess(''), 5000);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to apply configuration');
    } finally {
      setApplying(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
          <p className="mt-4 text-slate-400">Loading configuration...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Sniffer Configuration</h1>
        <p className="mt-2 text-slate-400">Configure network device and packet filters, then restart the sniffer</p>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-600 text-red-300 px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {success && (
        <div className="bg-green-900/30 border border-green-600 text-green-300 px-4 py-3 rounded-lg">
          {success}
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Device Selection */}
        <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg shadow-lg border border-slate-700 p-6">
          <h2 className="text-lg font-semibold mb-4 text-white">Network Device</h2>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-3">
              Select Interface
            </label>
            <select
              value={selectedDevice}
              onChange={(e) => setSelectedDevice(e.target.value)}
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all"
            >
              <option value="">Choose a device...</option>
              {devices.map((device, index) => (
                <option key={`${device.name}-${index}`} value={device.name}>
                  {device.name} {device.description ? `- ${device.description}` : ''}
                </option>
              ))}
            </select>
            <p className="mt-2 text-sm text-slate-400">
              Select the network interface to capture packets from
            </p>
          </div>
        </div>

        {/* Protocols */}
        <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg shadow-lg border border-slate-700 p-6">
          <h2 className="text-lg font-semibold mb-4 text-white">Protocols</h2>
          <div className="space-y-3">
            {(Object.keys(filters.protocols) as Array<keyof Filters['protocols']>).map((protocol) => (
              <label key={protocol} className="flex items-center cursor-pointer">
                <input
                  type="checkbox"
                  checked={filters.protocols[protocol]}
                  onChange={() => handleProtocolChange(protocol)}
                  className="w-4 h-4 text-cyan-500 rounded accent-cyan-500"
                />
                <span className="ml-3 text-slate-300 font-medium uppercase">{protocol}</span>
              </label>
            ))}
          </div>
        </div>
      </div>

      {/* IP and Port Filters */}
      <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg shadow-lg border border-slate-700 p-6">
        <h2 className="text-lg font-semibold mb-6 text-white">Advanced Filters</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Source IP (optional)
            </label>
            <input
              type="text"
              value={filters.src_ip}
              onChange={(e) => handleInputChange('src_ip', e.target.value)}
              placeholder="e.g., 192.168.1.1"
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Destination IP (optional)
            </label>
            <input
              type="text"
              value={filters.dst_ip}
              onChange={(e) => handleInputChange('dst_ip', e.target.value)}
              placeholder="e.g., 192.168.1.254"
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Ports (optional)
            </label>
            <input
              type="text"
              value={filters.ports}
              onChange={(e) => handleInputChange('ports', e.target.value)}
              placeholder="e.g., 80,443"
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all"
            />
          </div>
        </div>
        <p className="mt-3 text-sm text-slate-400">
          Use comma-separated values for multiple ports or hyphens for ranges (e.g., 8000-9000)
        </p>
      </div>

      {/* Apply Button */}
      <div className="flex gap-4">
        <button
          onClick={handleApplyConfiguration}
          disabled={applying || !selectedDevice}
          className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold rounded-lg transition-all"
        >
          {applying ? 'Applying Configuration...' : 'Apply & Restart Sniffer'}
        </button>
        <button
          onClick={fetchConfiguration}
          disabled={loading}
          className="px-6 py-3 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg transition-all border border-slate-600"
        >
          Refresh
        </button>
      </div>

      {/* Info Box */}
      <div className="bg-blue-900/20 border border-blue-700 rounded-lg p-4">
        <p className="text-sm text-blue-200">
          <strong>Note:</strong> Applying a new configuration will completely restart the packet sniffer. 
          Any active recording sessions will be stopped, and metrics will be reset.
        </p>
      </div>
    </div>
  );
}
