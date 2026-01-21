'use client';

import { useState, useEffect } from 'react';
import { filterAPI } from '@/lib/api';

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

export default function FiltersPage() {
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
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    fetchFilters();
  }, []);

  const fetchFilters = async () => {
    try {
      setLoading(true);
      const response = await filterAPI.getFilters();
      setFilters(response.data || filters);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to fetch filters');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    try {
      setSaving(true);
      await filterAPI.setFilters(filters);
      setSuccess('Filters updated successfully');
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to save filters');
    } finally {
      setSaving(false);
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

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
          <p className="mt-4 text-slate-400">Loading filters...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Packet Filters</h1>
        <p className="mt-2 text-slate-400">Configure BPF filters to capture specific packets</p>
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

      <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg shadow-lg border border-slate-700 p-6">
        {/* Protocol Selection */}
        <div className="mb-8">
          <h2 className="text-lg font-semibold mb-4 text-white">Protocols</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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

        {/* IP Filters */}
        <div className="mb-8 pb-8 border-b border-slate-700">
          <h2 className="text-lg font-semibold mb-4 text-white">IP Addresses</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
          </div>
        </div>

        {/* Port Filter */}
        <div className="mb-8">
          <h2 className="text-lg font-semibold mb-4 text-white">Ports</h2>
          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Port(s) (optional)
            </label>
            <input
              type="text"
              value={filters.ports}
              onChange={(e) => handleInputChange('ports', e.target.value)}
              placeholder="e.g., 80,443 or 8000-9000"
              className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded-lg text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-all"
            />
            <p className="mt-2 text-sm text-slate-400">
              Separate multiple ports with commas or use ranges with hyphens
            </p>
          </div>
        </div>

        {/* Save Button */}
        <div className="flex gap-4">
          <button
            onClick={handleSave}
            disabled={saving}
            className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white font-semibold rounded-lg transition-all"
          >
            {saving ? 'Saving...' : 'Save Filters'}
          </button>
          <button
            onClick={fetchFilters}
            disabled={loading}
            className="px-6 py-3 bg-slate-700 hover:bg-slate-600 text-white font-semibold rounded-lg transition-all border border-slate-600"
          >
            Refresh
          </button>
        </div>
      </div>
    </div>
  );
}
