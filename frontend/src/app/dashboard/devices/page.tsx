'use client';

import { useState, useEffect } from 'react';
import { deviceAPI } from '@/lib/api';

interface Device {
  name: string;
  description: string;
}

export default function DevicesPage() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [selectedDevice, setSelectedDevice] = useState('');
  const [loading, setLoading] = useState(true);
  const [selecting, setSelecting] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  useEffect(() => {
    fetchDevices();
  }, []);

  const fetchDevices = async () => {
    try {
      setLoading(true);
      const response = await deviceAPI.list();
      // Convert string array to Device objects
      const deviceList = (response.data || []).map((name: string) => ({
        name,
        description: `Network interface: ${name}`,
      }));
      setDevices(deviceList);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to fetch devices');
    } finally {
      setLoading(false);
    }
  };

  const handleSelectDevice = async () => {
    if (!selectedDevice) return;
    
    try {
      setSelecting(true);
      await deviceAPI.select(selectedDevice);
      setSuccess(`Successfully selected ${selectedDevice}`);
      setTimeout(() => setSuccess(''), 3000);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to select device');
    } finally {
      setSelecting(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
          <p className="mt-4 text-slate-400">Loading devices...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Network Devices</h1>
        <p className="mt-2 text-slate-400">Select a network interface to capture packets from</p>
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

      <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg shadow-lg border border-slate-700">
        <div className="p-6">
          <h2 className="text-lg font-semibold mb-4 text-white">Available Devices</h2>
          
          {devices.length === 0 ? (
            <p className="text-slate-400">No network devices found</p>
          ) : (
            <div className="space-y-3">
              {devices.map((device, index) => (
                <label
                  key={`${device.name}-${index}`}
                  className="flex items-center p-4 border border-slate-700 rounded-lg cursor-pointer hover:border-slate-600 hover:bg-slate-800/50 transition-all"
                >
                  <input
                    type="radio"
                    name="device"
                    value={device.name}
                    checked={selectedDevice === device.name}
                    onChange={(e) => setSelectedDevice(e.target.value)}
                    className="w-4 h-4 text-cyan-500 accent-cyan-500"
                  />
                  <div className="ml-3">
                    <p className="font-medium text-white">{device.name}</p>
                    <p className="text-sm text-slate-400">{device.description}</p>
                  </div>
                </label>
              ))}
            </div>
          )}

          <div className="mt-6">
            <button
              onClick={handleSelectDevice}
              disabled={!selectedDevice || selecting}
              className="w-full bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white font-semibold py-3 px-4 rounded-lg transition-all"
            >
              {selecting ? 'Selecting...' : 'Select Device'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
