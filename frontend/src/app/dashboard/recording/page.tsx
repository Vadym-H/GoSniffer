'use client';

import { useState, useEffect } from 'react';
import { recordingAPI } from '@/lib/api';

interface RecordingStatus {
  status: string;
  is_recording: boolean;
  start_time: string;
  end_time: string;
  duration_seconds: number;
  elapsed_seconds: number;
}

export default function RecordingPage() {
  const [recordingDuration, setRecordingDuration] = useState(60); // Default 60 seconds
  const [formats, setFormats] = useState({
    pcap: { recording: false, loading: false },
    csv: { recording: false, loading: false },
    json: { recording: false, loading: false },
  });
  const [status, setStatus] = useState<RecordingStatus | null>(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 1000);
    return () => clearInterval(interval);
  }, []);

  const fetchStatus = async () => {
    try {
      const [pcapRes, csvRes, jsonRes] = await Promise.all([
        recordingAPI.getStatusPcap(),
        recordingAPI.getStatusCsv(),
        recordingAPI.getStatusJson(),
      ]);

      // Update individual format statuses
      setFormats((prev) => ({
        pcap: { ...prev.pcap, recording: pcapRes.data.is_recording },
        csv: { ...prev.csv, recording: csvRes.data.is_recording },
        json: { ...prev.json, recording: jsonRes.data.is_recording },
      }));

      // Create combined status - show if ANY format is recording
      const anyRecording = pcapRes.data.is_recording || csvRes.data.is_recording || jsonRes.data.is_recording;
      const combinedStatus: RecordingStatus = {
        status: anyRecording ? 'recording' : 'stopped',
        is_recording: anyRecording,
        start_time: pcapRes.data.start_time || csvRes.data.start_time || jsonRes.data.start_time || '',
        end_time: pcapRes.data.end_time || csvRes.data.end_time || jsonRes.data.end_time || '',
        duration_seconds: pcapRes.data.duration_seconds || csvRes.data.duration_seconds || jsonRes.data.duration_seconds || 0,
        elapsed_seconds: pcapRes.data.elapsed_seconds || csvRes.data.elapsed_seconds || jsonRes.data.elapsed_seconds || 0,
      };
      setStatus(combinedStatus);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to fetch recording status');
    } finally {
      setLoading(false);
    }
  };

  const handleToggleRecording = async (format: 'pcap' | 'csv' | 'json') => {
    try {
      setFormats((prev) => ({
        ...prev,
        [format]: { ...prev[format], loading: true },
      }));

      if (formats[format].recording) {
        // Stop recording
        if (format === 'pcap') await recordingAPI.stopPcap();
        else if (format === 'csv') await recordingAPI.stopCsv();
        else await recordingAPI.stopJson();
      } else {
        // Start recording
        if (format === 'pcap') await recordingAPI.startPcap(recordingDuration);
        else if (format === 'csv') await recordingAPI.startCsv(recordingDuration);
        else await recordingAPI.startJson(recordingDuration);
      }

      await fetchStatus();
    } catch (err: any) {
      setError(err.response?.data?.message || `Failed to ${formats[format].recording ? 'stop' : 'start'} recording`);
    } finally {
      setFormats((prev) => ({
        ...prev,
        [format]: { ...prev[format], loading: false },
      }));
    }
  };

  const formatTime = (seconds: number) => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
          <p className="mt-4 text-slate-400">Loading recording status...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Packet Recording</h1>
        <p className="mt-2 text-slate-400">Start/stop recording captured packets in different formats</p>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-600 text-red-300 px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {/* Recording Duration Settings */}
      <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Recording Settings</h2>
        <div className="max-w-xs">
          <label className="block text-sm text-slate-400 font-medium uppercase mb-2">
            Duration (seconds)
          </label>
          <input
            type="number"
            min="1"
            max="3600"
            value={recordingDuration}
            onChange={(e) => setRecordingDuration(Math.max(1, parseInt(e.target.value) || 1))}
            className="w-full px-4 py-2 bg-slate-700 border border-slate-600 rounded text-white focus:border-cyan-500 focus:outline-none"
          />
          <p className="mt-2 text-xs text-slate-400">Set how long each recording should run</p>
        </div>
      </div>

      {/* Status Information */}
      {status && (
        <div className="bg-gradient-to-br from-slate-800 to-slate-900 border border-slate-700 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Recording Status</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <p className="text-sm text-slate-400 font-medium uppercase">Status</p>
              <p className="text-2xl font-bold text-white mt-1">
                {status.is_recording ? '🔴 Recording' : '⏹️ Stopped'}
              </p>
            </div>
            <div>
              <p className="text-sm text-slate-400 font-medium uppercase">Elapsed Time</p>
              <p className="text-2xl font-bold text-cyan-400 mt-1">
                {formatTime(status.elapsed_seconds)}
              </p>
            </div>
            <div>
              <p className="text-sm text-slate-400 font-medium uppercase">Duration</p>
              <p className="text-2xl font-bold text-cyan-400 mt-1">
                {formatTime(status.duration_seconds)}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Recording Formats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {(['pcap', 'csv', 'json'] as const).map((format) => (
          <div key={format} className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg shadow-lg border border-slate-700 p-6">
            <h3 className="text-lg font-semibold mb-4 uppercase text-white">{format}</h3>
            
            <div className="mb-6">
              <p className="text-slate-400 text-sm">
                {format === 'pcap' && 'Binary pcap format (tcpdump compatible)'}
                {format === 'csv' && 'Comma-separated values for spreadsheet analysis'}
                {format === 'json' && 'Structured JSON format for programmatic access'}
              </p>
            </div>

            <div className="mb-6 p-4 bg-slate-700/50 rounded border border-slate-700">
              <p className="text-sm text-slate-400 uppercase">Status</p>
              <p className="text-2xl font-bold mt-2">
                {formats[format].recording ? (
                  <span className="text-green-400">● Recording</span>
                ) : (
                  <span className="text-red-400">● Stopped</span>
                )}
              </p>
            </div>

            <button
              onClick={() => handleToggleRecording(format)}
              disabled={formats[format].loading}
              className={`w-full py-3 px-4 rounded-lg font-semibold transition-all ${
                formats[format].recording
                  ? 'bg-red-600 hover:bg-red-700 disabled:opacity-50 text-white'
                  : 'bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white'
              }`}
            >
              {formats[format].loading
                ? 'Processing...'
                : formats[format].recording
                ? 'Stop Recording'
                : 'Start Recording'}
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}
