'use client';

import { useState, useEffect } from 'react';
import { fileAPI } from '@/lib/api';

interface FileInfo {
  name: string;
  size: number;
  modified: number;
  type: 'pcap' | 'csv' | 'json';
}

export default function FilesPage() {
  const [files, setFiles] = useState<FileInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [downloading, setDownloading] = useState<string | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    fetchFiles();
    const interval = setInterval(fetchFiles, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchFiles = async () => {
    try {
      const response = await fileAPI.listFiles();
      setFiles(response.data.files || []);
      setError('');
    } catch (err: any) {
      setError(err.message || 'Failed to fetch files');
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async (file: FileInfo) => {
    try {
      setDownloading(file.name);
      const response = await fileAPI.downloadFile(file.name, file.type);
      
      // Create a blob URL and trigger download
      const url = window.URL.createObjectURL(response.data);
      const link = document.createElement('a');
      link.href = url;
      link.download = file.name;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (err: any) {
      setError('Failed to download file');
    } finally {
      setDownloading(null);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDate = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleString();
  };

  const groupedFiles = {
    pcap: files.filter((f) => f.type === 'pcap'),
    csv: files.filter((f) => f.type === 'csv'),
    json: files.filter((f) => f.type === 'json'),
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <div className="inline-block animate-spin rounded-full h-12 w-12 border-b-2 border-cyan-500"></div>
          <p className="mt-4 text-slate-400">Loading files...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold text-white">Captured Files</h1>
        <p className="mt-2 text-slate-400">Download recorded packet captures in various formats</p>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-600 text-red-300 px-4 py-3 rounded-lg">
          {error}
        </div>
      )}

      {files.length === 0 ? (
        <div className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg shadow-lg p-12 text-center border border-slate-700">
          <p className="text-slate-400 text-lg">No capture files available yet</p>
          <p className="text-slate-500 mt-2">Start recording packets to create files</p>
        </div>
      ) : (
        <div className="space-y-6">
          {(['pcap', 'csv', 'json'] as const).map((format) => (
            groupedFiles[format].length > 0 && (
              <div key={format} className="bg-gradient-to-br from-slate-800 to-slate-900 rounded-lg shadow-lg overflow-hidden border border-slate-700">
                <div className="bg-slate-800/50 px-6 py-4 border-b border-slate-700">
                  <h2 className="text-lg font-semibold text-white">
                    {format.toUpperCase()} Files ({groupedFiles[format].length})
                  </h2>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full">
                    <thead className="bg-slate-700 border-b border-slate-600">
                      <tr>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-white">
                          Filename
                        </th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-white">
                          Size
                        </th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-white">
                          Modified
                        </th>
                        <th className="px-6 py-3 text-left text-sm font-semibold text-white">
                          Action
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {groupedFiles[format].map((file) => (
                        <tr key={file.name} className="border-b border-slate-700 hover:bg-slate-700/50 transition-colors">
                          <td className="px-6 py-4 text-sm text-white font-mono break-all">
                            {file.name}
                          </td>
                          <td className="px-6 py-4 text-sm text-slate-300">
                            {formatFileSize(file.size)}
                          </td>
                          <td className="px-6 py-4 text-sm text-slate-300">
                            {formatDate(file.modified)}
                          </td>
                          <td className="px-6 py-4 text-sm">
                            <button
                              onClick={() => handleDownload(file)}
                              disabled={downloading === file.name}
                              className="px-4 py-2 bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-white rounded font-medium transition-all"
                            >
                              {downloading === file.name ? 'Downloading...' : 'Download'}
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )
          ))}
        </div>
      )}
    </div>
  );
}
