'use client';

import Link from 'next/link';
import { useRouter, usePathname } from 'next/navigation';
import { useState } from 'react';
import { authAPI } from '@/lib/api';

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const router = useRouter();
  const pathname = usePathname();
  const [loading, setLoading] = useState(false);

  const handleLogout = async () => {
    setLoading(true);
    try {
      await authAPI.logout();
      router.push('/');
    } catch (err) {
      console.error('Logout error:', err);
      router.push('/');
    }
  };

  const isActive = (path: string) => pathname === path;

  return (
    <div className="min-h-screen bg-slate-950">
      {/* Navigation */}
      <nav className="bg-gradient-to-r from-slate-900 to-slate-800 border-b border-slate-700 shadow-lg">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center h-16">
            <div className="flex items-center gap-8">
              <h1 className="text-2xl font-bold bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">GoSniffer</h1>
              <div className="flex gap-2">
                <Link
                  href="/dashboard"
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive('/dashboard')
                      ? 'bg-cyan-500 text-slate-900'
                      : 'text-slate-300 hover:text-white border border-slate-700 hover:border-slate-600'
                  }`}
                >
                  Dashboard
                </Link>
                <Link
                  href="/dashboard/devices"
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive('/dashboard/devices')
                      ? 'bg-cyan-500 text-slate-900'
                      : 'text-slate-300 hover:text-white border border-slate-700 hover:border-slate-600'
                  }`}
                >
                  Devices
                </Link>
                <Link
                  href="/dashboard/filters"
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive('/dashboard/filters')
                      ? 'bg-cyan-500 text-slate-900'
                      : 'text-slate-300 hover:text-white border border-slate-700 hover:border-slate-600'
                  }`}
                >
                  Filters
                </Link>
                <Link
                  href="/dashboard/recording"
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive('/dashboard/recording')
                      ? 'bg-cyan-500 text-slate-900'
                      : 'text-slate-300 hover:text-white border border-slate-700 hover:border-slate-600'
                  }`}
                >
                  Recording
                </Link>
                <Link
                  href="/dashboard/files"
                  className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                    isActive('/dashboard/files')
                      ? 'bg-cyan-500 text-slate-900'
                      : 'text-slate-300 hover:text-white border border-slate-700 hover:border-slate-600'
                  }`}
                >
                  Files
                </Link>
              </div>
            </div>
            <button
              onClick={handleLogout}
              disabled={loading}
              className="px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-lg text-sm font-medium transition-colors disabled:opacity-50 border border-red-700"
            >
              {loading ? 'Logging out...' : 'Logout'}
            </button>
          </div>
        </div>
      </nav>

      {/* Main content */}
      <main className="max-w-7xl mx-auto py-6 sm:px-6 lg:px-8">
        {children}
      </main>
    </div>
  );
}
