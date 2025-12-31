"use client";

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import { listScans, getResult } from '@/lib/api';
import { ScanSummary, ScanResult } from '@/lib/types';
import TerminalShell from '@/components/TerminalShell';
import ScanHistoryTable from '@/components/ScanHistoryTable';
import { History, ArrowLeft, RefreshCw, AlertTriangle } from 'lucide-react';

export default function HistoryPage() {
    const [scans, setScans] = useState<ScanSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const fetchScans = async () => {
        setLoading(true);
        setError(null);
        try {
            const data = await listScans(100, 0);
            setScans(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to load scans");
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchScans();
    }, []);

    return (
        <TerminalShell>
            <div className="flex flex-col gap-6 h-full">
                {/* Header */}
                <div className="flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        <Link
                            href="/"
                            className="cyber-button-outline flex items-center gap-2 text-sm py-2 px-4"
                        >
                            <ArrowLeft size={16} />
                            <span className="uppercase tracking-wider">Back to Scan</span>
                        </Link>
                        <h1 className="section-title flex items-center gap-2 text-lg">
                            <History size={18} className="text-terminal-accent" />
                            SCAN HISTORY
                        </h1>
                    </div>
                    <button
                        onClick={fetchScans}
                        disabled={loading}
                        className="cyber-button-outline flex items-center gap-2 text-sm py-2 px-4"
                    >
                        <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
                        <span className="uppercase tracking-wider">Refresh</span>
                    </button>
                </div>

                {/* Content */}
                <div className="terminal-box p-6 flex-1 overflow-hidden">
                    {loading && scans.length === 0 ? (
                        <div className="flex items-center justify-center h-full text-terminal-dim">
                            <RefreshCw className="animate-spin mr-2" size={20} />
                            Loading scans...
                        </div>
                    ) : error ? (
                        <div className="flex items-center justify-center h-full">
                            <div className="text-terminal-red flex items-center gap-2">
                                <AlertTriangle size={20} />
                                {error}
                            </div>
                        </div>
                    ) : scans.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-full text-terminal-dim">
                            <History size={48} className="mb-4 opacity-30" />
                            <p>No scans yet.</p>
                            <Link
                                href="/"
                                className="mt-4 cyber-button text-sm py-2 px-4"
                            >
                                Run your first scan
                            </Link>
                        </div>
                    ) : (
                        <ScanHistoryTable scans={scans} />
                    )}
                </div>
            </div>
        </TerminalShell>
    );
}
