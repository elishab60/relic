'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Link from 'next/link';
import { getScanHistory, getResult } from '@/lib/api';
import { ScanListItem, ScanResult } from '@/lib/types';
import ScanHistoryTable from '@/components/ScanHistoryTable';
import ResultTabs from '@/components/ResultTabs';

export default function HistoryPage() {
    const router = useRouter();
    const [scans, setScans] = useState<ScanListItem[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [selectedScan, setSelectedScan] = useState<ScanResult | null>(null);
    const [loadingDetails, setLoadingDetails] = useState(false);

    useEffect(() => {
        loadScans();
    }, []);

    async function loadScans() {
        try {
            setLoading(true);
            setError(null);
            const data = await getScanHistory();
            setScans(data);
        } catch (err) {
            setError(err instanceof Error ? err.message : 'Failed to load scan history');
        } finally {
            setLoading(false);
        }
    }

    async function handleSelectScan(scanId: string) {
        try {
            setLoadingDetails(true);
            const result = await getResult(scanId);
            setSelectedScan(result);
        } catch (err) {
            console.error('Failed to load scan details:', err);
        } finally {
            setLoadingDetails(false);
        }
    }

    function handleBack() {
        setSelectedScan(null);
    }

    return (
        <main className="min-h-screen bg-gray-900 text-white">
            {/* Header */}
            <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur-sm sticky top-0 z-10">
                <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                        {selectedScan && (
                            <button
                                onClick={handleBack}
                                className="text-gray-400 hover:text-white transition-colors"
                            >
                                ← Back
                            </button>
                        )}
                        <h1 className="text-xl font-bold">
                            {selectedScan ? 'Scan Details' : 'Scan History'}
                        </h1>
                    </div>
                    <Link
                        href="/"
                        className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 rounded text-sm transition-colors"
                    >
                        New Scan
                    </Link>
                </div>
            </header>

            {/* Content */}
            <div className="max-w-7xl mx-auto px-4 py-6">
                {loading ? (
                    <div className="text-center py-12 text-gray-400">
                        <p>Loading scan history...</p>
                    </div>
                ) : error ? (
                    <div className="text-center py-12 text-red-400">
                        <p>{error}</p>
                        <button
                            onClick={loadScans}
                            className="mt-4 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded transition-colors"
                        >
                            Retry
                        </button>
                    </div>
                ) : selectedScan ? (
                    <div>
                        {loadingDetails ? (
                            <div className="text-center py-12 text-gray-400">
                                <p>Loading scan details...</p>
                            </div>
                        ) : (
                            <div>
                                <div className="mb-6 p-4 bg-gray-800 rounded-lg">
                                    <div className="flex items-center justify-between">
                                        <div>
                                            <p className="text-gray-400 text-sm">Target</p>
                                            <p className="font-mono">{selectedScan.target}</p>
                                        </div>
                                        <div className="text-right">
                                            <p className={`text-4xl font-bold ${selectedScan.grade === 'A' ? 'text-green-400' :
                                                selectedScan.grade === 'B' ? 'text-lime-400' :
                                                    selectedScan.grade === 'C' ? 'text-yellow-400' :
                                                        selectedScan.grade === 'D' ? 'text-orange-400' :
                                                            'text-red-400'
                                                }`}>
                                                {selectedScan.grade}
                                            </p>
                                            <p className="text-gray-400 text-sm">Score: {selectedScan.score}/100</p>
                                        </div>
                                    </div>
                                </div>
                                <ResultTabs result={selectedScan} />
                            </div>
                        )}
                    </div>
                ) : (
                    <div className="bg-gray-800/50 rounded-lg overflow-hidden">
                        <ScanHistoryTable scans={scans} onSelectScan={handleSelectScan} />
                    </div>
                )}
            </div>
        </main>
    );
}
