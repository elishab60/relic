"use client";

import React, { useState, useEffect } from 'react';
import TerminalShell from '@/components/TerminalShell';
import LogConsole from '@/components/LogConsole';
import ResultTabs from '@/components/ResultTabs';
import BootAnimation from '@/components/BootAnimation';
import AsciiAnimation from '@/components/AsciiAnimation';
import { useScanLogs } from '@/lib/sse';
import { startScan, getResult } from '@/lib/api';
import { ScanResult } from '@/lib/types';
import { Shield, Play, Loader2, Terminal } from 'lucide-react';

export default function Page() {
    const [booting, setBooting] = useState(true);
    const [target, setTarget] = useState('');
    const [scanId, setScanId] = useState<string | null>(null);
    const [result, setResult] = useState<ScanResult | null>(null);

    const { logs, status } = useScanLogs(scanId);

    useEffect(() => {
        if (status === 'done' && scanId && !result) {
            getResult(scanId).then(setResult);
        }
    }, [status, scanId, result]);

    const handleStart = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!target) return;

        setResult(null);
        try {
            const { scan_id } = await startScan(target);
            setScanId(scan_id);
        } catch (err) {
            alert("Failed to start scan");
        }
    };

    // Show boot animation on first load
    if (booting) {
        return <BootAnimation onComplete={() => setBooting(false)} />;
    }

    return (
        <TerminalShell>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 h-full">
                <div className="flex flex-col gap-6">
                    {/* Scan Input Section */}
                    <div className="terminal-box-glow p-6">
                        <h2 className="section-title mb-4 flex items-center gap-3">
                            <Shield className="text-terminal-red" size={14} />
                            TARGET
                        </h2>

                        <form onSubmit={handleStart} className="flex gap-4">
                            <div className="flex-1 relative">
                                <input
                                    type="text"
                                    placeholder="Enter target (e.g., localhost:3000)"
                                    className="cyber-input w-full pl-10"
                                    value={target}
                                    onChange={(e) => setTarget(e.target.value)}
                                    disabled={status === 'running'}
                                />
                                <Terminal
                                    className="absolute left-3 top-1/2 -translate-y-1/2 text-terminal-dim"
                                    size={16}
                                />
                            </div>
                            <button
                                type="submit"
                                disabled={status === 'running' || !target}
                                className="cyber-button flex items-center gap-2"
                            >
                                {status === 'running' ? (
                                    <Loader2 className="animate-spin" size={18} />
                                ) : (
                                    <Play size={18} />
                                )}
                                <span className="uppercase tracking-wider">SCAN</span>
                            </button>
                        </form>
                    </div>

                    {/* Logs Section */}
                    <div className="flex-1 flex flex-col">
                        <h3 className="section-title mb-3">
                            LOGS
                        </h3>
                        <LogConsole logs={logs} />
                    </div>
                </div>

                {/* Results Section */}
                <div className="terminal-box p-6 min-h-[500px]">
                    {result ? (
                        <ResultTabs result={result} />
                    ) : (
                        <AsciiAnimation isScanning={status === 'running'} />
                    )}
                </div>
            </div>
        </TerminalShell>
    );
}
