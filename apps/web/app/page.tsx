"use client";

import React, { useState, useEffect } from 'react';
import Link from 'next/link';
import TerminalShell from '@/components/TerminalShell';
import LogConsole from '@/components/LogConsole';
import ResultTabs from '@/components/ResultTabs';
import BootAnimation from '@/components/BootAnimation';
import AsciiAnimation from '@/components/AsciiAnimation';
import { useBootContext } from '@/components/BootProvider';
import { useScanLogs } from '@/lib/sse';
import { startScan, getResult } from '@/lib/api';
import { ScanResult } from '@/lib/types';
import { Shield, Play, Loader2, Terminal, AlertTriangle, X, Crosshair, Lock, Unlock, History } from 'lucide-react';

// Authorization Modal Component - Cyberpunk Terminal Style
function AuthorizationModal({
    target,
    onConfirm,
    onCancel
}: {
    target: string;
    onConfirm: () => void;
    onCancel: () => void;
}) {
    const [acknowledged, setAcknowledged] = useState(false);
    const [isAnimating, setIsAnimating] = useState(true);

    useEffect(() => {
        const timer = setTimeout(() => setIsAnimating(false), 300);
        return () => clearTimeout(timer);
    }, []);

    return (
        <div className="fixed inset-0 bg-terminal-bg/95 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            {/* Scanline effect overlay */}
            <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-10">
                <div className="absolute inset-0" style={{
                    backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(95, 158, 160, 0.1) 2px, rgba(95, 158, 160, 0.1) 4px)'
                }} />
            </div>

            <div className={`
                terminal-box border-terminal-red/50 max-w-lg w-full 
                shadow-[0_0_30px_rgba(201,76,76,0.2),inset_0_0_30px_rgba(201,76,76,0.05)]
                transition-all duration-300
                ${isAnimating ? 'scale-95 opacity-0' : 'scale-100 opacity-100'}
            `}>
                {/* Header with scanline effect */}
                <div className="relative border-b border-terminal-red/30 bg-terminal-red/5">
                    {/* Corner decorations */}
                    <div className="absolute top-0 left-0 w-3 h-3 border-l-2 border-t-2 border-terminal-red/60" />
                    <div className="absolute top-0 right-0 w-3 h-3 border-r-2 border-t-2 border-terminal-red/60" />

                    <div className="flex items-center gap-3 p-4">
                        <div className="flex items-center justify-center w-8 h-8 bg-terminal-red/20 rounded border border-terminal-red/40">
                            <AlertTriangle className="text-terminal-red" size={18} />
                        </div>
                        <div className="flex-1">
                            <h2 className="section-title text-terminal-red flex items-center gap-2">
                                <span className="text-terminal-dim">[</span>
                                AUTHORIZATION REQUIRED
                                <span className="text-terminal-dim">]</span>
                            </h2>
                        </div>
                        <button
                            onClick={onCancel}
                            className="w-8 h-8 flex items-center justify-center text-terminal-dim hover:text-terminal-red hover:bg-terminal-red/10 rounded transition-all duration-200"
                        >
                            <X size={18} />
                        </button>
                    </div>
                </div>

                {/* Body */}
                <div className="p-5 space-y-5">
                    {/* Target display */}
                    <div className="space-y-2">
                        <div className="flex items-center gap-2 text-terminal-dim text-xs uppercase tracking-wider">
                            <Crosshair size={12} />
                            <span>Target</span>
                        </div>
                        <div className="bg-terminal-bg border border-terminal-border rounded px-4 py-3 font-mono">
                            <div className="flex items-center gap-2">
                                <span className="text-terminal-accent">$</span>
                                <code className="text-terminal-textBright break-all">{target}</code>
                            </div>
                        </div>
                    </div>

                    {/* Legal Notice - Terminal style */}
                    <div className="bg-terminal-bg border border-terminal-red/30 rounded overflow-hidden">
                        <div className="px-4 py-2 bg-terminal-red/10 border-b border-terminal-red/20 flex items-center gap-2">
                            <AlertTriangle size={14} className="text-terminal-red" />
                            <span className="text-terminal-red text-xs uppercase tracking-wider font-bold">Legal Notice</span>
                        </div>
                        <div className="p-4 font-mono text-sm space-y-2">
                            <div className="flex gap-2">
                                <span className="text-terminal-red">•</span>
                                <span className="text-terminal-text">Unauthorized scanning of systems is <span className="text-terminal-textBright font-semibold">illegal</span></span>
                            </div>
                            <div className="flex gap-2">
                                <span className="text-terminal-red">•</span>
                                <span className="text-terminal-text">You must have <span className="text-terminal-textBright font-semibold">explicit permission</span> from the target owner</span>
                            </div>
                            <div className="flex gap-2">
                                <span className="text-terminal-red">•</span>
                                <span className="text-terminal-text">This tool is for <span className="text-terminal-textBright font-semibold">authorized security testing only</span></span>
                            </div>
                            <div className="flex gap-2">
                                <span className="text-terminal-red">•</span>
                                <span className="text-terminal-text">Misuse may result in <span className="text-terminal-textBright font-semibold">criminal prosecution</span></span>
                            </div>
                        </div>
                    </div>

                    {/* Checkbox - Custom styled */}
                    <label className="flex items-start gap-3 cursor-pointer group p-3 rounded border border-transparent hover:border-terminal-accent/30 hover:bg-terminal-accent/5 transition-all duration-200">
                        <div className={`
                            flex-shrink-0 w-5 h-5 mt-0.5 rounded border-2 flex items-center justify-center transition-all duration-200
                            ${acknowledged
                                ? 'bg-terminal-accent border-terminal-accent'
                                : 'border-terminal-border group-hover:border-terminal-accent/50'
                            }
                        `}>
                            {acknowledged && (
                                <svg className="w-3 h-3 text-terminal-bg" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth="3">
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                                </svg>
                            )}
                        </div>
                        <input
                            type="checkbox"
                            checked={acknowledged}
                            onChange={(e) => setAcknowledged(e.target.checked)}
                            className="sr-only"
                        />
                        <span className="text-sm text-terminal-text group-hover:text-terminal-textBright transition-colors leading-relaxed">
                            I confirm that I have <span className="text-terminal-accent font-semibold">explicit authorization</span> to
                            perform security testing on this target and accept full responsibility for my actions.
                        </span>
                    </label>
                </div>

                {/* Footer with corner decorations */}
                <div className="relative border-t border-terminal-border bg-terminal-bg/50">
                    {/* Corner decorations */}
                    <div className="absolute bottom-0 left-0 w-3 h-3 border-l-2 border-b-2 border-terminal-red/60" />
                    <div className="absolute bottom-0 right-0 w-3 h-3 border-r-2 border-b-2 border-terminal-red/60" />

                    <div className="flex gap-3 p-4">
                        <button
                            onClick={onCancel}
                            className="flex-1 cyber-button-outline flex items-center justify-center gap-2"
                        >
                            <X size={16} />
                            <span className="uppercase tracking-wider text-sm">Cancel</span>
                        </button>
                        <button
                            onClick={onConfirm}
                            disabled={!acknowledged}
                            className={`
                                flex-1 px-6 py-2 rounded flex items-center justify-center gap-2 font-bold 
                                uppercase tracking-wider text-sm transition-all duration-200
                                ${acknowledged
                                    ? 'bg-terminal-accent text-terminal-bg hover:bg-terminal-textBright shadow-[0_0_15px_rgba(95,158,160,0.3)]'
                                    : 'bg-terminal-border text-terminal-dim cursor-not-allowed'
                                }
                            `}
                        >
                            {acknowledged ? <Unlock size={16} /> : <Lock size={16} />}
                            <span>Confirm & Scan</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

import { useBoot } from '@/components/BootProvider';

export default function Page() {
    const { hasBooted, setHasBooted } = useBootContext();
    const [target, setTarget] = useState('');

    const handleBootComplete = () => {
        setHasBooted(true);
    };
    const [scanId, setScanId] = useState<string | null>(null);
    const [result, setResult] = useState<ScanResult | null>(null);
    const [showAuthModal, setShowAuthModal] = useState(false);
    const [scanError, setScanError] = useState<string | null>(null);

    const { logs, status } = useScanLogs(scanId);

    // Track the scanId for which we last fetched results
    const [fetchedForScanId, setFetchedForScanId] = useState<string | null>(null);

    useEffect(() => {
        // Only fetch if:
        // 1. status is 'done' (scan completed)
        // 2. we have a scanId
        // 3. we haven't already fetched for this scanId
        if (status === 'done' && scanId && fetchedForScanId !== scanId) {
            getResult(scanId).then((fetchedResult) => {
                // Double-check scanId hasn't changed during the async fetch
                setResult(fetchedResult);
                setFetchedForScanId(scanId);
            }).catch((err) => {
                console.error("Failed to fetch result:", err);
            });
        }

        // Regression Guard: Ensure UI state matches fetched result
        if (process.env.NODE_ENV === 'development' && result && scanId && result.scan_id !== scanId) {
            console.error(`[Regression] UI ScanID (${scanId}) mismatch with Result ScanID (${result.scan_id})`);
        }
    }, [status, scanId, fetchedForScanId, result]);

    const handleStartClick = (e: React.FormEvent) => {
        e.preventDefault();
        if (!target) return;
        setScanError(null);
        setShowAuthModal(true);
    };

    const handleConfirmScan = async () => {
        setShowAuthModal(false);
        setResult(null);
        setScanError(null);
        setFetchedForScanId(null); // Reset fetch tracker for new scan

        try {
            setScanId(null);
            // Pass authorized: true since user confirmed in modal
            const { scan_id } = await startScan(target, true);
            setScanId(scan_id);
        } catch (err) {
            const message = err instanceof Error ? err.message : "Failed to start scan";
            setScanError(message);
        }
    };

    const handleCancelScan = () => {
        setShowAuthModal(false);
    };

    // Show boot animation only if not seen this session
    if (!hasBooted) {
        return <BootAnimation onComplete={() => setHasBooted(true)} />;
    }

    return (
        <TerminalShell>
            {/* Authorization Modal */}
            {showAuthModal && (
                <AuthorizationModal
                    target={target}
                    onConfirm={handleConfirmScan}
                    onCancel={handleCancelScan}
                />
            )}

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8 h-full">
                <div className="flex flex-col gap-6">
                    {/* Scan Input Section */}
                    <div className="terminal-box-glow p-6">
                        <h2 className="section-title mb-4 flex items-center gap-3">
                            <Shield className="text-terminal-red" size={14} />
                            TARGET
                        </h2>

                        <div className="flex items-center gap-2 mb-4">
                            <Link
                                href="/history"
                                className="cyber-button-outline flex items-center gap-2 text-xs py-1.5 px-3"
                            >
                                <History size={14} />
                                <span className="uppercase tracking-wider">History</span>
                            </Link>
                        </div>

                        <form onSubmit={handleStartClick} className="flex gap-4">
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

                        {/* Error Display */}
                        {scanError && (
                            <div className="mt-4 p-3 bg-terminal-red/10 border border-terminal-red/30 rounded text-terminal-red text-sm font-mono">
                                <div className="flex items-start gap-2">
                                    <AlertTriangle size={16} className="mt-0.5 flex-shrink-0" />
                                    <span>{scanError}</span>
                                </div>
                            </div>
                        )}
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
