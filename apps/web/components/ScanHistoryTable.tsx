"use client";

import React, { useState } from 'react';
import { ScanSummary, ScanResult } from '@/lib/types';
import { getResult } from '@/lib/api';
import { ChevronDown, ChevronRight, Copy, Check, ExternalLink, Shield, AlertTriangle, Clock, Target } from 'lucide-react';

interface ScanHistoryTableProps {
    scans: ScanSummary[];
}

function formatDate(dateStr: string | null): string {
    if (!dateStr) return 'N/A';
    const date = new Date(dateStr);
    return date.toLocaleString();
}

function getGradeColor(grade: string | null): string {
    if (!grade) return 'text-terminal-dim';
    if (grade === 'A' || grade === 'B') return 'text-terminal-accent';
    if (grade === 'C') return 'text-terminal-text';
    return 'text-terminal-red';
}

function getStatusColor(status: string): string {
    switch (status) {
        case 'completed': return 'text-terminal-accent';
        case 'running': return 'text-terminal-text animate-pulse';
        case 'failed': return 'text-terminal-red';
        default: return 'text-terminal-dim';
    }
}

interface ExpandedScan {
    scanId: string;
    result: ScanResult | null;
    loading: boolean;
    error: string | null;
}

export default function ScanHistoryTable({ scans }: ScanHistoryTableProps) {
    const [expanded, setExpanded] = useState<ExpandedScan | null>(null);
    const [copied, setCopied] = useState(false);

    const handleExpand = async (scanId: string) => {
        if (expanded?.scanId === scanId) {
            setExpanded(null);
            return;
        }

        setExpanded({ scanId, result: null, loading: true, error: null });

        try {
            const result = await getResult(scanId);
            setExpanded({ scanId, result, loading: false, error: null });
        } catch (err) {
            setExpanded({
                scanId,
                result: null,
                loading: false,
                error: err instanceof Error ? err.message : 'Failed to load details'
            });
        }
    };

    const handleCopyJson = (result: ScanResult) => {
        navigator.clipboard.writeText(JSON.stringify(result, null, 2));
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
    };

    return (
        <div className="overflow-auto h-full">
            <table className="w-full text-sm font-mono">
                <thead className="text-terminal-dim text-xs uppercase tracking-wider border-b border-terminal-border">
                    <tr>
                        <th className="text-left py-3 px-2 w-8"></th>
                        <th className="text-left py-3 px-2">Target</th>
                        <th className="text-left py-3 px-2 w-24">Status</th>
                        <th className="text-left py-3 px-2 w-16">Grade</th>
                        <th className="text-left py-3 px-2 w-20">Findings</th>
                        <th className="text-left py-3 px-2 w-40">Date</th>
                    </tr>
                </thead>
                <tbody>
                    {scans.map((scan) => (
                        <React.Fragment key={scan.scan_id}>
                            <tr
                                className="border-b border-terminal-border/30 hover:bg-terminal-bgLight/30 cursor-pointer transition-colors"
                                onClick={() => handleExpand(scan.scan_id)}
                            >
                                <td className="py-3 px-2">
                                    {expanded?.scanId === scan.scan_id ? (
                                        <ChevronDown size={16} className="text-terminal-accent" />
                                    ) : (
                                        <ChevronRight size={16} className="text-terminal-dim" />
                                    )}
                                </td>
                                <td className="py-3 px-2">
                                    <div className="flex items-center gap-2">
                                        <Target size={14} className="text-terminal-dim" />
                                        <span className="text-terminal-textBright truncate max-w-xs">
                                            {scan.target}
                                        </span>
                                    </div>
                                </td>
                                <td className={`py-3 px-2 uppercase text-xs ${getStatusColor(scan.status)}`}>
                                    {scan.status}
                                </td>
                                <td className={`py-3 px-2 font-bold text-lg ${getGradeColor(scan.grade)}`}>
                                    {scan.grade || '-'}
                                </td>
                                <td className="py-3 px-2">
                                    <span className={scan.findings_count > 0 ? 'text-terminal-red' : 'text-terminal-dim'}>
                                        {scan.findings_count}
                                    </span>
                                </td>
                                <td className="py-3 px-2 text-terminal-dim text-xs">
                                    {formatDate(scan.started_at)}
                                </td>
                            </tr>

                            {/* Expanded Details */}
                            {expanded?.scanId === scan.scan_id && (
                                <tr>
                                    <td colSpan={6} className="bg-terminal-bgLight/50 border-b border-terminal-border">
                                        <div className="p-4">
                                            {expanded.loading ? (
                                                <div className="text-terminal-dim flex items-center gap-2">
                                                    <Clock className="animate-spin" size={16} />
                                                    Loading scan details...
                                                </div>
                                            ) : expanded.error ? (
                                                <div className="text-terminal-red flex items-center gap-2">
                                                    <AlertTriangle size={16} />
                                                    {expanded.error}
                                                </div>
                                            ) : expanded.result ? (
                                                <ScanDetails
                                                    result={expanded.result}
                                                    onCopyJson={() => handleCopyJson(expanded.result!)}
                                                    copied={copied}
                                                />
                                            ) : null}
                                        </div>
                                    </td>
                                </tr>
                            )}
                        </React.Fragment>
                    ))}
                </tbody>
            </table>
        </div>
    );
}

function ScanDetails({ result, onCopyJson, copied }: { result: ScanResult; onCopyJson: () => void; copied: boolean }) {
    const [showRaw, setShowRaw] = useState(false);

    return (
        <div className="space-y-4">
            {/* Header with actions */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <span className="text-terminal-dim text-xs">ID: {result.scan_id}</span>
                    <span className="text-terminal-dim text-xs">Score: {result.score}/100</span>
                </div>
                <button
                    onClick={onCopyJson}
                    className="cyber-button-outline text-xs py-1 px-3 flex items-center gap-2"
                >
                    {copied ? <Check size={12} /> : <Copy size={12} />}
                    {copied ? 'Copied!' : 'Copy JSON'}
                </button>
            </div>

            {/* Findings */}
            {result.findings && result.findings.length > 0 && (
                <div>
                    <h4 className="text-terminal-accent text-xs uppercase tracking-wider mb-2 flex items-center gap-2">
                        <Shield size={12} />
                        Findings ({result.findings.length})
                    </h4>
                    <div className="space-y-2">
                        {result.findings.map((finding, i) => (
                            <div key={i} className="terminal-box p-3 text-xs">
                                <div className="flex justify-between mb-1">
                                    <span className="font-bold text-terminal-textBright">{finding.title}</span>
                                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${finding.severity === 'critical' || finding.severity === 'high'
                                        ? 'bg-terminal-red/20 text-terminal-red border border-terminal-red/30'
                                        : finding.severity === 'medium'
                                            ? 'bg-terminal-text/20 text-terminal-text border border-terminal-text/30'
                                            : 'bg-terminal-dim/20 text-terminal-dim border border-terminal-dim/30'
                                        }`}>
                                        {finding.severity}
                                    </span>
                                </div>
                                <p className="text-terminal-dim mb-1">{finding.impact}</p>
                                {finding.recommendation && (
                                    <p className="text-terminal-text">
                                        <span className="text-terminal-accent">▸ FIX:</span> {finding.recommendation}
                                    </p>
                                )}
                            </div>
                        ))}
                    </div>
                </div>
            )}

            {/* Raw Data Toggle */}
            <div>
                <button
                    onClick={() => setShowRaw(!showRaw)}
                    className="text-xs text-terminal-dim hover:text-terminal-text flex items-center gap-1"
                >
                    {showRaw ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
                    {showRaw ? 'Hide' : 'Show'} Raw Data
                </button>
                {showRaw && (
                    <pre className="mt-2 p-3 bg-terminal-bg border border-terminal-border rounded text-[10px] text-terminal-dim overflow-x-auto max-h-60">
                        {JSON.stringify(result, null, 2)}
                    </pre>
                )}
            </div>
        </div>
    );
}
