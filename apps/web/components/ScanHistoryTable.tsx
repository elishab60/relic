"use client";

import React, { useState } from 'react';
import { ScanSummary, ScanResult } from '@/lib/types';
import { getResult } from '@/lib/api';
import { getProfileFromScanRecord, getProfileBadgeInfo, labelFromProfile } from '@/lib/scanConfig';
import { ChevronDown, ChevronRight, Copy, Check, Shield, AlertTriangle, Clock, Target, Code, Terminal, Gauge } from 'lucide-react';

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

function getConfidenceColor(confidence?: string): string {
    if (!confidence) return 'text-terminal-dim border-terminal-dim';
    switch (confidence.toLowerCase()) {
        case 'high': return 'text-green-400 border-green-400';
        case 'medium': return 'text-yellow-400 border-yellow-400';
        case 'low': return 'text-terminal-dim border-terminal-dim';
        default: return 'text-terminal-dim border-terminal-dim';
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
                        <th className="text-left py-3 px-2 w-24">Profile</th>
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
                                {/* Profile Badge (PR-02b) */}
                                <td className="py-3 px-2">
                                    {(() => {
                                        const profile = getProfileFromScanRecord(scan.config_json, null);
                                        const badge = getProfileBadgeInfo(profile);
                                        return (
                                            <span className={`px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${badge.colorClass}`}>
                                                {badge.label}
                                            </span>
                                        );
                                    })()}
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
                                    <td colSpan={7} className="bg-terminal-bgLight/50 border-b border-terminal-border">
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
    const [copiedCurl, setCopiedCurl] = useState<number | null>(null);

    const copyToClipboard = (text: string, index: number) => {
        navigator.clipboard.writeText(text);
        setCopiedCurl(index);
        setTimeout(() => setCopiedCurl(null), 2000);
    };

    return (
        <div className="space-y-4">
            {/* Header with actions */}
            <div className="flex items-center justify-between">
                <div className="flex items-center gap-4">
                    <span className="text-terminal-dim text-xs">ID: {result.scan_id}</span>
                    <span className="text-terminal-dim text-xs">Score: {result.score}/100</span>
                    {/* PR-02b: Show scan configuration */}
                    {(() => {
                        const profile = getProfileFromScanRecord(null, result as Record<string, any>);
                        const badge = getProfileBadgeInfo(profile);
                        return (
                            <span className="text-terminal-dim text-xs flex items-center gap-1">
                                <Gauge size={10} />
                                Aggressiveness: <span className="text-terminal-text">{labelFromProfile(profile)}</span>
                                <span className="text-terminal-dim mx-1">|</span>
                                Profile: <span className={`px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ${badge.colorClass}`}>
                                    {badge.label}
                                </span>
                            </span>
                        );
                    })()}
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
                    <div className="space-y-3">
                        {result.findings.map((finding, i) => (
                            <div key={i} className="terminal-box p-3 text-xs">
                                {/* Title and badges */}
                                <div className="flex justify-between items-start mb-2">
                                    <span className="font-bold text-terminal-textBright">{finding.title}</span>
                                    <div className="flex gap-2 flex-shrink-0">
                                        {finding.confidence && (
                                            <span className={`px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${getConfidenceColor(finding.confidence)}`}>
                                                {finding.confidence}
                                            </span>
                                        )}
                                        <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${finding.severity === 'critical' || finding.severity === 'high'
                                            ? 'bg-terminal-red/20 text-terminal-red border border-terminal-red/30'
                                            : finding.severity === 'medium'
                                                ? 'bg-terminal-text/20 text-terminal-text border border-terminal-text/30'
                                                : 'bg-terminal-dim/20 text-terminal-dim border border-terminal-dim/30'
                                            }`}>
                                            {finding.severity}
                                        </span>
                                    </div>
                                </div>

                                {/* Impact */}
                                <p className="text-terminal-dim mb-1">{finding.impact}</p>

                                {/* Recommendation */}
                                {finding.recommendation && (
                                    <p className="text-terminal-text mb-2">
                                        <span className="text-terminal-accent">▸ FIX:</span> {finding.recommendation}
                                    </p>
                                )}

                                {/* Evidence Section (PR-01) */}
                                {finding.evidence_snippet && (
                                    <div className="mt-3 bg-black/30 p-2 rounded border border-terminal-border/50">
                                        <div className="flex justify-between items-center mb-1">
                                            <span className="text-[10px] font-bold text-terminal-dim uppercase flex items-center gap-1">
                                                <Code size={10} /> Evidence
                                            </span>
                                            {finding.evidence_hash && (
                                                <span className="text-[9px] font-mono text-terminal-dim">
                                                    SHA256: {finding.evidence_hash.substring(0, 8)}...
                                                </span>
                                            )}
                                        </div>
                                        <pre className="text-[10px] font-mono text-terminal-text overflow-x-auto whitespace-pre-wrap break-all max-h-24 overflow-y-auto">
                                            {finding.evidence_snippet}
                                        </pre>
                                    </div>
                                )}

                                {/* Reproduction Section (PR-01) */}
                                {finding.repro_curl && (
                                    <div className="mt-3">
                                        <div className="flex justify-between items-center mb-1">
                                            <span className="text-[10px] font-bold text-terminal-dim uppercase flex items-center gap-1">
                                                <Terminal size={10} /> Reproduction
                                            </span>
                                            <button
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    copyToClipboard(finding.repro_curl!, i);
                                                }}
                                                className="text-[10px] flex items-center gap-1 text-terminal-dim hover:text-terminal-text transition-colors"
                                            >
                                                {copiedCurl === i ? <Check size={10} className="text-green-400" /> : <Copy size={10} />}
                                                {copiedCurl === i ? 'Copied' : 'Copy'}
                                            </button>
                                        </div>
                                        <div className="bg-black/50 p-2 rounded border border-terminal-border/50 font-mono text-[10px] text-terminal-text overflow-x-auto">
                                            {finding.repro_curl}
                                        </div>
                                    </div>
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
