'use client';

import React, { useState } from 'react';
import { Network, Server, Shield, ChevronDown, ChevronRight, AlertTriangle, Check, Info, Wifi } from 'lucide-react';

interface OpenPort {
    port: number;
    service: string;
    risk: string;
}

interface NetworkExposure {
    confirmed_open: OpenPort[];
    suspected_open: OpenPort[];
    unexpected_services: OpenPort[];
    total_scanned: number;
    cdn_detected: boolean;
    cdn_provider?: string;
    cdn_catchall_count?: number;
    filtered_count?: number;
    scan_duration_ms?: number;
}

interface NetworkExposureSectionProps {
    networkExposure: NetworkExposure | null | undefined;
}

// Risk level styling
const RISK_COLORS: Record<string, { text: string; bg: string; border: string }> = {
    high: { text: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/50' },
    medium: { text: 'text-amber-400', bg: 'bg-amber-400/10', border: 'border-amber-400/50' },
    low: { text: 'text-green-400', bg: 'bg-green-400/10', border: 'border-green-400/50' },
    info: { text: 'text-cyan-400', bg: 'bg-cyan-400/10', border: 'border-cyan-400/50' },
};

function PortBadge({ port }: { port: OpenPort }) {
    const riskStyle = RISK_COLORS[port.risk] || RISK_COLORS.info;

    return (
        <div className={`
            flex items-center gap-2 px-3 py-1.5 rounded-lg border
            ${riskStyle.bg} ${riskStyle.border} transition-all duration-200
        `}>
            <Server size={14} className={riskStyle.text} />
            <span className="font-mono text-sm font-medium text-terminal-text">
                {port.port}
            </span>
            <span className="text-terminal-dim text-xs">/tcp</span>
            <span className="text-xs text-terminal-dim">→</span>
            <span className="text-sm text-terminal-text">{port.service.toUpperCase()}</span>
            <span className={`
                text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border
                ${riskStyle.text} ${riskStyle.border}
            `}>
                {port.risk}
            </span>
        </div>
    );
}

export default function NetworkExposureSection({ networkExposure }: NetworkExposureSectionProps) {
    const [isExpanded, setIsExpanded] = useState(true);

    if (!networkExposure) {
        return null;
    }

    const {
        confirmed_open,
        suspected_open,
        unexpected_services,
        total_scanned,
        cdn_detected,
        cdn_provider,
        cdn_catchall_count,
        filtered_count,
        scan_duration_ms
    } = networkExposure;

    const confirmedOpen = confirmed_open || [];
    const suspectedOpen = suspected_open || [];
    const unexpectedServices = unexpected_services || [];

    const totalOpen = confirmedOpen.length;
    const hasUnexpected = unexpectedServices.length > 0;

    return (
        <div className="space-y-4">
            {/* Section Header */}
            <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="w-full flex items-center justify-between group"
            >
                <h3 className="section-title flex items-center gap-2">
                    <Network size={14} className="text-terminal-accent" />
                    OPEN PORTS
                    <span className="text-terminal-dim font-normal">
                        ({totalOpen} confirmed)
                    </span>
                </h3>
                <div className="flex items-center gap-2">
                    {cdn_detected && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-cyan-400/10 text-cyan-400 border border-cyan-400/20 flex items-center gap-1">
                            <Shield size={10} />
                            CDN: {cdn_provider}
                        </span>
                    )}
                    {hasUnexpected && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-amber-400/10 text-amber-400 border border-amber-400/20 flex items-center gap-1">
                            <AlertTriangle size={10} />
                            UNEXPECTED
                        </span>
                    )}
                    {isExpanded ? (
                        <ChevronDown size={16} className="text-terminal-dim group-hover:text-terminal-text transition-colors" />
                    ) : (
                        <ChevronRight size={16} className="text-terminal-dim group-hover:text-terminal-text transition-colors" />
                    )}
                </div>
            </button>

            {isExpanded && (
                <div className="terminal-box p-4 space-y-4">
                    {/* No ports found */}
                    {totalOpen === 0 && (
                        <div className="text-center py-6 text-terminal-dim">
                            <Shield size={24} className="mx-auto mb-2 opacity-50" />
                            <p className="text-sm">No open ports detected</p>
                            <p className="text-xs mt-1">
                                {filtered_count && filtered_count > 0
                                    ? `${filtered_count} ports were filtered by firewall`
                                    : 'All scanned ports appear closed or filtered'
                                }
                            </p>
                        </div>
                    )}

                    {/* Confirmed Open Ports */}
                    {confirmedOpen.length > 0 && (
                        <div className="space-y-2">
                            <div className="flex items-center gap-2 text-xs font-bold text-terminal-dim uppercase tracking-wider">
                                <Check size={12} className="text-green-400" />
                                Confirmed Open
                            </div>
                            <div className="flex flex-wrap gap-2">
                                {confirmedOpen.map((port, i) => (
                                    <PortBadge key={`${port.port}-${i}`} port={port} />
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Suspected Open Ports */}
                    {suspectedOpen.length > 0 && (
                        <div className="space-y-2">
                            <div className="flex items-center gap-2 text-xs font-bold text-terminal-dim uppercase tracking-wider">
                                <Info size={12} className="text-amber-400" />
                                Suspected Open
                            </div>
                            <div className="flex flex-wrap gap-2">
                                {suspectedOpen.map((port, i) => (
                                    <PortBadge key={`${port.port}-${i}`} port={port} />
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Unexpected Services Warning */}
                    {hasUnexpected && (
                        <div className="flex items-start gap-3 bg-amber-400/10 border border-amber-400/30 rounded-lg p-3">
                            <AlertTriangle size={16} className="text-amber-400 shrink-0 mt-0.5" />
                            <div>
                                <div className="text-sm font-bold text-amber-400">Unexpected Services</div>
                                <p className="text-xs text-terminal-dim mt-1">
                                    {unexpectedServices.length} ports running services that may indicate security risks:
                                    {' '}
                                    {unexpectedServices.map(p => `${p.port}/${p.service}`).join(', ')}
                                </p>
                            </div>
                        </div>
                    )}

                    {/* Footer: Scan stats */}
                    <div className="pt-4 border-t border-terminal-border/50 flex flex-wrap gap-4 text-xs text-terminal-dim">
                        <div className="flex items-center gap-1">
                            <Wifi size={10} />
                            Scanned: {total_scanned} ports
                        </div>
                        {scan_duration_ms && (
                            <div>
                                Duration: {(scan_duration_ms / 1000).toFixed(1)}s
                            </div>
                        )}
                        {filtered_count && filtered_count > 0 && (
                            <div>
                                Filtered: {filtered_count}
                            </div>
                        )}
                        {cdn_catchall_count && cdn_catchall_count > 0 && (
                            <div className="text-cyan-400">
                                CDN catch-all: {cdn_catchall_count} (ignored)
                            </div>
                        )}
                    </div>
                </div>
            )}
        </div>
    );
}
