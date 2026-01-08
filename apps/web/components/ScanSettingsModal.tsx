"use client";

import React, { useEffect, useState } from 'react';
import { X, Settings, Zap, Shield, Crosshair, Radio, AlertTriangle } from 'lucide-react';
import {
    PathProfile,
    PortScanProfile,
    labelFromProfile,
    getProfileDescription,
    getPortScanProfileStats,
    ScanConfig
} from '@/lib/scanConfig';

interface ScanSettingsModalProps {
    open: boolean;
    onClose: () => void;
    value: ScanConfig;
    onChange: (newValue: ScanConfig) => void;
}

interface PathProfileOption {
    value: PathProfile;
    label: string;
    description: string;
    paths: number;
    maxPages: number;
    icon: React.ReactNode;
}

interface PortScanProfileOption {
    value: PortScanProfile;
    label: string;
    description: string;
    ports: number;
    estimatedTime: string;
    icon: React.ReactNode;
    impact: "fast" | "medium" | "slow";
}

const PATH_PROFILE_OPTIONS: PathProfileOption[] = [
    {
        value: "minimal",
        label: "Low",
        description: "Fastest scan with minimal footprint",
        paths: 13,
        maxPages: 20,
        icon: <Zap size={16} className="text-terminal-dim" />
    },
    {
        value: "standard",
        label: "Balanced",
        description: "Balanced coverage and speed",
        paths: 48,
        maxPages: 50,
        icon: <Shield size={16} className="text-terminal-accent" />
    },
    {
        value: "thorough",
        label: "High",
        description: "Deep discovery, comprehensive scan",
        paths: 98,
        maxPages: 100,
        icon: <Crosshair size={16} className="text-terminal-textBright" />
    }
];

const PORT_SCAN_PROFILE_OPTIONS: PortScanProfileOption[] = [
    {
        value: "light",
        label: "Light",
        description: "Common service ports only",
        ports: 12,
        estimatedTime: "< 5s",
        impact: "fast",
        icon: <Zap size={16} className="text-terminal-dim" />
    },
    {
        value: "mid",
        label: "Balanced",
        description: "Top 100 most common ports",
        ports: 100,
        estimatedTime: "~30s",
        impact: "medium",
        icon: <Shield size={16} className="text-terminal-accent" />
    },
    {
        value: "high",
        label: "Comprehensive",
        description: "Top 1000 ports (thorough)",
        ports: 1000,
        estimatedTime: "2-5 min",
        impact: "slow",
        icon: <AlertTriangle size={16} className="text-amber-400" />
    }
];

function ImpactBadge({ impact }: { impact: "fast" | "medium" | "slow" }) {
    const styles = {
        fast: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
        medium: "bg-terminal-accent/20 text-terminal-accent border-terminal-accent/30",
        slow: "bg-amber-500/20 text-amber-400 border-amber-500/30"
    };
    const labels = {
        fast: "FAST",
        medium: "MEDIUM",
        slow: "SLOW"
    };
    return (
        <span className={`text-[9px] px-1.5 py-0.5 rounded border ${styles[impact]} uppercase font-bold`}>
            {labels[impact]}
        </span>
    );
}

export default function ScanSettingsModal({
    open,
    onClose,
    value,
    onChange
}: ScanSettingsModalProps) {
    const [isAnimating, setIsAnimating] = useState(true);
    const [selectedPathProfile, setSelectedPathProfile] = useState<PathProfile>(value.path_profile);
    const [selectedPortScanProfile, setSelectedPortScanProfile] = useState<PortScanProfile>(value.port_scan_profile);

    useEffect(() => {
        if (open) {
            setIsAnimating(true);
            setSelectedPathProfile(value.path_profile);
            setSelectedPortScanProfile(value.port_scan_profile);
            const timer = setTimeout(() => setIsAnimating(false), 200);
            return () => clearTimeout(timer);
        }
    }, [open, value]);

    const handleSave = () => {
        onChange({
            path_profile: selectedPathProfile,
            port_scan_profile: selectedPortScanProfile
        });
        onClose();
    };

    const handleCancel = () => {
        setSelectedPathProfile(value.path_profile);
        setSelectedPortScanProfile(value.port_scan_profile);
        onClose();
    };

    if (!open) return null;

    return (
        <div className="fixed inset-0 bg-terminal-bg/95 backdrop-blur-sm flex items-center justify-center z-50 p-4">
            {/* Scanline effect overlay */}
            <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-10">
                <div className="absolute inset-0" style={{
                    backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(95, 158, 160, 0.1) 2px, rgba(95, 158, 160, 0.1) 4px)'
                }} />
            </div>

            <div className={`
                terminal-box border-terminal-accent/50 max-w-lg w-full max-h-[90vh] overflow-y-auto
                shadow-[0_0_30px_rgba(95,158,160,0.2),inset_0_0_30px_rgba(95,158,160,0.05)]
                transition-all duration-200
                ${isAnimating ? 'scale-95 opacity-0' : 'scale-100 opacity-100'}
            `}>
                {/* Header */}
                <div className="relative border-b border-terminal-accent/30 bg-terminal-accent/5 sticky top-0 z-10">
                    {/* Corner decorations */}
                    <div className="absolute top-0 left-0 w-3 h-3 border-l-2 border-t-2 border-terminal-accent/60" />
                    <div className="absolute top-0 right-0 w-3 h-3 border-r-2 border-t-2 border-terminal-accent/60" />

                    <div className="flex items-center gap-3 p-4">
                        <div className="flex items-center justify-center w-8 h-8 bg-terminal-accent/20 rounded border border-terminal-accent/40">
                            <Settings className="text-terminal-accent" size={18} />
                        </div>
                        <div className="flex-1">
                            <h2 className="section-title text-terminal-accent flex items-center gap-2">
                                <span className="text-terminal-dim">[</span>
                                SCAN SETTINGS
                                <span className="text-terminal-dim">]</span>
                            </h2>
                        </div>
                        <button
                            onClick={handleCancel}
                            className="w-8 h-8 flex items-center justify-center text-terminal-dim hover:text-terminal-accent hover:bg-terminal-accent/10 rounded transition-all duration-200"
                        >
                            <X size={18} />
                        </button>
                    </div>
                </div>

                {/* Body */}
                <div className="p-5 space-y-6">
                    {/* Path Discovery Section */}
                    <div className="space-y-3">
                        <div className="flex items-center gap-2 text-terminal-dim text-xs uppercase tracking-wider">
                            <Crosshair size={12} />
                            <span>Path Discovery</span>
                        </div>

                        <p className="text-terminal-text text-xs">
                            Controls the depth of path discovery during scanning.
                        </p>

                        {/* Radio Options */}
                        <div className="space-y-2">
                            {PATH_PROFILE_OPTIONS.map((option) => (
                                <label
                                    key={option.value}
                                    className={`
                                        flex items-start gap-3 p-3 rounded border cursor-pointer transition-all duration-200
                                        ${selectedPathProfile === option.value
                                            ? 'border-terminal-accent bg-terminal-accent/10'
                                            : 'border-terminal-border hover:border-terminal-accent/50 hover:bg-terminal-accent/5'
                                        }
                                    `}
                                >
                                    {/* Custom Radio */}
                                    <div className={`
                                        flex-shrink-0 w-4 h-4 mt-0.5 rounded-full border-2 flex items-center justify-center transition-all duration-200
                                        ${selectedPathProfile === option.value
                                            ? 'border-terminal-accent'
                                            : 'border-terminal-border'
                                        }
                                    `}>
                                        {selectedPathProfile === option.value && (
                                            <div className="w-2 h-2 rounded-full bg-terminal-accent" />
                                        )}
                                    </div>
                                    <input
                                        type="radio"
                                        name="path_profile"
                                        value={option.value}
                                        checked={selectedPathProfile === option.value}
                                        onChange={() => setSelectedPathProfile(option.value)}
                                        className="sr-only"
                                    />

                                    {/* Icon */}
                                    <div className="flex-shrink-0 mt-0.5">
                                        {option.icon}
                                    </div>

                                    {/* Content */}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2">
                                            <span className={`
                                                font-bold text-sm
                                                ${selectedPathProfile === option.value
                                                    ? 'text-terminal-textBright'
                                                    : 'text-terminal-text'
                                                }
                                            `}>
                                                {option.label}
                                            </span>
                                            {option.value === "standard" && (
                                                <span className="text-[10px] px-1.5 py-0.5 bg-terminal-accent/20 text-terminal-accent rounded uppercase">
                                                    Default
                                                </span>
                                            )}
                                        </div>
                                        <p className="text-terminal-dim text-xs mt-1">
                                            {option.description}
                                        </p>
                                        {/* Stats */}
                                        <div className="flex items-center gap-3 mt-2">
                                            <span className="text-[10px] text-terminal-text font-mono">
                                                <span className="text-terminal-dim">Paths:</span> {option.paths}
                                            </span>
                                            <span className="text-[10px] text-terminal-text font-mono">
                                                <span className="text-terminal-dim">Max Pages:</span> {option.maxPages}
                                            </span>
                                        </div>
                                    </div>
                                </label>
                            ))}
                        </div>
                    </div>

                    {/* Divider */}
                    <div className="border-t border-terminal-border/50" />

                    {/* Port Scanning Section */}
                    <div className="space-y-3">
                        <div className="flex items-center gap-2 text-terminal-dim text-xs uppercase tracking-wider">
                            <Radio size={12} />
                            <span>Port Scanning</span>
                        </div>

                        <p className="text-terminal-text text-xs">
                            Controls how many ports are scanned for open services.
                        </p>

                        {/* Radio Options */}
                        <div className="space-y-2">
                            {PORT_SCAN_PROFILE_OPTIONS.map((option) => (
                                <label
                                    key={option.value}
                                    className={`
                                        flex items-start gap-3 p-3 rounded border cursor-pointer transition-all duration-200
                                        ${selectedPortScanProfile === option.value
                                            ? 'border-terminal-accent bg-terminal-accent/10'
                                            : 'border-terminal-border hover:border-terminal-accent/50 hover:bg-terminal-accent/5'
                                        }
                                    `}
                                >
                                    {/* Custom Radio */}
                                    <div className={`
                                        flex-shrink-0 w-4 h-4 mt-0.5 rounded-full border-2 flex items-center justify-center transition-all duration-200
                                        ${selectedPortScanProfile === option.value
                                            ? 'border-terminal-accent'
                                            : 'border-terminal-border'
                                        }
                                    `}>
                                        {selectedPortScanProfile === option.value && (
                                            <div className="w-2 h-2 rounded-full bg-terminal-accent" />
                                        )}
                                    </div>
                                    <input
                                        type="radio"
                                        name="port_scan_profile"
                                        value={option.value}
                                        checked={selectedPortScanProfile === option.value}
                                        onChange={() => setSelectedPortScanProfile(option.value)}
                                        className="sr-only"
                                    />

                                    {/* Icon */}
                                    <div className="flex-shrink-0 mt-0.5">
                                        {option.icon}
                                    </div>

                                    {/* Content */}
                                    <div className="flex-1 min-w-0">
                                        <div className="flex items-center gap-2">
                                            <span className={`
                                                font-bold text-sm
                                                ${selectedPortScanProfile === option.value
                                                    ? 'text-terminal-textBright'
                                                    : 'text-terminal-text'
                                                }
                                            `}>
                                                {option.label}
                                            </span>
                                            {option.value === "light" && (
                                                <span className="text-[10px] px-1.5 py-0.5 bg-terminal-accent/20 text-terminal-accent rounded uppercase">
                                                    Default
                                                </span>
                                            )}
                                            <ImpactBadge impact={option.impact} />
                                        </div>
                                        <p className="text-terminal-dim text-xs mt-1">
                                            {option.description}
                                        </p>
                                        {/* Stats */}
                                        <div className="flex items-center gap-3 mt-2">
                                            <span className="text-[10px] text-terminal-text font-mono">
                                                <span className="text-terminal-dim">Ports:</span> {option.ports}
                                            </span>
                                            <span className="text-[10px] text-terminal-text font-mono">
                                                <span className="text-terminal-dim">Est. Time:</span> {option.estimatedTime}
                                            </span>
                                        </div>
                                    </div>
                                </label>
                            ))}
                        </div>

                        {/* Warning for HIGH profile */}
                        {selectedPortScanProfile === "high" && (
                            <div className="flex items-start gap-2 p-3 rounded border border-amber-500/30 bg-amber-500/10">
                                <AlertTriangle size={14} className="text-amber-400 flex-shrink-0 mt-0.5" />
                                <p className="text-xs text-amber-200">
                                    <strong>Warning:</strong> Comprehensive port scan can take several minutes and generates significant network traffic. Use only on targets you own or have explicit permission to scan.
                                </p>
                            </div>
                        )}
                    </div>
                </div>

                {/* Footer */}
                <div className="relative border-t border-terminal-border bg-terminal-bg/50 sticky bottom-0">
                    {/* Corner decorations */}
                    <div className="absolute bottom-0 left-0 w-3 h-3 border-l-2 border-b-2 border-terminal-accent/60" />
                    <div className="absolute bottom-0 right-0 w-3 h-3 border-r-2 border-b-2 border-terminal-accent/60" />

                    <div className="flex gap-3 p-4">
                        <button
                            onClick={handleCancel}
                            className="flex-1 cyber-button-outline flex items-center justify-center gap-2"
                        >
                            <X size={16} />
                            <span className="uppercase tracking-wider text-sm">Cancel</span>
                        </button>
                        <button
                            onClick={handleSave}
                            className="flex-1 cyber-button flex items-center justify-center gap-2"
                        >
                            <Settings size={16} />
                            <span className="uppercase tracking-wider text-sm">Save</span>
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}
