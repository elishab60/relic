"use client";

import React, { useEffect, useState } from 'react';
import { X, Settings, Zap, Shield, Crosshair } from 'lucide-react';
import {
    PathProfile,
    labelFromProfile,
    getProfileDescription
} from '@/lib/scanConfig';

interface ScanSettingsModalProps {
    open: boolean;
    onClose: () => void;
    value: PathProfile;
    onChange: (newValue: PathProfile) => void;
}

interface ProfileOption {
    value: PathProfile;
    label: string;
    description: string;
    paths: number;
    maxPages: number;
    icon: React.ReactNode;
}

const PROFILE_OPTIONS: ProfileOption[] = [
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

export default function ScanSettingsModal({
    open,
    onClose,
    value,
    onChange
}: ScanSettingsModalProps) {
    const [isAnimating, setIsAnimating] = useState(true);
    const [selectedValue, setSelectedValue] = useState<PathProfile>(value);

    useEffect(() => {
        if (open) {
            setIsAnimating(true);
            setSelectedValue(value);
            const timer = setTimeout(() => setIsAnimating(false), 200);
            return () => clearTimeout(timer);
        }
    }, [open, value]);

    const handleSave = () => {
        onChange(selectedValue);
        onClose();
    };

    const handleCancel = () => {
        setSelectedValue(value); // Reset to original
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
                terminal-box border-terminal-accent/50 max-w-md w-full 
                shadow-[0_0_30px_rgba(95,158,160,0.2),inset_0_0_30px_rgba(95,158,160,0.05)]
                transition-all duration-200
                ${isAnimating ? 'scale-95 opacity-0' : 'scale-100 opacity-100'}
            `}>
                {/* Header */}
                <div className="relative border-b border-terminal-accent/30 bg-terminal-accent/5">
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
                <div className="p-5 space-y-5">
                    {/* Aggressiveness Section */}
                    <div className="space-y-3">
                        <div className="flex items-center gap-2 text-terminal-dim text-xs uppercase tracking-wider">
                            <Crosshair size={12} />
                            <span>Aggressiveness</span>
                        </div>

                        <p className="text-terminal-text text-xs">
                            Controls the depth of path discovery during scanning.
                        </p>

                        {/* Radio Options */}
                        <div className="space-y-2">
                            {PROFILE_OPTIONS.map((option) => (
                                <label
                                    key={option.value}
                                    className={`
                                        flex items-start gap-3 p-3 rounded border cursor-pointer transition-all duration-200
                                        ${selectedValue === option.value
                                            ? 'border-terminal-accent bg-terminal-accent/10'
                                            : 'border-terminal-border hover:border-terminal-accent/50 hover:bg-terminal-accent/5'
                                        }
                                    `}
                                >
                                    {/* Custom Radio */}
                                    <div className={`
                                        flex-shrink-0 w-4 h-4 mt-0.5 rounded-full border-2 flex items-center justify-center transition-all duration-200
                                        ${selectedValue === option.value
                                            ? 'border-terminal-accent'
                                            : 'border-terminal-border'
                                        }
                                    `}>
                                        {selectedValue === option.value && (
                                            <div className="w-2 h-2 rounded-full bg-terminal-accent" />
                                        )}
                                    </div>
                                    <input
                                        type="radio"
                                        name="path_profile"
                                        value={option.value}
                                        checked={selectedValue === option.value}
                                        onChange={() => setSelectedValue(option.value)}
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
                                                ${selectedValue === option.value
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
                </div>

                {/* Footer */}
                <div className="relative border-t border-terminal-border bg-terminal-bg/50">
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
