"use client";

import React, { useState, useEffect } from 'react';
import { Shield } from 'lucide-react';

interface AsciiAnimationProps {
    isScanning?: boolean;
}

export default function AsciiAnimation({ isScanning = false }: AsciiAnimationProps) {
    const [scanProgress, setScanProgress] = useState(0);
    const [dots, setDots] = useState(0);
    const [pulsePhase, setPulsePhase] = useState(0);

    // Scan bar animation - ONLY when scanning
    useEffect(() => {
        if (!isScanning) {
            setScanProgress(50); // Static center position
            return;
        }
        const interval = setInterval(() => {
            setScanProgress(prev => (prev + 1) % 100);
        }, 50);
        return () => clearInterval(interval);
    }, [isScanning]);

    // Dots animation - ONLY when scanning
    useEffect(() => {
        if (!isScanning) {
            setDots(0); // Static, no dots
            return;
        }
        const interval = setInterval(() => {
            setDots(prev => (prev + 1) % 4);
        }, 500);
        return () => clearInterval(interval);
    }, [isScanning]);

    // Pulse phase - ONLY when scanning
    useEffect(() => {
        if (!isScanning) {
            setPulsePhase(0);
            return;
        }
        const interval = setInterval(() => {
            setPulsePhase(prev => (prev + 1) % 3);
        }, 800);
        return () => clearInterval(interval);
    }, [isScanning]);

    // Generate scan bar visualization
    const renderScanBar = () => {
        const width = 40;
        const position = Math.floor((scanProgress / 100) * width);
        let bar = '';
        for (let i = 0; i < width; i++) {
            if (i === position) {
                bar += '█';
            } else if (i === position - 1 || i === position + 1) {
                bar += '▓';
            } else if (i === position - 2 || i === position + 2) {
                bar += '░';
            } else {
                bar += '·';
            }
        }
        return bar;
    };

    return (
        <div className="h-full flex flex-col items-center justify-center gap-8 py-8 font-mono">
            {/* Shield icon with subtle pulse */}
            <div className="relative">
                <Shield
                    size={48}
                    className={`text-terminal-red ${isScanning ? 'opacity-80' : 'opacity-60'}`}
                />
                {isScanning && (
                    <div
                        className="absolute inset-0 flex items-center justify-center"
                        style={{ opacity: pulsePhase === 0 ? 0.3 : 0 }}
                    >
                        <Shield size={56} className="text-terminal-red" />
                    </div>
                )}
            </div>

            {/* Main status text */}
            <div className="text-center space-y-3">
                <div className="text-terminal-text text-sm tracking-widest uppercase">
                    {isScanning ? 'Scanning Target' : 'Awaiting Target'}
                </div>
                <div className="text-terminal-dim text-xs">
                    {isScanning
                        ? 'Security audit in progress...'
                        : 'Enter target URL to begin security audit'}
                </div>
            </div>

            {/* Scanning visualization */}
            <div className="space-y-4 w-full max-w-xs">
                {/* Scan bar */}
                <div className="text-center">
                    <pre className={`text-terminal-accent text-xs tracking-tighter ${isScanning ? 'opacity-80' : 'opacity-40'}`}>
                        [{renderScanBar()}]
                    </pre>
                </div>

                {/* Status indicators */}
                <div className="space-y-1 text-xs text-terminal-dim">
                    <div className="flex justify-between">
                        <span>[MODULE]</span>
                        <span>STATUS</span>
                    </div>
                    <div className="border-t border-terminal-border pt-1 space-y-0.5">
                        <div className="flex justify-between">
                            <span>scanner</span>
                            <span className={isScanning ? 'text-terminal-accent' : 'text-terminal-text'}>
                                {isScanning ? 'ACTIVE' : 'READY'}
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span>network</span>
                            <span className={isScanning ? 'text-terminal-accent' : 'text-terminal-text'}>
                                {isScanning ? 'BUSY' : 'IDLE'}
                            </span>
                        </div>
                        <div className="flex justify-between">
                            <span>analyzer</span>
                            <span className="text-terminal-text">STANDBY</span>
                        </div>
                    </div>
                </div>

                {/* Loading indicator */}
                <div className="text-center text-terminal-dim text-xs pt-2">
                    <span className="text-terminal-accent">{'>'}</span>
                    {isScanning ? (
                        <span> scanning{'.'.repeat(dots)}</span>
                    ) : (
                        <span> waiting</span>
                    )}
                </div>
            </div>
        </div>
    );
}
