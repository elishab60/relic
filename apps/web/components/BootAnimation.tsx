"use client";

import React, { useState, useEffect, useRef, useMemo } from 'react';
import { Shield, Bug, Code, FileText, Scale } from 'lucide-react';

// Complete project tree structure
const PROJECT_TREE = [
    'relic/',
    '├── .github/',
    '│   └── workflows/',
    '│       └── ci.yml',
    '├── apps/',
    '│   └── web/',
    '│       ├── app/',
    '│       │   ├── api/',
    '│       │   ├── globals.css',
    '│       │   ├── layout.tsx',
    '│       │   └── page.tsx',
    '│       ├── components/',
    '│       │   ├── AiAnalysisSection.tsx',
    '│       │   ├── AiProviderToggle.tsx',
    '│       │   ├── BootAnimation.tsx',
    '│       │   ├── LogConsole.tsx',
    '│       │   ├── ResultTabs.tsx',
    '│       │   └── TerminalShell.tsx',
    '│       ├── lib/',
    '│       │   ├── api.ts',
    '│       │   ├── sse.ts',
    '│       │   ├── types.ts',
    '│       │   └── utils.ts',
    '│       └── tailwind.config.ts',
    '├── services/',
    '│   └── scanner/',
    '│       ├── app/',
    '│       │   ├── ai/',
    '│       │   │   ├── analyzer.py',
    '│       │   │   ├── clients.py',
    '│       │   │   ├── prompt_loader.py',
    '│       │   │   └── validation.py',
    '│       │   ├── scanner/',
    '│       │   │   ├── crawler.py',
    '│       │   │   ├── engine.py',
    '│       │   │   ├── tls_checks.py',
    '│       │   │   ├── vuln_checks.py',
    '│       │   │   ├── waf_detection.py',
    '│       │   │   └── xss_detector.py',
    '│       │   ├── cli.py',
    '│       │   ├── config.py',
    '│       │   ├── main.py',
    '│       │   ├── pdf.py',
    '│       │   └── routes.py',
    '│       └── tests/',
    '├── docker-compose.yml',
    '├── README.md',
    '└── LICENSE (MIT)',
];

const MODULES_LOADING = [
    { name: 'Core Engine' },
    { name: 'Scanner Module' },
    { name: 'Vulnerability Analyzer' },
    { name: 'TLS/SSL Validator' },
    { name: 'XSS Detector' },
    { name: 'AI Analyzer' },
    { name: 'PDF Generator' },
    { name: 'Web Interface' },
];

// Floating hex addresses - subtle background
function HexFloat({ delay }: { delay: number }) {
    const [visible, setVisible] = useState(false);
    const address = useMemo(() => {
        return `0x${Math.random().toString(16).slice(2, 10).toUpperCase()}`;
    }, []);
    const position = useMemo(() => ({
        left: `${10 + Math.random() * 80}%`,
        top: `${10 + Math.random() * 80}%`,
    }), []);

    useEffect(() => {
        const timeout = setTimeout(() => setVisible(true), delay);
        return () => clearTimeout(timeout);
    }, [delay]);

    if (!visible) return null;

    return (
        <div
            className="absolute text-[9px] font-mono text-terminal-dim/15 select-none"
            style={position}
        >
            {address}
        </div>
    );
}

interface BootAnimationProps {
    onComplete: () => void;
}

export default function BootAnimation({ onComplete }: BootAnimationProps) {
    const [treeIndex, setTreeIndex] = useState(0);
    const [modulesLoaded, setModulesLoaded] = useState(0);
    const [phase, setPhase] = useState<'tree' | 'modules' | 'ready' | 'closing'>('tree');
    const [windowScale, setWindowScale] = useState(1);
    const containerRef = useRef<HTMLDivElement>(null);

    // Generate hex floats
    const hexFloats = useMemo(() => {
        return Array.from({ length: 10 }, (_, i) => ({
            id: i,
            delay: Math.random() * 2000,
        }));
    }, []);

    // Tree scrolling
    useEffect(() => {
        if (phase !== 'tree') return;

        const interval = setInterval(() => {
            setTreeIndex(prev => {
                if (prev >= PROJECT_TREE.length - 1) {
                    setPhase('modules');
                    return prev;
                }
                return prev + 1;
            });
        }, 40);

        return () => clearInterval(interval);
    }, [phase]);

    // Module loading
    useEffect(() => {
        if (phase !== 'modules') return;

        const interval = setInterval(() => {
            setModulesLoaded(prev => {
                if (prev >= MODULES_LOADING.length) {
                    setPhase('ready');
                    return prev;
                }
                return prev + 1;
            });
        }, 150);

        return () => clearInterval(interval);
    }, [phase]);

    // Ready phase -> closing animation
    useEffect(() => {
        if (phase !== 'ready') return;

        const timer = setTimeout(() => {
            setPhase('closing');
            setWindowScale(1.5);
            setTimeout(() => {
                setWindowScale(50);
                setTimeout(onComplete, 400);
            }, 200);
        }, 300);

        return () => clearTimeout(timer);
    }, [phase, onComplete]);

    // Auto-scroll
    useEffect(() => {
        if (containerRef.current) {
            containerRef.current.scrollTop = containerRef.current.scrollHeight;
        }
    }, [treeIndex, modulesLoaded]);

    const progress = phase === 'tree'
        ? (treeIndex / PROJECT_TREE.length) * 50
        : phase === 'modules'
            ? 50 + (modulesLoaded / MODULES_LOADING.length) * 45
            : 100;

    const isClosing = phase === 'closing';

    return (
        <div
            className={`fixed inset-0 z-50 bg-terminal-bg transition-opacity duration-300 ${isClosing ? 'opacity-0' : 'opacity-100'}`}
        >
            {/* Subtle floating hex addresses */}
            <div className="absolute inset-0 overflow-hidden pointer-events-none">
                {hexFloats.map(hex => (
                    <HexFloat key={hex.id} delay={hex.delay} />
                ))}
            </div>

            {/* Subtle top gradient */}
            <div className="absolute inset-0 pointer-events-none">
                <div className="absolute top-0 left-0 right-0 h-24 bg-gradient-to-b from-terminal-red/5 to-transparent" />
            </div>

            {/* Corner brackets */}
            <div className="absolute top-6 left-6 text-terminal-border text-[10px] font-mono">┌─</div>
            <div className="absolute top-6 right-6 text-terminal-border text-[10px] font-mono">─┐</div>
            <div className="absolute bottom-24 left-6 text-terminal-border text-[10px] font-mono">└─</div>
            <div className="absolute bottom-24 right-6 text-terminal-border text-[10px] font-mono">─┘</div>

            <div className="h-full flex flex-col items-center justify-center px-4 relative z-10">
                {/* RELIC Logo */}
                <pre className="text-terminal-red text-[10px] md:text-xs font-mono mb-3 text-center leading-tight select-none">
                    {`██████╗ ███████╗██╗     ██╗ ██████╗
██╔══██╗██╔════╝██║     ██║██╔════╝
██████╔╝█████╗  ██║     ██║██║     
██╔══██╗██╔══╝  ██║     ██║██║     
██║  ██║███████╗███████╗██║╚██████╗
╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝`}
                </pre>

                <div className="text-terminal-dim text-xs mb-4 text-center">
                    Security Framework v1.0.0
                </div>

                {/* Terminal output - LARGE */}
                <div
                    ref={containerRef}
                    className="w-full max-w-4xl h-72 md:h-80 overflow-hidden font-mono text-xs md:text-sm border border-terminal-border rounded-lg bg-terminal-bgLight/50 p-4 transition-transform duration-500 ease-out"
                    style={{
                        transform: `scale(${windowScale})`,
                        opacity: isClosing ? 0 : 1,
                    }}
                >
                    {/* Terminal header */}
                    <div className="flex items-center gap-2 mb-3 pb-2 border-b border-terminal-border">
                        <div className="flex gap-1.5">
                            <div className="w-2.5 h-2.5 rounded-full bg-terminal-red/60" />
                            <div className="w-2.5 h-2.5 rounded-full bg-terminal-dim/40" />
                            <div className="w-2.5 h-2.5 rounded-full bg-terminal-accent/60" />
                        </div>
                        <span className="text-terminal-dim text-[10px] ml-2">relic@scanner ~ boot</span>
                    </div>

                    {phase === 'tree' && (
                        <div className="space-y-0.5">
                            <div className="text-terminal-text mb-2">{'>'} Loading project structure...</div>
                            {PROJECT_TREE.slice(0, treeIndex + 1).map((line, i) => (
                                <div
                                    key={i}
                                    className={`text-terminal-dim ${i === treeIndex ? 'text-terminal-accent' : ''}`}
                                >
                                    {line}
                                </div>
                            ))}
                        </div>
                    )}

                    {phase === 'modules' && (
                        <div className="space-y-1.5">
                            <div className="text-terminal-text mb-3">{'>'} Initializing security modules...</div>
                            {MODULES_LOADING.slice(0, modulesLoaded).map((mod, i) => (
                                <div key={i} className="flex justify-between items-center">
                                    <span className="text-terminal-dim">[+] {mod.name}</span>
                                    <span className="text-terminal-accent font-bold">OK</span>
                                </div>
                            ))}
                        </div>
                    )}

                    {(phase === 'ready' || phase === 'closing') && (
                        <div className="space-y-3">
                            <div className="text-terminal-accent text-lg">{'>'} All systems operational</div>
                            <div className="text-terminal-text animate-pulse">{'>'} Launching security interface...</div>
                        </div>
                    )}
                </div>

                {/* Progress bar */}
                <div className={`w-full max-w-lg mt-6 transition-opacity duration-300 ${isClosing ? 'opacity-0' : 'opacity-100'}`}>
                    <div className="h-1 bg-terminal-border rounded-full overflow-hidden">
                        <div
                            className="h-full bg-terminal-accent transition-all duration-100 ease-linear"
                            style={{ width: `${progress}%` }}
                        />
                    </div>
                    <div className="text-terminal-dim text-xs text-center mt-2 font-mono">
                        {Math.round(progress)}%
                    </div>
                </div>
            </div>

            {/* Footer credits with icons */}
            <div className={`absolute bottom-6 left-0 right-0 z-10 transition-opacity duration-300 ${isClosing ? 'opacity-0' : 'opacity-100'}`}>
                <div className="flex flex-col items-center gap-3">
                    {/* Icons row */}
                    <div className="flex items-center gap-6 text-terminal-dim/50">
                        <Shield size={16} />
                        <Bug size={16} />
                        <Code size={16} />
                        <FileText size={16} />
                    </div>

                    {/* Info text */}
                    <div className="text-center font-mono text-[11px] space-y-1.5">
                        <div className="flex items-center justify-center gap-2 text-terminal-text">
                            <Shield size={12} className="text-terminal-red" />
                            <span>Open Source Security Scanner</span>
                            <span className="text-terminal-dim">•</span>
                            <Bug size={12} className="text-terminal-accent" />
                            <span>Agentic Pentesting Tool</span>
                        </div>
                        <div className="flex items-center justify-center gap-3 text-terminal-dim">
                            <div className="flex items-center gap-1.5">
                                <Scale size={11} />
                                <span>MIT License</span>
                            </div>
                            <span className="text-terminal-border">|</span>
                            <span className="text-terminal-accent">Created by Elisha BAJEMON</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
