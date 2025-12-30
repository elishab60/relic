import React from 'react';
import Link from 'next/link';
import { History } from 'lucide-react';

export default function TerminalShell({ children }: { children: React.ReactNode }) {
    return (
        <div className="min-h-screen bg-terminal-bg p-4 md:p-8 flex flex-col">
            <header className="mb-8 border-b border-terminal-border pb-6 flex items-start justify-between">
                {/* Pixel-style RELIC logo */}
                <div>
                    <Link href="/" className="group">
                        <h1 className="pixel-title text-xl md:text-2xl group-hover:text-terminal-textBright transition-colors">
                            RELIC
                        </h1>
                        <p className="text-terminal-dim text-xs mt-1 font-mono">
                            Security Framework v1.2.6
                        </p>
                    </Link>
                </div>

                {/* Navigation */}
                <Link
                    href="/history"
                    className="flex items-center gap-2 px-4 py-2 rounded border border-terminal-border text-terminal-text hover:bg-terminal-border/30 hover:text-terminal-textBright transition-all group"
                >
                    <History size={18} className="group-hover:scale-110 transition-transform" />
                    <span className="font-mono text-sm hidden md:inline">History</span>
                </Link>
            </header>

            <main className="flex-1 flex flex-col gap-6 max-w-7xl mx-auto w-full">
                {children}
            </main>

            {/* Terminal Footer */}
            <footer className="mt-8 pt-4 border-t border-terminal-border">
                <div className="flex items-center gap-2 text-terminal-text text-sm font-mono">
                    <span>user@relic</span>
                    <span className="text-terminal-dim">:</span>
                    <span>~</span>
                    <span className="text-terminal-dim">$</span>
                    <span className="animate-pulse">▌</span>
                </div>
            </footer>
        </div>
    );
}
