import React, { useEffect, useRef, useMemo } from 'react';
import { ScanLog } from '@/lib/types';
import { cn } from '@/lib/utils';

export default function LogConsole({ logs }: { logs: ScanLog[] }) {
    const bottomRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs]);

    // Process and filter logs for cleaner display
    const processedLogs = useMemo(() => {
        return logs.filter(log => {
            const msg = log.msg?.trim() || '';
            if (!msg) return false;
            if (/^[=\-]{10,}$/.test(msg)) return false;
            if (msg.startsWith('{"timestamp":')) return false;
            // Skip verbose internal logs
            const skipPrefixes = [
                'Starting tech fingerprinting', 'Analyzing HTTP headers...',
                'Analyzing HTML content...', 'Attempting Wappalyzer',
                'Wappalyzer not available', 'Performing controlled 404',
                'Starting streaming crawl', 'Probing CORS with Origin',
                'Starting path discovery', 'Path discovery completed',
                'Entering check_https', 'Checking HTTP ->', 'HTTP redirects to',
                'Checking HTTPS reachability', 'HTTPS is reachable',
                'Tech fingerprinting complete', 'DNS resolved to'
            ];
            if (skipPrefixes.some(p => msg.startsWith(p))) return false;
            // Skip intermediate progress bars
            if (/^[|\-\\\/] \[#/.test(msg)) {
                if (!msg.includes('25%') && !msg.includes('50%') && !msg.includes('75%') && !msg.includes('100%')) {
                    return false;
                }
            }
            return true;
        }).map(log => {
            let msg = log.msg || '';
            // Symbol replacements
            msg = msg.replace(/-->/g, '→');
            msg = msg.replace(/\[OK\]/g, '✓');
            msg = msg.replace(/\[!!\]/g, '✗');
            msg = msg.replace(/\[!\]/g, '⚠');
            msg = msg.replace(/\[LOW\]/g, '◦');
            msg = msg.replace(/\[MED\]/g, '•');
            msg = msg.replace(/\[HIGH\]/g, '◆');
            msg = msg.replace(/\[--\]/g, '○');
            // Phase headers - make them cleaner
            msg = msg.replace(/^\[PORT-SCAN\]\s*/, '');
            msg = msg.replace(/^\[PORTS\]\s*/, '');
            msg = msg.replace(/^\[RESULTS\]\s*/, '');
            msg = msg.replace(/^\[OPEN\]\s*/, '');
            msg = msg.replace(/^\[INFO\]\s*/, 'ℹ ');
            msg = msg.replace(/^\[SECURITY-SCAN\]\s*/, '');
            msg = msg.replace(/^\[INIT\]\s*/, '');
            msg = msg.replace(/^\[TLS\]\s*/, '');
            msg = msg.replace(/^\[TECH\]\s*/, '');
            msg = msg.replace(/^\[HEADERS\]\s*/, '');
            msg = msg.replace(/^\[CRAWL\]\s*/, '');
            msg = msg.replace(/^\[VULN\]\s*/, '');
            msg = msg.replace(/^📂\s*/, '');
            msg = msg.replace(/^\[DONE\]\s*/, '');
            // Reduce excessive indentation
            msg = msg.replace(/^    /, '  ');
            // Shorten discovered asset URLs
            if (msg.includes('Discovered asset:')) {
                const path = msg.split('Discovered asset:')[1]?.trim().replace(/https?:\/\/[^/]+/, '') || '';
                msg = `  ◦ ${path}`;
            }
            return { ...log, msg };
        });
    }, [logs]);

    // Format timestamp with seconds and milliseconds
    const formatTime = (ts: string) => {
        try {
            const d = new Date(ts);
            const h = d.getHours().toString().padStart(2, '0');
            const m = d.getMinutes().toString().padStart(2, '0');
            const s = d.getSeconds().toString().padStart(2, '0');
            const ms = d.getMilliseconds().toString().padStart(3, '0');
            return `${h}:${m}:${s}.${ms}`;
        } catch {
            return ts.split('T')[1]?.split('.')[0] || '';
        }
    };

    // Determine log type for styling
    const getLogType = (msg: string, level: string): 'phase' | 'success' | 'warning' | 'error' | 'info' | 'detail' => {
        const upperLevel = level?.toUpperCase() || '';
        if (upperLevel === 'ERROR') return 'error';
        if (upperLevel === 'WARNING' || msg.includes('⚠')) return 'warning';
        if (msg.startsWith('SCAN INITIATED') || msg.startsWith('PARALLEL INIT') ||
            msg.startsWith('PORT SCAN') || msg.startsWith('TLS') ||
            msg.startsWith('TECH') || msg.startsWith('SECURITY HEADERS') ||
            msg.startsWith('CONTENT CRAWL') || msg.startsWith('VULNERABILITY') ||
            msg.startsWith('PATH DISCOVERY')) return 'phase';
        if (msg.startsWith('SCAN COMPLETE') || msg.startsWith('PORT SCAN COMPLETE')) return 'success';
        if (msg.startsWith('✓') || msg.startsWith('CONFIRMED')) return 'success';
        if (msg.startsWith('◦') || msg.startsWith('  ◦') || msg.startsWith('  •') ||
            msg.startsWith('Duration') || msg.startsWith('Ports scanned') ||
            msg.startsWith('Findings') || msg.includes('Medium:') || msg.includes('Low:')) return 'detail';
        return 'info';
    };

    const getLogStyles = (type: ReturnType<typeof getLogType>) => {
        switch (type) {
            case 'phase': return 'text-cyan-400 font-medium';
            case 'success': return 'text-emerald-400';
            case 'warning': return 'text-amber-400';
            case 'error': return 'text-red-400 font-medium';
            case 'detail': return 'text-slate-400';
            default: return 'text-slate-300';
        }
    };

    return (
        <div className="terminal-box p-4 h-[400px] overflow-y-auto font-mono text-[11px]">
            <div className="space-y-[2px]">
                {processedLogs.length === 0 && (
                    <div className="text-slate-500 italic py-4 text-center">
                        Awaiting scan...
                    </div>
                )}
                {processedLogs.map((log, i) => {
                    const logType = getLogType(log.msg, log.level);
                    const isPhase = logType === 'phase';
                    const isSuccess = log.msg.startsWith('SCAN COMPLETE');

                    return (
                        <div
                            key={i}
                            className={cn(
                                "flex gap-3 py-[3px] px-2 rounded-sm",
                                isPhase && "mt-3 bg-cyan-500/5 border-l-2 border-cyan-500/50",
                                isSuccess && "mt-3 bg-emerald-500/5 border-l-2 border-emerald-500/50",
                                !isPhase && !isSuccess && "hover:bg-white/[0.02]"
                            )}
                        >
                            <span className="text-slate-600 shrink-0 w-20 tabular-nums text-[10px]">
                                {formatTime(log.ts)}
                            </span>
                            <span className={cn("flex-1", getLogStyles(logType))}>
                                {isPhase && <span className="text-cyan-500 mr-1">▶</span>}
                                {isSuccess && <span className="text-emerald-500 mr-1">✓</span>}
                                {log.msg}
                            </span>
                        </div>
                    );
                })}
                <div ref={bottomRef} />
            </div>
        </div>
    );
}
