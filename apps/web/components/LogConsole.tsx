import React, { useEffect, useRef } from 'react';
import { ScanLog } from '@/lib/types';
import { cn } from '@/lib/utils';

export default function LogConsole({ logs }: { logs: ScanLog[] }) {
    const bottomRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs]);

    return (
        <div className="terminal-box p-4 h-[400px] overflow-y-auto font-mono text-sm">
            <div className="flex flex-col gap-1">
                {logs.length === 0 && (
                    <div className="text-terminal-dim italic flex items-center gap-2">
                        <span className="text-terminal-text">[*]</span>
                        <span>Awaiting target...</span>
                    </div>
                )}
                {logs.map((log, i) => (
                    <div key={i} className="flex gap-3 hover:bg-terminal-bg/50 rounded px-1 -mx-1">
                        <span className="text-terminal-dim shrink-0 text-xs">[{log.ts}]</span>
                        <span className={cn(
                            "font-bold shrink-0 w-16 text-xs uppercase",
                            log.level === 'INFO' && "text-terminal-text",
                            log.level === 'WARNING' && "text-terminal-text",
                            log.level === 'ERROR' && "text-terminal-red",
                        )}>{log.level}</span>
                        <span className="text-terminal-text break-all">{log.msg}</span>
                    </div>
                ))}
                <div ref={bottomRef} />
            </div>
        </div>
    );
}
