import React from 'react';
import { ScanResult } from '@/lib/types';
import { Download } from 'lucide-react';

export default function ResultTabs({ result }: { result: ScanResult | null }) {
    if (!result) return null;

    return (
        <div className="flex flex-col gap-6">
            <div className="flex justify-between items-center bg-terminal-dim/10 p-4 rounded border border-terminal-border">
                <div>
                    <div className="text-sm text-terminal-dim">Target</div>
                    <div className="text-xl font-bold">{result.target}</div>
                </div>
                <div className="text-right">
                    <div className="text-sm text-terminal-dim">Grade</div>
                    <div className={`text-4xl font-bold ${result.grade === 'A' ? 'text-green-500' :
                        result.grade === 'B' ? 'text-blue-500' :
                            result.grade === 'C' ? 'text-yellow-500' : 'text-red-500'
                        }`}>{result.grade}</div>
                </div>
            </div>

            <div className="space-y-4">
                <h3 className="text-lg font-semibold text-terminal-accent border-b border-terminal-border pb-2">Top Findings</h3>
                {result.findings.map((finding, i) => (
                    <div key={i} className="bg-terminal-dim/5 border border-terminal-border p-4 rounded hover:border-terminal-accent/50 transition-colors">
                        <div className="flex justify-between mb-2">
                            <span className="font-bold text-white">{finding.title}</span>
                            <span className={`text-xs px-2 py-0.5 rounded border ${finding.severity === 'High' ? 'border-red-500 text-red-500' :
                                finding.severity === 'Medium' ? 'border-yellow-500 text-yellow-500' :
                                    'border-blue-500 text-blue-500'
                                }`}>{finding.severity}</span>
                        </div>
                        <p className="text-sm text-terminal-dim mb-2">{finding.impact}</p>
                        <p className="text-xs text-terminal-accent">Rec: {finding.recommendation}</p>
                    </div>
                ))}
            </div>

            <a
                href={`/api/scan/${result.scan_id}/pdf`}
                target="_blank"
                className="flex items-center justify-center gap-2 bg-terminal-accent text-black font-bold py-3 rounded hover:bg-terminal-accent/90 transition-colors"
            >
                <Download size={18} /> Download Executive Report
            </a>

            {result.debug_info && (
                <div className="space-y-4 pt-6 border-t border-terminal-border">
                    <h3 className="text-lg font-semibold text-terminal-accent">Debug Info (Raw Data)</h3>
                    <div className="bg-terminal-dim/5 border border-terminal-border p-4 rounded overflow-x-auto">
                        <pre className="text-xs text-terminal-dim font-mono">
                            {JSON.stringify(result.debug_info, null, 2)}
                        </pre>
                    </div>
                </div>
            )}
        </div>
    );
}
