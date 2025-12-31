import React, { useState, useEffect } from 'react';
import { ScanResult } from '@/lib/types';
import { Bot, Code, AlertTriangle, Shield, Target, Copy, Check, Terminal } from 'lucide-react';
import { getAiDebug } from '@/lib/api';
import AiProviderToggle from './AiProviderToggle';
import AiAnalysisSection from './AiAnalysisSection';

export default function ResultTabs({ result }: { result: ScanResult | null }) {
    const [showAiDebug, setShowAiDebug] = useState(false);
    const [aiView, setAiView] = useState<any>(null);
    const [loadingAi, setLoadingAi] = useState(false);
    const [selectedProvider, setSelectedProvider] = useState('ollama');
    const [copiedId, setCopiedId] = useState<string | null>(null);

    useEffect(() => {
        if (showAiDebug && !aiView && result?.scan_id) {
            setLoadingAi(true);
            getAiDebug(result.scan_id)
                .then(data => setAiView(data.ai_view))
                .catch(err => console.error("Failed to load AI view", err))
                .finally(() => setLoadingAi(false));
        }
    }, [showAiDebug, result?.scan_id, aiView]);

    if (!result) return null;

    const getSeverityClass = (severity: string) => {
        const s = severity.toLowerCase();
        if (s === 'critical' || s === 'high') return 'border-terminal-red text-terminal-red';
        if (s === 'medium') return 'border-terminal-text text-terminal-text';
        return 'border-terminal-dim text-terminal-dim';
    };

    const getConfidenceColor = (confidence?: string) => {
        if (!confidence) return 'text-terminal-dim border-terminal-dim';
        switch (confidence.toLowerCase()) {
            case 'high': return 'text-green-400 border-green-400';
            case 'medium': return 'text-yellow-400 border-yellow-400';
            case 'low': return 'text-terminal-dim border-terminal-dim';
            default: return 'text-terminal-dim border-terminal-dim';
        }
    };

    const getGradeColor = (grade: string) => {
        if (grade === 'A' || grade === 'B') return 'text-terminal-text';
        if (grade === 'C') return 'text-terminal-text';
        if (grade === 'N/A') return 'text-terminal-dim';
        return 'text-terminal-red';
    };

    const copyToClipboard = (text: string, id: string) => {
        navigator.clipboard.writeText(text);
        setCopiedId(id);
        setTimeout(() => setCopiedId(null), 2000);
    };

    return (
        <div className="flex flex-col gap-6">
            <AiProviderToggle selectedProvider={selectedProvider} onSelect={setSelectedProvider} />

            {/* WAF Blocked Warning */}
            {result.scan_status === 'blocked' && (
                <div className="bg-terminal-red/10 border border-terminal-red/50 p-4 rounded flex items-start gap-3">
                    <AlertTriangle className="text-terminal-red shrink-0 mt-0.5" size={20} />
                    <div>
                        <div className="font-bold text-terminal-red">BLOCKED BY WAF</div>
                        <p className="text-sm mt-1 text-terminal-text opacity-90">
                            Security mechanism detected ({result.blocking_mechanism || 'WAF'}).
                        </p>
                    </div>
                </div>
            )}

            {/* Target & Grade Header */}
            <div className="flex justify-between items-center terminal-box-glow p-4">
                <div className="flex items-center gap-3">
                    <Target className="text-terminal-text" size={24} />
                    <div>
                        <div className="text-xs text-terminal-dim uppercase tracking-wider">Target</div>
                        <div className="text-xl font-bold text-terminal-textBright">{result.target}</div>
                    </div>
                </div>
                <div className="text-right">
                    <div className="text-xs text-terminal-dim uppercase tracking-wider">Grade</div>
                    <div className={`text-5xl font-bold ${getGradeColor(result.grade)}`}>
                        {result.grade}
                    </div>
                </div>
            </div>

            {/* Findings List */}
            <div className="space-y-4">
                <h3 className="section-title flex items-center gap-2">
                    <Shield size={14} />
                    FINDINGS
                </h3>

                {(!result.findings || result.findings.length === 0) ? (
                    <div className="text-terminal-dim italic p-4 terminal-box">
                        <span className="text-terminal-text">[✓]</span> No critical vulnerabilities detected
                    </div>
                ) : (
                    result.findings.map((finding, i) => (
                        <div
                            key={i}
                            className="terminal-box p-4 hover:border-terminal-accent/50 transition-all duration-200"
                        >
                            <div className="flex justify-between mb-2">
                                <span className="font-bold text-terminal-textBright">
                                    {finding.title}
                                </span>
                                <div className="flex gap-2">
                                    {finding.confidence && (
                                        <span className={`text-xs px-2 py-0.5 rounded border font-bold uppercase ${getConfidenceColor(finding.confidence)}`}>
                                            CONFIDENCE: {finding.confidence}
                                        </span>
                                    )}
                                    <span className={`text-xs px-2 py-0.5 rounded border font-bold uppercase ${getSeverityClass(finding.severity)}`}>
                                        {finding.severity}
                                    </span>
                                </div>
                            </div>
                            <p className="text-sm text-terminal-dim mb-2">{finding.impact}</p>
                            <p className="text-xs text-terminal-text mb-4">
                                <span className="text-terminal-dim">▸ FIX:</span> {finding.recommendation}
                            </p>

                            {/* Evidence Section */}
                            {finding.evidence_snippet && (
                                <div className="mt-4 bg-black/30 p-3 rounded border border-terminal-border/50">
                                    <div className="flex justify-between items-center mb-2">
                                        <span className="text-xs font-bold text-terminal-dim uppercase flex items-center gap-2">
                                            <Code size={12} /> Evidence
                                        </span>
                                        {finding.evidence_hash && (
                                            <span className="text-[10px] font-mono text-terminal-dim">
                                                SHA256: {finding.evidence_hash.substring(0, 8)}...
                                            </span>
                                        )}
                                    </div>
                                    <pre className="text-xs font-mono text-terminal-text overflow-x-auto whitespace-pre-wrap break-all">
                                        {finding.evidence_snippet}
                                    </pre>
                                </div>
                            )}

                            {/* Reproduction Section */}
                            {finding.repro_curl && (
                                <div className="mt-4">
                                    <div className="flex justify-between items-center mb-2">
                                        <span className="text-xs font-bold text-terminal-dim uppercase flex items-center gap-2">
                                            <Terminal size={12} /> Reproduction
                                        </span>
                                        <button
                                            onClick={() => copyToClipboard(finding.repro_curl!, `curl-${i}`)}
                                            className="text-xs flex items-center gap-1 text-terminal-dim hover:text-terminal-text transition-colors"
                                        >
                                            {copiedId === `curl-${i}` ? <Check size={12} className="text-green-400" /> : <Copy size={12} />}
                                            {copiedId === `curl-${i}` ? 'Copied' : 'Copy cURL'}
                                        </button>
                                    </div>
                                    <div className="bg-black/50 p-3 rounded border border-terminal-border/50 font-mono text-xs text-terminal-text overflow-x-auto">
                                        {finding.repro_curl}
                                    </div>
                                </div>
                            )}
                        </div>
                    ))
                )}
            </div>

            {/* AI Analysis Section */}
            <AiAnalysisSection scanId={result.scan_id} provider={selectedProvider} />

            {/* Debug Info */}
            {result.debug_info && (
                <div className="space-y-4 pt-6 border-t border-terminal-border">
                    <div className="flex items-center justify-between">
                        <h3 className="section-title">DEBUG</h3>
                        <div className="flex gap-2">
                            <button
                                onClick={() => setShowAiDebug(false)}
                                className={`px-3 py-1 rounded text-xs font-bold flex items-center gap-2 transition-all ${!showAiDebug
                                    ? 'bg-terminal-accent text-terminal-bg'
                                    : 'bg-terminal-bg text-terminal-dim hover:text-terminal-text border border-terminal-border'
                                    }`}
                            >
                                <Code size={14} /> JSON
                            </button>
                            <button
                                onClick={() => setShowAiDebug(true)}
                                className={`px-3 py-1 rounded text-xs font-bold flex items-center gap-2 transition-all ${showAiDebug
                                    ? 'bg-terminal-accent text-terminal-bg'
                                    : 'bg-terminal-bg text-terminal-dim hover:text-terminal-text border border-terminal-border'
                                    }`}
                            >
                                <Bot size={14} /> AI
                            </button>
                        </div>
                    </div>

                    <div className="terminal-box p-4 overflow-x-auto relative">
                        {showAiDebug && loadingAi && (
                            <div className="absolute inset-0 flex items-center justify-center bg-terminal-bg/80 backdrop-blur-sm">
                                <span className="text-terminal-text animate-pulse">Loading...</span>
                            </div>
                        )}
                        <pre className="text-xs text-terminal-dim font-mono">
                            {showAiDebug
                                ? JSON.stringify(aiView || {}, null, 2)
                                : JSON.stringify(result.debug_info, null, 2)
                            }
                        </pre>
                    </div>
                </div>
            )}
        </div>
    );
}
