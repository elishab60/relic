import { useState, useRef } from 'react';
import { generateAiAnalysis } from '../lib/api';
import { Bot, Download, Zap, AlertCircle, FileText } from 'lucide-react';

interface AiAnalysisSectionProps {
    scanId: string;
    provider: string;
}

export default function AiAnalysisSection({ scanId, provider }: AiAnalysisSectionProps) {
    const [analysis, setAnalysis] = useState<any | null>(null);
    const [loading, setLoading] = useState(false);
    const [isDownloading, setIsDownloading] = useState(false);
    const [error, setError] = useState<string | null>(null);

    const handleDownloadPdf = async () => {
        setIsDownloading(true);
        try {
            const url = new URL(`/api/scan/${scanId}/ai-report.pdf`, window.location.origin);
            if (provider) {
                url.searchParams.append("provider", provider);
            }

            const res = await fetch(url.toString());
            if (!res.ok) throw new Error("Failed to download PDF");

            const blob = await res.blob();
            const blobUrl = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = blobUrl;
            a.download = `ai_report_${scanId}.pdf`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(blobUrl);
            document.body.removeChild(a);
        } catch (e) {
            console.error(e);
            alert("Failed to download PDF report.");
        } finally {
            setIsDownloading(false);
        }
    };

    const [streamedText, setStreamedText] = useState("");
    const isGeneratingRef = useRef(false);

    const handleGenerate = async () => {
        if (isGeneratingRef.current) return;
        isGeneratingRef.current = true;

        setLoading(true);
        setError(null);
        setStreamedText("");
        setAnalysis(null);

        try {
            const result = await generateAiAnalysis(scanId, provider, (chunk) => {
                setStreamedText(prev => prev + chunk);
            });
            setAnalysis(result);
            await handleDownloadPdf();
        } catch (err: any) {
            setError(err.message || "Failed to generate analysis");
        } finally {
            setLoading(false);
            isGeneratingRef.current = false;
        }
    };

    return (
        <div className="space-y-6 pt-6 border-t border-terminal-border">
            <div className="flex justify-between items-center">
                <h3 className="section-title flex items-center gap-2">
                    <Bot size={14} />
                    AI ANALYSIS
                </h3>
                <div className="flex gap-3">
                    {analysis && (
                        <button
                            onClick={handleDownloadPdf}
                            disabled={isDownloading}
                            className="cyber-button-outline flex items-center gap-2 text-sm py-1.5 px-4"
                        >
                            <Download size={14} />
                            {isDownloading ? "..." : "PDF"}
                        </button>
                    )}
                    <button
                        onClick={handleGenerate}
                        disabled={loading}
                        className="cyber-button flex items-center gap-2 text-sm py-1.5 px-4"
                    >
                        <Zap size={14} />
                        {loading ? "ANALYZING..." : "GENERATE"}
                    </button>
                </div>
            </div>

            {error && (
                <div className="terminal-box border-terminal-red/50 bg-terminal-red/5 p-4">
                    <div className="flex items-start gap-3">
                        <AlertCircle className="text-terminal-red shrink-0 mt-0.5" size={18} />
                        <div>
                            <p className="font-bold text-terminal-red text-sm">ERROR: {error}</p>
                            {(error.includes("Ollama") || error.includes("OpenRouter") || error.includes("connect") || error.includes("API key")) && (
                                <div className="mt-2 text-xs text-terminal-dim">
                                    <p>Check that Ollama is running or OpenRouter API key is configured.</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {(analysis || streamedText) && (
                <div className="terminal-box p-4 overflow-x-auto">
                    <div className="flex items-center gap-2 mb-3 pb-2 border-b border-terminal-border">
                        <FileText size={14} className="text-terminal-text" />
                        <span className="text-xs uppercase tracking-wider text-terminal-dim">
                            {analysis ? "Complete" : "Generating..."}
                        </span>
                        {loading && <span className="text-terminal-text animate-pulse ml-auto">▌</span>}
                    </div>
                    <pre className="text-xs text-terminal-text font-mono whitespace-pre-wrap">
                        {analysis ? JSON.stringify(analysis, null, 2) : streamedText}
                    </pre>
                </div>
            )}
        </div>
    );
}
