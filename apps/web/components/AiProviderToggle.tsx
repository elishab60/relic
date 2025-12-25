import { useEffect, useState } from 'react';
import { getAiProviderStatus } from '../lib/api';
import { Cpu, Cloud } from 'lucide-react';

interface ProviderStatus {
    available: boolean;
    model?: string;
    configured?: boolean;
}

interface AiProviderToggleProps {
    selectedProvider: string;
    onSelect: (provider: string) => void;
}

export default function AiProviderToggle({ selectedProvider, onSelect }: AiProviderToggleProps) {
    const [status, setStatus] = useState<Record<string, ProviderStatus>>({});
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        getAiProviderStatus()
            .then(setStatus)
            .catch(console.error)
            .finally(() => setLoading(false));
    }, []);

    const getStatusColor = (provider: string) => {
        if (loading) return "bg-terminal-dim";
        return status[provider]?.available ? "bg-terminal-text" : "bg-terminal-red";
    };

    const getStatusText = (provider: string) => {
        if (loading) return "...";
        return status[provider]?.available ? "ONLINE" : "OFFLINE";
    };

    return (
        <div className="flex flex-col items-center gap-3 mb-4">
            <div className="flex terminal-box p-1">
                {[
                    { id: 'ollama', label: 'Ollama', sub: 'Local', icon: Cpu },
                    { id: 'openrouter', label: 'OpenRouter', sub: 'Cloud', icon: Cloud },
                ].map(({ id, label, sub, icon: Icon }) => (
                    <button
                        key={id}
                        onClick={() => onSelect(id)}
                        className={`px-4 py-2 rounded text-sm font-medium transition-all flex items-center gap-2 ${selectedProvider === id
                                ? 'bg-terminal-accent text-terminal-bg'
                                : 'text-terminal-dim hover:text-terminal-text hover:bg-terminal-border/30'
                            }`}
                    >
                        <Icon size={16} />
                        <span>{label}</span>
                        <span className={`text-xs ${selectedProvider === id ? 'text-terminal-bg/70' : 'text-terminal-dim'
                            }`}>
                            ({sub})
                        </span>
                    </button>
                ))}
            </div>

            <div className="flex gap-6 text-xs text-terminal-dim font-mono">
                {['ollama', 'openrouter'].map((provider) => (
                    <div key={provider} className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${getStatusColor(provider)}`} />
                        <span className="uppercase tracking-wider">
                            {provider}:
                            <span className={status[provider]?.available ? 'text-terminal-text' : 'text-terminal-red'}>
                                {' '}{getStatusText(provider)}
                            </span>
                        </span>
                    </div>
                ))}
            </div>
        </div>
    );
}
