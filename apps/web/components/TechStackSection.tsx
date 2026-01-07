'use client';

import React, { useState } from 'react';
import {
    Cpu,
    Globe,
    Server,
    Shield,
    Package,
    BarChart3,
    Code,
    Database,
    ChevronDown,
    ChevronRight,
    AlertTriangle,
    Info
} from 'lucide-react';
import { TechFingerprint, TechDetection, TechCategory } from '@/lib/types';

interface TechStackSectionProps {
    fingerprint: TechFingerprint | null | undefined;
}

// Category configuration with icons and labels
const CATEGORY_CONFIG: Record<TechCategory, {
    icon: React.ElementType;
    label: string;
    color: string;
    bgColor: string;
}> = {
    frontend_framework: { icon: Code, label: 'Frontend', color: 'text-blue-400', bgColor: 'bg-blue-400/10' },
    backend_runtime: { icon: Server, label: 'Backend', color: 'text-purple-400', bgColor: 'bg-purple-400/10' },
    cms: { icon: Package, label: 'CMS', color: 'text-green-400', bgColor: 'bg-green-400/10' },
    ecommerce: { icon: Package, label: 'E-commerce', color: 'text-yellow-400', bgColor: 'bg-yellow-400/10' },
    server: { icon: Server, label: 'Server', color: 'text-orange-400', bgColor: 'bg-orange-400/10' },
    cdn: { icon: Globe, label: 'CDN', color: 'text-cyan-400', bgColor: 'bg-cyan-400/10' },
    waf: { icon: Shield, label: 'WAF', color: 'text-red-400', bgColor: 'bg-red-400/10' },
    hosting: { icon: Cpu, label: 'Hosting', color: 'text-indigo-400', bgColor: 'bg-indigo-400/10' },
    analytics: { icon: BarChart3, label: 'Analytics', color: 'text-pink-400', bgColor: 'bg-pink-400/10' },
    tag_manager: { icon: BarChart3, label: 'Tags', color: 'text-rose-400', bgColor: 'bg-rose-400/10' },
    api_style: { icon: Code, label: 'API', color: 'text-teal-400', bgColor: 'bg-teal-400/10' },
    database: { icon: Database, label: 'Database', color: 'text-amber-400', bgColor: 'bg-amber-400/10' },
    javascript_library: { icon: Code, label: 'JS Libs', color: 'text-yellow-300', bgColor: 'bg-yellow-300/10' },
    build_tool: { icon: Package, label: 'Build', color: 'text-gray-400', bgColor: 'bg-gray-400/10' },
    unknown: { icon: Info, label: 'Other', color: 'text-terminal-dim', bgColor: 'bg-terminal-dim/10' },
};

// Confidence badge colors
const CONFIDENCE_COLORS: Record<string, string> = {
    high: 'text-green-400 border-green-400/50',
    medium: 'text-yellow-400 border-yellow-400/50',
    low: 'text-terminal-dim border-terminal-dim/50',
};

function TechBadge({ tech }: { tech: TechDetection }) {
    const [showEvidence, setShowEvidence] = useState(false);
    const config = CATEGORY_CONFIG[tech.category] || CATEGORY_CONFIG.unknown;
    const Icon = config.icon;

    return (
        <div className="group relative">
            <button
                onClick={() => setShowEvidence(!showEvidence)}
                className={`
                    flex items-center gap-2 px-3 py-1.5 rounded-lg border border-terminal-border/50
                    ${config.bgColor} hover:border-terminal-accent/50 transition-all duration-200
                    cursor-pointer
                `}
            >
                <Icon size={14} className={config.color} />
                <span className="text-sm font-medium text-terminal-text">
                    {tech.name}
                    {tech.version && (
                        <span className="text-terminal-dim ml-1">v{tech.version}</span>
                    )}
                </span>
                <span className={`
                    text-[10px] uppercase font-bold px-1.5 py-0.5 rounded border
                    ${CONFIDENCE_COLORS[tech.confidence] || CONFIDENCE_COLORS.low}
                `}>
                    {tech.confidence}
                </span>
                {showEvidence ? (
                    <ChevronDown size={12} className="text-terminal-dim" />
                ) : (
                    <ChevronRight size={12} className="text-terminal-dim" />
                )}
            </button>

            {/* Evidence dropdown */}
            {showEvidence && tech.evidence.length > 0 && (
                <div className="absolute z-10 top-full left-0 mt-1 w-80 max-w-[90vw] bg-terminal-bg border border-terminal-border rounded-lg shadow-lg p-3">
                    <div className="text-xs font-bold text-terminal-dim uppercase mb-2 flex items-center gap-1">
                        <Info size={10} />
                        Evidence ({tech.source})
                    </div>
                    <ul className="space-y-1">
                        {tech.evidence.map((ev, i) => (
                            <li
                                key={i}
                                className="text-xs font-mono text-terminal-text break-all bg-black/30 px-2 py-1 rounded"
                            >
                                {ev.length > 150 ? ev.slice(0, 147) + '...' : ev}
                            </li>
                        ))}
                    </ul>
                </div>
            )}
        </div>
    );
}

function CategoryGroup({
    category,
    technologies
}: {
    category: TechCategory;
    technologies: TechDetection[]
}) {
    const config = CATEGORY_CONFIG[category] || CATEGORY_CONFIG.unknown;
    const Icon = config.icon;

    return (
        <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs font-bold text-terminal-dim uppercase tracking-wider">
                <Icon size={12} className={config.color} />
                {config.label}
            </div>
            <div className="flex flex-wrap gap-2">
                {technologies.map((tech, i) => (
                    <TechBadge key={`${tech.name}-${i}`} tech={tech} />
                ))}
            </div>
        </div>
    );
}

export default function TechStackSection({ fingerprint }: TechStackSectionProps) {
    const [isExpanded, setIsExpanded] = useState(true);

    if (!fingerprint) {
        return null;
    }

    const { technologies, blocked_by_waf, probe_failures, detection_methods, summary } = fingerprint;

    // Group technologies by category
    const groupedTech: Record<TechCategory, TechDetection[]> = {} as Record<TechCategory, TechDetection[]>;
    technologies.forEach(tech => {
        if (!groupedTech[tech.category]) {
            groupedTech[tech.category] = [];
        }
        groupedTech[tech.category].push(tech);
    });

    // Order categories for display
    const categoryOrder: TechCategory[] = [
        'frontend_framework',
        'backend_runtime',
        'cms',
        'ecommerce',
        'server',
        'cdn',
        'waf',
        'hosting',
        'analytics',
        'tag_manager',
        'api_style',
        'database',
        'javascript_library',
        'build_tool',
        'unknown'
    ];

    const orderedCategories = categoryOrder.filter(cat => groupedTech[cat]?.length > 0);

    return (
        <div className="space-y-4">
            {/* Section Header */}
            <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="w-full flex items-center justify-between group"
            >
                <h3 className="section-title flex items-center gap-2">
                    <Cpu size={14} className="text-terminal-accent" />
                    TECH STACK
                    <span className="text-terminal-dim font-normal">
                        ({technologies.length} detected)
                    </span>
                </h3>
                <div className="flex items-center gap-2">
                    {detection_methods.includes('wappalyzer') && (
                        <span className="text-[10px] px-2 py-0.5 rounded bg-terminal-accent/10 text-terminal-accent border border-terminal-accent/20">
                            WAPPALYZER
                        </span>
                    )}
                    {isExpanded ? (
                        <ChevronDown size={16} className="text-terminal-dim group-hover:text-terminal-text transition-colors" />
                    ) : (
                        <ChevronRight size={16} className="text-terminal-dim group-hover:text-terminal-text transition-colors" />
                    )}
                </div>
            </button>

            {isExpanded && (
                <div className="terminal-box p-4 space-y-6">
                    {/* WAF Warning */}
                    {blocked_by_waf && (
                        <div className="flex items-start gap-3 bg-terminal-red/10 border border-terminal-red/30 rounded-lg p-3">
                            <AlertTriangle size={16} className="text-terminal-red shrink-0 mt-0.5" />
                            <div>
                                <div className="text-sm font-bold text-terminal-red">Detection Limited</div>
                                <p className="text-xs text-terminal-dim mt-1">
                                    WAF or challenge page blocked some probes. Results may be incomplete.
                                </p>
                            </div>
                        </div>
                    )}

                    {/* No technologies detected */}
                    {technologies.length === 0 && (
                        <div className="text-center py-6 text-terminal-dim">
                            <Info size={24} className="mx-auto mb-2 opacity-50" />
                            <p className="text-sm">No technologies detected</p>
                            <p className="text-xs mt-1">
                                The target may be using uncommon technologies or blocking detection.
                            </p>
                        </div>
                    )}

                    {/* Technology Groups */}
                    {orderedCategories.map(category => (
                        <CategoryGroup
                            key={category}
                            category={category}
                            technologies={groupedTech[category]}
                        />
                    ))}

                    {/* Footer: Detection methods and probe info */}
                    {technologies.length > 0 && (
                        <div className="pt-4 border-t border-terminal-border/50 flex flex-wrap gap-4 text-xs text-terminal-dim">
                            <div className="flex items-center gap-1">
                                <Info size={10} />
                                Methods: {detection_methods.filter(m => !m.includes('unavailable')).join(', ') || 'heuristics'}
                            </div>
                            {fingerprint.probe_count > 0 && (
                                <div>
                                    Probes: {fingerprint.probe_count}
                                </div>
                            )}
                            {probe_failures.length > 0 && (
                                <div className="text-terminal-red">
                                    Failures: {probe_failures.length}
                                </div>
                            )}
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
