export interface ScanLog {
    ts: string;
    level: string;
    msg: string;
}

export interface ScanSummary {
    scan_id: string;
    target: string;
    status: string;
    started_at: string | null;
    finished_at: string | null;
    score: number | null;
    grade: string | null;
    findings_count: number;
    // PR-02b: Scan configuration
    config_json?: Record<string, any> | null;
}

export interface Finding {
    title: string;
    severity: string;
    impact: string;
    recommendation: string;
    confidence?: 'low' | 'medium' | 'high';
    repro_curl?: string;
    evidence_snippet?: string;
    evidence_hash?: string;
}

// Tech Fingerprinting Types
export interface TechDetection {
    name: string;
    category: TechCategory;
    confidence: 'low' | 'medium' | 'high';
    evidence: string[];
    version?: string | null;
    source: string;
}

export type TechCategory =
    | 'frontend_framework'
    | 'backend_runtime'
    | 'cms'
    | 'ecommerce'
    | 'server'
    | 'cdn'
    | 'waf'
    | 'hosting'
    | 'analytics'
    | 'tag_manager'
    | 'api_style'
    | 'database'
    | 'javascript_library'
    | 'build_tool'
    | 'unknown';

export interface TechFingerprint {
    technologies: TechDetection[];
    blocked_by_waf: boolean;
    probe_failures: string[];
    raw_headers_sample?: Record<string, string> | null;
    detection_methods: string[];
    probe_count: number;
    summary: Record<string, string[]>;
}

export interface ScanResult {
    scan_id: string;
    target: string;
    status: string;
    score: number;
    grade: string;
    findings: Finding[];
    timestamp: string;
    debug_info?: {
        tech_fingerprint?: TechFingerprint;
        [key: string]: any;
    };
    scan_status?: 'ok' | 'blocked' | 'partial';
    blocking_mechanism?: string | null;
    visibility_level?: 'good' | 'limited' | 'poor';
}

export interface ScanListItem {
    scan_id: string;
    target: string;
    status: string;
    started_at: string;
    score: number | null;
    grade: string | null;
    findings_count: number;
}
