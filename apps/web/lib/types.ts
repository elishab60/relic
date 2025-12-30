export interface ScanLog {
    ts: string;
    level: string;
    msg: string;
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

export interface ScanResult {
    scan_id: string;
    target: string;
    status: string;
    score: number;
    grade: string;
    findings: Finding[];
    timestamp: string;
    debug_info?: Record<string, any>;
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
