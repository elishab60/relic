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
}
