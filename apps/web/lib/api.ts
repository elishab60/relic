import { ScanResult, ScanSummary } from "./types";

const BASE_URL = "/api/scan";

/**
 * Fetch list of all scans with summary metadata.
 */
export async function listScans(limit = 50, offset = 0): Promise<ScanSummary[]> {
    const res = await fetch(`/api/scans?limit=${limit}&offset=${offset}`);
    if (!res.ok) throw new Error("Failed to fetch scans");
    return res.json();
}

/**
 * Error response from the API when policy check fails.
 */
export interface PolicyError {
    error_code: string;
    message: string;
    details?: Record<string, any>;
}

/**
 * Scan configuration options.
 */
export interface ScanConfigPayload {
    path_profile: "minimal" | "standard" | "thorough";
    port_scan_profile?: "light" | "mid" | "high";
}

/**
 * Start a security scan against a target.
 * 
 * @param target - URL or hostname to scan
 * @param authorized - User acknowledgement that they have permission to scan
 * @param config - Optional scan configuration (path_profile, etc.)
 * @returns Object with scan_id if successful
 * @throws Error with detailed message if policy check fails
 */
export async function startScan(
    target: string,
    authorized: boolean = false,
    config?: ScanConfigPayload
): Promise<{ scan_id: string }> {
    const payload: {
        target: string;
        authorized: boolean;
        config?: ScanConfigPayload;
    } = { target, authorized };

    // Include config if provided
    if (config) {
        payload.config = config;
    }

    const res = await fetch(`${BASE_URL}/start`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
    });

    if (!res.ok) {
        // Try to parse structured error response
        try {
            const errorData: PolicyError = await res.json();
            if (errorData.error_code) {
                throw new Error(`${errorData.error_code}: ${errorData.message}`);
            }
            throw new Error(errorData.message || "Failed to start scan");
        } catch (e) {
            if (e instanceof Error && e.message.includes("error_code")) {
                throw e; // Re-throw structured error
            }
            throw new Error("Failed to start scan");
        }
    }

    return res.json();
}

export async function getResult(scanId: string): Promise<ScanResult> {
    const res = await fetch(`${BASE_URL}/${scanId}`);
    if (!res.ok) throw new Error("Failed to fetch result");
    return res.json();
}

export async function getAiDebug(scanId: string): Promise<any> {
    const res = await fetch(`${BASE_URL}/${scanId}/ai-debug`);
    if (!res.ok) throw new Error("Failed to fetch AI debug info");
    return res.json();
}

export async function getAiProviderStatus(): Promise<any> {
    const res = await fetch(`/api/ai/providers/status`);
    if (!res.ok) throw new Error("Failed to fetch AI provider status");
    return res.json();
}

export async function generateAiAnalysis(
    scanId: string,
    provider?: string,
    onChunk?: (chunk: string) => void
): Promise<any> {
    const url = new URL(`${BASE_URL}/${scanId}/ai-analysis`, window.location.origin);
    if (provider) {
        url.searchParams.append("provider", provider);
    }

    const controller = new AbortController();
    // Increase timeout to 10 minutes for very long streams
    const timeoutId = setTimeout(() => controller.abort(), 600000);

    try {
        const res = await fetch(url.toString(), {
            method: "POST",
            signal: controller.signal,
        });

        if (!res.ok) {
            const errorData = await res.json().catch(() => ({}));
            throw new Error(errorData.detail || "Failed to generate AI analysis");
        }

        if (!res.body) {
            throw new Error("Response body is empty");
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let fullText = "";

        while (true) {
            const { done, value } = await reader.read();
            if (done) break;

            const chunk = decoder.decode(value, { stream: true });
            fullText += chunk;
            if (onChunk) {
                onChunk(chunk);
            }
        }

        // Try to parse the full text as JSON at the end
        try {
            return JSON.parse(fullText);
        } catch (e) {
            console.warn("Failed to parse final AI response as JSON", e);
            // Return raw text if parsing fails, or a structured error
            return { raw_text: fullText, error: "Failed to parse JSON" };
        }

    } finally {
        clearTimeout(timeoutId);
    }
}
