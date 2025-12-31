import { useEffect, useState } from "react";
import { ScanLog } from "./types";

export function useScanLogs(scanId: string | null) {
    const [logs, setLogs] = useState<ScanLog[]>([]);
    const [status, setStatus] = useState<string>("idle");
    const [activeScanId, setActiveScanId] = useState<string | null>(null);
    const [prevScanId, setPrevScanId] = useState<string | null>(scanId);

    // Reset state immediately when scanId changes
    useEffect(() => {
        if (scanId !== activeScanId) {
            setLogs([]);
            setStatus("idle");
            setActiveScanId(scanId);
        }
    }, [scanId, activeScanId]);

    useEffect(() => {
        if (!scanId) return;

        setStatus("running");

        // Connect directly to backend - use relative URL for Docker compatibility
        const baseUrl = typeof window !== 'undefined' ? '' : 'http://localhost:8000';
        const eventSource = new EventSource(`${baseUrl}/api/scan/${scanId}/events`);

        eventSource.onmessage = (event) => {
            // Keep alive or generic messages
        };

        eventSource.addEventListener("log", (e) => {
            try {
                const data = JSON.parse(e.data);
                // Parse log entry
                const log: ScanLog = {
                    ts: data.timestamp || data.ts || new Date().toISOString(),
                    level: data.level || "INFO",
                    msg: data.message || data.msg || data.text || JSON.stringify(data)
                };
                setLogs((prev) => [...prev, log]);
            } catch (err) {
                console.error("Failed to parse log event:", err);
            }
        });

        eventSource.addEventListener("done", (e) => {
            const data = JSON.parse(e.data);
            setStatus(data.status);
            eventSource.close();
        });

        eventSource.onerror = () => {
            eventSource.close();
            setStatus("error");
        };

        return () => {
            eventSource.close();
        };
    }, [scanId]);

    // Guard against stale state:
    // If the prop scanId doesn't match the activeScanId (state),
    // it means we are in the transition render. Return "idle".
    const isReady = scanId === activeScanId;

    return {
        logs: isReady ? logs : [],
        status: isReady ? status : "idle"
    };
}
