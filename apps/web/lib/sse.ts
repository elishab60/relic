import { useEffect, useState } from "react";
import { ScanLog } from "./types";

export function useScanLogs(scanId: string | null) {
    const [logs, setLogs] = useState<ScanLog[]>([]);
    const [status, setStatus] = useState<string>("idle");
    const [activeScanId, setActiveScanId] = useState<string | null>(null);

    useEffect(() => {
        if (!scanId) return;

        // Reset state for new scan
        setLogs([]);
        setStatus("running");
        setActiveScanId(scanId);

        // Connect directly to backend
        const eventSource = new EventSource(`http://localhost:8000/scan/${scanId}/events`);

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
    // it means we are in the transition render. Return "initializing" or "idle".
    const isReady = scanId === activeScanId;

    return {
        logs: isReady ? logs : [],
        status: isReady ? status : "idle"
    };
}
