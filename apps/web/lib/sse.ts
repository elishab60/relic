import { useEffect, useState } from "react";
import { ScanLog } from "./types";

export function useScanLogs(scanId: string | null) {
    const [logs, setLogs] = useState<ScanLog[]>([]);
    const [status, setStatus] = useState<string>("idle");

    useEffect(() => {
        if (!scanId) return;

        setLogs([]);
        setStatus("running");

        // Direct connection to backend to avoid Next.js proxy buffering
        const eventSource = new EventSource(`http://localhost:8000/scan/${scanId}/events`);

        eventSource.onmessage = (event) => {
            // Keep alive or generic messages
        };

        eventSource.addEventListener("log", (e) => {
            try {
                const data = JSON.parse(e.data);
                // Robust parsing with fallbacks
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

    return { logs, status };
}
