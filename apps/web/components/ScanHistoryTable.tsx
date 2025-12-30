'use client';

import { ScanListItem } from '@/lib/types';

interface ScanHistoryTableProps {
    scans: ScanListItem[];
    onSelectScan: (scanId: string) => void;
}

function getGradeColor(grade: string | null): string {
    if (!grade) return 'text-gray-400';
    switch (grade.toUpperCase()) {
        case 'A': return 'text-green-400';
        case 'B': return 'text-lime-400';
        case 'C': return 'text-yellow-400';
        case 'D': return 'text-orange-400';
        case 'F': return 'text-red-400';
        default: return 'text-gray-400';
    }
}

function getStatusBadge(status: string): { bg: string; text: string } {
    switch (status) {
        case 'completed': return { bg: 'bg-green-900/50', text: 'text-green-300' };
        case 'running': return { bg: 'bg-blue-900/50', text: 'text-blue-300' };
        case 'failed': return { bg: 'bg-red-900/50', text: 'text-red-300' };
        default: return { bg: 'bg-gray-900/50', text: 'text-gray-300' };
    }
}

function formatDate(dateString: string): string {
    const date = new Date(dateString);
    return date.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

function truncateTarget(target: string, maxLength: number = 50): string {
    if (target.length <= maxLength) return target;
    return target.substring(0, maxLength - 3) + '...';
}

export default function ScanHistoryTable({ scans, onSelectScan }: ScanHistoryTableProps) {
    if (scans.length === 0) {
        return (
            <div className="text-center py-12 text-gray-400">
                <p className="text-lg">No scans yet</p>
                <p className="text-sm mt-2">Start a scan from the home page to see results here.</p>
            </div>
        );
    }

    return (
        <div className="overflow-x-auto">
            <table className="w-full border-collapse">
                <thead>
                    <tr className="border-b border-gray-700 text-gray-400 text-sm">
                        <th className="text-left py-3 px-4">Target</th>
                        <th className="text-center py-3 px-4">Status</th>
                        <th className="text-center py-3 px-4">Grade</th>
                        <th className="text-center py-3 px-4">Score</th>
                        <th className="text-center py-3 px-4">Findings</th>
                        <th className="text-right py-3 px-4">Date</th>
                    </tr>
                </thead>
                <tbody>
                    {scans.map((scan) => {
                        const statusStyle = getStatusBadge(scan.status);
                        return (
                            <tr
                                key={scan.scan_id}
                                onClick={() => onSelectScan(scan.scan_id)}
                                className="border-b border-gray-800 hover:bg-gray-800/50 cursor-pointer transition-colors"
                            >
                                <td className="py-3 px-4 font-mono text-sm text-gray-200">
                                    {truncateTarget(scan.target)}
                                </td>
                                <td className="py-3 px-4 text-center">
                                    <span className={`px-2 py-1 rounded text-xs ${statusStyle.bg} ${statusStyle.text}`}>
                                        {scan.status}
                                    </span>
                                </td>
                                <td className={`py-3 px-4 text-center text-xl font-bold ${getGradeColor(scan.grade)}`}>
                                    {scan.grade || '-'}
                                </td>
                                <td className="py-3 px-4 text-center text-gray-300">
                                    {scan.score !== null ? scan.score : '-'}
                                </td>
                                <td className="py-3 px-4 text-center text-gray-300">
                                    {scan.findings_count}
                                </td>
                                <td className="py-3 px-4 text-right text-gray-400 text-sm">
                                    {formatDate(scan.started_at)}
                                </td>
                            </tr>
                        );
                    })}
                </tbody>
            </table>
        </div>
    );
}
