/**
 * Frontend tests for PR-03b: Evidence & Reproducibility UI
 * 
 * Tests for:
 * - Confidence badge rendering for all three levels
 * - Missing confidence handling
 * - Copy curl button functionality
 * - Findings without repro_curl
 */

import { render, screen, fireEvent } from '@testing-library/react';
import ResultTabs from '../components/ResultTabs';

// Mock clipboard API
const mockWriteText = jest.fn();
Object.assign(navigator, {
    clipboard: {
        writeText: mockWriteText,
    },
});

describe('ResultTabs - Confidence Badge', () => {
    const baseFinding = {
        title: 'Test Finding',
        severity: 'high',
        impact: 'Test impact',
        recommendation: 'Test recommendation',
    };

    const baseResult = {
        scan_id: 'test-123',
        target: 'https://example.com',
        status: 'completed',
        score: 85,
        grade: 'B',
        timestamp: new Date().toISOString(),
        findings: [],
    };

    it('renders high confidence badge with red color', () => {
        const result = {
            ...baseResult,
            findings: [{ ...baseFinding, confidence: 'high' }],
        };

        render(<ResultTabs result={result} />);
        expect(screen.getByText('High confidence')).toBeInTheDocument();
        expect(screen.getByText('High confidence')).toHaveClass('text-red-400');
    });

    it('renders medium confidence badge with orange color', () => {
        const result = {
            ...baseResult,
            findings: [{ ...baseFinding, confidence: 'medium' }],
        };

        render(<ResultTabs result={result} />);
        expect(screen.getByText('Medium confidence')).toBeInTheDocument();
        expect(screen.getByText('Medium confidence')).toHaveClass('text-orange-400');
    });

    it('renders low confidence badge with gray color', () => {
        const result = {
            ...baseResult,
            findings: [{ ...baseFinding, confidence: 'low' }],
        };

        render(<ResultTabs result={result} />);
        expect(screen.getByText('Low confidence')).toBeInTheDocument();
        expect(screen.getByText('Low confidence')).toHaveClass('text-terminal-dim');
    });

    it('renders unknown confidence when field is missing', () => {
        const result = {
            ...baseResult,
            findings: [baseFinding], // No confidence field
        };

        render(<ResultTabs result={result} />);
        expect(screen.getByText('Confidence: unknown')).toBeInTheDocument();
    });

    it('does not crash when confidence is undefined', () => {
        const result = {
            ...baseResult,
            findings: [{ ...baseFinding, confidence: undefined }],
        };

        expect(() => render(<ResultTabs result={result} />)).not.toThrow();
    });
});

describe('ResultTabs - Reproduction cURL', () => {
    const baseResult = {
        scan_id: 'test-123',
        target: 'https://example.com',
        status: 'completed',
        score: 85,
        grade: 'B',
        timestamp: new Date().toISOString(),
        findings: [],
    };

    it('renders repro_curl section when present', () => {
        const curlCommand = "curl 'https://example.com/page?q=<script>'";
        const result = {
            ...baseResult,
            findings: [{
                title: 'XSS Vulnerability',
                severity: 'high',
                impact: 'Test impact',
                recommendation: 'Test recommendation',
                confidence: 'high',
                repro_curl: curlCommand,
            }],
        };

        render(<ResultTabs result={result} />);
        expect(screen.getByText('Reproduction')).toBeInTheDocument();
        expect(screen.getByText(curlCommand)).toBeInTheDocument();
    });

    it('does NOT render repro_curl section when field is missing', () => {
        const result = {
            ...baseResult,
            findings: [{
                title: 'Info Finding',
                severity: 'info',
                impact: 'Test impact',
                recommendation: 'Test recommendation',
                // No repro_curl
            }],
        };

        render(<ResultTabs result={result} />);
        expect(screen.queryByText('Reproduction')).not.toBeInTheDocument();
    });

    it('copies exact curl string to clipboard when Copy button is clicked', async () => {
        const curlCommand = "curl 'https://example.com/page?q=<script>'";
        const result = {
            ...baseResult,
            findings: [{
                title: 'XSS Vulnerability',
                severity: 'high',
                impact: 'Test impact',
                recommendation: 'Test recommendation',
                repro_curl: curlCommand,
            }],
        };

        render(<ResultTabs result={result} />);
        const copyButton = screen.getByText('Copy cURL');
        fireEvent.click(copyButton);

        expect(mockWriteText).toHaveBeenCalledWith(curlCommand);
    });

    it('shows Copied text after clicking copy button', async () => {
        const result = {
            ...baseResult,
            findings: [{
                title: 'XSS Vulnerability',
                severity: 'high',
                impact: 'Test impact',
                recommendation: 'Test recommendation',
                repro_curl: "curl 'https://example.com'",
            }],
        };

        render(<ResultTabs result={result} />);
        const copyButton = screen.getByText('Copy cURL');
        fireEvent.click(copyButton);

        expect(screen.getByText('Copied')).toBeInTheDocument();
    });
});

describe('ResultTabs - Backward Compatibility', () => {
    it('renders findings without any new fields (legacy scan)', () => {
        const result = {
            scan_id: 'legacy-123',
            target: 'https://example.com',
            status: 'completed',
            score: 70,
            grade: 'C',
            timestamp: new Date().toISOString(),
            findings: [{
                title: 'Legacy Finding',
                severity: 'medium',
                impact: 'Legacy impact',
                recommendation: 'Legacy recommendation',
                // No confidence, repro_curl, evidence_snippet
            }],
        };

        expect(() => render(<ResultTabs result={result} />)).not.toThrow();
        expect(screen.getByText('Legacy Finding')).toBeInTheDocument();
    });
});
