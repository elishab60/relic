import { render, screen, fireEvent, waitFor, act } from '@testing-library/react';
import Page from '../app/page';
import { startScan, getResult } from '../lib/api';
import { useScanLogs } from '../lib/sse';

// Mock dependencies
jest.mock('../lib/api');
jest.mock('../lib/sse');
jest.mock('../components/TerminalShell', () => ({ children }: { children: React.ReactNode }) => <div>{children}</div>);
jest.mock('../components/BootAnimation', () => ({ onComplete }: { onComplete: () => void }) => {
    onComplete();
    return null;
});

describe('Page Component Regression Test', () => {
    beforeEach(() => {
        jest.clearAllMocks();
        (useScanLogs as jest.Mock).mockReturnValue({ logs: [], status: 'idle' });
    });

    it('should handle second scan without crashing', async () => {
        // Setup initial state
        (startScan as jest.Mock).mockResolvedValue({ scan_id: 'scan-1' });
        (getResult as jest.Mock).mockResolvedValue({
            scan_id: 'scan-1',
            target: 'localhost',
            findings: [],
            grade: 'A',
            scan_status: 'completed'
        });

        // Render page
        render(<Page />);

        // Start first scan
        const input = screen.getByPlaceholderText(/Enter target/i);
        fireEvent.change(input, { target: { value: 'localhost' } });
        fireEvent.click(screen.getByText('SCAN'));

        // Confirm modal
        fireEvent.click(screen.getByText(/I confirm/i));
        fireEvent.click(screen.getByText('Confirm & Scan'));

        // Simulate scan running
        (useScanLogs as jest.Mock).mockReturnValue({ logs: [], status: 'running' });

        // Simulate scan done
        (useScanLogs as jest.Mock).mockReturnValue({ logs: [], status: 'done' });

        await waitFor(() => expect(getResult).toHaveBeenCalledWith('scan-1'));

        // Start SECOND scan
        (startScan as jest.Mock).mockResolvedValue({ scan_id: 'scan-2' });

        // Reset status mock for second scan to simulate race condition
        // The hook should return 'idle' or 'running' for new scan, NOT 'done'
        // But we want to test if the component crashes if it *was* done

        fireEvent.click(screen.getByText('SCAN'));
        fireEvent.click(screen.getByText(/I confirm/i));
        fireEvent.click(screen.getByText('Confirm & Scan'));

        // If the fix works, this should not throw and we should see the new scan start
        expect(startScan).toHaveBeenCalledTimes(2);
    });
});
