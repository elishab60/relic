/** @type {import('next').NextConfig} */
const nextConfig = {
    output: 'standalone',
    async rewrites() {
        // For local development, use 127.0.0.1:8000
        // For Docker, SCANNER_BASE_URL will be set to http://scanner:8000
        const scannerUrl = process.env.SCANNER_BASE_URL || 'http://127.0.0.1:8000';
        return [
            {
                source: '/api/scan/:path*',
                destination: `${scannerUrl}/scan/:path*`,
            },
            {
                source: '/api/scans',
                destination: `${scannerUrl}/scans`,
            },
            {
                source: '/api/ai/:path*',
                destination: `${scannerUrl}/api/ai/:path*`,
            },
        ];
    },
};

module.exports = nextConfig;

