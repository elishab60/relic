import { NextResponse, NextRequest } from 'next/server';

const SCANNER_URL = process.env.SCANNER_BASE_URL || 'http://localhost:8000';

export async function GET(request: NextRequest) {
    try {
        const searchParams = request.nextUrl.searchParams;
        const limit = searchParams.get('limit') || '50';
        const offset = searchParams.get('offset') || '0';

        const res = await fetch(`${SCANNER_URL}/scans?limit=${limit}&offset=${offset}`, {
            method: 'GET',
            headers: { 'Content-Type': 'application/json' },
        });

        if (!res.ok) {
            const error = await res.json();
            return NextResponse.json(error, { status: res.status });
        }

        const data = await res.json();
        return NextResponse.json(data);
    } catch (error) {
        return NextResponse.json({ detail: 'Failed to fetch scans' }, { status: 500 });
    }
}
