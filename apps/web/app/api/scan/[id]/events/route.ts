import { NextRequest, NextResponse } from 'next/server';

const SCANNER_URL = process.env.SCANNER_BASE_URL || 'http://localhost:8000';

export async function GET(
    request: NextRequest,
    { params }: { params: Promise<{ id: string }> }
) {
    const { id } = await params;

    try {
        // Fetch with streaming enabled
        const response = await fetch(`${SCANNER_URL}/scan/${id}/events`, {
            headers: {
                'Accept': 'text/event-stream',
            },
            cache: 'no-store',
        });

        if (!response.ok || !response.body) {
            return NextResponse.json(
                { error: 'Failed to connect to scanner' },
                { status: response.status || 500 }
            );
        }

        // Create a TransformStream to pass chunks through immediately
        const { readable, writable } = new TransformStream();

        // Pipe the response body to our transform stream
        // This runs in the background and forwards each chunk as it arrives
        (async () => {
            const reader = response.body!.getReader();
            const writer = writable.getWriter();

            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) {
                        await writer.close();
                        break;
                    }
                    // Write each chunk immediately
                    await writer.write(value);
                }
            } catch (error) {
                console.error('SSE proxy error:', error);
                await writer.abort(error);
            }
        })();

        // Return the readable side of our transform stream
        return new NextResponse(readable, {
            headers: {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache, no-transform',
                'Connection': 'keep-alive',
                'X-Accel-Buffering': 'no',
            },
        });
    } catch (error) {
        console.error('SSE connection error:', error);
        return NextResponse.json(
            { error: 'Failed to connect to scanner service' },
            { status: 503 }
        );
    }
}
