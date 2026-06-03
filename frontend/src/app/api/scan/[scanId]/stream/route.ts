import { NextRequest, NextResponse } from 'next/server';

const SCANNER_URL = process.env.NEXT_PUBLIC_SCANNER_URL || 'http://localhost:4000';

export async function GET(req: NextRequest, { params }: { params: Promise<{ scanId: string }> }) {
  try {
    const { scanId } = await params;
    const apiKey = process.env.SCANNER_API_KEY || '';

    const backendResponse = await fetch(`${SCANNER_URL}/scan/${scanId}/stream`, {
      method: 'GET',
      headers: {
        'X-API-Key': apiKey,
      },
    });

    return new NextResponse(backendResponse.body, {
      status: backendResponse.status,
      statusText: backendResponse.statusText,
      headers: {
        'Content-Type': backendResponse.headers.get('Content-Type') || 'text/event-stream',
        'Cache-Control': 'no-cache',
        'Connection': 'keep-alive',
      },
    });
  } catch (error: unknown) {
    return NextResponse.json({ error: error instanceof Error ? error.message : 'Unknown error' }, { status: 500 });
  }
}
