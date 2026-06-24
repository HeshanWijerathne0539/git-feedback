import { NextRequest, NextResponse } from 'next/server';
import path from 'path';
import fs from 'fs';
import { decryptBuffer } from '@/lib/crypto';

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ filename: string }> }
) {
  try {
    const { filename } = await params;
    
    // Prevent directory traversal attacks
    const safeFilename = path.basename(filename);
    const filePath = path.join(process.cwd(), 'public', 'uploads', safeFilename);
    
    if (!fs.existsSync(filePath)) {
      return new NextResponse('Image not found', { status: 404 });
    }
    
    const encryptedBuffer = fs.readFileSync(filePath);
    
    try {
      const decryptedBuffer = decryptBuffer(encryptedBuffer);
      
      // Serve as WebP
      return new NextResponse(new Uint8Array(decryptedBuffer), {
        headers: {
          'Content-Type': 'image/webp',
          'Cache-Control': 'public, max-age=31536000, immutable',
        },
      });
    } catch (decryptErr) {
      console.warn('Failed to decrypt image, attempting fallback as raw file:', decryptErr);
      // Fallback for legacy files that were uploaded unencrypted
      return new NextResponse(new Uint8Array(encryptedBuffer), {
        headers: {
          'Content-Type': 'image/webp',
          'Cache-Control': 'public, max-age=31536000, immutable',
        },
      });
    }
  } catch (error) {
    console.error('Error serving image:', error);
    return new NextResponse('Error serving image', { status: 500 });
  }
}
