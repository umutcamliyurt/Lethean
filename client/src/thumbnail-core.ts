export const MAX_THUMB_SOURCE_PIXELS = 80_000_000;

type AnyCanvas = OffscreenCanvas | HTMLCanvasElement;

export async function makeThumbnail(source: Blob, targetShortSide: number, newCanvas: (w: number, h: number) => AnyCanvas): Promise<Blob> {
  const bitmap = await createImageBitmap(source);
  try {
    if (bitmap.width * bitmap.height > MAX_THUMB_SOURCE_PIXELS) throw new Error('Image too large to thumbnail');
    const scale = Math.min(1, targetShortSide / Math.min(bitmap.width, bitmap.height));
    const w = Math.max(1, Math.min(Math.round(bitmap.width * scale), targetShortSide * 3));
    const h = Math.max(1, Math.min(Math.round(bitmap.height * scale), targetShortSide * 3));
    const canvas = newCanvas(w, h);
    const ctx = canvas.getContext('2d') as OffscreenCanvasRenderingContext2D | CanvasRenderingContext2D | null;
    if (!ctx) throw new Error('Canvas unavailable');
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(bitmap, 0, 0, w, h);
    if ('convertToBlob' in canvas) return canvas.convertToBlob({ type: 'image/webp', quality: 0.8 });
    return new Promise<Blob>((resolve, reject) =>
      canvas.toBlob((b) => (b ? resolve(b) : reject(new Error('Encode failed'))), 'image/webp', 0.8));
  } finally {
    bitmap.close();
  }
}
