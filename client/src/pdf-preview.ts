
import type { PDFDocumentProxy, RenderTask } from 'pdfjs-dist';

type PdfjsModule = typeof import('pdfjs-dist');

let pdfjsPromise: Promise<PdfjsModule> | null = null;

function loadPdfjs(): Promise<PdfjsModule> {
  if (!pdfjsPromise) {
    pdfjsPromise = import('pdfjs-dist').then((mod) => {
      mod.GlobalWorkerOptions.workerSrc = new URL(
        './vendor/pdfjs/pdf.worker.min.mjs',
        import.meta.url
      ).toString();
      return mod;
    }).catch((err) => {
      pdfjsPromise = null;
      throw err;
    });
  }
  return pdfjsPromise;
}

export interface PdfPreviewHandle {
  readonly pageCount: number;
  readonly currentPage: number;
  goToPage(page: number): Promise<void>;
  destroy(): void;
}

export interface PdfPreviewOptions {
  onPageChange?: (page: number, pageCount: number) => void;
}

const MAX_RENDER_SCALE = 3;
const MIN_RENDER_SCALE = 0.1;

export async function openPdfPreview(
  container: HTMLElement,
  bytes: Uint8Array,
  options: PdfPreviewOptions = {}
): Promise<PdfPreviewHandle> {
  const pdfjs = await loadPdfjs();

  const loadingTask = pdfjs.getDocument({ data: bytes });

  let doc: PDFDocumentProxy;
  try {
    doc = await loadingTask.promise;
  } catch {
    throw new Error('This file could not be read as a PDF.');
  }

  let destroyed = false;
  let currentPage = 1;
  let renderTask: RenderTask | null = null;
  let resizeTimer: ReturnType<typeof setTimeout> | null = null;

  const canvas = document.createElement('canvas');
  canvas.className = 'lightbox-pdf-canvas';
  container.appendChild(canvas);

  async function renderPage(pageNum: number): Promise<void> {
    if (destroyed) return;
    if (renderTask) {
      renderTask.cancel();
      renderTask = null;
    }

    const page = await doc.getPage(pageNum);
    if (destroyed) return;

    const containerWidth = container.clientWidth || canvas.clientWidth || 800;
    const unscaledViewport = page.getViewport({ scale: 1 });
    const fitScale = containerWidth / unscaledViewport.width;
    const scale = Math.min(MAX_RENDER_SCALE, Math.max(MIN_RENDER_SCALE, fitScale));
    const viewport = page.getViewport({ scale });

    const outputScale = window.devicePixelRatio || 1;
    canvas.width = Math.max(1, Math.floor(viewport.width * outputScale));
    canvas.height = Math.max(1, Math.floor(viewport.height * outputScale));
    canvas.style.width = `${Math.floor(viewport.width)}px`;
    canvas.style.height = `${Math.floor(viewport.height)}px`;

    const task = page.render({
      canvas,
      viewport,
      transform: outputScale !== 1 ? [outputScale, 0, 0, outputScale, 0, 0] : undefined,
    });
    renderTask = task;
    try {
      await task.promise;
    } catch (err) {
      const isCancelled = err instanceof pdfjs.RenderingCancelledException
        || (err as { name?: string } | null)?.name === 'RenderingCancelledException';
      if (!isCancelled) throw err;
    } finally {
      if (renderTask === task) renderTask = null;
    }
  }

  await renderPage(currentPage);
  if (destroyed) {
    void loadingTask.destroy();
    return {
      get pageCount() { return 0; },
      get currentPage() { return 0; },
      async goToPage() {},
      destroy() {},
    };
  }
  options.onPageChange?.(currentPage, doc.numPages);

  const onResize = (): void => {
    if (resizeTimer) clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => { void renderPage(currentPage); }, 150);
  };
  window.addEventListener('resize', onResize);

  return {
    get pageCount() { return doc.numPages; },
    get currentPage() { return currentPage; },
    async goToPage(page: number) {
      if (destroyed) return;
      const clamped = Math.min(Math.max(1, Math.floor(page)), doc.numPages);
      if (clamped === currentPage) return;
      currentPage = clamped;
      await renderPage(currentPage);
      if (!destroyed) options.onPageChange?.(currentPage, doc.numPages);
    },
    destroy() {
      if (destroyed) return;
      destroyed = true;
      if (resizeTimer) clearTimeout(resizeTimer);
      window.removeEventListener('resize', onResize);
      if (renderTask) renderTask.cancel();
      void loadingTask.destroy();
      canvas.remove();
    },
  };
}
