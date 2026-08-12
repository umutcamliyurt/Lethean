import type { EncryptedFilePayload } from './types.js';

const POOL_SIZE = Math.min(6, Math.max(1, (navigator.hardwareConcurrency || 2) - 1));

interface PendingJob {
  resolve: (value: EncryptedFilePayload) => void;
  reject: (err: Error) => void;
}

type EncryptSuccess = { id: number; ok: true; result: EncryptedFilePayload };
type EncryptFailure = { id: number; ok: false; error: string };
type WorkerResponse = EncryptSuccess | EncryptFailure;

type DispatchPayload =
  | { kind: 'file'; wrappingKeyRaw: Uint8Array; file: File; parentId: string | null }
  | { kind: 'folder'; wrappingKeyRaw: Uint8Array; name: string; parentId: string | null };

class EncryptWorkerPool {
  private idle: Worker[] = [];
  private waiters: Array<(worker: Worker) => void> = [];
  private jobsByWorker = new Map<Worker, number>();
  private pending = new Map<number, PendingJob>();
  private nextId = 1;

  constructor(size: number) {
    for (let i = 0; i < size; i++) {
      this.idle.push(this.createWorker());
    }
  }

  private createWorker(): Worker {
    const worker = new Worker(new URL('./crypto-worker.js', import.meta.url), { type: 'module' });
    worker.onmessage = (event: MessageEvent<WorkerResponse>) => this.handleMessage(worker, event.data);
    worker.onerror = (event: ErrorEvent) => this.handleWorkerError(worker, event);
    return worker;
  }

  private acquireWorker(): Promise<Worker> {
    const worker = this.idle.pop();
    if (worker) return Promise.resolve(worker);
    return new Promise((resolve) => this.waiters.push(resolve));
  }

  private releaseWorker(worker: Worker): void {
    this.jobsByWorker.delete(worker);
    const waiter = this.waiters.shift();
    if (waiter) waiter(worker);
    else this.idle.push(worker);
  }

  private handleMessage(worker: Worker, data: WorkerResponse): void {
    const job = this.pending.get(data.id);
    this.pending.delete(data.id);
    this.releaseWorker(worker);
    if (!job) return;
    if (data.ok) job.resolve(data.result);
    else job.reject(new Error(data.error));
  }

  private handleWorkerError(worker: Worker, event: ErrorEvent): void {
    const id = this.jobsByWorker.get(worker);
    if (id != null) {
      const job = this.pending.get(id);
      this.pending.delete(id);
      job?.reject(new Error(`Encryption worker error: ${event.message || 'unknown error'}`));
    }
    this.releaseWorker(worker);
  }

  private async dispatch(payload: DispatchPayload): Promise<EncryptedFilePayload> {
    const worker = await this.acquireWorker();
    const id = this.nextId++;
    this.jobsByWorker.set(worker, id);
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      worker.postMessage({ id, ...payload });
    });
  }

  encryptFile(wrappingKeyRaw: Uint8Array, file: File, parentId: string | null): Promise<EncryptedFilePayload> {
    return this.dispatch({ kind: 'file', wrappingKeyRaw, file, parentId });
  }

  encryptFolder(wrappingKeyRaw: Uint8Array, name: string, parentId: string | null): Promise<EncryptedFilePayload> {
    return this.dispatch({ kind: 'folder', wrappingKeyRaw, name, parentId });
  }
}

export const encryptPool = new EncryptWorkerPool(POOL_SIZE);