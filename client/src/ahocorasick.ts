interface AnalyzeResult {
  coverageRatio: number;
  wordCount: number;
}

const ROOT = 0;
const NONE = -1;

export class AhoCorasick {
  private size = 1;
  private firstChild: Int32Array;
  private nextSibling: Int32Array;
  private label: Uint16Array;
  private depth: Uint16Array;
  private wordEnd: Uint8Array;
  private fail: Int32Array;
  private outputLen: Uint16Array;

  constructor(words: Iterable<string>) {
    const capacity = 1024;
    this.firstChild = new Int32Array(capacity).fill(NONE);
    this.nextSibling = new Int32Array(capacity).fill(NONE);
    this.label = new Uint16Array(capacity);
    this.depth = new Uint16Array(capacity);
    this.wordEnd = new Uint8Array(capacity);
    for (const word of words) {
      if (word && word.length <= 0xffff) this._insert(word);
    }
    this._trim();
    this.fail = new Int32Array(this.size);
    this.outputLen = new Uint16Array(this.size);
    this._buildFailLinks();
  }

  private _grow(): void {
    const cap = this.firstChild.length * 2;
    const grow = <T extends Int32Array | Uint16Array | Uint8Array>(a: T, fill?: number): T => {
      const next = new (a.constructor as { new (n: number): T })(cap);
      if (fill !== undefined) next.fill(fill, a.length);
      next.set(a);
      return next;
    };
    this.firstChild = grow(this.firstChild, NONE);
    this.nextSibling = grow(this.nextSibling, NONE);
    this.label = grow(this.label);
    this.depth = grow(this.depth);
    this.wordEnd = grow(this.wordEnd);
  }

  private _trim(): void {
    const n = this.size;
    this.firstChild = this.firstChild.slice(0, n);
    this.nextSibling = this.nextSibling.slice(0, n);
    this.label = this.label.slice(0, n);
    this.depth = this.depth.slice(0, n);
    this.wordEnd = this.wordEnd.slice(0, n);
  }

  private child(node: number, ch: number): number {
    for (let c = this.firstChild[node]!; c !== NONE; c = this.nextSibling[c]!) {
      if (this.label[c] === ch) return c;
    }
    return NONE;
  }

  private _insert(word: string): void {
    let node = ROOT;
    for (let i = 0; i < word.length; i++) {
      const ch = word.charCodeAt(i);
      let next = this.child(node, ch);
      if (next === NONE) {
        if (this.size === this.firstChild.length) this._grow();
        next = this.size++;
        this.label[next] = ch;
        this.depth[next] = i + 1;
        this.nextSibling[next] = this.firstChild[node]!;
        this.firstChild[node] = next;
      }
      node = next;
    }
    this.wordEnd[node] = 1;
  }

  private _buildFailLinks(): void {
    const queue = new Int32Array(this.size);
    let tail = 0;
    this.fail[ROOT] = ROOT;
    for (let c = this.firstChild[ROOT]!; c !== NONE; c = this.nextSibling[c]!) {
      this.fail[c] = ROOT;
      this.outputLen[c] = this.wordEnd[c] ? this.depth[c]! : 0;
      queue[tail++] = c;
    }
    let head = 0;
    while (head < tail) {
      const node = queue[head++]!;
      for (let c = this.firstChild[node]!; c !== NONE; c = this.nextSibling[c]!) {
        const ch = this.label[c]!;
        let failNode = this.fail[node]!;
        while (failNode !== ROOT && this.child(failNode, ch) === NONE) failNode = this.fail[failNode]!;
        const candidate = this.child(failNode, ch);
        const f = candidate !== NONE && candidate !== c ? candidate : ROOT;
        this.fail[c] = f;
        this.outputLen[c] = this.wordEnd[c] ? this.depth[c]! : this.outputLen[f]!;
        queue[tail++] = c;
      }
    }
  }

  private step(node: number, ch: number): number {
    for (;;) {
      const next = this.child(node, ch);
      if (next !== NONE) return next;
      if (node === ROOT) return ROOT;
      node = this.fail[node]!;
    }
  }

  hasMatch(text: string): boolean {
    let node = ROOT;
    for (let i = 0; i < text.length; i++) {
      node = this.step(node, text.charCodeAt(i));
      if (this.outputLen[node]) return true;
    }
    return false;
  }

  analyze(text: string): AnalyzeResult {
    let node = ROOT;
    let lastEnd = -1;
    let coveredChars = 0;
    let wordCount = 0;

    for (let i = 0; i < text.length; i++) {
      node = this.step(node, text.charCodeAt(i));
      const len = this.outputLen[node]!;
      if (len) {
        const start = i - len + 1;
        const effectiveStart = Math.max(start, lastEnd + 1);
        if (effectiveStart <= i) {
          coveredChars += i - effectiveStart + 1;
          wordCount += 1;
          lastEnd = i;
        }
      }
    }

    return {
      coverageRatio: text.length ? coveredChars / text.length : 0,
      wordCount,
    };
  }
}
