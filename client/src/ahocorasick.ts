interface AnalyzeResult {
  coverageRatio: number;
  wordCount: number;
}

class Node {
  children: Map<string, Node> = new Map();
  fail: Node | null = null;
  depth = 0;
  isWordEnd = false;
  hasOutput = false;
  outputLen = 0;
}

export class AhoCorasick {
  private root: Node;

  constructor(words: Iterable<string>) {
    this.root = new Node();
    this.root.fail = this.root;
    for (const word of words) {
      if (word) this._insert(word);
    }
    this._buildFailLinks();
  }

  private _insert(word: string): void {
    let node = this.root;
    let depth = 0;
    for (const ch of word) {
      depth += 1;
      let next = node.children.get(ch);
      if (!next) {
        next = new Node();
        next.depth = depth;
        node.children.set(ch, next);
      }
      node = next;
    }
    node.isWordEnd = true;
  }

  private _buildFailLinks(): void {
    const queue: Node[] = [];
    for (const child of this.root.children.values()) {
      child.fail = this.root;
      child.hasOutput = child.isWordEnd;
      child.outputLen = child.isWordEnd ? child.depth : 0;
      queue.push(child);
    }
    let head = 0;
    while (head < queue.length) {
      const node = queue[head++]!;
      for (const [ch, child] of node.children) {
        let failNode = node.fail!;
        while (failNode !== this.root && !failNode.children.has(ch)) failNode = failNode.fail!;
        const candidate = failNode.children.get(ch);
        child.fail = candidate && candidate !== child ? candidate : this.root;
        if (child.isWordEnd) {
          child.hasOutput = true;
          child.outputLen = child.depth;
        } else {
          child.hasOutput = child.fail.hasOutput;
          child.outputLen = child.fail.outputLen;
        }
        queue.push(child);
      }
    }
  }

  hasMatch(text: string): boolean {
    let node = this.root;
    for (const ch of text) {
      while (node !== this.root && !node.children.has(ch)) node = node.fail!;
      node = node.children.get(ch) || this.root;
      if (node.hasOutput) return true;
    }
    return false;
  }

  analyze(text: string): AnalyzeResult {
    let node = this.root;
    let lastEnd = -1;
    let coveredChars = 0;
    let wordCount = 0;

    for (let i = 0; i < text.length; i++) {
      const ch = text[i]!;
      while (node !== this.root && !node.children.has(ch)) node = node.fail!;
      node = node.children.get(ch) || this.root;

      if (node.hasOutput) {
        const start = i - node.outputLen + 1;
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
