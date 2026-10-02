import * as api from './api.js';
import { newTextFileBtn } from './dom.js';
import { getWrappingKeyRaw } from './state.js';
import { encryptPool } from './encrypt-pool.js';
import { escapeHtml, showToast, icon } from './utils.js';
import { getCurrentFolderId, addUploadedRecord, removeRecordLocally, getDecryptedBytes } from './gallery.js';
import { showLightbox, closeLightbox } from './lightbox.js';
import type { FileMeta, FileRecord } from './types.js';

const MAX_NAME_LENGTH = 255;
const DEFAULT_NEW_FILE_NAME = 'Untitled.md';

function sanitizeFileName(name: string): string {
  const trimmed = name.trim().slice(0, MAX_NAME_LENGTH);
  return trimmed || DEFAULT_NEW_FILE_NAME;
}

function parentIdOf(meta: FileMeta): string | null {
  return (meta.parentId as string | null | undefined) ?? null;
}

export function isMarkdownFile(meta: FileMeta): boolean {
  return meta.mime === 'text/markdown' || /\.(md|markdown)$/i.test(meta.name);
}

function mimeForFileName(name: string): string {
  return /\.(md|markdown)$/i.test(name) ? 'text/markdown' : 'text/plain';
}


function dispatchInput(textarea: HTMLTextAreaElement): void {
  textarea.dispatchEvent(new Event('input', { bubbles: true }));
}

function wrapSelection(textarea: HTMLTextAreaElement, before: string, after: string, placeholder: string): void {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const selected = textarea.value.slice(start, end) || placeholder;
  textarea.focus();
  textarea.setRangeText(`${before}${selected}${after}`, start, end, 'end');
  textarea.setSelectionRange(start + before.length, start + before.length + selected.length);
  dispatchInput(textarea);
}

function currentLineRange(textarea: HTMLTextAreaElement): { lineStart: number; lineEnd: number } {
  const { value, selectionStart, selectionEnd } = textarea;
  const lineStart = value.lastIndexOf('\n', selectionStart - 1) + 1;
  const nextBreak = value.indexOf('\n', selectionEnd);
  const lineEnd = nextBreak === -1 ? value.length : nextBreak;
  return { lineStart, lineEnd };
}

function toggleLinePrefix(textarea: HTMLTextAreaElement, marker: string): void {
  const { lineStart, lineEnd } = currentLineRange(textarea);
  const lines = textarea.value.slice(lineStart, lineEnd).split('\n');
  const nonBlank = lines.filter((l) => l.trim() !== '');
  const allPrefixed = nonBlank.length > 0 && nonBlank.every((l) => l.startsWith(marker));
  const nextLines = lines.map((l) => {
    if (l.trim() === '') return l;
    return allPrefixed ? l.slice(marker.length) : marker + l;
  });
  textarea.focus();
  textarea.setRangeText(nextLines.join('\n'), lineStart, lineEnd, 'end');
  dispatchInput(textarea);
}

function toggleNumberedList(textarea: HTMLTextAreaElement): void {
  const { lineStart, lineEnd } = currentLineRange(textarea);
  const lines = textarea.value.slice(lineStart, lineEnd).split('\n');
  const numbered = /^\d+\.\s/;
  const nonBlank = lines.filter((l) => l.trim() !== '');
  const allNumbered = nonBlank.length > 0 && nonBlank.every((l) => numbered.test(l));
  let n = 1;
  const nextLines = lines.map((l) => {
    if (l.trim() === '') return l;
    return allNumbered ? l.replace(numbered, '') : `${n++}. ${l}`;
  });
  textarea.focus();
  textarea.setRangeText(nextLines.join('\n'), lineStart, lineEnd, 'end');
  dispatchInput(textarea);
}

function insertLink(textarea: HTMLTextAreaElement): void {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const label = textarea.value.slice(start, end) || 'link text';
  const url = 'https://';
  textarea.focus();
  textarea.setRangeText(`[${label}](${url})`, start, end, 'end');
  const urlStart = start + label.length + 3;
  textarea.setSelectionRange(urlStart, urlStart + url.length);
  dispatchInput(textarea);
}

function insertCode(textarea: HTMLTextAreaElement): void {
  const selected = textarea.value.slice(textarea.selectionStart, textarea.selectionEnd);
  if (selected.includes('\n')) wrapSelection(textarea, '```\n', '\n```', 'code');
  else wrapSelection(textarea, '`', '`', 'code');
}

function insertHr(textarea: HTMLTextAreaElement): void {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const needsLeadingBreak = start > 0 && textarea.value[start - 1] !== '\n';
  textarea.focus();
  textarea.setRangeText(`${needsLeadingBreak ? '\n' : ''}\n---\n`, start, end, 'end');
  dispatchInput(textarea);
}

function insertTable(textarea: HTMLTextAreaElement): void {
  const start = textarea.selectionStart;
  const end = textarea.selectionEnd;
  const lead = start > 0 && textarea.value[start - 1] !== '\n' ? '\n\n' : '';
  const header = 'Column 1';
  const table = `${lead}| ${header} | Column 2 | Column 3 |\n| --- | --- | --- |\n|  |  |  |\n`;
  textarea.focus();
  textarea.setRangeText(table, start, end, 'end');
  const selStart = start + lead.length + 2;
  textarea.setSelectionRange(selStart, selStart + header.length);
  dispatchInput(textarea);
}

function toggleTaskList(textarea: HTMLTextAreaElement): void {
  const { lineStart, lineEnd } = currentLineRange(textarea);
  const lines = textarea.value.slice(lineStart, lineEnd).split('\n');
  const task = /^(\s*)- \[[ xX]\] /;
  const nonBlank = lines.filter((l) => l.trim() !== '');
  const allTasks = nonBlank.length > 0 && nonBlank.every((l) => task.test(l));
  const next = lines.map((l) => {
    if (l.trim() === '') return l;
    if (allTasks) return l.replace(task, '$1');
    const m = l.match(/^(\s*)(?:[-*+]|\d+[.)])\s+(.*)$/);
    return m ? `${m[1]}- [ ] ${m[2]}` : `- [ ] ${l}`;
  });
  textarea.focus();
  textarea.setRangeText(next.join('\n'), lineStart, lineEnd, 'end');
  dispatchInput(textarea);
}

function cycleHeading(textarea: HTMLTextAreaElement): void {
  const { lineStart, lineEnd } = currentLineRange(textarea);
  const lines = textarea.value.slice(lineStart, lineEnd).split('\n');
  const next = lines.map((l) => {
    if (l.trim() === '') return l;
    const m = l.match(/^(#{1,6})\s+(.*)$/);
    if (!m) return `## ${l}`;
    const level = m[1]!.length;
    return level >= 4 ? m[2]! : `${'#'.repeat(level + 1)} ${m[2]}`;
  });
  textarea.focus();
  textarea.setRangeText(next.join('\n'), lineStart, lineEnd, 'end');
  dispatchInput(textarea);
}

const MARKDOWN_ACTIONS: Record<string, (textarea: HTMLTextAreaElement) => void> = {
  bold: (t) => wrapSelection(t, '**', '**', 'bold text'),
  italic: (t) => wrapSelection(t, '_', '_', 'italic text'),
  strike: (t) => wrapSelection(t, '~~', '~~', 'strikethrough'),
  heading: cycleHeading,
  quote: (t) => toggleLinePrefix(t, '> '),
  code: insertCode,
  link: insertLink,
  bullet: (t) => toggleLinePrefix(t, '- '),
  numbered: toggleNumberedList,
  task: toggleTaskList,
  table: insertTable,
  hr: insertHr,
};

const LIST_LINE = /^(\s*)([-*+]|\d+[.)])(\s+)(\[[ xX]\]\s+)?/;

function indentSelectedLines(textarea: HTMLTextAreaElement, outdent: boolean): void {
  const { lineStart, lineEnd } = currentLineRange(textarea);
  const lines = textarea.value.slice(lineStart, lineEnd).split('\n');
  const next = lines.map((l) => {
    if (!outdent) return l.trim() === '' ? l : '  ' + l;
    return l.replace(/^( {1,2}|\t)/, '');
  });
  textarea.focus();
  textarea.setRangeText(next.join('\n'), lineStart, lineEnd, 'select');
  dispatchInput(textarea);
}

function handleEnter(textarea: HTMLTextAreaElement, e: KeyboardEvent): void {
  if (e.shiftKey || e.altKey || e.ctrlKey || e.metaKey || e.isComposing) return;
  if (textarea.selectionStart !== textarea.selectionEnd) return;
  const pos = textarea.selectionStart;
  const lineStart = textarea.value.lastIndexOf('\n', pos - 1) + 1;
  const before = textarea.value.slice(lineStart, pos);

  const quote = before.match(/^(\s*(?:>\s?)+)(.*)$/);
  const list = before.match(LIST_LINE);
  if (!list && !quote) return;

  e.preventDefault();
  if (list) {
    const rest = before.slice(list[0].length);
    if (rest.trim() === '') {
      textarea.setRangeText('', lineStart, pos, 'end');
    } else {
      const marker = list[2]!;
      const nextMarker = /^\d/.test(marker) ? `${parseInt(marker, 10) + 1}${marker.slice(-1)}` : marker;
      const task = list[4] ? '[ ] ' : '';
      textarea.setRangeText(`\n${list[1]}${nextMarker}${list[3]}${task}`, pos, pos, 'end');
    }
  } else if (quote) {
    if (quote[2]!.trim() === '') textarea.setRangeText('', lineStart, pos, 'end');
    else textarea.setRangeText(`\n${quote[1]}`, pos, pos, 'end');
  }
  dispatchInput(textarea);
}

function handleEditorKeydown(textarea: HTMLTextAreaElement, e: KeyboardEvent): void {
  if (e.isComposing) return;
  const mod = e.ctrlKey || e.metaKey;

  if (mod && !e.altKey) {
    const key = e.key.toLowerCase();
    if (key === 'b' && !e.shiftKey) { e.preventDefault(); MARKDOWN_ACTIONS.bold!(textarea); return; }
    if (key === 'i' && !e.shiftKey) { e.preventDefault(); MARKDOWN_ACTIONS.italic!(textarea); return; }
    if (key === 'k' && !e.shiftKey) { e.preventDefault(); MARKDOWN_ACTIONS.link!(textarea); return; }
    if (key === 'x' && e.shiftKey) { e.preventDefault(); MARKDOWN_ACTIONS.strike!(textarea); return; }
    return;
  }

  if (e.key === 'Enter') { handleEnter(textarea, e); return; }

  if (e.key === 'Tab' && !mod && !e.altKey) {
    const multiLine = textarea.value.slice(textarea.selectionStart, textarea.selectionEnd).includes('\n');
    const { lineStart } = currentLineRange(textarea);
    const onListLine = LIST_LINE.test(textarea.value.slice(lineStart, textarea.selectionStart));
    if (multiLine || onListLine) {
      e.preventDefault();
      indentSelectedLines(textarea, e.shiftKey);
    }
  }
}

function handlePasteUrl(textarea: HTMLTextAreaElement, e: ClipboardEvent): void {
  const text = e.clipboardData?.getData('text/plain')?.trim() ?? '';
  const { selectionStart: s, selectionEnd: end } = textarea;
  if (s === end || !/^https?:\/\/\S+$/i.test(text)) return;
  e.preventDefault();
  const label = textarea.value.slice(s, end);
  textarea.setRangeText(`[${label}](${text})`, s, end, 'end');
  dispatchInput(textarea);
}

const ALLOWED_LINK_PROTOCOLS = /^(https?:|mailto:)/i;
const HAS_CONTROL_OR_MARKUP_CHARS = /[\x00-\x1f\x7f<>`]/;

function sanitizeHref(escapedUrl: string): string | null {
  const trimmed = escapedUrl.trim();
  if (!ALLOWED_LINK_PROTOCOLS.test(trimmed)) return null;
  if (HAS_CONTROL_OR_MARKUP_CHARS.test(trimmed)) return null;
  return trimmed;
}

function renderEmphasis(text: string): string {
  return text
    .replace(/\*\*\*([^*\n]+)\*\*\*/g, '<strong><em>$1</em></strong>')
    .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
    .replace(/__([^_\n]+)__/g, '<strong>$1</strong>')
    .replace(/~~([^~\n]+)~~/g, '<del>$1</del>')
    .replace(/==([^=\n]+)==/g, '<mark>$1</mark>')
    .replace(/\*([^*\n]+)\*/g, '<em>$1</em>')
    .replace(/(^|[^\w])_([^_\n]+)_(?!\w)/g, '$1<em>$2</em>');
}

function renderInline(escapedText: string): string {
  const stash: string[] = [];
  const hold = (html: string): string => {
    stash.push(html);
    return `\u0000${stash.length - 1}\u0000`;
  };
  const anchor = (href: string, labelHtml: string): string =>
    hold(`<a href="${href}" target="_blank" rel="noopener noreferrer nofollow">${labelHtml}</a>`);

  let text = escapedText.replace(/`([^`\n]+)`/g, (_m, code: string) => hold(`<code>${code}</code>`));

  text = text.replace(/\\([\\*_{}\[\]()#+\-.!|~=])/g, (_m, ch: string) => hold(ch));

  text = text.replace(/!\[([^\]\n]*)\]\(([^)\s]+)(?:\s+&quot;[^)]*&quot;)?\)/g, (_m, alt: string, url: string) => {
    const href = sanitizeHref(url);
    const label = alt || 'image';
    return href ? anchor(href, `\u{1F5BC} ${label}`) : `${label} (${url})`;
  });

  text = text.replace(/\[([^\]\n]+)\]\(([^)\s]+)(?:\s+&quot;[^)]*&quot;)?\)/g, (_m, label: string, url: string) => {
    const href = sanitizeHref(url);
    return href ? anchor(href, renderEmphasis(label)) : `${label} (${url})`;
  });

  text = text.replace(/&lt;((?:https?:\/\/|mailto:)[^\s]+?)&gt;/gi, (_m, url: string) => {
    const href = sanitizeHref(url);
    return href ? anchor(href, url) : _m;
  });

  text = text.replace(/(^|[\s(])(https?:\/\/[^\s\u0000]*[^\s\u0000.,;:!?)'])/gi, (_m, pre: string, url: string) => {
    const href = sanitizeHref(url);
    return href ? `${pre}${anchor(href, url)}` : _m;
  });

  text = renderEmphasis(text);

  for (let pass = 0; pass < 3 && text.includes('\u0000'); pass++) {
    text = text.replace(/\u0000(\d+)\u0000/g, (_m, idx: string) => stash[Number(idx)] ?? '');
  }
  return text;
}

const MARKDOWN_PREVIEW_MAX_CHARS = 2 * 1024 * 1024;
const LIST_ITEM_RE = /^(\s*)([-*+]|\d+[.)])\s+(.*)$/;
const TABLE_DELIM_RE = /^\s*\|?\s*:?-+:?\s*(\|\s*:?-+:?\s*)*\|?\s*$/;
const FENCE_RE = /^\s{0,3}(`{3,}|~{3,})\s*([\w+#.-]*)[^`]*$/;
const MAX_NESTING = 20;

function splitTableRow(line: string): string[] {
  let s = line.trim();
  if (s.startsWith('|')) s = s.slice(1);
  if (s.endsWith('|') && !s.endsWith('\\|')) s = s.slice(0, -1);
  return s.split(/(?<!\\)\|/).map((c) => c.trim().replace(/\\\|/g, '|'));
}

function renderList(lines: string[], start: number, depth: number): { html: string; next: number } {
  const first = LIST_ITEM_RE.exec(lines[start]!)!;
  const baseIndent = first[1]!.length;
  const ordered = /^\d/.test(first[2]!);
  const items: string[] = [];
  let hasTask = false;
  let i = start;

  while (i < lines.length) {
    const m = LIST_ITEM_RE.exec(lines[i]!);
    if (!m) break;
    const indent = m[1]!.length;
    if (indent !== baseIndent && !(indent < baseIndent + 2 && indent > baseIndent)) break;
    if (/^\d/.test(m[2]!) !== ordered) break;

    let content = m[3]!;
    let checkbox = '';
    const task = content.match(/^\[([ xX])\]\s+(.*)$/);
    if (task) {
      hasTask = true;
      checkbox = `<input type="checkbox" disabled${task[1] !== ' ' ? ' checked' : ''}> `;
      content = task[2]!;
    }
    let body = renderInline(content);
    let nested = '';
    i++;

    while (i < lines.length) {
      const line = lines[i]!;
      const nm = LIST_ITEM_RE.exec(line);
      const lead = line.length - line.trimStart().length;
      if (nm && nm[1]!.length >= baseIndent + 2 && depth < MAX_NESTING) {
        const sub = renderList(lines, i, depth + 1);
        nested += sub.html;
        i = sub.next;
        continue;
      }
      if (!nm && line.trim() !== '' && lead > baseIndent) {
        body += '<br>' + renderInline(line.trim());
        i++;
        continue;
      }
      break;
    }
    items.push(`<li${task ? ' class="task-list-item"' : ''}>${checkbox}${body}${nested}</li>`);
  }

  const tag = ordered ? 'ol' : 'ul';
  const startNum = ordered ? parseInt(first[2]!, 10) : 1;
  const attrs = (ordered && startNum !== 1 ? ` start="${startNum}"` : '') + (hasTask ? ' class="task-list"' : '');
  return { html: `<${tag}${attrs}>${items.join('')}</${tag}>`, next: i };
}

function renderBlocks(lines: string[], depth: number): string[] {
  const out: string[] = [];
  let paragraph: string[] = [];
  let rawParagraph: string[] = [];
  let i = 0;

  const flushParagraph = (): void => {
    if (paragraph.length) {
      out.push(`<p>${paragraph.join('<br>')}</p>`);
      paragraph = [];
      rawParagraph = [];
    }
  };

  while (i < lines.length) {
    const line = lines[i]!;

    const fence = FENCE_RE.exec(line);
    if (fence) {
      flushParagraph();
      const marker = fence[1]!;
      const lang = fence[2]!.replace(/[^\w+#.-]/g, '');
      const code: string[] = [];
      i++;
      while (i < lines.length) {
        const close = lines[i]!.trim();
        if (close.startsWith(marker[0]!.repeat(marker.length)) && /^(`+|~+)$/.test(close)) break;
        code.push(lines[i]!);
        i++;
      }
      i++;
      const cls = lang ? ` class="language-${lang}"` : '';
      out.push(`<pre${lang ? ` data-lang="${lang}"` : ''}><code${cls}>${code.join('\n')}</code></pre>`);
      continue;
    }

    if (rawParagraph.length && /^\s*(=+|-+)\s*$/.test(line)) {
      const level = line.trim().startsWith('=') ? 1 : 2;
      const html = renderInline(rawParagraph.join(' '));
      paragraph = [];
      rawParagraph = [];
      out.push(`<h${level}>${html}</h${level}>`);
      i++;
      continue;
    }

    if (/^\s{0,3}([-*_])(\s*\1){2,}\s*$/.test(line)) {
      flushParagraph();
      out.push('<hr>');
      i++;
      continue;
    }

    const heading = line.match(/^\s{0,3}(#{1,6})\s+(.*?)(?:\s+#+)?\s*$/);
    if (heading) {
      flushParagraph();
      const level = heading[1]!.length;
      out.push(`<h${level}>${renderInline(heading[2]!)}</h${level}>`);
      i++;
      continue;
    }

    if (/^\s{0,3}&gt;/.test(line)) {
      flushParagraph();
      const quote: string[] = [];
      while (i < lines.length && /^\s{0,3}&gt;/.test(lines[i]!)) {
        quote.push(lines[i]!.replace(/^\s{0,3}&gt;\s?/, ''));
        i++;
      }
      const inner = depth < MAX_NESTING ? renderBlocks(quote, depth + 1).join('') : quote.map((l) => `<p>${renderInline(l)}</p>`).join('');
      out.push(`<blockquote>${inner}</blockquote>`);
      continue;
    }

    if (line.includes('|') && i + 1 < lines.length && lines[i + 1]!.includes('-') && TABLE_DELIM_RE.test(lines[i + 1]!)) {
      const headers = splitTableRow(line);
      const aligns = splitTableRow(lines[i + 1]!).map((c) => {
        const l = c.startsWith(':');
        const r = c.endsWith(':');
        return l && r ? 'center' : r ? 'right' : l ? 'left' : '';
      });
      if (headers.length === aligns.length) {
        flushParagraph();
        const cell = (tag: string, text: string, idx: number): string =>
          `<${tag}${aligns[idx] ? ` style="text-align:${aligns[idx]}"` : ''}>${renderInline(text)}</${tag}>`;
        const rows: string[] = [];
        i += 2;
        while (i < lines.length && lines[i]!.trim() !== '' && lines[i]!.includes('|')) {
          const cells = splitTableRow(lines[i]!);
          rows.push(`<tr>${headers.map((_h, idx) => cell('td', cells[idx] ?? '', idx)).join('')}</tr>`);
          i++;
        }
        out.push(
          `<div class="editor-table-wrap"><table><thead><tr>${headers.map((h, idx) => cell('th', h, idx)).join('')}</tr></thead>` +
          `<tbody>${rows.join('')}</tbody></table></div>`,
        );
        continue;
      }
    }

    if (LIST_ITEM_RE.test(line)) {
      flushParagraph();
      const list = renderList(lines, i, 0);
      out.push(list.html);
      i = list.next;
      continue;
    }

    if (line.trim() === '') { flushParagraph(); i++; continue; }

    rawParagraph.push(line);
    paragraph.push(renderInline(line));
    i++;
  }

  flushParagraph();
  return out;
}

export function renderMarkdownPreview(source: string): string {
  if (source.length > MARKDOWN_PREVIEW_MAX_CHARS) {
    return '<p class="editor-preview-empty">This document is too large to preview here. It will still save and open normally.</p>';
  }
  const lines = source.replace(/\r\n?/g, '\n').replace(/^\t+/gm, (t) => '    '.repeat(t.length)).split('\n').map(escapeHtml);
  return renderBlocks(lines, 0).join('\n') || '<p class="editor-preview-empty">Nothing to preview yet.</p>';
}

const TOOLBAR_BUTTONS: Array<{ action: string; icon: string; label: string; text?: string } | 'sep'> = [
  { action: 'bold', icon: 'mdBold', label: 'Bold' },
  { action: 'italic', icon: 'mdItalic', label: 'Italic' },
  { action: 'strike', icon: 'mdStrike', label: 'Strikethrough' },
  'sep',
  { action: 'heading', icon: 'mdHeading', label: 'Heading (click again for next level)' },
  { action: 'quote', icon: 'mdQuote', label: 'Quote' },
  { action: 'code', icon: 'mdCode', label: 'Code' },
  'sep',
  { action: 'link', icon: 'mdLink', label: 'Link' },
  { action: 'bullet', icon: 'mdListBullet', label: 'Bulleted list' },
  { action: 'numbered', icon: 'mdListNumbered', label: 'Numbered list' },
  { action: 'task', icon: '', label: 'Task list', text: '\u2611' },
  { action: 'table', icon: '', label: 'Table', text: '\u25A6' },
  { action: 'hr', icon: 'mdHr', label: 'Horizontal rule' },
];

function toolbarHtml(): string {
  return TOOLBAR_BUTTONS.map((btn) => {
    if (btn === 'sep') return '<span class="editor-toolbar-sep"></span>';
    return `<button type="button" class="btn-icon" data-md="${btn.action}" title="${btn.label}" aria-label="${btn.label}">${btn.text ? `<span aria-hidden="true">${btn.text}</span>` : icon(btn.icon)}</button>`;
  }).join('');
}

interface EditorPanelOptions {
  heading: string;
  subtitle?: string;
  name: string;
  content: string;
  saveLabel: string;
  onSave: (name: string, content: string) => Promise<void>;
}

function renderEditorPanel(opts: EditorPanelOptions): void {
  showLightbox(`
    <div class="settings-panel settings-panel-editor">
      <h2>${escapeHtml(opts.heading)}</h2>
      ${opts.subtitle ? `<p class="subtitle">${escapeHtml(opts.subtitle)}</p>` : ''}
      <form id="editor-form" style="display:flex;flex-direction:column;height:100%;min-height:0;">
        <div class="field">
          <input type="text" id="editor-name-input" autocomplete="off" spellcheck="false" maxlength="${MAX_NAME_LENGTH}" required
            placeholder="File name" aria-label="File name">
        </div>

        <div class="editor-tabs-row">
          <div class="editor-tabs" role="tablist">
            <button type="button" class="editor-tab active" id="editor-tab-write" role="tab" aria-selected="true">Write</button>
            <button type="button" class="editor-tab" id="editor-tab-preview" role="tab" aria-selected="false">Preview</button>
          </div>
          <button type="submit" class="btn-icon" id="editor-save-btn"
            title="${escapeHtml(opts.saveLabel)}" aria-label="${escapeHtml(opts.saveLabel)}">${icon('save')}</button>
        </div>

        <div class="editor-toolbar" id="editor-toolbar" role="toolbar" aria-label="Formatting">
          ${toolbarHtml()}
        </div>

        <div class="field editor-content-field" style="flex:1 1 auto;display:flex;flex-direction:column;min-height:0;">
          <textarea id="editor-content-textarea" class="editor-textarea" spellcheck="false"
            placeholder="Start typing\u2026" aria-label="File content" style="flex:1 1 auto;min-height:0;max-height:none;resize:none;"></textarea>
          <div class="editor-preview hidden" id="editor-preview" aria-live="polite" style="flex:1 1 auto;min-height:0;max-height:none;overflow:auto;"></div>
        </div>
      </form>
    </div>
  `);

  const form = document.getElementById('editor-form') as HTMLFormElement;
  const nameInput = document.getElementById('editor-name-input') as HTMLInputElement;
  const tabWrite = document.getElementById('editor-tab-write') as HTMLButtonElement;
  const tabPreview = document.getElementById('editor-tab-preview') as HTMLButtonElement;
  const toolbar = document.getElementById('editor-toolbar') as HTMLDivElement;
  const textarea = document.getElementById('editor-content-textarea') as HTMLTextAreaElement;
  const previewEl = document.getElementById('editor-preview') as HTMLDivElement;
  const saveBtn = document.getElementById('editor-save-btn') as HTMLButtonElement;
  const toolbarButtons = Array.from(toolbar.querySelectorAll<HTMLButtonElement>('button[data-md]'));
  const saveIconHtml = icon('save');

  nameInput.value = opts.name;
  textarea.value = opts.content;

  textarea.focus();
  textarea.setSelectionRange(textarea.value.length, textarea.value.length);

  let mode: 'write' | 'preview' = 'write';
  const setMode = (next: 'write' | 'preview'): void => {
    mode = next;
    const isWrite = mode === 'write';
    tabWrite.classList.toggle('active', isWrite);
    tabWrite.setAttribute('aria-selected', String(isWrite));
    tabPreview.classList.toggle('active', !isWrite);
    tabPreview.setAttribute('aria-selected', String(!isWrite));
    toolbar.classList.toggle('hidden', !isWrite);
    textarea.classList.toggle('hidden', !isWrite);
    previewEl.classList.toggle('hidden', isWrite);
    if (isWrite) {
      textarea.focus();
    } else {
      previewEl.innerHTML = renderMarkdownPreview(textarea.value);
    }
  };
  tabWrite.addEventListener('click', () => setMode('write'));
  tabPreview.addEventListener('click', () => setMode('preview'));

  textarea.addEventListener('keydown', (e) => handleEditorKeydown(textarea, e));
  textarea.addEventListener('paste', (e) => handlePasteUrl(textarea, e));

  toolbar.addEventListener('click', (e) => {
    const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('button[data-md]');
    const action = btn?.dataset.md;
    if (!action) return;
    MARKDOWN_ACTIONS[action]?.(textarea);
  });

  const setBusy = (busy: boolean): void => {
    saveBtn.disabled = busy;
    nameInput.disabled = busy;
    textarea.disabled = busy;
    tabWrite.disabled = busy;
    tabPreview.disabled = busy;
    for (const btn of toolbarButtons) btn.disabled = busy;
    saveBtn.innerHTML = busy ? '<span class="spinner"></span>' : saveIconHtml;
  };

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      await opts.onSave(sanitizeFileName(nameInput.value), textarea.value);
    } catch (err) {
      showToast((err as Error).message, 'error');
      setBusy(false);
    }
  });
}

async function encryptAndUploadText(name: string, content: string, parentId: string | null): Promise<FileRecord> {
  const wrappingKeyRaw = getWrappingKeyRaw();
  if (!wrappingKeyRaw) throw new Error('Vault is locked.');
  const file = new File([content], name, { type: mimeForFileName(name) });
  const payload = await encryptPool.encryptFile(wrappingKeyRaw, file, parentId);
  return api.uploadFile(payload);
}

export function openNewTextFileModal(): void {
  renderEditorPanel({
    heading: 'New text file',
    name: DEFAULT_NEW_FILE_NAME,
    content: '',
    saveLabel: 'Create',
    onSave: async (name, content) => {
      const record = await encryptAndUploadText(name, content, getCurrentFolderId());
      await addUploadedRecord(record);
      closeLightbox();
      showToast('Text file created.');
    },
  });
}

const EDIT_MAX_BYTES = 2 * 1024 * 1024;

export function editTextFile(record: FileRecord, meta: FileMeta): void {
  if (meta.isFolder) return;

  void (async () => {
    showLightbox(`<div class="lightbox-content"><div class="spinner spinner-lg"></div></div>`);

    let content: string;
    try {
      const bytes = await getDecryptedBytes(record);
      if (bytes.length > EDIT_MAX_BYTES) {
        throw new Error('This file is too large to edit here.');
      }
      content = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
    } catch (err) {
      closeLightbox();
      showToast("Couldn't load this file for editing. " + (err as Error).message, 'error');
      return;
    }

    renderEditorPanel({
      heading: 'Edit file',
      name: meta.name,
      content,
      saveLabel: 'Save',
      onSave: async (name, newContent) => {
        const newRecord = await encryptAndUploadText(name, newContent, parentIdOf(meta));
        await addUploadedRecord(newRecord);
        try {
          await api.deleteFile(record.id);
        } catch {
        }
        removeRecordLocally(record.id);
        closeLightbox();
        showToast('Saved.');
      },
    });
  })();
}

newTextFileBtn?.addEventListener('click', () => openNewTextFileModal());