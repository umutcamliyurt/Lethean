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

const MARKDOWN_ACTIONS: Record<string, (textarea: HTMLTextAreaElement) => void> = {
  bold: (t) => wrapSelection(t, '**', '**', 'bold text'),
  italic: (t) => wrapSelection(t, '_', '_', 'italic text'),
  strike: (t) => wrapSelection(t, '~~', '~~', 'strikethrough'),
  heading: (t) => toggleLinePrefix(t, '## '),
  quote: (t) => toggleLinePrefix(t, '> '),
  code: insertCode,
  link: insertLink,
  bullet: (t) => toggleLinePrefix(t, '- '),
  numbered: toggleNumberedList,
  hr: insertHr,
};

const ALLOWED_LINK_PROTOCOLS = /^(https?:|mailto:)/i;
const HAS_CONTROL_OR_MARKUP_CHARS = /[\x00-\x1f\x7f<>`]/;

function sanitizeHref(escapedUrl: string): string | null {
  const trimmed = escapedUrl.trim();
  if (!ALLOWED_LINK_PROTOCOLS.test(trimmed)) return null;
  if (HAS_CONTROL_OR_MARKUP_CHARS.test(trimmed)) return null;
  return trimmed;
}

function renderInline(escapedText: string): string {
  const codeSpans: string[] = [];
  let text = escapedText.replace(/`([^`\n]+)`/g, (_m, code: string) => {
    codeSpans.push(`<code>${code}</code>`);
    return `\u0000${codeSpans.length - 1}\u0000`;
  });

  text = text.replace(/\[([^\]\n]+)\]\(([^)\s]+)\)/g, (_m, label: string, url: string) => {
    const href = sanitizeHref(url);
    return href ? `<a href="${href}" target="_blank" rel="noopener noreferrer nofollow">${label}</a>` : `${label} (${url})`;
  });

  text = text
    .replace(/\*\*([^*\n]+)\*\*/g, '<strong>$1</strong>')
    .replace(/__([^_\n]+)__/g, '<strong>$1</strong>')
    .replace(/~~([^~\n]+)~~/g, '<del>$1</del>')
    .replace(/\*([^*\n]+)\*/g, '<em>$1</em>')
    .replace(/(^|[^\w])_([^_\n]+)_(?!\w)/g, '$1<em>$2</em>');

  return text.replace(/\u0000(\d+)\u0000/g, (_m, idx: string) => codeSpans[Number(idx)] ?? '');
}

const MARKDOWN_PREVIEW_MAX_CHARS = 2 * 1024 * 1024;

export function renderMarkdownPreview(source: string): string {
  if (source.length > MARKDOWN_PREVIEW_MAX_CHARS) {
    return '<p class="editor-preview-empty">This document is too large to preview here. It will still save and open normally.</p>';
  }
  const lines = source.replace(/\r\n?/g, '\n').split('\n').map(escapeHtml);
  const out: string[] = [];
  let paragraph: string[] = [];
  let i = 0;

  const flushParagraph = (): void => {
    if (paragraph.length) {
      out.push(`<p>${paragraph.join('<br>')}</p>`);
      paragraph = [];
    }
  };

  while (i < lines.length) {
    const line = lines[i]!;

    if (/^```/.test(line)) {
      flushParagraph();
      const code: string[] = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i]!)) { code.push(lines[i]!); i++; }
      i++;
      out.push(`<pre><code>${code.join('\n')}</code></pre>`);
      continue;
    }

    if (/^(-{3,}|\*{3,}|_{3,})\s*$/.test(line)) {
      flushParagraph();
      out.push('<hr>');
      i++;
      continue;
    }

    const heading = line.match(/^(#{1,6})\s+(.*)$/);
    if (heading) {
      flushParagraph();
      const level = heading[1]!.length;
      out.push(`<h${level}>${renderInline(heading[2]!)}</h${level}>`);
      i++;
      continue;
    }

    if (/^&gt;\s?/.test(line)) {
      flushParagraph();
      const quote: string[] = [];
      while (i < lines.length && /^&gt;\s?/.test(lines[i]!)) { quote.push(lines[i]!.replace(/^&gt;\s?/, '')); i++; }
      out.push(`<blockquote>${quote.map((l) => `<p>${renderInline(l)}</p>`).join('')}</blockquote>`);
      continue;
    }

    if (/^[-*]\s+/.test(line)) {
      flushParagraph();
      const items: string[] = [];
      while (i < lines.length && /^[-*]\s+/.test(lines[i]!)) { items.push(lines[i]!.replace(/^[-*]\s+/, '')); i++; }
      out.push(`<ul>${items.map((it) => `<li>${renderInline(it)}</li>`).join('')}</ul>`);
      continue;
    }

    if (/^\d+\.\s+/.test(line)) {
      flushParagraph();
      const items: string[] = [];
      while (i < lines.length && /^\d+\.\s+/.test(lines[i]!)) { items.push(lines[i]!.replace(/^\d+\.\s+/, '')); i++; }
      out.push(`<ol>${items.map((it) => `<li>${renderInline(it)}</li>`).join('')}</ol>`);
      continue;
    }

    if (line.trim() === '') { flushParagraph(); i++; continue; }

    paragraph.push(renderInline(line));
    i++;
  }

  flushParagraph();
  return out.join('\n') || '<p class="editor-preview-empty">Nothing to preview yet.</p>';
}

const TOOLBAR_BUTTONS: Array<{ action: string; icon: string; label: string } | 'sep'> = [
  { action: 'bold', icon: 'mdBold', label: 'Bold' },
  { action: 'italic', icon: 'mdItalic', label: 'Italic' },
  { action: 'strike', icon: 'mdStrike', label: 'Strikethrough' },
  'sep',
  { action: 'heading', icon: 'mdHeading', label: 'Heading' },
  { action: 'quote', icon: 'mdQuote', label: 'Quote' },
  { action: 'code', icon: 'mdCode', label: 'Code' },
  'sep',
  { action: 'link', icon: 'mdLink', label: 'Link' },
  { action: 'bullet', icon: 'mdListBullet', label: 'Bulleted list' },
  { action: 'numbered', icon: 'mdListNumbered', label: 'Numbered list' },
  { action: 'hr', icon: 'mdHr', label: 'Horizontal rule' },
];

function toolbarHtml(): string {
  return TOOLBAR_BUTTONS.map((btn) => {
    if (btn === 'sep') return '<span class="editor-toolbar-sep"></span>';
    return `<button type="button" class="btn-icon" data-md="${btn.action}" title="${btn.label}" aria-label="${btn.label}">${icon(btn.icon)}</button>`;
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