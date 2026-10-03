import { Marked } from 'marked';
import type { Tokens } from 'marked';
import DOMPurify from 'dompurify';
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

const MARKDOWN_PREVIEW_MAX_CHARS = 2 * 1024 * 1024;

const escapeText = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');

const md = new Marked({ gfm: true, breaks: true, async: false });
md.use({
  renderer: {
    html: ({ text }: Tokens.HTML | Tokens.Tag): string => escapeText(text),
    image: ({ href, text }: Tokens.Image): string => `<a href="${escapeText(href)}">\u{1F5BC} ${escapeText(text || 'image')}</a>`,
  },
});

const SANITIZE_CONFIG = {
  ALLOWED_TAGS: [
    'p', 'br', 'hr', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'strong', 'em', 'del', 'code', 'pre', 'blockquote',
    'ul', 'ol', 'li', 'input',
    'table', 'thead', 'tbody', 'tr', 'th', 'td', 'a',
  ],
  ALLOWED_ATTR: ['href', 'title', 'start', 'align', 'class', 'type', 'checked', 'disabled'],
  ALLOW_DATA_ATTR: false,
  ALLOWED_URI_REGEXP: /^(?:https?:|mailto:)/i,
};

DOMPurify.addHook('afterSanitizeAttributes', (node: Element): void => {
  if (node.tagName === 'A' && node.hasAttribute('href')) {
    node.setAttribute('target', '_blank');
    node.setAttribute('rel', 'noopener noreferrer nofollow');
  }
  if (node.tagName === 'INPUT') {
    node.setAttribute('type', 'checkbox');
    node.setAttribute('disabled', '');
  }
});

export function renderMarkdownPreview(source: string): string {
  if (source.length > MARKDOWN_PREVIEW_MAX_CHARS) {
    return '<p class="editor-preview-empty">This document is too large to preview here. It will still save and open normally.</p>';
  }
  const html = DOMPurify.sanitize(md.parse(source) as string, SANITIZE_CONFIG);
  return html.trim() || '<p class="editor-preview-empty">Nothing to preview yet.</p>';
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