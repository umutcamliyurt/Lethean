(() => {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const state = { overview: null, tokens: [], shares: [] };


  function el(tag, opts = {}, children = []) {
    const n = document.createElement(tag);
    if (opts.class) n.className = opts.class;
    if (opts.text != null) n.textContent = opts.text;
    if (opts.attrs) for (const [k, v] of Object.entries(opts.attrs)) n.setAttribute(k, v);
    if (opts.on) for (const [k, v] of Object.entries(opts.on)) n.addEventListener(k, v);
    for (const c of [].concat(children)) if (c) n.append(c);
    return n;
  }

  function formatBytes(n) {
    if (n == null) return '—';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let i = 0;
    let v = n;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    const digits = i === 0 || v >= 100 ? 0 : v >= 10 ? 1 : 2;
    return `${v.toFixed(digits)} ${units[i]}`;
  }

  function formatDate(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d)) return '—';
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  }

  function plural(n, word) { return `${n} ${word}${n === 1 ? '' : 's'}`; }

  function toast(message, isError) {
    const t = el('div', { class: 'toast' + (isError ? ' error' : ''), text: message });
    $('toasts').append(t);
    setTimeout(() => t.remove(), 4500);
  }

  class ApiError extends Error {
    constructor(message, status) { super(message); this.status = status; }
  }

  async function api(method, path, body) {
    const headers = { 'X-Admin-Request': '1' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    const res = await fetch('/api' + path, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      credentials: 'same-origin',
    });
    if (res.status === 401 && path !== '/login') showAuth();
    if (!res.ok) {
      let detail = res.statusText || 'Request failed';
      try {
        const data = await res.json();
        if (typeof data.detail === 'string') detail = data.detail;
        else if (Array.isArray(data.detail)) detail = 'Invalid input';
      } catch {  }
      throw new ApiError(detail, res.status);
    }
    if (res.status === 204) return null;
    return res.json();
  }


  function showAuth() {
    $('app-screen').classList.add('hidden');
    closeModal();
    $('auth-screen').classList.remove('hidden');
    $('password').focus();
  }

  function showApp() {
    $('auth-screen').classList.add('hidden');
    $('app-screen').classList.remove('hidden');
  }

  function setStatus(message, { error = false, busy = false } = {}) {
    const s = $('auth-status');
    s.className = 'auth-status' + (error ? ' error' : '');
    s.replaceChildren();
    if (busy) s.append(el('div', { class: 'spinner' }));
    if (message) s.append(el('span', { text: message }));
  }


  function openModal(panel) {
    const lb = $('lightbox');
    lb.replaceChildren(panel);
    lb.classList.remove('hidden');
    const first = panel.querySelector('input:not([readonly]), button');
    if (first) first.focus();
  }

  function closeModal() {
    const lb = $('lightbox');
    lb.classList.add('hidden');
    lb.replaceChildren();
  }

  function field(labelText, input, hint) {
    const id = input.id;
    return el('div', { class: 'field' }, [
      el('label', { text: labelText, attrs: id ? { for: id } : {} }),
      input,
      hint ? el('p', { class: 'field-hint', text: hint }) : null,
    ]);
  }

  function panel(title, subtitle, body, actions) {
    return el('div', { class: 'settings-panel', attrs: { role: 'dialog', 'aria-modal': 'true', 'aria-label': title } }, [
      el('h2', { text: title }),
      subtitle ? el('p', { class: 'subtitle', text: subtitle }) : null,
      ...body,
      actions ? el('div', { class: 'panel-actions' }, actions) : null,
    ]);
  }

  function textInput(id, { value = '', placeholder = '', mode } = {}) {
    const attrs = { type: 'text', id, autocomplete: 'off', spellcheck: 'false', maxlength: '120' };
    if (placeholder) attrs.placeholder = placeholder;
    if (mode) attrs.inputmode = mode;
    const i = el('input', { attrs });
    i.value = value;
    return i;
  }

  function parseQuota(raw) {
    const s = raw.trim();
    if (!s) return { value: null };
    const n = Number(s);
    if (!Number.isFinite(n) || n <= 0) return { error: 'Quota must be a positive number of GB, or blank for the default.' };
    return { value: n };
  }

  async function copyText(text, button) {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      const ta = el('textarea', { attrs: { readonly: '' } });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      document.execCommand('copy');
      ta.remove();
    }
    const old = button.textContent;
    button.textContent = 'Copied';
    setTimeout(() => { button.textContent = old; }, 1400);
  }


  function renderStats() {
    const o = state.overview;
    const box = $('admin-stats');
    box.replaceChildren();
    if (!o) return;
    const tiles = [
      ['Storage used', formatBytes(o.total_bytes), plural(o.file_count, 'file')],
      ['Vaults', String(o.vault_count), 'with at least one file'],
      ['Access tokens', String(o.token_count), `${o.tokens_bound} bound · ${o.tokens_unbound} unused`],
      ['Share links', String(o.active_shares), `${o.expired_shares} expired`],
    ];
    for (const [label, value, sub] of tiles) {
      box.append(el('div', { class: 'admin-stat' }, [
        el('p', { class: 'label', text: label }),
        el('p', { class: 'value', text: value }),
        el('p', { class: 'sub', text: sub }),
      ]));
    }
  }

  function head(cols) {
    return el('div', { class: 'admin-head', attrs: { role: 'row' } },
      cols.map((c) => el('span', { text: c, attrs: { role: 'columnheader' } })));
  }

  function renderTokens() {
    const table = $('tokens-table');
    table.replaceChildren();
    if (!state.tokens.length) {
      table.append(el('div', { class: 'admin-empty', text: 'No access tokens yet. Create one to let someone upload.' }));
      return;
    }
    table.append(head(['Token', 'Status', 'Usage', 'Quota', '']));

    for (const t of state.tokens) {
      const pct = t.quota_bytes > 0 ? Math.min(100, (t.total_bytes / t.quota_bytes) * 100) : 0;
      const fill = el('div', { class: 'admin-bar-fill' + (pct >= 100 ? ' full' : pct >= 85 ? ' high' : '') });
      fill.style.width = pct.toFixed(1) + '%';

      const usageText = t.bound ? `${formatBytes(t.total_bytes)} · ${plural(t.file_count, 'file')}` : '—';
      const statusText = t.bound ? `bound ${t.vault}…` : 'unused';

      const row = el('div', { class: 'admin-row', attrs: { role: 'row' } }, [
        el('div', { class: 'admin-cell' }, [
          el('div', { class: 'admin-title' + (t.label ? '' : ' unlabeled'), text: t.label || '(unlabeled)' }),
          el('div', { class: 'admin-sub', text: 'id ' + t.id }),
          el('div', { class: 'admin-sub only-sm', text: `${statusText} · ${usageText} of ${formatBytes(t.quota_bytes)}` }),
        ]),
        el('div', { class: 'admin-cell col-extra' }, [
          el('span', { class: 'admin-pill' + (t.bound ? ' on' : ''), text: t.bound ? 'Bound' : 'Unused' }),
          t.bound ? el('div', { class: 'admin-sub', text: t.vault + '…' }) : null,
        ]),
        el('div', { class: 'admin-cell col-extra' }, [
          el('div', { class: 'admin-mono', text: usageText }),
          t.bound ? el('div', { class: 'admin-bar' }, fill) : null,
        ]),
        el('div', { class: 'admin-cell col-extra' }, [
          el('div', { class: 'admin-mono', text: formatBytes(t.quota_bytes) }),
          t.custom_quota ? null : el('div', { class: 'admin-sub', text: 'default' }),
        ]),
        el('div', { class: 'admin-actions' }, [
          el('button', { text: 'Edit', attrs: { type: 'button' }, on: { click: () => openEditModal(t) } }),
          el('button', { class: 'btn-danger', text: 'Revoke', attrs: { type: 'button' }, on: { click: () => openRevokeModal(t) } }),
        ]),
      ]);
      table.append(row);
    }
  }

  function renderShares() {
    const table = $('shares-table');
    table.replaceChildren();
    $('shares-label').textContent = `Active share links (${state.shares.length})`;
    const expired = state.overview ? state.overview.expired_shares : 0;
    $('purge-btn').textContent = expired ? `Purge ${expired} expired` : 'Purge expired';

    if (!state.shares.length) {
      table.append(el('div', { class: 'admin-empty', text: 'No active share links.' }));
      return;
    }
    table.append(head(['File', 'Vault', 'Downloads', 'Expires', '']));

    for (const s of state.shares) {
      table.append(el('div', { class: 'admin-row', attrs: { role: 'row' } }, [
        el('div', { class: 'admin-cell' }, [
          el('div', { class: 'admin-title admin-mono', text: s.file + '…' }),
          el('div', { class: 'admin-sub', text: formatBytes(s.size) + (s.deletable ? ' · delete allowed' : '') }),
          el('div', { class: 'admin-sub only-sm', text: `${s.downloads_used}/${s.max_downloads} downloads · expires ${formatDate(s.expires_at)}` }),
        ]),
        el('div', { class: 'admin-cell col-extra admin-mono', text: s.vault + '…' }),
        el('div', { class: 'admin-cell col-extra admin-mono', text: `${s.downloads_used} / ${s.max_downloads}` }),
        el('div', { class: 'admin-cell col-extra admin-mono', text: formatDate(s.expires_at) }),
        el('div', { class: 'admin-actions' }, [
          el('button', { class: 'btn-danger', text: 'Revoke', attrs: { type: 'button' }, on: { click: () => revokeShare(s) } }),
        ]),
      ]));
    }
  }

  function render() {
    renderStats();
    renderTokens();
    renderShares();
  }

  async function refresh() {
    const btn = $('refresh-btn');
    btn.disabled = true;
    try {
      const [overview, tokens, shares] = await Promise.all([
        api('GET', '/overview'), api('GET', '/tokens'), api('GET', '/shares'),
      ]);
      state.overview = overview;
      state.tokens = tokens;
      state.shares = shares;
      render();
    } catch (err) {
      if (err.status !== 401) toast(err.message, true);
    } finally {
      btn.disabled = false;
    }
  }


  function openCreateModal() {
    const defaultGb = state.overview ? +(state.overview.default_quota_bytes / 1024 ** 3).toFixed(2) : 10;
    const label = textInput('new-label', { placeholder: 'e.g. Alex' });
    const quota = textInput('new-quota', { placeholder: `${defaultGb} (default)`, mode: 'decimal' });
    const decoy = el('input', { attrs: { type: 'checkbox', id: 'new-decoy', checked: '' } });
    decoy.checked = true;
    const err = el('p', { class: 'field-hint error' });

    const decoyRow = el('label', { class: 'share-checkbox-row neutral' }, [
      decoy,
      el('span', { class: 'share-checkbox-text' }, [
        el('strong', { text: 'Also create a decoy-vault token' }),
        el('small', { text: 'For the Duress Code panel\'s "Decoy files" section. Same quota as the real token.' }),
      ]),
    ]);

    const submit = el('button', { class: 'btn-primary', text: 'Create', attrs: { type: 'submit' } });
    const form = el('form', {}, [
      field('Label', label, 'A note for you (e.g. a name). Never sent to clients.'),
      field('Quota (GB)', quota, 'Leave blank to use the server default.'),
      decoyRow,
      err,
      el('div', { class: 'panel-actions' }, [
        el('button', { text: 'Cancel', attrs: { type: 'button' }, on: { click: closeModal } }),
        submit,
      ]),
    ]);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const q = parseQuota(quota.value);
      if (q.error) { err.textContent = q.error; return; }
      err.textContent = '';
      submit.disabled = true;
      try {
        const res = await api('POST', '/tokens', { label: label.value, quota_gb: q.value, decoy: decoy.checked });
        showCreated(res);
        refresh();
      } catch (ex) {
        err.textContent = ex.message;
        submit.disabled = false;
      }
    });
    openModal(el('div', { class: 'settings-panel' }, [
      el('h2', { text: 'New access token' }),
      el('p', { class: 'subtitle', text: 'Tokens bind to the first vault that uploads with them.' }),
      form,
    ]));
  }

  function tokenBlock(title, value) {
    const input = el('input', { attrs: { type: 'text', readonly: '', 'aria-label': title } });
    input.value = value;
    input.addEventListener('focus', () => input.select());
    const btn = el('button', { class: 'btn-primary', text: 'Copy', attrs: { type: 'button' } });
    btn.addEventListener('click', () => copyText(value, btn));
    return el('div', { class: 'admin-token-block' }, [
      el('p', { class: 'share-section-label', text: title }),
      el('div', { class: 'share-link-row' }, [input, btn]),
    ]);
  }

  function showCreated(res) {
    const blocks = [tokenBlock('Access token', res.token)];
    if (res.decoy_token) blocks.push(tokenBlock('Decoy vault token', res.decoy_token));
    openModal(panel(
      'Token created',
      'Copy these now. Tokens are hashed at rest, so they can never be shown again.',
      blocks,
      [el('button', { class: 'btn-primary', text: 'Done', attrs: { type: 'button' }, on: { click: closeModal } })],
    ));
  }

  function openEditModal(t) {
    const label = textInput('edit-label', { value: t.label || '' });
    const quota = textInput('edit-quota', {
      value: t.custom_quota ? String(+(t.quota_bytes / 1024 ** 3).toFixed(3)) : '',
      placeholder: `${+(t.quota_bytes / 1024 ** 3).toFixed(2)} (default)`,
      mode: 'decimal',
    });
    const err = el('p', { class: 'field-hint error' });
    const submit = el('button', { class: 'btn-primary', text: 'Save', attrs: { type: 'submit' } });
    const form = el('form', {}, [
      field('Label', label),
      field('Quota (GB)', quota, 'Leave blank to use the server default.'),
      err,
      el('div', { class: 'panel-actions' }, [
        el('button', { text: 'Cancel', attrs: { type: 'button' }, on: { click: closeModal } }),
        submit,
      ]),
    ]);
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const q = parseQuota(quota.value);
      if (q.error) { err.textContent = q.error; return; }
      submit.disabled = true;
      try {
        await api('PATCH', '/tokens/' + t.id, { label: label.value, quota_gb: q.value });
        closeModal();
        toast('Token updated');
        refresh();
      } catch (ex) {
        err.textContent = ex.message;
        submit.disabled = false;
      }
    });
    openModal(el('div', { class: 'settings-panel' }, [
      el('h2', { text: 'Edit token' }),
      el('p', { class: 'subtitle', text: 'id ' + t.id }),
      form,
    ]));
  }

  function openRevokeModal(t) {
    const confirm = el('button', { class: 'btn-danger', text: 'Revoke token', attrs: { type: 'button' } });
    confirm.addEventListener('click', async () => {
      confirm.disabled = true;
      try {
        await api('DELETE', '/tokens/' + t.id);
        closeModal();
        toast('Token revoked');
        refresh();
      } catch (ex) {
        toast(ex.message, true);
        confirm.disabled = false;
      }
    });
    openModal(panel(
      'Revoke token?',
      `${t.label || '(unlabeled)'} (${t.id}). Uploads and vault rotation with this token will stop working. ` +
        'Files already stored are not deleted, and anyone holding the vault ID can still read them.',
      [],
      [el('button', { text: 'Cancel', attrs: { type: 'button' }, on: { click: closeModal } }), confirm],
    ));
  }

  async function revokeShare(s) {
    try {
      await api('DELETE', '/shares/' + s.id);
      toast('Share link revoked');
      refresh();
    } catch (ex) {
      toast(ex.message, true);
    }
  }

  async function purgeExpired() {
    const btn = $('purge-btn');
    btn.disabled = true;
    try {
      const res = await api('POST', '/shares/purge-expired');
      toast(`Purged ${plural(res.removed, 'expired link')}`);
      refresh();
    } catch (ex) {
      toast(ex.message, true);
    } finally {
      btn.disabled = false;
    }
  }


  $('auth-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const submit = $('auth-submit');
    submit.disabled = true;
    setStatus('Signing in…', { busy: true });
    try {
      await api('POST', '/login', { password: $('password').value });
      $('password').value = '';
      setStatus('');
      showApp();
      refresh();
    } catch (ex) {
      setStatus(ex.message, { error: true });
    } finally {
      submit.disabled = false;
    }
  });

  $('logout-btn').addEventListener('click', async () => {
    try { await api('POST', '/logout'); } catch {  }
    state.overview = null; state.tokens = []; state.shares = [];
    showAuth();
  });

  $('refresh-btn').addEventListener('click', refresh);
  $('new-token-btn').addEventListener('click', openCreateModal);
  $('purge-btn').addEventListener('click', purgeExpired);

  $('lightbox').addEventListener('mousedown', (e) => {
    if (e.target === $('lightbox')) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('lightbox').classList.contains('hidden')) closeModal();
  });

  (async function boot() {
    try {
      await api('GET', '/session');
      showApp();
      refresh();
    } catch {
      showAuth();
    }
  })();
})();
