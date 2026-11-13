'use strict';
(() => {
  const $ = (id) => document.getElementById(id);
  const { t, message } = language;
  const LEVELS = {
    malicious: ['Bösartig', 'Malicious'], suspicious: ['Verdächtig', 'Suspicious'], no_finding: ['Kein Befund', 'No finding'],
    unchecked: ['Nicht geprüft', 'Unchecked'], internal: ['Intern', 'Internal'], pending: ['Läuft', 'Running'],
  };
  const VERDICTS = {
    malicious: ['Bösartig', 'Malicious'], suspicious: ['Verdächtig', 'Suspicious'], weak: ['Schwacher Hinweis', 'Weak signal'],
    clean: ['Unauffällig', 'Clean'], info: ['Bekannt', 'Known'], not_found: ['Nicht bekannt', 'Unknown'],
  };
  const STATES = {
    pending: ['Prüft …', 'Checking …'], waiting: ['Wartet auf Limit', 'Waiting for quota'], error: ['Fehler', 'Error'], no_key: ['Kein API-Key', 'No API key'],
    limit: ['Limit erreicht', 'Rate limit reached'], skipped: ['Abgebrochen', 'Cancelled'],
  };
  const TYPES = { ipv4: 'IPv4', ipv6: 'IPv6', domain: 'Domain', url: 'URL', md5: 'MD5', sha1: 'SHA-1', sha256: 'SHA-256' };

  let meta = null;
  let job = null;
  let jobId = null;
  let timer = null;
  const rows = new Map();
  const fileNames = new Map(); // SHA-256 -> Dateinamen, bleiben im Browser
  let hashing = null;

  function label(labels, key) {
    return Object.hasOwn(labels, key) ? t(...labels[key]) : '';
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  async function api(path, method = 'GET', body) {
    const opt = { method, headers: {} };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.body = JSON.stringify(body);
    }
    const res = await fetch('api/' + path, opt);
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || 'Der Dienst hat nicht wie erwartet geantwortet');
      err.status = res.status;
      err.code = data.error_code;
      throw err;
    }
    return data;
  }

  async function init() {
    try {
      meta = await api('meta');
    } catch (e) {
      showError(e.message, e.code);
      $('app').hidden = false;
      return;
    }
    const needLogin = meta.auth_required && !meta.authenticated;
    $('login').hidden = !needLogin;
    $('app').hidden = needLogin;
    if (needLogin) {
      const setup = !!meta.setup_required;
      $('setupFields').hidden = !setup;
      $('setupLabel').hidden = !setup;
      $('loginTitle').hidden = setup;
      $('signInLabel').hidden = setup;
      $('setupCode').required = setup;
      $('password').autocomplete = setup ? 'new-password' : 'current-password';
      $('password').minLength = setup ? 12 : 0;
      $(setup ? 'setupCode' : 'password').focus();
      return;
    }
    applyMeta();
    $('input').focus();
  }

  function applyMeta() {
    $('logoutBtn').hidden = !meta.auth_required;
    $('sourcesBtn').hidden = false;
    $('maxItems').textContent = meta.max_indicators;
    const active = meta.sources.filter((s) => s.configured).length;
    $('sourcesCount').textContent = `${active}/${meta.sources.length}`;

  }

  // --- Prüfung -----------------------------------------------------------

  async function start() {
    const input = $('input').value.trim();
    showError('');
    if (!input) { showError('Bitte mindestens einen Wert eingeben.'); $('input').focus(); return; }
    setRunning(true);
    try {
      const first = await api('check', 'POST', { input, fresh: $('fresh').checked });
      rows.clear();
      $('items').replaceChildren();
      jobId = first.id;
      render(first);
      poll();
    } catch (e) {
      setRunning(false);
      handleError(e);
    }
  }

  async function poll() {
    if (!job || job.finished) { setRunning(false); refreshMeta(); return; }
    timer = setTimeout(async () => {
      try {
        render(await api('jobs/' + jobId));
        poll();
      } catch (e) {
        setRunning(false);
        handleError(e);
      }
    }, 800);
  }

  async function refreshMeta() {
    try { meta = await api('meta'); } catch { /* Anzeige bleibt beim letzten Stand */ }
  }

  async function cancel() {
    if (jobId) await api('jobs/' + jobId, 'DELETE').catch(() => {});
  }

  function handleError(e) {
    if (e.status === 401) { location.reload(); return; }
    showError(e.message, e.code);
  }

  function setRunning(on) {
    $('checkBtn').disabled = on;
    $('fileBtn').disabled = on;
    $('checkBtn').textContent = on ? t('Prüfung läuft …', 'Checking …') : t('Prüfen', 'Check');
    $('cancelBtn').hidden = !on;
    $('progress').hidden = !on;
  }

  function showError(msg, code) {
    setMessage($('formError'), msg, code);
    $('formError').hidden = !msg;
  }

  // --- Darstellung -------------------------------------------------------

  function render(view) {
    job = view;
    const has = view.items.length > 0;
    $('empty').hidden = has || view.unknown.length > 0;
    $('exportBar').hidden = !has;
    $('progressBar').style.width = view.total ? `${Math.round(view.done / view.total * 100)}%` : '100%';
    renderSummary(view);
    renderNotices(view);
    view.items.forEach((item, i) => renderItem(item, i));
  }

  function renderSummary(view) {
    const box = $('summary');
    box.hidden = view.items.length === 0;
    const count = (l) => view.items.filter((i) => i.assessment.level === l).length;
    const parts = [[count('malicious'), t('bösartig', 'malicious')], [count('suspicious'), t('verdächtig', 'suspicious')], [count('no_finding'), t('ohne Befund', 'without findings')],
      [count('unchecked'), t('nicht geprüft', 'unchecked')], [count('internal'), t('intern', 'internal')]].filter(([n]) => n > 0);
    box.replaceChildren(document.createTextNode(`${view.items.length} ${view.items.length === 1 ? t('Wert', 'indicator') : t('Werte', 'indicators')}: `));
    parts.forEach(([n, label], i) => {
      if (i) box.append(' · ');
      box.append(el('b', '', String(n)), ` ${label}`);
    });
    if (!view.finished) {
      const waiting = view.items.some((it) => it.results.some((r) => r.status === 'waiting'));
      box.append(` · ${view.done} ${t('von', 'of')} ${view.total} ${t('Abfragen', 'lookups')}${waiting ? t(', einige warten auf das Limit', ', some are waiting for quota') : ''}`);
    } else if (view.cancelled) {
      box.append(t(' · abgebrochen', ' · cancelled'));
    }
  }

  function renderNotices(view) {
    const box = $('notices');
    box.replaceChildren();
    if (view.unknown.length) box.append(el('p', 'notice', `${t('Nicht erkannt und übersprungen', 'Unrecognized and skipped')}: ${view.unknown.join(', ')}`));
    if (view.truncated) box.append(el('p', 'notice', `${view.truncated} ${t('Werte über dem Limit wurden nicht geprüft.', 'indicators exceeded the limit and were skipped.')}`));
    if (view.items.length && view.items.every((i) => i.results.every((r) => r.status === 'no_key') && !i.indicator.internal)) {
      box.append(el('p', 'notice', t('Für diese Werte ist keine Quelle eingerichtet. Trage unter „Quellen“ API-Keys ein.', 'No source is configured for these indicators. Add API keys under “Sources”.')));
    }
  }

  function renderItem(item, i) {
    let row = rows.get(i);
    if (!row) {
      row = buildRow(i);
      rows.set(i, row);
      $('items').append(row.root);
    }
    const a = item.assessment;
    row.root.dataset.level = a.level;
    row.type.textContent = TYPES[item.indicator.type] || item.indicator.type;
    row.value.textContent = item.indicator.defanged;
    row.badge.dataset.level = a.level;
    row.badge.textContent = label(LEVELS, a.level) + (a.confidence ? ` · ${message(a.confidence)}` : '');
    row.meta.textContent = metaLine(item);
    if (row.root.open) fillBody(row, item);
  }

  function fileLabel(item) {
    return (fileNames.get(item.indicator.value) || []).join(', ');
  }

  function metaLine(item) {
    const a = item.assessment;
    if (a.level === 'internal') return t('Nicht übertragen', 'Never transmitted');
    const name = fileLabel(item);
    const left = `${name ? `${name} · ` : ''}${a.answered} ${t('von', 'of')} ${a.total} ${t('Quellen geantwortet', 'sources responded')}`;
    return a.hits ? `${left}, ${a.hits} ${t('mit Treffer', 'with hits')}` : left;
  }

  function buildRow(i) {
    const root = el('details', 'item');
    const sum = el('summary');
    const type = el('span', 'item-type');
    const value = el('span', 'item-value');
    const badge = el('span', 'badge');
    const metaEl = el('span', 'item-meta');
    sum.append(type, value, badge, metaEl);
    const body = el('div', 'item-body');
    root.append(sum, body);
    const row = { root, type, value, badge, meta: metaEl, body, sig: '' };
    root.addEventListener('toggle', () => {
      if (root.open) fillBody(row, job.items[i]);
    });
    return row;
  }

  function fillBody(row, item) {
    const sig = language.current + JSON.stringify(item);
    if (sig === row.sig) return;
    row.sig = sig;
    const a = item.assessment;
    const nodes = [el('p', 'action', message(a.action, a.action_code))];
    if (a.reasons.length) {
      const list = el('ul', 'reasons');
      a.reasons.forEach((r) => list.append(el('li', '', reasonText(r, item))));
      nodes.push(list);
    }
    (item.indicator.notes || []).forEach((n) => nodes.push(el('p', 'item-notes', message(n))));
    if (item.results.length) nodes.push(sourceTable(item.results));
    if (!item.indicator.internal) nodes.push(externalLinks(item.indicator));
    if (navigator.clipboard) {
      const actions = el('div', 'copy-row');
      actions.append(copyButton(t('Wert kopieren', 'Copy value'), item.indicator.value), copyButton(t('Entschärft kopieren', 'Copy defanged value'), item.indicator.defanged));
      nodes.push(actions);
    }
    row.body.replaceChildren(...nodes);
  }

  // --- Weiter analysieren -------------------------------------------------

  // Feldnamen der Suchsprache von ANY.RUN TI Lookup
  const ANYRUN_FIELDS = { url: 'url', domain: 'domainName', ipv4: 'destinationIP', ipv6: 'destinationIP', md5: 'md5', sha1: 'sha1', sha256: 'sha256' };

  // Die Links öffnen nur die Seite des Dienstes. Der Wert wird zusätzlich
  // kopiert, falls die Seite ihn nicht selbst übernimmt. Interne Werte
  // bekommen keine Links, damit sie nicht versehentlich hinausgehen.
  function externalLinks(ind) {
    const box = el('div', 'external');
    box.append(el('p', 'hint small', t('Weiter analysieren: öffnet den Dienst und kopiert den Wert. Gratis-Analysen sind dort öffentlich, also keine vertraulichen Inhalte einreichen.', 'Investigate further: opens the service and copies the value. Free analyses are public, so avoid submitting confidential data.')));
    const row = el('div', 'copy-row');
    const field = ANYRUN_FIELDS[ind.type];
    if (field) {
      const lookup = JSON.stringify({ query: `${field}:"${ind.value}"`, dateRange: 180 });
      row.append(externalLink('ANY.RUN TI Lookup', 'https://intelligence.any.run/analysis/lookup#' + encodeURIComponent(lookup), ind.value));
    }
    // Format von dir getestet: die URL oder Domain wird unverändert angehängt
    if (ind.type === 'url' || ind.type === 'domain') row.append(externalLink('ANY.RUN Safebrowsing', 'https://app.any.run/safe/' + ind.value, ind.value));
    row.append(externalLink('Joe Sandbox', 'https://www.joesandbox.com/', ind.value));
    box.append(row);
    return box;
  }

  function externalLink(label, href, value) {
    const a = el('a', 'btn ghost', `${label} ↗`);
    a.href = href;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.addEventListener('click', () => {
      if (navigator.clipboard) navigator.clipboard.writeText(value).catch(() => {});
    });
    return a;
  }

  function copyButton(label, text) {
    const b = el('button', 'btn ghost', label);
    b.type = 'button';
    b.addEventListener('click', async () => {
      await navigator.clipboard.writeText(text);
      b.textContent = t('Kopiert', 'Copied');
      setTimeout(() => { b.textContent = label; }, 1200);
    });
    return b;
  }

  function sourceTable(results) {
    const table = el('table', 'src-table');
    const body = el('tbody');
    results.forEach((r) => {
      const tr = el('tr');
      const name = el('td', 'src-name', r.name);
      const state = el('td', 'src-state');
      if (r.status === 'ok') {
        const b = el('span', 'badge', label(VERDICTS, r.verdict) || r.verdict);
        b.dataset.v = r.verdict;
        state.append(b);
      } else {
        state.append(el('span', 'badge', label(STATES, r.status) || r.status));
      }
      const detail = el('td', 'src-detail');
      if (r.error) detail.append(el('div', 'line', message(r.error)));
      if (r.summary) detail.append(el('div', 'line', message(r.summary) + (r.cached ? t(' (aus Zwischenspeicher)', ' (cached)') : '')));
      (r.details || []).forEach((d) => {
        const kv = el('div', 'kv');
        kv.append(el('b', '', `${message(d.k)}: `), d.v);
        detail.append(kv);
      });
      if (r.tags && r.tags.length) {
        const tags = el('div', 'tags');
        r.tags.forEach((t) => tags.append(el('span', 'tag', t)));
        detail.append(tags);
      }
      if (isSafeLink(r.link)) {
        const a = el('a', '', t('Bericht öffnen', 'Open report'));
        a.href = r.link;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        detail.append(a);
      }
      tr.append(name, state, detail);
      body.append(tr);
    });
    table.append(body);
    return table;
  }

  function isSafeLink(link) {
    if (!link) return false;
    try { return new URL(link).protocol === 'https:'; } catch { return false; }
  }

  // --- Dateien -----------------------------------------------------------

  const CHUNK = 4 * 1024 * 1024;

  async function hashFile(file, state, onProgress) {
    const sha = new Sha256();
    for (let pos = 0; pos < file.size; pos += CHUNK) {
      if (state.cancelled) return null;
      sha.update(new Uint8Array(await file.slice(pos, pos + CHUNK).arrayBuffer()));
      onProgress(Math.min(pos + CHUNK, file.size) / file.size);
    }
    return sha.digestHex();
  }

  function formatSize(n) {
    if (n < 1024 * 1024) return `${Math.max(1, Math.round(n / 1024))} KB`;
    if (n < 1024 ** 3) return `${(n / 1024 ** 2).toLocaleString(language.current, { minimumFractionDigits: 1, maximumFractionDigits: 1 })} MB`;
    return `${(n / 1024 ** 3).toLocaleString(language.current, { minimumFractionDigits: 1, maximumFractionDigits: 1 })} GB`;
  }

  async function hashFiles(files) {
    if (hashing || !files.length || !$('cancelBtn').hidden) return;
    const state = { cancelled: false };
    hashing = state;
    const status = $('fileStatus');
    status.hidden = false;
    showError('');
    $('fileBtn').disabled = true;
    $('checkBtn').disabled = true;
    $('cancelBtn').hidden = false;
    const hashes = [];
    const failed = [];
    for (const [i, file] of files.entries()) {
      const prefix = files.length > 1 ? `${i + 1}/${files.length}: ` : '';
      try {
        const hash = await hashFile(file, state, (p) => {
          status.textContent = `${prefix}${t('Hash von', 'Hashing')} ${file.name} (${formatSize(file.size)}): ${Math.round(p * 100)} %`;
        });
        if (hash === null) break;
        hashes.push(hash);
        const names = fileNames.get(hash) || [];
        if (!names.includes(file.name)) fileNames.set(hash, [...names, file.name]);
      } catch {
        failed.push(file.name); // z. B. Ordner oder vom Virenscanner gesperrte Datei
      }
    }
    hashing = null;
    $('fileBtn').disabled = false;
    $('checkBtn').disabled = false;
    $('cancelBtn').hidden = true;
    $('fileInput').value = '';
    status.hidden = true;
    if (failed.length) showError(`Nicht lesbar: ${failed.join(', ')}`);
    if (state.cancelled || !hashes.length) return;
    const box = $('input');
    const known = box.value.split(/\s+/);
    const fresh = hashes.filter((h, i) => hashes.indexOf(h) === i && !known.includes(h));
    box.value = [box.value.trim(), ...fresh].filter(Boolean).join('\n');
    const error = $('formError').dataset.message;
    await start();
    if (error && !$('formError').textContent) showError(error);
  }

  // --- Quellen -----------------------------------------------------------

  let keyBusy = false; // nur eine Key-Änderung zur Zeit

  function renderSources() {
    const box = $('sourcesList');
    box.replaceChildren();
    const shown = new Set();
    meta.sources.forEach((s) => {
      const row = el('div', 'source-row');
      const top = el('div', 'source-top');
      top.append(el('span', 'source-name', s.name));
      const state = el('span', 'badge', s.configured ? t('Aktiv', 'Active') : label(STATES, 'no_key'));
      if (s.configured) state.dataset.v = 'clean';
      top.append(state);
      row.append(top);
      const limits = [];
      if (s.limit.per_minute) limits.push(`${s.limit.per_minute}/${t('Minute', 'minute')}`);
      if (s.limit.per_day) limits.push(`${s.limit.per_day}/${t('Tag', 'day')}, ${s.used_today} ${t('heute genutzt', 'used today')}`);
      row.append(el('span', 'hint small', [message(s.license), limits.join(', ')].filter(Boolean).join('. ')));
      if (s.signup && isSafeLink(s.signup)) {
        const a = el('a', 'small', s.key_name ? t('API-Key holen', 'Get API key') : 'Website');
        a.href = s.signup; a.target = '_blank'; a.rel = 'noopener noreferrer';
        row.append(a);
      }
      if (meta.editable && s.key_name && !shown.has(s.key_name)) {
        shown.add(s.key_name);
        const names = meta.sources.filter(src => src.key_name === s.key_name).map(src => src.name).join(', ');
        const form = el('form');
        const input = el('input');
        input.type = 'password';
        input.required = true;
        input.maxLength = 4096;
        input.autocomplete = 'off';
        const caption = el('label', '', t('Neuer API-Key für ', 'New API key for ') + names);
        caption.append(input);
        const save = el('button', 'btn', t('Testen und speichern', 'Test and save'));
        form.append(caption, save);
        const send = async (value, done) => {
          if (keyBusy) return;
          keyBusy = true;
          box.querySelectorAll('button').forEach(b => { b.disabled = true; });
          $('keyStatus').textContent = value ? t('Key wird beim Dienst getestet …', 'Testing key with the service …') : '';
          try {
            await api('key', 'PUT', { name: s.key_name, value });
            input.value = '';
            meta = await api('meta');
            applyMeta();
            renderSources();
            $('keyStatus').textContent = names + done;
          } catch (error) {
            if (error.status === 401) { location.reload(); return; }
            $('keyStatus').textContent = names + ': ' + message(error.message, error.code);
          } finally {
            keyBusy = false;
            box.querySelectorAll('button').forEach(b => { b.disabled = false; });
          }
        };
        form.addEventListener('submit', event => {
          event.preventDefault();
          send(input.value, t(': geprüft und gespeichert', ': tested and saved'));
        });
        row.append(form);
        if ((meta.web_keys || []).includes(s.key_name)) {
          const remove = el('button', 'btn ghost small', t('Web-Key entfernen', 'Remove web key'));
          remove.type = 'button';
          remove.title = t('Danach gilt wieder der Key aus der .env, falls vorhanden', 'The key from .env applies again, if set');
          remove.addEventListener('click', () => {
            if (confirm(t('Web-Key für ', 'Remove web key for ') + names + '?')) send('', t(': Web-Key entfernt', ': web key removed'));
          });
          row.append(remove);
        }
      }
      box.append(row);
    });
  }

  // --- Export ------------------------------------------------------------

  // Tabellenprogramme führen Zellen mit diesen Zeichen als Formel aus.
  function csvCell(v) {
    let s = String(v ?? '');
    if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
    return '"' + s.replace(/"/g, '""') + '"';
  }

  function exportCSV() {
    const lines = [[t('Typ', 'Type'), t('Wert (entschärft)', 'Defanged value'), t('Datei', 'File'), t('Einstufung', 'Assessment'), t('Konfidenz', 'Confidence'), t('Empfehlung', 'Recommendation'), t('Quelle', 'Source'), 'Status', t('Quellen-Ergebnis', 'Source verdict'), t('Zusammenfassung', 'Summary'), t('Bericht', 'Report')]];
    job.items.forEach((it) => {
      const a = it.assessment;
      const base = [it.indicator.type, it.indicator.defanged, fileLabel(it), label(LEVELS, a.level), message(a.confidence) || '', message(a.action, a.action_code)];
      if (!it.results.length) lines.push([...base, '', '', '', '', '']);
      it.results.forEach((r) => lines.push([...base, r.name, label(STATES, r.status) || 'OK', label(VERDICTS, r.verdict) || '', message(r.summary || r.error) || '', r.link || '']));
    });
    return '﻿' + lines.map((l) => l.map(csvCell).join(';')).join('\r\n');
  }

  function exportMD() {
    const out = [`# OSINT-Check ${t('Bericht', 'report')}`, '', `${t('Erstellt', 'Created')}: ${new Date().toLocaleString(language.current)}`, ''];
    job.items.forEach((it) => {
      const a = it.assessment;
      const name = fileLabel(it);
      out.push(`## \`${it.indicator.defanged}\``, '', ...(name ? [`- **${t('Datei', 'File')}:** ${name}`] : []), `- **${t('Typ', 'Type')}:** ${TYPES[it.indicator.type]}`, `- **${t('Einstufung', 'Assessment')}:** ${label(LEVELS, a.level)}${a.confidence ? ` (${t('Konfidenz', 'confidence')} ${message(a.confidence)})` : ''}`, `- **${t('Empfehlung', 'Recommendation')}:** ${message(a.action, a.action_code)}`);
      a.reasons.forEach((r) => out.push(`- ${reasonText(r, it)}`));
      if (it.results.length) {
        out.push('', t('| Quelle | Ergebnis | Details |', '| Source | Result | Details |'), '|---|---|---|');
        const esc = (s) => String(s || '').replace(/\|/g, '\\|').replace(/\n/g, ' ');
        it.results.forEach((r) => out.push(`| ${esc(r.name)} | ${esc(label(VERDICTS, r.verdict) || label(STATES, r.status))} | ${esc(message(r.summary || r.error))} |`));
      }
      out.push('');
    });
    return out.join('\n');
  }

  function download(format) {
    if (!job) return;
    const stamp = new Date().toISOString().slice(0, 16).replace(/[:T]/g, '-');
    const files = {
      csv: [exportCSV(), 'text/csv', 'csv'],
      json: [JSON.stringify({ ...job, files: Object.fromEntries(fileNames) }, null, 2), 'application/json', 'json'],
      md: [exportMD(), 'text/markdown', 'md'],
    };
    const [content, type, ext] = files[format];
    const url = URL.createObjectURL(new Blob([content], { type }));
    const a = el('a');
    a.href = url;
    a.download = `osint-check-${stamp}.${ext}`;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }

  // --- Ereignisse --------------------------------------------------------

  $('checkBtn').addEventListener('click', start);
  $('cancelBtn').addEventListener('click', () => {
    if (hashing) hashing.cancelled = true;
    else cancel();
  });
  $('fileBtn').addEventListener('click', () => $('fileInput').click());
  $('fileInput').addEventListener('change', (e) => hashFiles([...e.target.files]));
  const dropZone = document.querySelector('.input-panel');
  ['dragenter', 'dragover'].forEach((type) => document.addEventListener(type, (e) => {
    e.preventDefault(); // sonst öffnet der Browser die Datei und verlässt die Seite
    if (e.dataTransfer && [...e.dataTransfer.types].includes('Files')) dropZone.classList.add('dragging');
  }));
  document.addEventListener('dragleave', (e) => {
    if (!e.relatedTarget) dropZone.classList.remove('dragging');
  });
  document.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragging');
    hashFiles([...e.dataTransfer.files]);
  });
  $('input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && !$('checkBtn').disabled) start();
  });
  $('sourcesBtn').addEventListener('click', async () => {
    await refreshMeta();
    renderSources();
    $('sourcesDialog').showModal();
  });
  $('exportBar').addEventListener('click', (e) => {
    const f = e.target.closest('[data-export]')?.dataset.export;
    if (f) download(f);
  });
  $('logoutBtn').addEventListener('click', async () => {
    await api('logout', 'POST').catch(() => {});
    location.reload();
  });
  $('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      if (meta.setup_required) {
        await api('setup', 'POST', { code: $('setupCode').value.trim(), password: $('password').value });
        meta.setup_required = false;
        $('setupCode').value = '';
      }
      await api('login', 'POST', { password: $('password').value });
      location.reload();
    } catch (err) {
      setMessage($('loginError'), err.message, err.code);
      $('loginError').hidden = false;
    }
  });

  function reasonText(reason, item) {
    for (const result of item.results) {
      if (reason === result.name + ': ' + result.summary) {
        return result.name + ': ' + message(result.summary);
      }
    }
    return message(reason);
  }

  function setMessage(node, value, code = '') {
    node.dataset.message = value;
    node.dataset.code = code;
    node.textContent = message(value, code);
  }

  language.bind(() => {
    $('checkBtn').textContent = !$('cancelBtn').hidden && !hashing
      ? t('Prüfung läuft …', 'Checking …') : t('Prüfen', 'Check');
    document.querySelectorAll('[data-message]').forEach(node => {
      node.textContent = message(node.dataset.message, node.dataset.code);
    });
    if (job) render(job);
  });
  init();
})();
