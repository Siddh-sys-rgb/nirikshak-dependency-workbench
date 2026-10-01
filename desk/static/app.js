'use strict';
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];
const escape = (value) => String(value ?? '').replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const state = { csrf:'', scans:[], selected:null, routeVersion:0, busy:false };
const date = (value) => value ? new Intl.DateTimeFormat('en-IN', {day:'numeric',month:'short',year:'numeric',hour:'2-digit',minute:'2-digit',timeZoneName:'short'}).format(new Date(value)) : 'Not retrieved';
const baseline = 'Jinja2==3.1.4\nrequests==2.32.4';
const update = 'Jinja2==3.1.6\nrequests==2.19.1';

async function api(path, options={}) {
  const response = await fetch(path, {...options, headers:{ ...(options.body ? {'Content-Type':'application/json','X-CSRF-Token':state.csrf} : {}), ...options.headers }});
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || 'The request could not be completed.');
  return data;
}

function toast(message) {
  $('#toast').textContent = message;
  $('#toast').hidden = false;
  window.clearTimeout(state.toastTimer);
  state.toastTimer = window.setTimeout(() => { $('#toast').hidden = true; }, 5000);
}

function metric(value, label, tone='') {
  return `<div class="metric ${tone}"><strong>${escape(value)}</strong><span>${escape(label)}</span></div>`;
}

function evidence(finding) {
  const severity = finding.severity;
  const tone = ['HIGH','CRITICAL'].includes(severity) ? 'red' : severity === 'UNKNOWN' ? 'gray' : 'amber';
  return `<details class="finding"><summary><span class="finding-title"><strong>${escape(finding.summary)}</strong><small>${escape(finding.key)} · ${finding.ids.length} source record${finding.ids.length===1?'':'s'}</small></span><span class="finding-right"><span class="pill ${tone}">${escape(severity)}</span><span class="finding-arrow" aria-hidden="true">›</span></span></summary><div class="finding-detail"><p>${escape(finding.details || 'The available record does not include a description. Follow the source link for more information.')}</p><div class="markers">Upstream fixed-version markers: ${escape(finding.fixed_markers.join(', ') || 'Not provided')}<br>These are advisory metadata; upgrade compatibility has not been tested.</div><div class="evidence-links"><a href="${escape(finding.evidence_url)}" target="_blank" rel="noopener noreferrer">Original OSV record ↗</a>${finding.references.slice(0,3).map((url,i)=>`<a href="${escape(url)}" target="_blank" rel="noopener noreferrer">Reference ${i+1} ↗</a>`).join('')}</div></div></details>`;
}

function packageCard(pkg) {
  const checked = pkg.state === 'complete';
  const label = checked ? (pkg.findings.length ? `${pkg.findings.length} finding${pkg.findings.length===1?'':'s'}` : 'No known findings') : pkg.state === 'unverified' ? 'Unverified' : pkg.state === 'partial' ? 'Partial evidence' : 'Lookup failed';
  const tone = checked ? (pkg.findings.length ? 'red' : 'teal') : 'amber';
  const age = pkg.freshness === 'stale' ? ' · stale (>24h)' : pkg.freshness === 'unknown' ? ' · freshness unknown' : '';
  return `<article class="package-card"><div class="package-head"><div class="package-name"><span class="package-icon" aria-hidden="true">◇</span><span><strong>${escape(pkg.name)} <span class="version">${escape(pkg.version)}</span></strong><small>PyPI · manifest line ${pkg.line}</small></span></div><div class="package-state"><span class="pill ${tone}">${label}</span><span class="pill gray">${checked?'Checked':'Not fully checked'}</span></div></div>${pkg.findings.map(evidence).join('')}${!checked || !pkg.findings.length ? `<div class="empty-package">${escape(pkg.reason || 'No known matching advisories in this exact-version snapshot. This is not a guarantee of security.')}</div>` : ''}<div class="package-source"><span>${escape(pkg.source)}</span><span>Retrieved ${escape(date(pkg.retrieved_at))}${escape(age)}</span></div></article>`;
}

function renderReport(report) {
  state.selected = report.id;
  renderScanList();
  $('#report-name').textContent = report.name;
  $('#export-link').hidden = false;
  $('#report-meta').innerHTML = `<span class="pill">${report.mode==='offline'?'Offline cache':'Live OSV lookup'}</span><span>Saved ${escape(date(report.created_at))}</span><span>Immutable snapshot</span>`;
  $('#export-link').href = `/api/scans/${encodeURIComponent(report.id)}/export`;
  const sum = report.summary;
  $('#metrics').innerHTML = metric(sum.findings,'Advisory families','red') + metric(sum.checked,'Packages checked') + metric(sum.unchecked,'Packages unchecked') + metric(sum.unsupported,'Unsupported lines');
  const coverage = $('#coverage-note');
  coverage.classList.toggle('warning', !sum.complete);
  coverage.textContent = sum.complete ? `All ${sum.packages} submitted pins have complete lookup evidence. Retrieval dates below determine freshness; this is not a security certification.` : `Coverage gap: ${sum.unchecked} package lookup(s) incomplete and ${sum.unsupported} unsupported line(s). An absence of findings cannot be treated as a clean manifest.`;
  $('#packages').innerHTML = report.packages.length ? report.packages.map(packageCard).join('') : '<p class="empty">No supported exact-version pins could be checked.</p>';
  $('#unsupported').hidden = !report.unsupported.length;
  $('#unsupported').innerHTML = `<h2>Unsupported manifest lines</h2><p>These inputs were not executed, followed, installed or evaluated.</p>${report.unsupported.map(line=>`<p><strong>Line ${line.line} · ${escape(line.reason)}</strong><code>${escape(line.text)}</code></p>`).join('')}`;
}

function renderScanList() {
  $('#scan-list').innerHTML = state.scans.length ? state.scans.map(scan=>`<a class="scan-item ${scan.id===state.selected?'selected':''}" href="#scan/${encodeURIComponent(scan.id)}"><strong>${escape(scan.name)}</strong><small>${escape(date(scan.created_at))}</small><span class="scan-tag">${scan.summary.findings} families · ${scan.summary.checked}/${scan.summary.packages} checked</span></a>`).join('') : '<p class="empty">No saved scans. Create your first review.</p>';
  const before = $('#before').value, after = $('#after').value;
  const options = state.scans.map(scan=>`<option value="${escape(scan.id)}">${escape(scan.name)}</option>`).join('');
  $('#before').innerHTML = options;
  $('#after').innerHTML = options;
  $('#before').value = state.scans.some(s=>s.id===before) ? before : state.scans.some(s=>s.id==='demo-baseline') ? 'demo-baseline' : state.scans.at(-1)?.id || '';
  $('#after').value = state.scans.some(s=>s.id===after) ? after : state.scans.some(s=>s.id==='demo-update') ? 'demo-update' : state.scans[0]?.id || '';
}

async function refreshScans() {
  const result = await api('/api/scans');
  state.scans = result.scans;
  renderScanList();
}

function changeCard(finding, label, tone) {
  return `<article class="comparison-card"><span class="pill ${tone}">${label}</span><span class="package-code">${escape(finding.package)} / ${escape(finding.key)}</span><p>${escape(finding.summary)}</p><a href="${escape(finding.evidence_url)}" target="_blank" rel="noopener noreferrer">Review evidence ↗</a></article>`;
}

async function showComparison() {
  if (!$('#before').value || !$('#after').value) {
    $('#comparison-output').innerHTML = '<p class="empty">Save at least one scan to compare snapshots.</p>';
    return;
  }
  const expected = state.routeVersion;
  const before = $('#before').value, after = $('#after').value;
  $('#comparison-output').innerHTML = '<p class="empty">Loading comparison evidence…</p>';
  const data = await api(`/api/compare?before=${encodeURIComponent(before)}&after=${encodeURIComponent(after)}`);
  if (expected !== state.routeVersion || before !== $('#before').value || after !== $('#after').value) return;
  const covered = data.coverage;
  const incomplete = covered.unverified_packages.length || covered.unsupported_before || covered.unsupported_after;
  $('#comparison-output').innerHTML = `<div class="metrics comparison-metrics">${metric(data.new.length,'New families','red')}${metric(data.resolved.length,'Resolved families','teal')}${metric(data.unchanged.length,'Unchanged families')}</div><div class="coverage-note ${incomplete?'warning':''}">Compared ${covered.compared_packages.length} common fully checked package(s): ${escape(covered.compared_packages.join(', ') || 'none')}.${covered.unverified_packages.length?` Unverified common packages: ${escape(covered.unverified_packages.join(', '))}.`:''} ${covered.unsupported_before+covered.unsupported_after} unsupported line(s) across the snapshots.</div><div class="version-changes">${data.changed_versions.map(change=>`<span class="version-change">${escape(change.package)} ${escape(change.before)} → ${escape(change.after)}</span>`).join('')}</div><p class="change-note">${escape(data.note)}</p><div class="comparison-lists"><div class="comparison-column"><h2>New in the updated evidence</h2>${data.new.map(f=>changeCard(f,'New','red')).join('') || '<p class="empty">No new families within the compared scope.</p>'}</div><div class="comparison-column"><h2>Resolved within the compared scope</h2>${data.resolved.map(f=>changeCard(f,'Resolved','teal')).join('') || '<p class="empty">No resolved families within the compared scope.</p>'}</div></div><div class="section-heading"><h2>Unchanged evidence</h2></div>${data.unchanged.map(f=>changeCard(f,'Unchanged','gray')).join('') || '<p class="empty">No unchanged families within the compared scope.</p>'}<div class="section-heading"><h2>Package list changes</h2></div><p class="change-note">Added: ${escape(data.added_packages.join(', ') || 'none')} · Removed: ${escape(data.removed_packages.join(', ') || 'none')}. Added and removed packages are outside the advisory comparison scope.</p>`;
}

async function route() {
  const version = ++state.routeVersion;
  const hash = location.hash.slice(1);
  const view = hash === 'compare' ? 'compare' : hash === 'sources' ? 'sources' : 'workbench';
  $$('.view').forEach(node => { node.hidden = node.id !== view; });
  $$('[data-nav]').forEach(node => node.classList.toggle('active', node.dataset.nav === view));
  try {
    if (view === 'compare') await showComparison();
    else if (view === 'workbench') {
      const id = hash.startsWith('scan/') ? decodeURIComponent(hash.slice(5)) : state.selected || (state.scans.some(s=>s.id==='demo-baseline') ? 'demo-baseline' : state.scans[0]?.id);
      if (id) {
        const report = await api(`/api/scans/${encodeURIComponent(id)}`);
        if (version === state.routeVersion) renderReport(report);
      } else {
        $('#report-name').textContent = 'Your first review starts here';
        $('#report-meta').textContent = 'Create a scan to check exact pins against the advisory cache.';
        $('#metrics').innerHTML = metric(0,'Advisory families')+metric(0,'Packages checked')+metric(0,'Packages unchecked')+metric(0,'Unsupported lines');
        $('#coverage-note').textContent = 'No manifest has been submitted. No security conclusion can be drawn.';
        $('#packages').innerHTML = '<p class="empty">Use New dependency scan to get started.</p>';
        $('#export-link').hidden = true;
      }
    }
  } catch (error) {
    toast(error.message);
    if (view === 'workbench') {
      $('#report-name').textContent = 'Snapshot could not be loaded';
      $('#packages').innerHTML = '<p class="empty">Choose an available scan from the list.</p>';
      $('#metrics').innerHTML = '';
      $('#coverage-note').textContent = 'No result is available for this snapshot.';
      $('#report-meta').textContent = '';
      $('#export-link').hidden = true;
      $('#unsupported').hidden = true;
    }
  }
}

$$('[data-new]').forEach(button => button.addEventListener('click', () => {
  $('#scan-error').hidden = true;
  $('#scan-dialog').showModal();
}));
$('#close-dialog').addEventListener('click', () => { if (!state.busy) $('#scan-dialog').close(); });
$('#scan-dialog').addEventListener('cancel', event => { if (state.busy) event.preventDefault(); });
$('#use-baseline').addEventListener('click', () => { $('#manifest').value = baseline; });
$('#use-update').addEventListener('click', () => { $('#manifest').value = update; });
$('#manifest-file').addEventListener('change', async event => {
  const file = event.target.files[0];
  if (!file) return;
  if (!file.name.toLowerCase().endsWith('.txt') || file.size > 32768) {
    $('#scan-error').textContent = 'Choose a UTF-8 .txt file no larger than 32 KiB.';
    $('#scan-error').hidden = false;
    event.target.value = '';
    return;
  }
  try {
    const bytes = await file.arrayBuffer();
    $('#manifest').value = new TextDecoder('utf-8', {fatal:true}).decode(bytes);
    $('#file-name').textContent = file.name;
    $('#scan-error').hidden = true;
  } catch {
    $('#scan-error').textContent = 'The file is not valid UTF-8 text.';
    $('#scan-error').hidden = false;
    event.target.value = '';
  }
});
$('#scan-mode').addEventListener('change', () => {
  const live = $('#scan-mode').value === 'live';
  $('#consent-row').hidden = !live;
  $('#offline-help').hidden = live;
  $('#live-consent').checked = false;
});
$('#scan-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (state.busy) return;
  const live = $('#scan-mode').value === 'live';
  if (live && !$('#live-consent').checked) {
    $('#scan-error').textContent = 'Confirm the package-name and version upload before a live lookup.';
    $('#scan-error').hidden = false;
    return;
  }
  state.busy = true;
  $('#scan-error').hidden = true;
  $$('#scan-form button, #scan-form input, #scan-form select, #scan-form textarea').forEach(node => { node.disabled = true; });
  $('#save-scan').textContent = live ? 'Querying OSV…' : 'Saving snapshot…';
  try {
    const report = await api('/api/scans', {method:'POST',body:JSON.stringify({name:$('#scan-name').value,text:$('#manifest').value,mode:$('#scan-mode').value,live_consent:$('#live-consent').checked})});
    $('#scan-dialog').close();
    await refreshScans();
    $('#export-link').hidden = false;
    location.hash = `scan/${encodeURIComponent(report.id)}`;
    toast(report.summary.complete ? 'Snapshot saved with complete lookup evidence.' : 'Snapshot saved. Review the visible coverage gaps.');
  } catch (error) {
    $('#scan-error').textContent = error.message;
    $('#scan-error').hidden = false;
  } finally {
    state.busy = false;
    $$('#scan-form button, #scan-form input, #scan-form select, #scan-form textarea').forEach(node => { node.disabled = false; });
    $('#save-scan').textContent = 'Save scan';
  }
});
$('#compare-form').addEventListener('submit', async event => {
  event.preventDefault();
  try { await showComparison(); } catch(error) {
    $('#comparison-output').innerHTML = '<p class="empty">Comparison unavailable. No change conclusion can be drawn.</p>';
    toast(error.message);
  }
});
window.addEventListener('hashchange', route);
(async () => {
  try {
    const bootstrap = await api('/api/bootstrap');
    state.csrf = bootstrap.csrf;
    await refreshScans();
    await route();
  } catch (error) { toast(error.message); }
})();
