/* ═══════════════════════════════════════════════
   IFX Analyzer — Frontend JS
   ═══════════════════════════════════════════════ */

const $ = id => document.getElementById(id);
const dropZone   = $('drop-zone');
const fileInput  = $('file-input');
const fileList   = $('file-list');
const fileItems  = $('file-items');
const actionRow  = $('action-row');
const btnAnalyze = $('btn-analyze');
const btnClear   = $('btn-clear');
const btnNew     = $('btn-new-analysis');
const progressPanel = $('progress-panel');
const progressBar   = $('progress-bar');
const progressLabel = $('progress-label');
const navResults    = $('nav-results');
const alertBadge    = $('alert-badge');

let selectedFiles = [];
let knownPatterns = [];

// ── Load known patterns ──────────────────────────
async function loadPatterns() {
  try {
    const r = await fetch('/api/patterns');
    const d = await r.json();
    knownPatterns = d.patterns || [];
    $('patterns-list').textContent = knownPatterns.join(', ') || 'onstat.*';
  } catch(e) { /* silently ignore */ }
}

function isRecognized(filename) {
  return knownPatterns.some(p => filename.startsWith(p));
}

// ── Tab navigation ───────────────────────────────
document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    const tab = item.dataset.tab;
    switchTab(tab);
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    item.classList.add('active');
  });
});

function switchTab(name) {
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  $(`tab-${name}`).classList.add('active');
}

// ── File handling ────────────────────────────────
dropZone.addEventListener('click', () => fileInput.click());

dropZone.addEventListener('dragover', e => {
  e.preventDefault();
  dropZone.classList.add('dragover');
});

dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));

dropZone.addEventListener('drop', e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');
  addFiles(Array.from(e.dataTransfer.files));
});

fileInput.addEventListener('change', () => {
  addFiles(Array.from(fileInput.files));
  fileInput.value = '';
});

function addFiles(newFiles) {
  const existing = new Set(selectedFiles.map(f => f.name));
  newFiles.forEach(f => {
    if (!existing.has(f.name)) selectedFiles.push(f);
  });
  renderFileList();
}

function renderFileList() {
  if (selectedFiles.length === 0) {
    fileList.style.display = 'none';
    actionRow.style.display = 'none';
    return;
  }

  fileList.style.display = 'block';
  actionRow.style.display = 'flex';
  fileItems.innerHTML = '';

  selectedFiles.forEach((f, i) => {
    const rec = isRecognized(f.name);
    const item = document.createElement('div');
    item.className = 'file-item';
    item.innerHTML = `
      <div class="file-icon">F</div>
      <div class="file-name">${f.name}</div>
      <span class="file-tag ${rec ? 'recognized' : 'unknown'}">${rec ? '✓ reconocido' : 'desconocido'}</span>
    `;
    fileItems.appendChild(item);
  });
}

btnClear.addEventListener('click', () => {
  selectedFiles = [];
  renderFileList();
  progressPanel.style.display = 'none';
});

// ── Run analysis ─────────────────────────────────
btnAnalyze.addEventListener('click', runAnalysis);

async function runAnalysis() {
  if (!selectedFiles.length) return;

  btnAnalyze.disabled = true;
  progressPanel.style.display = 'block';
  setProgress(0, 'Subiendo archivos...');

  const formData = new FormData();
  selectedFiles.forEach(f => formData.append('files[]', f));

  try {
    setProgress(20, 'Procesando archivos...');

    const response = await fetch('/api/analyze/files', {
      method: 'POST',
      body: formData,
    });

    setProgress(70, 'Analizando métricas...');

    const data = await response.json();

    setProgress(100, 'Análisis completado.');

    if (data.error) {
      showError(data.error);
      return;
    }

    setTimeout(() => {
      renderResults(data.results);
      switchTab('results');
      navResults.style.display = 'flex';
      document.querySelector('[data-tab="results"]').classList.add('active');
      document.querySelector('[data-tab="upload"]').classList.remove('active');
      progressPanel.style.display = 'none';
    }, 400);

  } catch(err) {
    showError('Error de conexión: ' + err.message);
  } finally {
    btnAnalyze.disabled = false;
  }
}

function setProgress(pct, label) {
  progressBar.style.width = pct + '%';
  progressLabel.textContent = label;
}

function showError(msg) {
  progressPanel.style.display = 'none';
  const banner = document.createElement('div');
  banner.className = 'error-banner';
  banner.textContent = '✕ ' + msg;
  $('tab-upload').appendChild(banner);
  setTimeout(() => banner.remove(), 6000);
}

// ── Render results ───────────────────────────────
function renderResults(results) {
  const list = $('results-list');
  const cards = $('summary-cards');
  const desc  = $('results-desc');
  list.innerHTML = '';
  cards.innerHTML = '';

  const totalAlerts   = results.reduce((a, r) => a + r.findings.filter(f => f.severity === 'alert').length, 0);
  const totalWarnings = results.reduce((a, r) => a + r.findings.filter(f => f.severity === 'warning').length, 0);
  const totalOk       = results.reduce((a, r) => a + r.findings.filter(f => f.severity === 'ok').length, 0);

  desc.textContent = `${results.length} analizador(es) ejecutado(s) — ${selectedFiles.length} archivo(s) procesado(s)`;

  // Badge in sidebar
  if (totalAlerts > 0) {
    alertBadge.textContent = totalAlerts;
    alertBadge.style.display = 'inline';
  } else {
    alertBadge.style.display = 'none';
  }

  // Summary cards
  cards.innerHTML = `
    <div class="summary-card alert">
      <div class="card-number">${totalAlerts}</div>
      <div class="card-label">Alertas críticas</div>
    </div>
    <div class="summary-card warning">
      <div class="card-number">${totalWarnings}</div>
      <div class="card-label">Advertencias</div>
    </div>
    <div class="summary-card ok">
      <div class="card-number">${totalOk}</div>
      <div class="card-label">Checks OK</div>
    </div>
    <div class="summary-card">
      <div class="card-number" style="color:var(--text2)">${results.length}</div>
      <div class="card-label">Analizadores</div>
    </div>
  `;

  // Sort: alerts first
  const sorted = [...results].sort((a, b) => {
    const order = {alert: 0, warning: 1, ok: 2, error: 3};
    return (order[a.status] ?? 4) - (order[b.status] ?? 4);
  });

  sorted.forEach(r => {
    const block = document.createElement('div');
    block.className = 'analyzer-block';

    const alertCount   = r.findings.filter(f => f.severity === 'alert').length;
    const warningCount = r.findings.filter(f => f.severity === 'warning').length;

    let chips = '';
    if (alertCount)   chips += `<span class="chip alert">▲ ${alertCount} alerta${alertCount > 1 ? 's' : ''}</span>`;
    if (warningCount) chips += `<span class="chip warning">◉ ${warningCount} advertencia${warningCount > 1 ? 's' : ''}</span>`;
    if (!alertCount && !warningCount && !r.error) chips += `<span class="chip ok">✓ OK</span>`;
    if (r.error) chips += `<span class="chip info">error</span>`;

    block.innerHTML = `
      <div class="analyzer-header">
        <div class="analyzer-status ${r.status}"></div>
        <div class="analyzer-name">${r.analyzer}</div>
        <div class="analyzer-chips">${chips}</div>
        <div class="analyzer-chevron">▶</div>
      </div>
      <div class="analyzer-body">
        ${r.error
          ? `<div class="finding"><div class="finding-bar info"></div><div class="finding-content"><div class="finding-title">Error al ejecutar</div><div class="finding-message">${r.error}</div></div></div>`
          : r.findings.map(f => renderFinding(f)).join('')
        }
      </div>
    `;

    // Auto-open if has alerts
    if (r.status === 'alert' || r.status === 'warning') {
      block.classList.add('open');
    }

    block.querySelector('.analyzer-header').addEventListener('click', () => {
      block.classList.toggle('open');
    });

    list.appendChild(block);
  });
}

function renderFinding(f) {
  const hasDetail = f.detail && f.detail.trim();
  const detailId  = 'detail-' + Math.random().toString(36).slice(2);

  return `
    <div class="finding">
      <div class="finding-bar ${f.severity}"></div>
      <div class="finding-content">
        <div class="finding-title">${f.title}</div>
        <div class="finding-message ${f.severity}">${f.message}</div>
        ${hasDetail ? `
          <span class="finding-detail-toggle" onclick="toggleDetail('${detailId}', this)">
            ▶ ver detalle
          </span>
          <pre class="finding-detail" id="${detailId}">${escapeHtml(f.detail)}</pre>
        ` : ''}
      </div>
      ${f.metric ? `<div class="finding-metric">${f.metric}</div>` : ''}
    </div>
  `;
}

function toggleDetail(id, el) {
  const box = document.getElementById(id);
  box.classList.toggle('open');
  el.textContent = box.classList.contains('open') ? '▼ ocultar detalle' : '▶ ver detalle';
}

function escapeHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

// ── New analysis ─────────────────────────────────
btnNew.addEventListener('click', () => {
  switchTab('upload');
  navResults.style.display = 'none';
  document.querySelector('[data-tab="upload"]').classList.add('active');
  document.querySelector('[data-tab="results"]').classList.remove('active');
  selectedFiles = [];
  renderFileList();
  progressPanel.style.display = 'none';
});

// ── Init ─────────────────────────────────────────
loadPatterns();
