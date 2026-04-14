const $ = id => document.getElementById(id);

const dropZone        = $('drop-zone');
const fileInputFolder = $('file-input-folder');
const fileInputFiles  = $('file-input-files');
const btnPickFolder   = $('btn-pick-folder');
const btnPickFiles    = $('btn-pick-files');
const fileList        = $('file-list');
const fileItems       = $('file-items');
const fileCountLbl    = $('file-count-label');
const actionRow       = $('action-row');
const btnAnalyze      = $('btn-analyze');
const btnClear        = $('btn-clear');
const progressPanel   = $('progress-panel');
const progressBar     = $('progress-bar');
const progressLabel   = $('progress-label');
const resultBanner    = $('result-banner');
const btnDownload     = $('btn-download');
const outputName      = $('output-name');

let selectedFiles = [];
let knownPatterns = [];

async function loadPatterns() {
  try {
    const r = await fetch('/api/patterns');
    const d = await r.json();
    knownPatterns = d.patterns || [];
  } catch(e) {}
}

function isRecognized(filename) {
  // Solo el nombre base, sin subcarpetas
  const base = filename.split(/[\\/]/).pop();
  return knownPatterns.some(p => base.startsWith(p));
}

// ── Botones de selección ─────────────────────────
btnPickFolder.addEventListener('click', e => { e.stopPropagation(); fileInputFolder.click(); });
btnPickFiles.addEventListener('click',  e => { e.stopPropagation(); fileInputFiles.click(); });

fileInputFolder.addEventListener('change', () => {
  addFiles(Array.from(fileInputFolder.files));
  fileInputFolder.value = '';
});
fileInputFiles.addEventListener('change', () => {
  addFiles(Array.from(fileInputFiles.files));
  fileInputFiles.value = '';
});

// ── Drag & drop (acepta carpetas y archivos) ─────
dropZone.addEventListener('dragover', e => { e.preventDefault(); dropZone.classList.add('dragover'); });
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', async e => {
  e.preventDefault();
  dropZone.classList.remove('dragover');

  // Intentar leer como carpeta con DataTransferItems (si el browser lo soporta)
  const items = e.dataTransfer.items;
  if (items && items.length > 0 && items[0].webkitGetAsEntry) {
    const allFiles = await readEntries(items);
    addFiles(allFiles);
  } else {
    addFiles(Array.from(e.dataTransfer.files));
  }
});

async function readEntries(items) {
  const files = [];
  const promises = [];
  for (const item of items) {
    const entry = item.webkitGetAsEntry();
    if (entry) promises.push(traverseEntry(entry, files));
  }
  await Promise.all(promises);
  return files;
}

async function traverseEntry(entry, files) {
  if (entry.isFile) {
    await new Promise(res => entry.file(f => { files.push(f); res(); }));
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    await new Promise(res => {
      reader.readEntries(async entries => {
        await Promise.all(entries.map(e => traverseEntry(e, files)));
        res();
      });
    });
  }
}

// ── Agregar archivos a la lista ──────────────────
function addFiles(newFiles) {
  const existing = new Set(selectedFiles.map(f => f.name));
  newFiles.forEach(f => { if (!existing.has(f.name)) selectedFiles.push(f); });
  renderFileList();
}

function renderFileList() {
  resultBanner.style.display = 'none';
  if (!selectedFiles.length) {
    fileList.style.display = 'none';
    actionRow.style.display = 'none';
    return;
  }
  fileList.style.display = 'block';
  actionRow.style.display = 'flex';

  const recognized = selectedFiles.filter(f => isRecognized(f.name));
  const ignored    = selectedFiles.length - recognized.length;
  fileCountLbl.textContent =
    `${selectedFiles.length} archivo(s) — ${recognized.length} reconocido(s)` +
    (ignored > 0 ? `, ${ignored} ignorado(s)` : '');

  // Solo mostrar los reconocidos + primeros ignorados
  fileItems.innerHTML = '';
  const toShow = [...recognized, ...selectedFiles.filter(f => !isRecognized(f.name))].slice(0, 50);
  toShow.forEach(f => {
    const rec = isRecognized(f.name);
    const item = document.createElement('div');
    item.className = 'file-item';
    item.innerHTML = `
      <div class="file-icon">F</div>
      <div class="file-name">${f.name}</div>
      <span class="file-tag ${rec ? 'recognized' : 'unknown'}">${rec ? '✓ reconocido' : 'ignorado'}</span>
    `;
    fileItems.appendChild(item);
  });
  if (selectedFiles.length > 50) {
    const more = document.createElement('div');
    more.className = 'file-item';
    more.style.color = 'var(--text3)';
    more.style.fontSize = '12px';
    more.style.padding = '8px 16px';
    more.textContent = `... y ${selectedFiles.length - 50} archivos más`;
    fileItems.appendChild(more);
  }
}

btnClear.addEventListener('click', () => {
  selectedFiles = [];
  renderFileList();
  progressPanel.style.display = 'none';
  resultBanner.style.display = 'none';
});

// ── Ejecutar análisis ────────────────────────────
btnAnalyze.addEventListener('click', runAnalysis);

async function runAnalysis() {
  if (!selectedFiles.length) return;

  const name = outputName.value.trim() || 'salidas_ifxcollect';
  btnAnalyze.disabled = true;
  resultBanner.style.display = 'none';
  progressPanel.style.display = 'block';
  setProgress(10, 'Subiendo archivos...');

  const formData = new FormData();
  selectedFiles.forEach(f => formData.append('files[]', f));
  formData.append('output_name', name);

  try {
    setProgress(30, 'Filtrando archivos relevantes...');
    const response = await fetch('/api/analyze/files', { method: 'POST', body: formData });
    setProgress(80, 'Generando archivos de salida...');

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.error || `Error del servidor (${response.status})`);
    }

    const blob = await response.blob();
    const url  = URL.createObjectURL(blob);

    setProgress(100, '¡Análisis completado!');
    setTimeout(() => {
      progressPanel.style.display = 'none';
      btnDownload.href = url;
      btnDownload.download = `${name}.zip`;
      $('result-sub').textContent = `Carpeta: ${name}/ con un .txt por cada analizador.`;
      resultBanner.style.display = 'flex';
    }, 400);

  } catch(err) {
    progressPanel.style.display = 'none';
    showError(err.message);
  } finally {
    btnAnalyze.disabled = false;
  }
}

function setProgress(pct, label) {
  progressBar.style.width = pct + '%';
  progressLabel.textContent = label;
}

function showError(msg) {
  const banner = document.createElement('div');
  banner.className = 'error-banner';
  banner.textContent = '✕ ' + msg;
  $('tab-upload').appendChild(banner);
  setTimeout(() => banner.remove(), 8000);
}

loadPatterns();
