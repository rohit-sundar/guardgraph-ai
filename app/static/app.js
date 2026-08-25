let selectedFile = null;
let currentReportData = null;

document.addEventListener('DOMContentLoaded', () => {
  setupUploadEvents();
  loadModelAccuracy();
  loadHistory();
  refreshHealth();
  const refreshBtn = document.getElementById('btnRefreshHistory');
  if (refreshBtn) refreshBtn.addEventListener('click', loadHistory);
  const backBtn = document.getElementById('btnBackToUpload');
  if (backBtn) backBtn.addEventListener('click', goBackToUpload);
  const confirmedBtn = document.getElementById('btnFeedbackConfirmed');
  if (confirmedBtn) confirmedBtn.addEventListener('click', () => submitFeedback('confirmed'));
  const falsePositiveBtn = document.getElementById('btnFeedbackFalsePositive');
  if (falsePositiveBtn) falsePositiveBtn.addEventListener('click', () => submitFeedback('false_positive'));
  const copyHashBtn = document.getElementById('btnCopyHash');
  if (copyHashBtn) copyHashBtn.addEventListener('click', copyTargetHash);
});

function copyTargetHash() {
  const hash = currentReportData && currentReportData.manifest && currentReportData.manifest.sha256;
  const btn = document.getElementById('btnCopyHash');
  if (!hash || !btn) return;
  navigator.clipboard.writeText(hash).then(() => {
    btn.classList.add('copied');
    setTimeout(() => btn.classList.remove('copied'), 1200);
  }).catch(() => {
    // Clipboard permission denied/unavailable (e.g. an insecure context, or a
    // browser policy blocking it) — nothing useful to recover into, but this
    // must not surface as an unhandled rejection.
  });
}

// Analyst feedback — records a correction against the currently-rendered
// report's sha256 (see POST /analyses/{sha256}/feedback). This only logs
// the correction; scripts/export_feedback_for_training.py is the separate,
// deliberate step that turns it into a training row, and nothing here
// triggers retraining.
async function submitFeedback(verdict) {
  const statusEl = document.getElementById('feedbackStatus');
  const sha256 = currentReportData && currentReportData.manifest && currentReportData.manifest.sha256;
  if (!sha256) {
    if (statusEl) {
      statusEl.textContent = 'No sample loaded.';
      statusEl.classList.remove('hidden');
    }
    return;
  }
  try {
    const resp = await fetch(`/analyses/${encodeURIComponent(sha256)}/feedback`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ verdict: verdict }),
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    if (statusEl) {
      statusEl.textContent = verdict === 'confirmed' ? 'Thanks — recorded.' : 'Recorded — thanks for the correction.';
      statusEl.classList.remove('hidden');
    }
  } catch (e) {
    if (statusEl) {
      statusEl.textContent = 'Could not record feedback (see console).';
      statusEl.classList.remove('hidden');
    }
    console.error('submitFeedback failed:', e);
  }
}

// Returns from a rendered report (fresh or historical) to the landing page.
// Re-fetches history since the results just viewed may be a new analysis
// that isn't in the currently-rendered list yet.
function goBackToUpload() {
  document.getElementById('resultsSection').classList.add('hidden');
  document.getElementById('progressSection').classList.add('hidden');
  document.getElementById('uploadSection').classList.remove('hidden');
  selectedFile = null;
  const fileInput = document.getElementById('fileInput');
  if (fileInput) fileInput.value = '';
  const preview = document.getElementById('filePreview');
  if (preview) {
    preview.classList.add('hidden');
    preview.style.display = 'none';
  }
  loadHistory();
}

// The header status pills. Polled rather than read once at load: the failure this
// exists to catch is a dependency dying DURING a session (someone stops Docker),
// which a load-time check would render green and then never revisit. 30s is slow
// enough to be free and fast enough to notice before the next upload.
const HEALTH_POLL_MS = 30000;

function setPill(id, textId, state, label, detail) {
  const pill = document.getElementById(id);
  const text = document.getElementById(textId);
  if (!pill || !text) return;
  pill.classList.remove('status-ok', 'status-warn', 'status-down', 'status-unknown');
  pill.classList.add(`status-${state}`);
  text.textContent = label;
  pill.title = detail || '';
}

async function refreshHealth() {
  try {
    const resp = await fetch('/health');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const h = await resp.json();

    const g = h.neo4j || {};
    if (!g.reachable) {
      setPill('pillGraph', 'pillGraphText', 'down', 'Correlation Engine: offline', g.detail);
    } else if (!g.grounded_techniques) {
      setPill('pillGraph', 'pillGraphText', 'warn', 'Correlation Engine: not loaded', g.detail);
    } else {
      setPill('pillGraph', 'pillGraphText', 'ok',
              `Correlation Engine: ${g.cached_samples} samples`, g.detail);
    }

    const l = h.ollama || {};
    if (!l.reachable) {
      setPill('pillLlm', 'pillLlmText', 'down', 'Qwen2.5 7B LLM: offline', l.detail);
    } else if (!l.model_resident) {
      setPill('pillLlm', 'pillLlmText', 'warn', 'Qwen2.5 7B LLM: loading', l.detail);
    } else {
      setPill('pillLlm', 'pillLlmText', 'ok', 'Qwen2.5 7B LLM: ready', l.detail);
    }
  } catch (err) {
    // The API itself is unreachable, so neither dependency is knowable. Say that
    // rather than blaming a dependency we did not manage to ask about.
    setPill('pillGraph', 'pillGraphText', 'unknown', 'Correlation Engine: unknown', String(err));
    setPill('pillLlm', 'pillLlmText', 'unknown', 'API unreachable', String(err));
  } finally {
    setTimeout(refreshHealth, HEALTH_POLL_MS);
  }
}

const HISTORY_BAND_VARS = {
  low: '--band-low', medium: '--band-medium', suspicious: '--band-suspicious',
  high: '--band-high', malicious: '--band-malicious',
};

// Every verdict this instance has ever reached, reopenable without
// re-uploading the sample — backed by Neo4j Sample nodes (GET /analyses), not
// tied to the current browser session.
async function loadHistory() {
  const listEl = document.getElementById('historyList');
  if (!listEl) return;
  listEl.innerHTML = '<div class="graph-placeholder-text">Loading&hellip;</div>';

  let rows;
  try {
    const resp = await fetch('/analyses?limit=30');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    rows = await resp.json();
  } catch (err) {
    listEl.innerHTML = '<div class="graph-placeholder-text">Could not load history (is Neo4j running?).</div>';
    return;
  }

  if (!rows.length) {
    listEl.innerHTML = '<div class="graph-placeholder-text">No analyses yet — upload an APK to get started.</div>';
    return;
  }

  listEl.innerHTML = '';
  rows.forEach(r => {
    const row = document.createElement('div');
    row.className = 'history-row';
    row.setAttribute('role', 'button');
    row.setAttribute('tabindex', '0');

    const name = document.createElement('span');
    name.className = 'history-name';
    name.textContent = r.app_name || r.sha256;   // sample-derived — textContent only
    name.title = r.sha256;

    const family = document.createElement('span');
    family.className = 'history-family';
    family.textContent = r.family || 'Unclassified';

    const score = document.createElement('span');
    score.className = 'history-score';
    if (r.risk_score !== null && r.risk_score !== undefined) {
      score.textContent = r.risk_score.toFixed(1);
      const varName = HISTORY_BAND_VARS[r.verdict_band] || '--band-unknown';
      score.style.color = `var(${varName})`;
    } else {
      score.textContent = '—';
    }

    const time = document.createElement('span');
    time.className = 'history-time';
    time.textContent = r.analyzed_at ? new Date(r.analyzed_at).toLocaleString() : '';

    row.appendChild(name);
    row.appendChild(family);
    row.appendChild(score);
    row.appendChild(time);

    const open = () => openHistoricalAnalysis(r.sha256);
    row.addEventListener('click', open);
    row.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });

    listEl.appendChild(row);
  });
}

async function openHistoricalAnalysis(sha256) {
  try {
    const resp = await fetch(`/analyses/${encodeURIComponent(sha256)}`);
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const data = await resp.json();
    document.getElementById('uploadSection').classList.add('hidden');
    document.getElementById('progressSection').classList.add('hidden');
    renderResults(data);
  } catch (err) {
    alert('Could not load that analysis: ' + err.message);
  }
}

// Model accuracy is a property of the currently-loaded classifier bundle, not of
// any single analysis — fetched once at page load rather than per-report.
async function loadModelAccuracy() {
  const statusEl = document.getElementById('modelAccuracyStatus');
  const tableEl = document.getElementById('modelAccuracyTable');
  if (!statusEl || !tableEl) return;

  let data;
  try {
    const resp = await fetch('/model/metrics');
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    data = await resp.json();
  } catch (err) {
    statusEl.textContent = 'Unavailable';
    tableEl.innerHTML = '<span class="model-accuracy-untrained">Could not reach /model/metrics.</span>';
    return;
  }

  if (!data.trained) {
    statusEl.textContent = 'Not trained';
    tableEl.innerHTML = '<span class="model-accuracy-untrained">' +
      'No trained TTP bundle found — classifier_confidence and ttp_severity read 0 until ' +
      '<code>python scripts/train_model.py --target ttp</code> runs.</span>';
    return;
  }

  const strat = data.stratified || {};
  const honest = data.family_held_out;

  if (!honest) {
    statusEl.textContent = `${data.trained_labels} labels trained`;
    const reason = data.family_held_out_error || 'not enough malware family groups to evaluate';
    tableEl.innerHTML = `<span class="model-accuracy-untrained">Family-held-out evaluation did not run (${esc(reason)}) — only the stratified (family-leaky) numbers below are available.</span>`;
    return;
  }

  statusEl.textContent = `${data.trained_labels} labels · ${data.n_samples} training rows · ${honest.n_family_groups} malware families`;

  const rows = [
    ['micro_f1', 'micro-F1', 'Overall accuracy across every technique combined — correct calls out of all calls made.'],
    ['jaccard_samples', 'Jaccard (per-sample)', "How closely the model's predicted technique set matches the true set, averaged per sample."],
    ['macro_f1', 'macro-F1', 'Accuracy averaged evenly across techniques, so a rare technique counts as much as a common one.'],
    ['hamming_loss', 'Hamming loss', 'Share of individual technique predictions that were wrong — lower is better.'],
  ];

  tableEl.innerHTML = `
    <div class="model-accuracy-row model-accuracy-header-row">
      <span></span><span class="metric-strat">Stratified (leaky)</span><span class="metric-honest">Family-held-out (honest)</span><span></span>
    </div>
    ${rows.map(([key, label, meaning]) => {
      const s = strat[key];
      const h = honest[key];
      if (s === undefined || h === undefined) return '';
      const delta = h - s;
      const lowerIsBetter = key === 'hamming_loss';
      const worse = lowerIsBetter ? delta > 0 : delta < 0;
      return `
        <div class="model-accuracy-row">
          <span class="metric-name" title="${esc(meaning)}">${esc(label)}</span>
          <span class="metric-strat">${s.toFixed(3)}</span>
          <span class="metric-honest">${h.toFixed(3)}</span>
          <span class="metric-delta">${worse ? '↓' : ''} ${worse ? Math.abs(delta).toFixed(3) : ''}</span>
        </div>`;
    }).join('')}
    <div class="model-accuracy-legend">
      <span>${honest.n_splits}-fold cross-validation, whole malware families held out each round</span>
      <span>Use the "honest" column when citing accuracy — it's the only one tested on unseen families</span>
    </div>
  `;
}

// Everything an analysed APK contains is attacker-controlled: package and
// permission names, YARA rule names, extracted C2 strings, certificate fields, and
// the exception text embedded in a coverage note. Several of those are interpolated
// into innerHTML below, so a crafted sample could declare
//   <uses-permission android:name="<img src=x onerror=...>">
// and run script in the analyst's browser, on the machine holding the malware
// corpus. Every interpolated VALUE goes through esc(); only markup this file writes
// itself is left raw. Where a block was simple enough to rebuild with textContent
// instead (see renderImpersonation), that is preferred over escaping.
function esc(value) {
  if (value === null || value === undefined) return '';
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// The narrative is Markdown, and Markdown permits raw HTML — which marked passes
// through verbatim. Sanitize the rendered output with DOMPurify rather than
// escaping the Markdown source, which would also break its formatting. If
// DOMPurify did not load, fall back to plain text: losing the formatting is the
// safe failure, rendering unsanitized HTML is not.
function renderMarkdown(el, markdownText) {
  const html = marked.parse(markdownText);
  if (typeof DOMPurify !== 'undefined') {
    el.innerHTML = DOMPurify.sanitize(html);
  } else {
    console.warn('DOMPurify unavailable — rendering the report as plain text.');
    el.textContent = markdownText;
  }
}


function setupUploadEvents() {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const btnStartAnalyze = document.getElementById('btnStartAnalyze');

  // Drag & drop handlers
  ['dragenter', 'dragover'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropZone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropZone.classList.remove('dragover');
    });
  });

  dropZone.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    if (dt && dt.files && dt.files.length > 0) {
      handleFileSelected(dt.files[0]);
    }
  });

  fileInput.addEventListener('change', function() {
    if (this.files && this.files.length > 0) {
      handleFileSelected(this.files[0]);
    }
  });

  btnStartAnalyze.addEventListener('click', () => {
    if (selectedFile) {
      uploadAndAnalyze(selectedFile);
    } else {
      alert("Please select an APK file first.");
    }
  });
}

function handleFileSelected(file) {
  if (!file) return;
  selectedFile = file;
  document.getElementById('fileName').textContent = file.name;
  document.getElementById('fileSize').textContent = (file.size / (1024 * 1024)).toFixed(2) + ' MB';
  const preview = document.getElementById('filePreview');
  if (preview) {
    preview.classList.remove('hidden');
    preview.style.display = 'flex';
  }
}

// Real pipeline phase count — must match app.core.progress.PHASES on the backend.
// Only used as a fallback when an event omits total_phases; every event from a
// current server carries its own, so this rarely matters in practice.
const PIPELINE_PHASE_COUNT = 11;

// Rotating "about the app" callouts shown on the progress screen — pure
// wait-filler, not tied to the real pipeline phase. Each one describes
// something the pipeline actually does or a capability that sets it apart,
// grounded in the real components (see PHASES.md / README.md).
const PROGRESS_TIPS = [
  "Every sample's SHA-256 hash and signing certificate are checked against known threat intel before a single instruction is analyzed.",
  "Control-flow graphs are parsed into behavioral subgraphs — the same technique used here to detect control-flow flattening obfuscation.",
  "Suspicious samples are launched on a real Android Virtual Device with Frida hooks intercepting SMS, overlay, and native library calls live.",
  "Every verdict is mapped to the MITRE ATT&CK Mobile framework — real adversary techniques, not just a risk number.",
  "The AI narrative is grounded in retrieved graph facts, then checked after generation to catch anything the model invented.",
  "Reflectively-loaded DEX payloads and dynamically resolved API calls are traced through register-constant propagation to see past basic obfuscation.",
  "Every analyzed sample joins a live Neo4j knowledge graph, so a new upload can be instantly correlated against known malware families and C2 infrastructure.",
  "App icons and display names are compared against known banking and UPI brands to catch impersonation before the payload even runs.",
  "The risk model is validated on malware families it has never seen — so the accuracy numbers reflect real unseen threats, not memorized ones.",
  "A finding only counts as CONFIRMED once static and dynamic analysis agree — a resolved crypto call has to actually execute at runtime, not just exist in the code.",
  "YARA rules and signature matching run alongside the graph-based pipeline, so known threats surface instantly while zero-days get the full analysis.",
  "WebView JavaScript bridges are inventoried automatically — a common attack surface where native app methods get exposed to untrusted web content.",
  "The correlation graph never forgets: a fresh upload can surface earlier samples that reused the same signing certificate or C2 infrastructure.",
  "From APK to a MITRE-mapped, evidence-grounded verdict — the full pipeline runs in minutes, not the hours a manual reverse-engineering pass would take.",
];

let _tipInterval = null;

function startProgressTips() {
  const el = document.getElementById('progressTipText');
  if (!el) return;
  stopProgressTips();

  let idx = -1;
  const showNext = () => {
    idx = (idx + 1) % PROGRESS_TIPS.length;
    el.classList.remove('visible');
    setTimeout(() => {
      el.textContent = PROGRESS_TIPS[idx];
      el.classList.add('visible');
    }, 300);
  };

  showNext();
  _tipInterval = setInterval(showNext, 8000);
}

function stopProgressTips() {
  if (_tipInterval) {
    clearInterval(_tipInterval);
    _tipInterval = null;
  }
}

async function uploadAndAnalyze(file) {
  document.getElementById('uploadSection').classList.add('hidden');
  document.getElementById('progressSection').classList.remove('hidden');
  document.getElementById('resultsSection').classList.add('hidden');
  resetPipelineSteps();
  startProgressTips();

  const formData = new FormData();
  formData.append("file", file);

  const startUrl = '/analyze/start?enable_dynamic=true';

  try {
    const startResp = await fetch(startUrl, {
      method: 'POST',
      body: formData
    });
    if (!startResp.ok) {
      throw new Error(`Server returned HTTP ${startResp.status}`);
    }
    const { job_id } = await startResp.json();
    await streamAnalysis(job_id);
  } catch (err) {
    handleAnalysisFailure("Analysis failed: " + err.message);
  }
}

function handleAnalysisFailure(message) {
  stopProgressTips();
  alert(message);
  document.getElementById('uploadSection').classList.remove('hidden');
  document.getElementById('progressSection').classList.add('hidden');
}

// Real pipeline progress over Server-Sent Events (app/core/progress.py). Replaces
// the earlier simulatePipelineProgress(), which was a fixed sequence of setTimeout
// delays with no connection to the actual pipeline — it reached 95% and sat there
// however long the real analysis took. Every event here is emitted at the moment
// the corresponding backend phase actually starts or finishes.
function streamAnalysis(jobId) {
  return new Promise((resolve, reject) => {
    const source = new EventSource(`/analyze/stream/${jobId}`);
    let settled = false;

    source.addEventListener('progress', (evt) => {
      try {
        applyProgressEvent(JSON.parse(evt.data));
      } catch (e) {
        // A malformed single event is not fatal to the stream — keep listening.
      }
    });

    source.addEventListener('complete', (evt) => {
      settled = true;
      source.close();

      let payload;
      try {
        payload = JSON.parse(evt.data);
      } catch (e) {
        reject(new Error('Malformed completion event from server'));
        return;
      }

      applyProgressEvent(payload);
      if (payload.status === 'complete' && payload.result) {
        setProgressPercent(100);
        renderResults(payload.result);
        resolve();
      } else {
        reject(new Error(payload.error || payload.detail || 'Analysis failed'));
      }
    });

    source.onerror = () => {
      // EventSource fires 'error' on a normal server-closed connection too, but we
      // always call source.close() ourselves inside the 'complete' handler first —
      // so an error reaching here after settled=true is the browser's harmless
      // post-close housekeeping, not a real failure.
      if (settled) return;
      settled = true;
      source.close();
      reject(new Error('Lost connection to the analysis stream'));
    };
  });
}

// Which phase_index values have reached a terminal state (done or skipped) in the
// run currently on screen — drives the percentage bar off real completed work
// instead of a guessed pace.
let _completedPhaseIndices = new Set();

function resetPipelineSteps() {
  document.querySelectorAll('.step-item').forEach(s => {
    s.classList.remove('active', 'completed', 'skipped', 'errored');
  });
  _completedPhaseIndices = new Set();
  setProgressPercent(0);

  const note = document.getElementById('progressLiveNote');
  if (note) note.textContent = 'Connecting…';
  const headline = document.getElementById('progressHeadline');
  if (headline) headline.textContent = 'Analyzing Target Package…';
}

function setProgressPercent(pct) {
  const fill = document.getElementById('progressBarFill');
  const percentText = document.getElementById('progressPercent');
  if (fill) fill.style.width = `${pct}%`;
  if (percentText) percentText.textContent = `${Math.round(pct)}%`;
}

function applyProgressEvent(event) {
  const note = document.getElementById('progressLiveNote');

  if (event.final) {
    if (event.status === 'error') {
      const headline = document.getElementById('progressHeadline');
      if (headline) headline.textContent = 'Analysis failed';
      if (note) note.textContent = event.detail || event.error || 'Unknown error';
      document.querySelectorAll('.step-item.active').forEach(s => {
        s.classList.remove('active');
        s.classList.add('errored');
      });
    }
    return;
  }

  const stepEl = document.querySelector(`.step-item[data-phase="${event.phase}"]`);
  if (stepEl) {
    if (event.status === 'start') {
      stepEl.classList.add('active');
      stepEl.classList.remove('completed', 'skipped');
    } else if (event.status === 'done') {
      stepEl.classList.remove('active');
      stepEl.classList.add('completed');
      if (typeof event.phase_index === 'number') _completedPhaseIndices.add(event.phase_index);
    } else if (event.status === 'skipped') {
      stepEl.classList.remove('active');
      stepEl.classList.add('skipped');
      if (typeof event.phase_index === 'number') _completedPhaseIndices.add(event.phase_index);
    }
  }

  if (note) {
    if (event.status === 'start') {
      note.textContent = `Running: ${event.name}…`;
    } else if (event.status === 'done') {
      note.textContent = `${event.name} complete.`;
    } else if (event.status === 'skipped') {
      note.textContent = `${event.name} skipped — ${event.detail || 'not needed on this path'}.`;
    }
  }

  const total = event.total_phases || PIPELINE_PHASE_COUNT;
  // Capped short of 100 until the terminal 'complete' event actually lands — a
  // cache hit reports phase 1 done plus nine "skipped" events almost instantly,
  // which would otherwise read 100% while the response body is still being
  // assembled, and then appear to hang right at the finish line.
  const pct = Math.min(97, Math.round((_completedPhaseIndices.size / total) * 100));
  setProgressPercent(pct);
}

function renderResults(data) {
  currentReportData = data;
  stopProgressTips();
  document.getElementById('progressSection').classList.add('hidden');
  document.getElementById('resultsSection').classList.remove('hidden');

  const manifest = data.manifest || {};
  const risk = data.risk_score || {};

  // Verdict tag & score
  const bandRaw = (risk.verdict_band || 'unknown').toLowerCase();
  const knownBands = ['low', 'medium', 'suspicious', 'high', 'malicious'];
  const isUnparseable = (data.limitations || []).some(
    l => l.startsWith('ANALYSIS INCOMPLETE')
  );
  const bandClass = isUnparseable
    ? 'unknown'
    : (knownBands.includes(bandRaw) ? bandRaw : 'unknown');

  const verdictTag = document.getElementById('verdictTag');
  verdictTag.textContent = bandRaw.toUpperCase();
  verdictTag.className = `verdict-tag verdict-${bandClass}`;

  const gaugeFill = document.getElementById('gaugeFill');
  gaugeFill.setAttribute('class', `gauge-fill gauge-${bandClass}`);

  const score = risk.total_score || 0;
  document.getElementById('scoreNum').textContent = score.toFixed(1);

  // Update gauge stroke-dashoffset (max 264)
  const strokeOffset = 264 - (264 * (score / 100));
  gaugeFill.style.strokeDashoffset = strokeOffset;

  // Badges — explicitly reset both first. Without this, a badge shown for
  // one sample stayed visible on the next report even when that sample's
  // own zero_day_indicator/is_known_malware was false, since .remove('hidden')
  // was only ever called on the truthy branch.
  document.getElementById('zeroDayBadge').classList.add('hidden');
  document.getElementById('knownMalwareBadge').classList.add('hidden');
  const feedbackStatusEl = document.getElementById('feedbackStatus');
  if (feedbackStatusEl) feedbackStatusEl.classList.add('hidden');
  const impBadge = document.getElementById('impersonationBadge');
  if (impBadge) impBadge.classList.add('hidden');
  const packerBadge = document.getElementById('packerBadge');
  if (packerBadge) packerBadge.classList.add('hidden');
  if (risk.zero_day_indicator) {
    document.getElementById('zeroDayBadge').classList.remove('hidden');
  }
  if (manifest.signature_yara && manifest.signature_yara.is_known_malware) {
    document.getElementById('knownMalwareBadge').classList.remove('hidden');
  }
  // Packer detection is one YARA rule among dozens on a heavily-flagged sample —
  // easy to miss scrolling the YARA tab. Pull it out to its own top-level badge,
  // same treatment as the impersonation/zero-day findings above. The rule's
  // description carries the specific family ("...matched: iJiami") since YARA
  // itself only reports the generic rule name.
  if (packerBadge && manifest.signature_yara) {
    const packerMatch = (manifest.signature_yara.yara_matches || [])
      .find(y => y.rule_name === 'AndroidPacker_KnownStubs');
    if (packerMatch) {
      const familyMatch = /matched:\s*(.+)$/.exec(packerMatch.description || '');
      const family = familyMatch ? familyMatch[1].trim() : 'a known packer';
      packerBadge.textContent = `Packed with ${family}`;
      packerBadge.classList.remove('hidden');
    }
  }

  // Metadata
  document.getElementById('targetPackage').textContent = manifest.target_package || 'Unknown';
  document.getElementById('targetHash').textContent = manifest.sha256 || 'Unknown';
  document.getElementById('familyBadge').textContent = manifest.predicted_family || 'Unclassified';
  document.getElementById('secondaryDexCount').textContent = `${manifest.secondary_dex_count || 0} payload assets`;
  const certAnomalies = manifest.cert_anomalies || [];
  const certEl = document.getElementById('certAnomalies');
  const certText = certAnomalies.length > 0 ? certAnomalies.join(', ') : 'None detected';
  certEl.textContent = certText;
  // These come straight from the cert's raw subject string and can run to a
  // full DN (CN/OU/O/L/ST) — truncate to one line like the SHA-256 hash above,
  // with the full text still reachable on hover, instead of letting a long
  // anomaly wrap into a multi-line paragraph that blows out the grid row.
  certEl.title = certAnomalies.length > 0 ? certText : '';
  certEl.className = certAnomalies.length > 0 ? 'spec-value warning truncate' : 'spec-value';

  // VirusTotal status — signature_yara is null entirely on a cache hit (Phase
  // 1.5 is skipped, see AnalysisManifest.signature_yara's docstring), which is
  // a different state from "queried and found nothing" and must read as such
  // rather than silently reusing whatever the previous sample's element showed.
  const vtEl = document.getElementById('vtStatus');
  const vtSigMatches = (manifest.signature_yara && manifest.signature_yara.signature_matches) || [];
  const vtMatch = vtSigMatches.find(s => s.source === 'VirusTotal' && s.detection_ratio);
  if (!manifest.signature_yara) {
    vtEl.textContent = 'Not queried (cached result)';
    vtEl.className = 'spec-value';
  } else if (vtMatch) {
    vtEl.textContent = vtMatch.detection_ratio + ' flagged';
    vtEl.className = 'spec-value highlight-red';
  } else {
    vtEl.textContent = 'No VirusTotal detections';
    vtEl.className = 'spec-value';
  }

  // A VT match is only actionable to click through on if VT was actually
  // queried and flagged something — not for a cache hit or a clean result,
  // where there's no VT analysis page worth sending an analyst to.
  const vtLink = document.getElementById('linkVtReport');
  if (vtLink) {
    if (vtMatch && manifest.sha256) {
      vtLink.href = `https://www.virustotal.com/gui/file/${encodeURIComponent(manifest.sha256)}`;
      vtLink.classList.remove('hidden');
    } else {
      vtLink.classList.add('hidden');
      vtLink.href = '#';
    }
  }

  // 0. Grounding — did the narrative cite anything it wasn't given?
  renderGrounding(data.grounding, data.narrative_report);

  // 1. AI Report Markdown
  const markdownText = data.narrative_report || 'No report generated.';
  renderMarkdown(document.getElementById('aiReportMarkdown'), markdownText);

  // 2. YARA + Signature Matches
  const yaraContainer = document.getElementById('yaraMatchesList');
  yaraContainer.innerHTML = '';
  const yaraMatches = (manifest.signature_yara && manifest.signature_yara.yara_matches) || [];
  const sigMatches = (manifest.signature_yara && manifest.signature_yara.signature_matches) || [];
  const totalDetections = yaraMatches.length + sigMatches.length;
  document.getElementById('yaraCount').textContent = totalDetections;

  // Render signature matches (VT / hash / cert) first
  if (sigMatches.length > 0) {
    const sigHeader = document.createElement('h5');
    sigHeader.className = 'yara-section-header';
    sigHeader.textContent = `Signature Matches (${sigMatches.length})`;
    yaraContainer.appendChild(sigHeader);

    sigMatches.forEach(sig => {
      const card = document.createElement('div');
      card.className = 'yara-match-card sig-match';
      const severityColor = sig.severity >= 0.8 ? '#ff4444' : sig.severity >= 0.5 ? '#ff8800' : '#ffcc00';
      card.innerHTML = `
        <div class="yara-card-header">
          <span class="rule-name">${esc(sig.source || sig.match_type)} Match</span>
          <span class="severity-pill" style="background: ${severityColor}22; color: ${severityColor}">Severity: ${esc(sig.severity)}</span>
        </div>
        <p class="rule-desc">${esc(sig.description || `${sig.match_type} match via ${sig.source}`)}</p>
        <div class="rule-target">
          ${sig.detection_ratio ? `<span class="vt-ratio">VT: <strong>${esc(sig.detection_ratio)}</strong></span>` : ''}
          ${sig.family ? ` &mdash; Family: <code>${esc(sig.family)}</code>` : ''}
          &mdash; Matched: <code>${esc(sig.matched_value ? sig.matched_value.substring(0, 16) + '...' : 'N/A')}</code>
        </div>
      `;
      yaraContainer.appendChild(card);
    });
  }

  // Render YARA rule matches
  if (yaraMatches.length > 0) {
    const yaraHeader = document.createElement('h5');
    yaraHeader.className = 'yara-section-header';
    yaraHeader.textContent = `YARA Rule Matches (${yaraMatches.length})`;
    yaraContainer.appendChild(yaraHeader);

    yaraMatches.forEach(rule => {
      const card = document.createElement('div');
      card.className = 'yara-match-card';
      const severityColor = rule.severity >= 0.8 ? '#ff4444' : rule.severity >= 0.5 ? '#ff8800' : '#ffcc00';
      card.innerHTML = `
        <div class="yara-card-header">
          <span class="rule-name">${esc(rule.rule_name)}</span>
          <span class="severity-pill" style="background: ${severityColor}22; color: ${severityColor}">Severity: ${esc(rule.severity)}</span>
        </div>
        <p class="rule-desc">${esc(rule.description || 'Detects threat behavior pattern in DEX targets.')}</p>
        <div class="rule-target">
          Target: <code>${esc(rule.scan_target || 'dex')}</code>
          ${rule.category && rule.category !== 'unknown' ? ` &mdash; Category: <code>${esc(rule.category)}</code>` : ''}
        </div>
      `;
      yaraContainer.appendChild(card);
    });
  }

  if (totalDetections === 0) {
    yaraContainer.innerHTML = '<p class="text-muted">No YARA rule or signature matches detected.</p>';
  }

  // 3. Topology & Obfuscation
  const obf = manifest.obfuscation || {};
  document.getElementById('statEntropy').textContent = (obf.string_entropy_score || 0).toFixed(2);
  document.getElementById('statFlattening').textContent = obf.flattening_suspected ? 'TRUE' : 'FALSE';
  document.getElementById('statReflections').textContent = obf.reflection_call_count || 0;
  document.getElementById('statParseFail').textContent = ((obf.method_parse_failure_rate || 0) * 100).toFixed(1) + '%';

  // CFG stats
  document.getElementById('statCfgNodes').textContent = manifest.total_nodes_parsed || 0;
  document.getElementById('statGraphDensity').textContent = (manifest.graph_density || 0).toFixed(4);
  const subgraphCount = (manifest.behavioral_subgraphs || []).length;
  document.getElementById('statSubgraphs').textContent = subgraphCount;

  const outliersContainer = document.getElementById('outlierNodesList');
  outliersContainer.innerHTML = '';
  const outlierDetails = obf.flattening_outlier_details || [];
  if (outlierDetails.length > 0) {
    // Highest-degree first: those are the most dispatcher-shaped blocks.
    const ranked = [...outlierDetails].sort((a, b) => (b.degree || 0) - (a.degree || 0));
    ranked.slice(0, MAX_OUTLIER_CHIPS).forEach(o => {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = shortenMethodSig(o);
      chip.title = `${o.method_signature} @0x${(o.block_offset || 0).toString(16)} (degree ${o.degree})`;
      outliersContainer.appendChild(chip);
    });
    if (ranked.length > MAX_OUTLIER_CHIPS) {
      const more = document.createElement('span');
      more.className = 'chip';
      more.textContent = `+${ranked.length - MAX_OUTLIER_CHIPS} more`;
      outliersContainer.appendChild(more);
    }
  } else {
    // Cached records predate the attributed field and carry bare block offsets,
    // which cannot be resolved to a method.
    (obf.flattening_outlier_nodes || []).forEach(node => {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = `block 0x${Number(node).toString(16)}`;
      chip.title = `Block offset ${node} — owning method not recorded`;
      outliersContainer.appendChild(chip);
    });
  }
  // Show coverage note
  if (obf.coverage_note) {
    const noteEl = document.createElement('div');
    noteEl.className = 'coverage-note';
    noteEl.textContent = obf.coverage_note;
    outliersContainer.appendChild(noteEl);
  }

  // Render interactive Cytoscape graph
  renderGraphExplorer(manifest);

  // Reverse Engineering Findings (crypto / DCL / WebView / native)
  renderReFindings(manifest);

  // Dynamic verification (Phase 8, opt-in) — tab stays hidden unless it ran
  renderDynamicVerification(manifest);

  // Coverage & limitations — always computed by the backend, was never
  // rendered anywhere before this. See renderLimitations for why that mattered.
  renderLimitations(data.limitations);

  // Brand impersonation / app identity
  renderImpersonation(manifest, risk);

  // MITRE ATT&CK Mobile Technique Mapping
  renderMitreMapping(manifest);

  // Correlated samples (Neo4j graph — shared techniques / C2 infrastructure)
  renderRelatedSamples(manifest);

  // 4. Permissions Matrix
  const permContainer = document.getElementById('permissionsList');
  permContainer.innerHTML = '';
  const perms = manifest.permissions || [];
  document.getElementById('permissionCount').textContent = perms.length;

  if (perms.length === 0) {
    // Show informative warning for packed manifests
    const isPackedManifest = !manifest.target_package || manifest.target_package === '';
    const warningDiv = document.createElement('div');
    warningDiv.className = 'packed-manifest-warning';
    if (isPackedManifest) {
      warningDiv.innerHTML = `
        <h5>AndroidManifest.xml is Packed / Corrupted</h5>
        <p>This APK uses <strong>manifest obfuscation</strong> — the AndroidManifest.xml has deliberately corrupted headers,
        preventing static permission extraction. This is a common <strong>evasion technique</strong> used by banking trojans and RATs.</p>
        <p class="warning-detail">The Android runtime can still parse the manifest at install time, but static analyzers (Androguard, aapt2) cannot.
        Permissions listed in the AI narrative are inferred from <strong>behavioral analysis</strong> (forensic anchors, DEX string patterns) rather than declared manifest entries.</p>
        <div class="warning-badge">This is itself a strong malware indicator</div>
      `;
    } else {
      warningDiv.innerHTML = '<p class="text-muted">No permissions declared in this APK manifest.</p>';
    }
    permContainer.appendChild(warningDiv);
  } else {
    perms.forEach(perm => {
      const pEl = document.createElement('div');
      const isDangerous = perm.includes('SMS') || perm.includes('CAMERA') || perm.includes('ACCESSIBILITY') || perm.includes('STORAGE') || perm.includes('CONTACTS') || perm.includes('PHONE') || perm.includes('LOCATION');
      pEl.className = `perm-item ${isDangerous ? 'perm-danger' : ''}`;
      // Show short permission name
      const shortPerm = perm.replace('android.permission.', '');
      pEl.innerHTML = `<span class="perm-name">${esc(shortPerm)}</span>${isDangerous ? '<span class="perm-badge">DANGEROUS</span>' : ''}`;
      permContainer.appendChild(pEl);
    });
  }

  // 5. Risk Score Breakdown (use real API values)
  renderRiskBreakdown(manifest, risk);
  renderWhyScore(risk);
}

// Click-to-reveal evidence: what specifically produced this component's number.
// Every fact quoted here already flows in `manifest` — this is a UI feature, not
// a new analysis; it just surfaces evidence the response already carries instead
// of leaving a bare percentage bar for an analyst to take on faith.
function _componentEvidence(key, manifest, risk) {
  const perms = manifest.permissions || [];
  const matrixFlags = manifest.permission_matrix_flags || [];
  const subgraphs = manifest.behavioral_subgraphs || [];
  const sigYara = manifest.signature_yara || null;

  switch (key) {
    case 'classifier_confidence':
    case 'ttp_severity': {
      const ttps = (manifest.ttp_context || []).filter(t => (t.probability || 0) >= (t.threshold ?? 0.5));
      if (ttps.length === 0) {
        return ['No technique cleared its calibrated decision threshold — the classifier had no vote (see the "no evidence" note in Limitations) or the model is untrained.'];
      }
      return ttps.slice(0, 8).map(t =>
        `${t.technique_id} ${t.name || ''} — ${(t.probability * 100).toFixed(0)}% (threshold ${(((t.threshold ?? 0.5)) * 100).toFixed(0)}%), tactic ${t.tactic || 'unknown'}`
      );
    }
    case 'permission_api': {
      const dangerous = perms.filter(p => /SMS|CAMERA|ACCESSIBILITY|STORAGE|CONTACTS|PHONE|LOCATION/i.test(p));
      const lines = [];
      if (matrixFlags.length) lines.push(`Permission-combination patterns: ${matrixFlags.join(', ')}`);
      if (dangerous.length) lines.push(`Dangerous individual permissions: ${dangerous.map(p => p.replace('android.permission.', '')).join(', ')}`);
      return lines.length ? lines : ['No dangerous permissions or matrix patterns matched.'];
    }
    case 'forensic_anchor': {
      const counts = {};
      subgraphs.forEach(s => { counts[s.primary_behavior_flag] = (counts[s.primary_behavior_flag] || 0) + 1; });
      const behaviors = Object.entries(counts);
      if (behaviors.length === 0) return ['No forensic-dictionary behavior anchors matched in the recovered code.'];
      return behaviors.map(([flag, n]) => `${flag} — matched in ${n} method${n === 1 ? '' : 's'}`);
    }
    case 'obfuscation': {
      const obf = manifest.obfuscation || {};
      const lines = [];
      if (obf.manifest_parse_failed) lines.push('AndroidManifest.xml failed to parse — treated as evasion, not absence of evidence.');
      if (obf.dex_method_count !== null && obf.dex_method_count !== undefined &&
          obf.declared_component_count !== null && obf.declared_component_count !== undefined) {
        lines.push(`${obf.dex_method_count} DEX methods recovered for ${obf.declared_component_count} declared components.`);
      }
      lines.push(obf.coverage_note || 'No coverage note recorded.');
      return lines;
    }
    case 'reputation': {
      if (manifest.cache_hit) return ['Hot-path cache hit — reputation carried over from this SHA-256\'s prior analysis.'];
      const vt = (sigYara?.signature_matches || []).find(s => s.source === 'VirusTotal' && s.detection_ratio);
      return vt ? [`VirusTotal: ${vt.detection_ratio} engines flagged this hash.`] : ['No VirusTotal signature match (online lookups may be disabled, or the hash is unseen).'];
    }
    case 'ioc': {
      const lines = [];
      if ((manifest.c2_indicators || []).length) lines.push(`Extracted C2 endpoints: ${manifest.c2_indicators.join(', ')}`);
      if ((manifest.cert_anomalies || []).length) lines.push(`Certificate anomalies: ${manifest.cert_anomalies.join(', ')}`);
      if (manifest.secondary_dex_count) lines.push(`${manifest.secondary_dex_count} secondary/hidden DEX payload(s).`);
      if ((manifest.dropper_signals || []).length) lines.push(`Dropper signals: ${manifest.dropper_signals.join(', ')}`);
      const yaraCount = (sigYara?.yara_matches || []).length;
      if (yaraCount) lines.push(`${yaraCount} YARA rule match${yaraCount === 1 ? '' : 'es'}.`);
      return lines.length ? lines : ['No IoC signals matched.'];
    }
    default:
      return [];
  }
}

// Caps must match the weights in app/reports/scoring.py's compute_risk_score
// (classifier*25, permission*20, ttp*15, anchor*15, obfuscation*15, reputation*5, ioc*5 — sums to 100).
// Shared by the full Risk Scoring tab breakdown and the "Why This Score" preview
// on the overview card, so the two never drift out of sync.
function _riskComponents(risk) {
  return [
    { key: 'permission_api', name: 'Permission & API Analysis', score: risk.permission_api_component, max: 20 },
    { key: 'forensic_anchor', name: 'Forensic Anchor Matching', score: risk.forensic_anchor_component, max: 15 },
    { key: 'obfuscation', name: 'Obfuscation Signals', score: risk.obfuscation_component, max: 15 },
    { key: 'reputation', name: 'Reputation & VT Engine Hits', score: risk.reputation_component, max: 5 },
    { key: 'ioc', name: 'IoC Match Component', score: risk.ioc_component, max: 5 },
    { key: 'ttp_severity', name: 'TTP Severity', score: risk.ttp_severity_component, max: 15 },
    { key: 'classifier_confidence', name: 'Classifier Confidence', score: risk.classifier_confidence_component, max: 25 },
  ];
}

function renderWhyScore(risk) {
  const section = document.getElementById('whyScoreSection');
  const list = document.getElementById('whyScoreList');
  if (!section || !list) return;

  // Top 3 by actual points contributed, not by percent-of-max — a maxed-out
  // 5-point component shouldn't outrank a 20-point component sitting at 80%.
  // Zero/null components are dropped so a mostly-unscored historical record
  // doesn't surface three meaningless zero-length bars.
  const top = _riskComponents(risk)
    .filter(c => typeof c.score === 'number' && c.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3);

  if (top.length === 0) {
    section.classList.add('hidden');
    return;
  }
  section.classList.remove('hidden');
  list.innerHTML = top.map(c => {
    const pct = Math.min(100, (c.score / c.max) * 100);
    return `
      <div class="why-score-row">
        <span class="why-score-label">${esc(c.name)}</span>
        <div class="why-score-bar-track"><div class="why-score-bar-fill" style="width:${pct}%;"></div></div>
        <span class="why-score-pts">${c.score.toFixed(1)} / ${c.max}</span>
      </div>`;
  }).join('');
}

function renderRiskBreakdown(manifest, risk) {
  const breakdownContainer = document.getElementById('riskBreakdownList');
  breakdownContainer.innerHTML = '';
  const components = _riskComponents(risk);

  components.forEach(c => {
    const scoreVal = c.score !== null && c.score !== undefined ? c.score : null;
    const item = document.createElement('div');
    item.className = 'spec-item explain-item';

    const detail = document.createElement('div');
    detail.className = 'explain-detail hidden';
    const facts = _componentEvidence(c.key, manifest, risk);
    facts.forEach(fact => {
      const line = document.createElement('div');
      line.className = 'explain-fact';
      line.textContent = fact; // fact strings are built from esc()-free concatenation
                                // of attacker-influenced values above — textContent
                                // is the sink, so no innerHTML risk regardless.
      detail.appendChild(line);
    });

    const header = document.createElement('div');
    header.className = 'explain-header';
    header.setAttribute('role', 'button');
    header.setAttribute('tabindex', '0');
    header.title = 'Click to see what evidence produced this number';
    const toggle = () => detail.classList.toggle('hidden');
    header.addEventListener('click', toggle);
    header.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggle(); } });

    if (scoreVal === null) {
      header.innerHTML = `
        <span class="spec-label">${esc(c.name)} <span class="explain-caret">▸</span></span>
        <span class="spec-value code" style="opacity:0.4;">N/A</span>
      `;
      item.appendChild(header);
      const bar = document.createElement('div');
      bar.className = 'progress-bar-container';
      bar.style.height = '6px';
      bar.innerHTML = '<div class="progress-bar-fill" style="width: 0%; opacity: 0.3;"></div>';
      item.appendChild(bar);
    } else {
      const pct = Math.min(100, (scoreVal / c.max) * 100);
      const barColor = pct > 66 ? '#ff4444' : pct > 33 ? '#ff8800' : '#22c55e';
      header.innerHTML = `
        <span class="spec-label">${esc(c.name)} <span class="explain-caret">▸</span></span>
        <span class="spec-value code">${scoreVal.toFixed(2)} / ${c.max}</span>
      `;
      item.appendChild(header);
      const bar = document.createElement('div');
      bar.className = 'progress-bar-container';
      bar.style.height = '6px';
      bar.innerHTML = `<div class="progress-bar-fill" style="width: ${pct}%; background: ${barColor};"></div>`;
      item.appendChild(bar);
    }
    item.appendChild(detail);
    breakdownContainer.appendChild(item);
  });
}

// A <details>/<summary> findings list — id-prefixed as `${prefix}Details` /
// `${prefix}Count` / `${prefix}List` — collapses behind a "Show findings"
// toggle once it holds more than `threshold` entries. Below that (including
// zero, where the list holds a single .re-empty note) it's pinned open with
// the toggle chrome hidden entirely: not worth a click for 1-4 lines.
function finalizeFindingsAccordion(prefix, threshold = 4, itemSelector = '.re-finding-item') {
  const details = document.getElementById(`${prefix}Details`);
  const list = document.getElementById(`${prefix}List`);
  const countEl = document.getElementById(`${prefix}Count`);
  if (!details || !list) return;

  const n = list.querySelectorAll(itemSelector).length;
  if (n > threshold) {
    details.open = false;
    details.classList.remove('no-toggle');
    if (countEl) countEl.textContent = n;
  } else {
    details.open = true;
    details.classList.add('no-toggle');
    if (countEl) countEl.textContent = '';
  }
}

function renderReFindings(manifest) {
  const sections = [
    { key: 'reCrypto', items: manifest.resolved_crypto_configs || [] },
    { key: 'reDcl', items: manifest.resolved_dcl_targets || [] },
    { key: 'reWebview', items: manifest.resolved_webview_bridges || [] },
    { key: 'reNative', items: manifest.resolved_native_bridges || [] },
  ];

  let total = 0;
  sections.forEach(({ key, items }) => {
    const container = document.getElementById(`${key}List`);
    if (!container) return;
    container.innerHTML = '';
    total += items.length;

    if (items.length === 0) {
      container.innerHTML = '<span class="re-empty">None found</span>';
    } else {
      items.forEach(finding => {
        const item = document.createElement('div');
        item.className = 're-finding-item';
        // WEAK: flags a real risk — highlight it distinctly rather than blending
        // it into the same neutral text as an ordinary resolved finding.
        item.classList.toggle('re-finding-weak', finding.includes('WEAK:'));
        item.textContent = finding;
        container.appendChild(item);
      });
    }
    finalizeFindingsAccordion(key);
  });

  const countEl = document.getElementById('reFindingsCount');
  if (countEl) countEl.textContent = total;
}

function renderLimitations(limitations) {
  const card = document.getElementById('limitationsCard');
  const list = document.getElementById('limitationsList');
  if (!card || !list) return;

  const items = limitations || [];
  if (items.length === 0) {
    card.classList.add('hidden');
    return;
  }
  card.classList.remove('hidden');
  list.innerHTML = '';
  items.forEach(text => {
    const item = document.createElement('div');
    item.className = 'limitation-item';
    if (text.startsWith('HISTORICAL RECORD')) {
      item.classList.add('historical-record');
    }
    item.textContent = text;
    list.appendChild(item);
  });
  finalizeFindingsAccordion('limitations', 3, '.limitation-item');
}

function renderDynamicVerification(manifest) {
  const tabBtn = document.getElementById('tabBtnDynamicVerification');
  const dyn = manifest.dynamic_verification || null;

  // Hidden entirely unless this request actually asked for a dynamic pass —
  // `dynamic_verification: null` (the default for every normal analysis) is
  // not "ran and found nothing", it's "wasn't requested", and showing an
  // empty tab for that on every report would be misleading, not honest.
  if (!dyn) {
    if (tabBtn) tabBtn.classList.add('hidden');
    return;
  }
  if (tabBtn) tabBtn.classList.remove('hidden');

  setText('dynDuration', dyn.ran ? `${dyn.duration_s}s` : 'did not complete');
  const coverageEl = document.getElementById('dynCoverage');
  if (coverageEl) {
    coverageEl.textContent = dyn.coverage_note || '—';
    coverageEl.title = dyn.coverage_note || '';
  }

  // Runtime Activity Summary — always populated when ran=true, regardless of
  // whether anything matched a static prediction. Without this, a run where
  // the app simply didn't do anything predictable rendered as three empty
  // "None found" sections and nothing else, which reads as broken even when
  // it's an honest, correctly-computed negative result.
  const summaryEl = document.getElementById('dynActivitySummary');
  if (summaryEl) {
    const es = dyn.event_summary || {};
    if (!dyn.ran || Object.keys(es).length === 0) {
      summaryEl.innerHTML = '';
    } else {
      const labels = {
        hook_installed: 'hook(s) installed successfully',
        hook_error: 'hook(s) failed to install',
        network: 'network connection attempt(s)',
        sms_send: 'SMS send attempt(s)',
        dcl_class_load: 'class(es) dynamically loaded',
        accessibility_bound: 'accessibility service bind(s)',
        crypto_invoked: 'crypto API invocation(s)',
        url_accessed: 'URL(s) requested',
        file_written: 'file write(s)',
        command_executed: 'command(s) executed',
        sms_intercepted: 'incoming SMS intercepted',
        overlay_window: 'overlay window(s) drawn',
        sensitive_content_query: 'sensitive content read(s)',
        clipboard_read: 'clipboard read(s)',
        target_crashed: 'process crash(es) mid-capture',
        ready: null, // internal marker, not analyst-relevant
      };
      const parts = Object.entries(es)
        .filter(([kind]) => labels[kind] !== null)
        .map(([kind, count]) => `${count} ${labels[kind] || kind}`);
      summaryEl.innerHTML = '';
      const item = document.createElement('div');
      item.className = 're-finding-item';
      item.textContent = parts.join(' · ');
      summaryEl.appendChild(item);
    }
  }

  // Live screenshots — hidden entirely unless at least one capture succeeded.
  // Every shot (event-triggered, reaction, final) renders as one equal-width
  // grid tile rather than separate flex rows, so 2 shots or 5 shots both read
  // as a balanced row instead of a left-aligned, unevenly-sized cluster.
  const screenshotSection = document.getElementById('dynScreenshotSection');
  const screenshotGrid = document.getElementById('dynScreenshotGrid');
  const EVENT_SCREENSHOT_LABELS = {
    sms_intercepted: 'SMS Intercepted',
    overlay_window: 'Overlay Drawn',
    accessibility_bound: 'Accessibility Bound',
    dcl_class_load: 'Payload Class Loaded',
    sms_send: 'SMS Sent',
    command_executed: 'OS Command Executed',
  };
  if (screenshotSection && screenshotGrid) {
    screenshotGrid.innerHTML = '';
    // Cache-bust: the same sha256 can be re-analyzed, producing a new
    // screenshot at the same URL — without this the browser would keep
    // showing a stale cached image from an earlier run.
    const bust = '?t=' + Date.now();
    const tiles = [
      ...(dyn.event_screenshots || [])
        .filter(shot => shot.url)
        .map(shot => ({
          label: EVENT_SCREENSHOT_LABELS[shot.kind] || shot.kind,
          alt: `Live capture taken when ${shot.kind} fired`,
          url: shot.url,
        })),
      ...(dyn.screenshot_reaction_url
        ? [{ label: 'Reaction — after SMS/tap stimuli', alt: "Live capture of the app's screen shortly after the SMS/tap stimuli fired", url: dyn.screenshot_reaction_url }]
        : []),
      ...(dyn.screenshot_url
        ? [{ label: 'Final — end of capture window', alt: "Live capture of the app's screen at the end of the dynamic-verification window", url: dyn.screenshot_url }]
        : []),
    ];
    tiles.forEach(tile => {
      const item = document.createElement('div');
      item.className = 'dyn-screenshot-item';
      const label = document.createElement('div');
      label.className = 'dyn-screenshot-label';
      label.textContent = tile.label;
      const img = document.createElement('img');
      img.className = 'dyn-screenshot-img';
      img.alt = tile.alt;
      img.src = tile.url + bust;
      item.appendChild(label);
      item.appendChild(img);
      screenshotGrid.appendChild(item);
    });
    screenshotSection.classList.toggle('hidden', tiles.length === 0);
  }

  const networkList = document.getElementById('dynNetworkList');
  const dclList = document.getElementById('dynDclList');
  const nativeList = document.getElementById('dynNativeList');
  const otherList = document.getElementById('dynOtherList');
  if (!networkList || !dclList || !otherList) return;

  networkList.innerHTML = '';
  const confirmedSet = new Set(dyn.network_confirmed || []);
  const unpredictedObserved = (dyn.network_observed_all || []).filter(
    v => !confirmedSet.has(v)
  );
  const networkRows = [
    ...(dyn.network_confirmed || []).map(v => ({ text: `CONFIRMED — runtime contacted ${v}`, ok: true })),
    ...unpredictedObserved.map(v => ({ text: `OBSERVED (no matching static prediction) — runtime contacted ${v}`, ok: true })),
    ...(dyn.network_predicted_not_seen || []).map(v => ({ text: `not observed — ${v} was not contacted during the capture window`, ok: false })),
  ];
  if (networkRows.length === 0) {
    networkList.appendChild(emptyNote('No statically-extracted C2 indicators to check against, and no network connections observed at runtime.'));
  } else {
    networkRows.forEach(row => {
      const item = document.createElement('div');
      item.className = 're-finding-item';
      item.classList.toggle('re-finding-weak', row.ok);
      item.textContent = row.text;
      networkList.appendChild(item);
    });
  }
  finalizeFindingsAccordion('dynNetwork');

  dclList.innerHTML = '';
  if (dyn.dcl_payload_executed) {
    const item = document.createElement('div');
    item.className = 're-finding-item re-finding-weak';
    item.textContent = 'CONFIRMED — a resolved DexClassLoader target was observed executing at runtime'
      + (dyn.dcl_classes_loaded.length ? `: ${dyn.dcl_classes_loaded.join(', ')}` : '');
    dclList.appendChild(item);
  } else if (dyn.dcl_classes_loaded && dyn.dcl_classes_loaded.length) {
    const item = document.createElement('div');
    item.className = 're-finding-item';
    item.textContent = `Classes loaded at runtime (no static DCL target match): ${dyn.dcl_classes_loaded.join(', ')}`;
    dclList.appendChild(item);
  } else {
    dclList.appendChild(emptyNote('No dynamic class-loading observed during the capture window.'));
  }
  finalizeFindingsAccordion('dynDcl');

  if (nativeList) {
    nativeList.innerHTML = '';
    if (dyn.native_library_confirmed) {
      const item = document.createElement('div');
      item.className = 're-finding-item re-finding-weak';
      item.textContent = 'CONFIRMED — a resolved native library was observed loading at runtime'
        + ((dyn.native_libraries_loaded || []).length ? `: ${dyn.native_libraries_loaded.join(', ')}` : '');
      nativeList.appendChild(item);
    } else if (dyn.native_libraries_loaded && dyn.native_libraries_loaded.length) {
      const item = document.createElement('div');
      item.className = 're-finding-item';
      item.textContent = `Native libraries loaded at runtime (no static resolution match): ${dyn.native_libraries_loaded.join(', ')}`;
      nativeList.appendChild(item);
    } else {
      nativeList.appendChild(emptyNote('No native library loading observed during the capture window.'));
    }
    finalizeFindingsAccordion('dynNative');
  }

  otherList.innerHTML = '';
  const otherRows = [];
  if (dyn.sms_api_invoked) {
    const dests = (dyn.sms_destinations || []).join(', ');
    otherRows.push('CONFIRMED — SmsManager.sendTextMessage was invoked at runtime'
      + (dests ? ` — destination(s): ${dests}` : ''));
  }
  if (dyn.accessibility_bound) {
    const svcs = (dyn.accessibility_services || []).join(', ');
    otherRows.push('CONFIRMED — an AccessibilityService was bound at runtime'
      + (svcs ? `: ${svcs}` : ''));
  }
  if (dyn.crypto_invoked) {
    const algos = (dyn.crypto_algorithms || []).join(', ');
    otherRows.push('CONFIRMED — Cipher.doFinal was invoked at runtime'
      + (algos ? ` — algorithm(s): ${algos}` : ''));
  }
  if (otherRows.length === 0) {
    otherList.appendChild(emptyNote('No SMS, accessibility, or crypto API invocation observed during the capture window.'));
  } else {
    otherRows.forEach(text => {
      const item = document.createElement('div');
      item.className = 're-finding-item re-finding-weak';
      item.textContent = text;
      otherList.appendChild(item);
    });
  }
  finalizeFindingsAccordion('dynOther');

  const iocList = document.getElementById('dynIocList');
  if (iocList) {
    iocList.innerHTML = '';
    const iocRows = [
      ...(dyn.urls_accessed || []).map(v => `URL requested: ${v}`),
      ...(dyn.files_written || []).map(v => `File written: ${v}`),
      ...(dyn.commands_executed || []).map(v => `Command executed: ${v}`),
    ];
    if (iocRows.length === 0) {
      iocList.appendChild(emptyNote('No URLs, file writes, or command execution observed during the capture window.'));
    } else {
      iocRows.forEach(text => {
        const item = document.createElement('div');
        item.className = 're-finding-item re-finding-weak';
        item.textContent = text;
        iocList.appendChild(item);
      });
    }
    finalizeFindingsAccordion('dynIoc');
  }

  const smsInterceptList = document.getElementById('dynSmsInterceptList');
  if (smsInterceptList) {
    smsInterceptList.innerHTML = '';
    const senders = dyn.sms_intercepted || [];
    if (senders.length === 0) {
      smsInterceptList.appendChild(emptyNote('The simulated inbound SMS was not observed being parsed by this app during the capture window.'));
    } else {
      senders.forEach(sender => {
        const item = document.createElement('div');
        item.className = 're-finding-item re-finding-weak';
        item.textContent = `CONFIRMED — app parsed an incoming SMS from ${sender}`;
        smsInterceptList.appendChild(item);
      });
    }
    finalizeFindingsAccordion('dynSmsIntercept');
  }

  const overlayList = document.getElementById('dynOverlayList');
  if (overlayList) {
    overlayList.innerHTML = '';
    const types = dyn.overlay_window_types || [];
    if (!dyn.overlay_detected || types.length === 0) {
      overlayList.appendChild(emptyNote('No system/overlay-class window addition observed during the capture window.'));
    } else {
      types.forEach(t => {
        const item = document.createElement('div');
        item.className = 're-finding-item re-finding-weak';
        item.textContent = `CONFIRMED — a system/overlay-class window was drawn at runtime (${t})`;
        overlayList.appendChild(item);
      });
    }
    finalizeFindingsAccordion('dynOverlay');
  }

  const sensitiveList = document.getElementById('dynSensitiveDataList');
  if (sensitiveList) {
    sensitiveList.innerHTML = '';
    const rows = [
      ...(dyn.sensitive_content_queries || []).map(v => `Content query: ${v}`),
      ...(dyn.clipboard_read ? ['CONFIRMED — clipboard contents were read at runtime'] : []),
    ];
    if (rows.length === 0) {
      sensitiveList.appendChild(emptyNote('No contacts/call-log/SMS-history or clipboard access observed during the capture window.'));
    } else {
      rows.forEach(text => {
        const item = document.createElement('div');
        item.className = 're-finding-item re-finding-weak';
        item.textContent = text;
        sensitiveList.appendChild(item);
      });
    }
    finalizeFindingsAccordion('dynSensitiveData');
  }

  const timelineList = document.getElementById('dynTimelineList');
  if (timelineList) {
    timelineList.innerHTML = '';
    const timeline = dyn.timeline || [];
    if (timeline.length === 0) {
      timelineList.appendChild(emptyNote('No timestamped events to show (either nothing fired, or the pass did not run).'));
    } else {
      timeline.forEach(ev => {
        const item = document.createElement('div');
        item.className = 're-finding-item';
        const seconds = (ev.t / 1000).toFixed(2);
        item.textContent = `t+${seconds}s — ${ev.kind}: ${ev.value}`;
        timelineList.appendChild(item);
      });
    }
    finalizeFindingsAccordion('dynTimeline');
  }

  const crashLogcatSection = document.getElementById('dynCrashLogcatSection');
  const crashLogcatText = document.getElementById('dynCrashLogcatText');
  if (crashLogcatSection && crashLogcatText) {
    const tail = dyn.crash_logcat_tail || [];
    if (tail.length) {
      crashLogcatSection.classList.remove('hidden');
      crashLogcatText.textContent = tail.join('\n');
    } else {
      crashLogcatSection.classList.add('hidden');
    }
  }
}

function renderGrounding(grounding, narrativeText) {
  const panel = document.getElementById('groundingPanel');
  const pill = document.getElementById('groundingPill');
  const list = document.getElementById('groundingChecks');
  if (!panel || !pill || !list) return;

  list.innerHTML = '';
  panel.classList.remove('hidden');

  // A missing grounding object is NOT a pass, and must not render as one — but
  // it has two different honest explanations depending on whether a narrative
  // actually exists:
  //   - no narrative at all: the LLM call itself failed, so no check ran because
  //     there was nothing to check.
  //   - a narrative IS present but grounding is still missing: this is a cache
  //     hit on a record written before grounding results were persisted
  //     (app/graph/cache.py's _RECORD_FIELDS) — the checks DID run once, at
  //     generation time, but that result wasn't saved for this older record.
  // Conflating these ("no narrative was generated") was wrong for the second
  // case: a narrative visibly renders below this panel in exactly that scenario.
  if (!grounding) {
    pill.textContent = 'NOT CHECKED';
    pill.className = 'grounding-pill grounding-none';
    const row = document.createElement('div');
    row.className = 'grounding-check';
    row.textContent = (narrativeText && narrativeText.trim())
      ? 'This is a cached result from before grounding checks were persisted — the checks ran once at generation time, but that result was not saved for this record. Re-upload the sample to get a checked report.'
      : 'No narrative was generated, so the fabrication checks did not run.';
    list.appendChild(row);
    return;
  }

  const passed = grounding.passed_count;
  const total = grounding.total_count;
  pill.textContent = grounding.passed
    ? `GROUNDED — ${passed}/${total} CHECKS PASSED`
    : `FABRICATION DETECTED — ${passed}/${total} PASSED`;
  pill.className = 'grounding-pill ' + (grounding.passed ? 'grounding-pass' : 'grounding-fail');

  (grounding.checks || []).forEach(check => {
    const row = document.createElement('div');
    row.className = 'grounding-check ' + (check.passed ? 'ok' : 'bad');

    const mark = document.createElement('span');
    mark.className = 'mark';
    mark.textContent = check.passed ? '✓' : '✗';

    const name = document.createElement('span');
    name.textContent = check.name;

    // check.detail can quote values the model emitted, which originate in an
    // attacker-controlled sample. textContent, never innerHTML.
    const detail = document.createElement('span');
    detail.className = 'detail';
    detail.textContent = '— ' + (check.detail || '');

    row.appendChild(mark);
    row.appendChild(name);
    row.appendChild(detail);
    list.appendChild(row);
  });
}


function renderImpersonation(manifest, risk) {
  const list = document.getElementById('impersonationList');
  const coverageEl = document.getElementById('impersonationCoverage');
  const countEl = document.getElementById('impersonationCount');
  if (!list || !coverageEl) return;

  const imp = manifest.impersonation || null;
  const findings = (imp && imp.findings) || [];
  const coverage = (imp && imp.coverage) || [];

  if (countEl) countEl.textContent = findings.length;

  setText('identityLabel', manifest.app_label || 'Not recovered');
  setText('identityIconHash', manifest.icon_phash || 'No raster icon (adaptive/XML)');

  list.innerHTML = '';
  if (!imp) {
    list.appendChild(emptyNote('Impersonation checks did not run for this analysis.'));
  } else if (findings.length === 0) {
    // "No findings" and "could not check" are different answers. Say which.
    list.appendChild(emptyNote(
      coverage.length > 0
        ? 'No impersonation of the brands that could be checked — see coverage below for what could not be.'
        : 'No impersonation detected against any protected brand.'
    ));
  } else {
    findings.forEach(f => {
      // Every value below originates in the uploaded APK (package name, label,
      // certificate) or in the reference table. Built with textContent, never
      // innerHTML — a crafted sample must not be able to run script here.
      const item = document.createElement('div');
      item.className = 're-finding-item re-finding-weak';

      const head = document.createElement('div');
      head.className = 'mitre-item-header';
      const kind = document.createElement('span');
      kind.className = 'mitre-id';
      kind.textContent = (f.kind || '').replace(/_/g, ' ').toUpperCase();
      const brandEl = document.createElement('span');
      brandEl.className = 'mitre-name';
      brandEl.textContent = `impersonates ${f.brand || 'unknown brand'}`;
      head.appendChild(kind);
      head.appendChild(brandEl);

      const detail = document.createElement('p');
      detail.className = 'mitre-description';
      detail.textContent = f.detail || '';

      const compare = document.createElement('div');
      compare.className = 'rule-target';
      const observed = document.createElement('code');
      observed.textContent = f.observed || '';
      const expected = document.createElement('code');
      expected.textContent = f.expected || '';
      compare.appendChild(document.createTextNode('this APK: '));
      compare.appendChild(observed);
      compare.appendChild(document.createTextNode('  —  genuine: '));
      compare.appendChild(expected);

      item.appendChild(head);
      item.appendChild(detail);
      item.appendChild(compare);
      list.appendChild(item);
    });
  }

  coverageEl.innerHTML = '';
  if (coverage.length === 0) {
    coverageEl.appendChild(emptyNote('All four checks ran against every protected brand.'));
  } else {
    coverage.forEach(note => {
      const row = document.createElement('div');
      row.className = 're-finding-item';
      row.textContent = note;
      coverageEl.appendChild(row);
    });
  }

  // The verdict card needs to say when the score came from identity rather than
  // behaviour — otherwise a near-inert clone reads as though its code earned the band.
  const badge = document.getElementById('impersonationBadge');
  if (badge) {
    const applied = risk && risk.impersonation_floor_applied;
    badge.classList.toggle('hidden', !applied);
    if (applied) {
      const brand = findings.length ? findings[0].brand : 'a protected brand';
      badge.textContent = `Verdict raised by brand impersonation — clone of ${brand}`;
    }
  }
}


function setText(id, value) {
  const el = document.getElementById(id);
  if (el) el.textContent = value;
}


function emptyNote(text) {
  const span = document.createElement('span');
  span.className = 're-empty';
  span.textContent = text;
  return span;
}


function renderMitreMapping(manifest) {
  const container = document.getElementById('mitreMappingList');
  if (!container) return;
  container.innerHTML = '';

  const ttps = manifest.ttp_context || [];
  const countEl = document.getElementById('mitreCount');
  if (countEl) countEl.textContent = ttps.length;

  if (ttps.length === 0) {
    container.innerHTML = '<span class="re-empty">No techniques predicted for this sample</span>';
    return;
  }

  ttps.forEach(t => {
    const pct = ((t.probability || 0) * 100).toFixed(1);
    // Per-technique calibrated threshold (0.10-0.90 across the trained labels —
    // see app/api/routes.py:_build_ttp_context). Without this a 0.98 that cleared
    // a 0.10 bar and a 0.98 that cleared a 0.90 bar render as the identical bar;
    // the tick mark shows the boundary this specific row actually had to pass.
    const threshold = (typeof t.threshold === 'number') ? t.threshold : 0.5;
    const thresholdPct = (threshold * 100).toFixed(1);
    const barColor = t.probability > 0.66 ? '#ff4444' : t.probability > 0.33 ? '#ff8800' : '#22c55e';
    const item = document.createElement('div');
    item.className = 'mitre-item';
    item.innerHTML = `
      <div class="mitre-item-header">
        <span class="mitre-id">${esc(t.technique_id)}</span>
        <span class="mitre-name">${esc(t.name || 'Unknown Technique')}</span>
        <span class="mitre-tactic">${esc(t.tactic || 'Unknown Tactic')}</span>
      </div>
      <div class="progress-bar-container mitre-bar-container" style="height:6px; margin: 0.4rem 0;" title="Decision threshold for this technique: ${thresholdPct}%">
        <div class="progress-bar-fill" style="width: ${pct}%; background: ${barColor};"></div>
        <div class="threshold-tick" style="left: ${thresholdPct}%;"></div>
      </div>
      <div class="mitre-item-footer">
        <span class="spec-value code">${pct}% confidence <span class="threshold-label">&middot; threshold ${thresholdPct}%</span></span>
      </div>
      ${t.description ? `
      <details class="mitre-desc-details">
        <summary class="mitre-desc-summary">Show technique description</summary>
        <p class="mitre-description">${esc(t.description)}</p>
      </details>` : ''}
    `;
    container.appendChild(item);
  });
}

function renderRelatedSamples(manifest) {
  const container = document.getElementById('relatedSamplesList');
  const headerRow = document.getElementById('relatedSamplesHeaderRow');
  if (!container) return;
  container.innerHTML = '';

  const related = manifest.related_samples || [];
  const countEl = document.getElementById('relatedCount');
  if (countEl) countEl.textContent = related.length;

  if (related.length === 0) {
    container.innerHTML = '<span class="re-empty">No overlapping samples in the graph yet</span>';
    if (headerRow) headerRow.classList.add('hidden');
    return;
  }
  // A "Risk Score" column header shown once, above the list, instead of
  // repeating the words on every single card.
  if (headerRow) headerRow.classList.remove('hidden');

  related.forEach(r => {
    const item = document.createElement('div');
    item.className = 'related-sample-item';
    const techCount = (r.shared_techniques || []).length;
    const c2Count = (r.shared_c2 || []).length;
    const sharedTech = (r.shared_techniques || [])
      .map(t => `<span class="chip" title="MITRE ATT&CK technique ${esc(t)} — also predicted for this sample">${esc(t)}</span>`)
      .join('');
    const confirmedC2 = new Set(r.shared_c2_confirmed || []);
    const sharedC2 = (r.shared_c2 || []).map(c => {
      const isConfirmed = confirmedC2.has(c);
      const title = isConfirmed
        ? 'A dynamic pass on this other sample actually observed it contacting this indicator, not just sharing the string'
        : 'Shared as a static string only — not (yet) dynamically confirmed live on this other sample';
      return `<span class="chip chip-danger" title="${esc(title)}">${isConfirmed ? '✓ ' : ''}${esc(c)}</span>`;
    }).join('');

    // A plain-language reason this sample surfaced at all — the technique/C2
    // chips below are the evidence, this line is the one-glance takeaway.
    const reasonParts = [];
    if (techCount > 0) reasonParts.push(`${techCount} MITRE technique${techCount === 1 ? '' : 's'}`);
    if (c2Count > 0) reasonParts.push(`${c2Count} C2 indicator${c2Count === 1 ? '' : 's'}`);
    const reason = reasonParts.length
      ? `Shares ${reasonParts.join(' and ')} with this sample`
      : 'Correlated in the graph';

    item.innerHTML = `
      <div class="related-sample-header">
        <span class="mitre-name">${esc(r.app_name || r.sha256)}</span>
        ${r.family ? `<span class="mitre-tactic">${esc(r.family)}</span>` : ''}
        ${r.risk_score !== null && r.risk_score !== undefined ? `<span class="spec-value code" title="This sample's own overall risk score">${Number(r.risk_score).toFixed(1)}</span>` : ''}
      </div>
      <div class="related-sample-reason">${esc(reason)}</div>
      ${sharedTech ? `<div class="related-sample-row"><span class="spec-label">Shared techniques:</span> ${sharedTech}</div>` : ''}
      ${sharedC2 ? `<div class="related-sample-row"><span class="spec-label">Shared C2 infrastructure:</span> ${sharedC2}</div>` : ''}
    `;
    container.appendChild(item);
  });
}

let cyInstance = null;
let cyLandscapeInstance = null;

// Every graph node's id follows "type:value" (e.g. "technique:T1582",
// "cert:ABCDEF..."), matching both get_threat_landscape's Python side and
// renderGraphExplorer's client-built ids — so the raw MITRE ID / thumbprint
// is always recoverable from the id even though the node's visible label
// shows the human-readable name instead.
function formatNodeDetails(node) {
  const type = node.data('type') || '';
  const label = node.data('label') || '';
  const id = node.data('id') || '';
  const rawValue = id.includes(':') ? id.slice(id.indexOf(':') + 1) : id;

  let idHtml = '';
  if (type === 'Technique' || type === 'Certificate') {
    idHtml = `<span class="node-detail-id">${esc(rawValue)}</span>`;
  } else if (type === 'Sample' && rawValue !== 'current' && rawValue !== label) {
    idHtml = `<span class="node-detail-id">${esc(rawValue.length > 24 ? rawValue.slice(0, 20) + '…' : rawValue)}</span>`;
  }
  return `<span class="node-detail-name">${esc(type)}: ${esc(label)}</span>${idHtml}`;
}

function showNodeDetails(targetElId, node) {
  const el = document.getElementById(targetElId);
  if (el) el.innerHTML = formatNodeDetails(node);
}

function clearNodeDetails(targetElId) {
  const el = document.getElementById(targetElId);
  if (el) el.innerHTML = '';
}

const LANDSCAPE_COLORS = {
  Sample: '#eab308',
  MalwareFamily: '#84cc16',
  Technique: '#3b82f6',
  C2Indicator: '#ef4444',
  Certificate: '#a855f7',
};

async function loadThreatLandscape() {
  const container = document.getElementById('landscapeGraphContainer');
  if (!container || typeof cytoscape === 'undefined') return;
  container.innerHTML = '<div class="graph-placeholder-text">Loading from Neo4j…</div>';
  clearNodeDetails('landscapeNodeDetails');

  let elements;
  try {
    const resp = await fetch('/graph/landscape?limit=30');
    const data = await resp.json();
    elements = [...(data.nodes || []), ...(data.edges || [])];
  } catch (e) {
    container.innerHTML = '<div class="graph-placeholder-text">Failed to load graph — is the server reachable?</div>';
    return;
  }

  if (elements.length === 0) {
    container.innerHTML = '<div class="graph-placeholder-text">No cached samples in Neo4j yet — analyze a few APKs first.</div>';
    return;
  }

  container.innerHTML = '';
  if (cyLandscapeInstance) {
    cyLandscapeInstance.destroy();
  }

  cyLandscapeInstance = cytoscape({
    container: container,
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': ele => LANDSCAPE_COLORS[ele.data('type')] || '#94a3b8',
          'label': 'data(label)',
          'color': '#e2e8f0',
          'font-size': '9px',
          'text-valign': 'center',
          'text-halign': 'center',
          'text-wrap': 'wrap',
          'text-max-width': '70px',
          'width': ele => ele.data('type') === 'Sample' ? 42 : 30,
          'height': ele => ele.data('type') === 'Sample' ? 42 : 30,
          'border-width': 2,
          'border-color': 'rgba(255,255,255,0.15)',
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 1.2,
          'line-color': 'rgba(148,163,184,0.35)',
          'target-arrow-color': 'rgba(148,163,184,0.35)',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
        }
      },
      // Click-to-isolate: everything NOT in the tapped node's neighborhood
      // fades out instead of leaving the whole tangled graph lit at once.
      {
        selector: '.landscape-faded',
        style: { 'opacity': 0.08 }
      },
      {
        selector: '.landscape-highlighted',
        style: {
          'border-width': 3,
          'border-color': '#f8fafc',
          'z-index': 999,
        }
      }
    ],
    layout: {
      name: 'cose',
      animate: false,
      padding: 30,
      nodeRepulsion: 18000,
      idealEdgeLength: 130,
      componentSpacing: 80,
    }
  });

  cyLandscapeInstance.ready(() => {
    cyLandscapeInstance.fit(undefined, 30);
  });

  cyLandscapeInstance.on('tap', 'node', function (evt) {
    const node = evt.target;
    showNodeDetails('landscapeNodeDetails', node);

    const neighborhood = node.closedNeighborhood();
    cyLandscapeInstance.elements().not(neighborhood).addClass('landscape-faded').removeClass('landscape-highlighted');
    neighborhood.removeClass('landscape-faded').addClass('landscape-highlighted');
  });

  // Tap on empty canvas background clears the isolation.
  cyLandscapeInstance.on('tap', function (evt) {
    if (evt.target === cyLandscapeInstance) {
      cyLandscapeInstance.elements().removeClass('landscape-faded landscape-highlighted');
      clearNodeDetails('landscapeNodeDetails');
    }
  });
}

function relayoutLandscape(layoutName) {
  if (!cyLandscapeInstance) return;
  const opts = { name: layoutName, animate: true, animationDuration: 500, padding: 30 };
  if (layoutName === 'cose') {
    opts.nodeRepulsion = 18000;
    opts.idealEdgeLength = 130;
    opts.componentSpacing = 80;
  }
  cyLandscapeInstance.layout(opts).run();
}

// Dispatchers drawn without a surrounding subgraph, and outlier chips listed under
// the stats. An obfuscated APK produces hundreds of both; past these counts the
// panel stops being readable and the extras add nothing an analyst can act on.
const MAX_STANDALONE_OUTLIERS = 12;
const MAX_OUTLIER_CHIPS = 24;

// Condenses an attributed node ({class_name, method_name}) to "Bar.baz". Block
// offsets alone are not identifying — offset 4 exists in nearly every method — so
// anything drawn or listed for a block is labelled by its owning method.
function shortenMethodSig(o) {
  const shortClass = (o.class_name || '').split('.').pop() || o.class_name || '';
  if (!shortClass) return o.node_id || `block ${o.block_offset}`;
  return o.method_name ? `${shortClass}.${o.method_name}` : shortClass;
}

function renderGraphExplorer(manifest) {
  const container = document.getElementById('cyGraphContainer');
  if (!container || typeof cytoscape === 'undefined') return;
  clearNodeDetails('cyGraphNodeDetails');

  // This sample's own neighborhood in the same Neo4j graph the Threat
  // Landscape tab draws from — real predicted family/techniques/C2, not a
  // synthetic mock of CFG structure. Built entirely from fields already on
  // this response (no extra request needed).
  const elements = [];
  const nodeSet = new Set();

  function addNode(id, label, type) {
    if (!nodeSet.has(id)) {
      nodeSet.add(id);
      elements.push({ data: { id, label, type } });
    }
  }
  function addEdge(source, target, label) {
    elements.push({
      data: { id: `e_${source}_${target}_${Math.random().toString(36).slice(2, 6)}`, source, target, label },
    });
  }

  const sampleId = 'sample:current';
  const sampleLabel = manifest.target_package || (manifest.sha256 || 'this sample').slice(0, 16);
  addNode(sampleId, sampleLabel, 'Sample');

  if (manifest.predicted_family) {
    const famId = `family:${manifest.predicted_family}`;
    addNode(famId, manifest.predicted_family, 'MalwareFamily');
    addEdge(sampleId, famId, 'CLASSIFIED_AS_FAMILY');
  }

  (manifest.ttp_context || []).forEach(t => {
    const techId = `technique:${t.technique_id}`;
    addNode(techId, t.name || t.technique_id, 'Technique');
    addEdge(sampleId, techId, 'MAPS_TO_TECHNIQUE');
  });

  (manifest.c2_indicators || []).forEach(c2 => {
    const c2Id = `c2:${c2}`;
    addNode(c2Id, c2, 'C2Indicator');
    addEdge(sampleId, c2Id, 'CONTACTS');
  });

  if (elements.length <= 1) {
    container.innerHTML = '<div class="graph-placeholder-text">No family/technique/C2 correlations recorded for this sample</div>';
    return;
  }

  container.innerHTML = '';
  if (cyInstance) {
    cyInstance.destroy();
    cyInstance = null;
  }

  // Nothing matched. Say so, rather than drawing the placeholder SMS-malware graph
  // that used to stand in here — an invented graph on an empty result reads as a
  // finding, which is the exact failure this panel is being fixed for. A cache hit
  // also lands here, since the hot path returns no behavioral subgraphs.
  if (elements.length === 0) {
    const why = manifest.cache_hit
      ? 'Cached result — subgraph topology is only produced on a full analysis run.'
      : 'No forensic anchors matched, so there is no behavioral subgraph to draw.';
    container.innerHTML = `<div class="graph-placeholder-text">${why}</div>`;
    return;
  }

  // Drop the "run analysis" placeholder before Cytoscape mounts its canvas.
  container.innerHTML = '';

  cyInstance = cytoscape({
    container: container,
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
          'background-color': ele => LANDSCAPE_COLORS[ele.data('type')] || '#94a3b8',
          'label': 'data(label)',
          'color': '#e2e8f0',
          'font-size': '10px',
          'text-valign': 'bottom',
          'text-margin-y': 6,
          'text-wrap': 'wrap',
          'text-max-width': '90px',
          'width': ele => ele.data('type') === 'Sample' ? 46 : 30,
          'height': ele => ele.data('type') === 'Sample' ? 46 : 30,
          'border-width': 2,
          'border-color': 'rgba(255,255,255,0.15)',
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': 'rgba(148, 163, 184, 0.3)',
          'target-arrow-color': 'rgba(148, 163, 184, 0.4)',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier',
          'arrow-scale': 0.8
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-color': '#10b981',
          'border-width': 4,
          'shadow-blur': 12,
          'shadow-color': '#10b981'
        }
      }
    ],
    layout: {
      name: 'concentric',
      animate: false,
      padding: 30,
      concentric: node => node.data('type') === 'Sample' ? 2 : 1,
      levelWidth: () => 1,
    }
  });

  cyInstance.ready(() => cyInstance.fit(undefined, 30));

  cyInstance.on('tap', 'node', function(evt) {
    showNodeDetails('cyGraphNodeDetails', evt.target);
  });
  cyInstance.on('tap', function(evt) {
    if (evt.target === cyInstance) clearNodeDetails('cyGraphNodeDetails');
  });
}

function resetGraphView() {
  if (cyInstance) {
    cyInstance.fit();
    cyInstance.center();
  }
}

function relayoutGraph(layoutName) {
  if (cyInstance) {
    cyInstance.layout({
      name: layoutName,
      animate: true,
      animationDuration: 500,
      padding: 30
    }).run();
  }
}

function switchTab(tabId, btnEl) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

  // btnEl is passed explicitly from each onclick="switchTab('x', this)" rather
  // than read off the implicit global `event` object — that global is
  // non-standard outside legacy IE/Chrome inline-handler contexts, undefined
  // under strict mode, and one refactor (e.g. wiring this up via
  // addEventListener instead of an inline attribute) away from silently
  // breaking tab highlighting.
  if (btnEl) btnEl.classList.add('active');
  const targetId = 'tab' + tabId.charAt(0).toUpperCase() + tabId.slice(1);
  const targetEl = document.getElementById(targetId);
  if (targetEl) targetEl.classList.add('active');

  // Trigger Cytoscape resize when switching to topology tab
  if (tabId === 'topology' && cyInstance) {
    setTimeout(() => {
      cyInstance.resize();
      cyInstance.fit();
    }, 100);
  }

  // Threat Landscape is a global graph view, not tied to the current report —
  // lazy-load it the first time the tab is opened rather than on every result.
  if (tabId === 'threatLandscape' && !cyLandscapeInstance) {
    loadThreatLandscape();
  }
}

function toggleExportMenu() {
  const menu = document.getElementById('exportMenuList');
  const btn = document.getElementById('btnExportToggle');
  if (!menu || !btn) return;
  const opening = menu.classList.contains('hidden');
  menu.classList.toggle('hidden', !opening);
  btn.setAttribute('aria-expanded', String(opening));
}

document.addEventListener('click', (e) => {
  const menuWrap = document.getElementById('exportMenu');
  const menu = document.getElementById('exportMenuList');
  if (!menuWrap || !menu || menu.classList.contains('hidden')) return;
  if (!menuWrap.contains(e.target)) {
    menu.classList.add('hidden');
    document.getElementById('btnExportToggle')?.setAttribute('aria-expanded', 'false');
  }
});

function _downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

function exportReport(format) {
  document.getElementById('exportMenuList')?.classList.add('hidden');
  document.getElementById('btnExportToggle')?.setAttribute('aria-expanded', 'false');

  if (!currentReportData) return;
  const sha = (currentReportData.manifest && currentReportData.manifest.sha256) || 'report';
  const shortSha = sha.slice(0, 12);

  if (format === 'json') {
    _downloadBlob(JSON.stringify(currentReportData, null, 2), `guardgraph-${shortSha}.json`, 'application/json');
  } else if (format === 'markdown') {
    const md = currentReportData.narrative_report || '# No AI narrative available for this report';
    _downloadBlob(md, `guardgraph-${shortSha}.md`, 'text/markdown');
  } else if (format === 'pdf') {
    // No bundled PDF library (this project avoids pulling dependencies from a
    // CDN) — the browser's own print-to-PDF does the job with zero added
    // weight. print.css scopes what actually renders on the printed page.
    window.print();
  }
}
