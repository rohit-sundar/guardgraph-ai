let selectedFile = null;
let currentReportData = null;

document.addEventListener('DOMContentLoaded', () => {
  setupUploadEvents();
});

function setupUploadEvents() {
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const btnTestSample = document.getElementById('btnTestSample');
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

  btnTestSample.addEventListener('click', (e) => {
    e.stopPropagation();
    runSampleAnalysis();
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

async function runSampleAnalysis() {
  document.getElementById('uploadSection').classList.add('hidden');
  document.getElementById('progressSection').classList.remove('hidden');
  document.getElementById('resultsSection').classList.add('hidden');

  simulatePipelineProgress();

  try {
    const response = await fetch('/analyze_sample', { method: 'POST' });
    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}`);
    }
    const data = await response.json();
    renderResults(data);
  } catch (err) {
    alert("Error running sample analysis: " + err.message);
    document.getElementById('uploadSection').classList.remove('hidden');
    document.getElementById('progressSection').classList.add('hidden');
  }
}

async function uploadAndAnalyze(file) {
  document.getElementById('uploadSection').classList.add('hidden');
  document.getElementById('progressSection').classList.remove('hidden');
  document.getElementById('resultsSection').classList.add('hidden');

  simulatePipelineProgress();

  const formData = new FormData();
  formData.append("file", file);

  try {
    const response = await fetch('/analyze', {
      method: 'POST',
      body: formData
    });
    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}`);
    }
    const data = await response.json();
    renderResults(data);
  } catch (err) {
    alert("Analysis failed: " + err.message);
    document.getElementById('uploadSection').classList.remove('hidden');
    document.getElementById('progressSection').classList.add('hidden');
  }
}

function simulatePipelineProgress() {
  const steps = [
    { id: 'step1', pct: 15, delay: 500 },
    { id: 'step2', pct: 30, delay: 1800 },
    { id: 'step3', pct: 45, delay: 3500 },
    { id: 'step4', pct: 60, delay: 5500 },
    { id: 'step5', pct: 75, delay: 7000 },
    { id: 'step6', pct: 90, delay: 8500 },
    { id: 'step7', pct: 95, delay: 10000 },
  ];

  const fill = document.getElementById('progressBarFill');
  const percentText = document.getElementById('progressPercent');

  // Reset steps
  document.querySelectorAll('.step-item').forEach(s => s.classList.remove('active', 'completed'));
  fill.style.width = '0%';
  percentText.textContent = '0%';

  steps.forEach(({ id, pct, delay }) => {
    setTimeout(() => {
      const stepEl = document.getElementById(id);
      if (stepEl) {
        document.querySelectorAll('.step-item').forEach(s => {
          if (s !== stepEl && !s.classList.contains('completed')) {
            s.classList.remove('active');
          }
        });
        stepEl.classList.add('active');
      }
      fill.style.width = `${pct}%`;
      percentText.textContent = `${pct}%`;
    }, delay);
  });
}

function renderResults(data) {
  currentReportData = data;
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

  // Badges
  if (risk.zero_day_indicator) {
    document.getElementById('zeroDayBadge').classList.remove('hidden');
  }
  if (manifest.signature_yara && manifest.signature_yara.is_known_malware) {
    document.getElementById('knownMalwareBadge').classList.remove('hidden');
  }

  // Metadata
  document.getElementById('targetPackage').textContent = manifest.target_package || 'Unknown';
  document.getElementById('targetHash').textContent = manifest.sha256 || 'Unknown';
  document.getElementById('familyBadge').textContent = manifest.predicted_family || 'trojan.btmob/spyagent';
  document.getElementById('secondaryDexCount').textContent = `${manifest.secondary_dex_count || 0} payload assets`;
  document.getElementById('certAnomalies').textContent = (manifest.cert_anomalies || ['Self-Signed']).join(', ');

  // 1. AI Report Markdown
  const markdownText = data.narrative_report || 'No report generated.';
  document.getElementById('aiReportMarkdown').innerHTML = marked.parse(markdownText);

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
    sigHeader.textContent = `🔍 Signature Matches (${sigMatches.length})`;
    yaraContainer.appendChild(sigHeader);

    sigMatches.forEach(sig => {
      const card = document.createElement('div');
      card.className = 'yara-match-card sig-match';
      const severityColor = sig.severity >= 0.8 ? '#ff4444' : sig.severity >= 0.5 ? '#ff8800' : '#ffcc00';
      card.innerHTML = `
        <div class="yara-card-header">
          <span class="rule-name">${sig.source || sig.match_type} Match</span>
          <span class="severity-pill" style="background: ${severityColor}22; color: ${severityColor}">Severity: ${sig.severity}</span>
        </div>
        <p class="rule-desc">${sig.description || `${sig.match_type} match via ${sig.source}`}</p>
        <div class="rule-target">
          ${sig.detection_ratio ? `<span class="vt-ratio">VT: <strong>${sig.detection_ratio}</strong></span>` : ''}
          ${sig.family ? ` &mdash; Family: <code>${sig.family}</code>` : ''}
          &mdash; Matched: <code>${sig.matched_value ? sig.matched_value.substring(0, 16) + '...' : 'N/A'}</code>
        </div>
      `;
      yaraContainer.appendChild(card);
    });

    // Update VT status from actual data
    if (sigMatches[0] && sigMatches[0].detection_ratio) {
      document.getElementById('vtStatus').textContent = sigMatches[0].detection_ratio + ' Engines Flagged';
    }
  }

  // Render YARA rule matches
  if (yaraMatches.length > 0) {
    const yaraHeader = document.createElement('h5');
    yaraHeader.className = 'yara-section-header';
    yaraHeader.textContent = `⚡ YARA Rule Matches (${yaraMatches.length})`;
    yaraContainer.appendChild(yaraHeader);

    yaraMatches.forEach(rule => {
      const card = document.createElement('div');
      card.className = 'yara-match-card';
      const severityColor = rule.severity >= 0.8 ? '#ff4444' : rule.severity >= 0.5 ? '#ff8800' : '#ffcc00';
      card.innerHTML = `
        <div class="yara-card-header">
          <span class="rule-name">${rule.rule_name}</span>
          <span class="severity-pill" style="background: ${severityColor}22; color: ${severityColor}">Severity: ${rule.severity}</span>
        </div>
        <p class="rule-desc">${rule.description || 'Detects threat behavior pattern in DEX targets.'}</p>
        <div class="rule-target">
          Target: <code>${rule.scan_target || 'dex'}</code>
          ${rule.category && rule.category !== 'unknown' ? ` &mdash; Category: <code>${rule.category}</code>` : ''}
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
    noteEl.innerHTML = `<span class="note-icon">📋</span> ${obf.coverage_note}`;
    outliersContainer.appendChild(noteEl);
  }

  // Render interactive Cytoscape graph
  renderGraphExplorer(manifest);

  // Reverse Engineering Findings (crypto / DCL / WebView / native)
  renderReFindings(manifest);

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
        <div class="warning-icon">⚠️</div>
        <h5>AndroidManifest.xml is Packed / Corrupted</h5>
        <p>This APK uses <strong>manifest obfuscation</strong> — the AndroidManifest.xml has deliberately corrupted headers, 
        preventing static permission extraction. This is a common <strong>evasion technique</strong> used by banking trojans and RATs.</p>
        <p class="warning-detail">The Android runtime can still parse the manifest at install time, but static analyzers (Androguard, aapt2) cannot. 
        Permissions listed in the AI narrative are inferred from <strong>behavioral analysis</strong> (forensic anchors, DEX string patterns) rather than declared manifest entries.</p>
        <div class="warning-badge">🔴 This is itself a strong malware indicator</div>
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
      pEl.innerHTML = `<span class="perm-name">${shortPerm}</span>${isDangerous ? '<span class="perm-badge">⚠ DANGEROUS</span>' : ''}`;
      permContainer.appendChild(pEl);
    });
  }

  // 5. Risk Score Breakdown (use real API values)
  const breakdownContainer = document.getElementById('riskBreakdownList');
  breakdownContainer.innerHTML = '';
  // Caps must match the weights in app/reports/scoring.py's compute_risk_score
  // (classifier*25, permission*20, ttp*15, anchor*15, obfuscation*15, reputation*5, ioc*5 — sums to 100).
  const components = [
    { name: 'Permission & API Analysis', score: risk.permission_api_component, max: 20 },
    { name: 'Forensic Anchor Matching', score: risk.forensic_anchor_component, max: 15 },
    { name: 'Obfuscation Signals', score: risk.obfuscation_component, max: 15 },
    { name: 'Reputation & VT Engine Hits', score: risk.reputation_component, max: 5 },
    { name: 'IoC Match Component', score: risk.ioc_component, max: 5 },
    { name: 'TTP Severity', score: risk.ttp_severity_component, max: 15 },
    { name: 'Classifier Confidence', score: risk.classifier_confidence_component, max: 25 },
  ];

  components.forEach(c => {
    const scoreVal = c.score !== null && c.score !== undefined ? c.score : null;
    const item = document.createElement('div');
    item.className = 'spec-item';
    if (scoreVal === null) {
      item.innerHTML = `
        <div style="display:flex; justify-content:space-between; margin-bottom:0.3rem;">
          <span class="spec-label">${c.name}</span>
          <span class="spec-value code" style="opacity:0.4;">N/A</span>
        </div>
        <div class="progress-bar-container" style="height:6px;">
          <div class="progress-bar-fill" style="width: 0%; opacity: 0.3;"></div>
        </div>
      `;
    } else {
      const pct = Math.min(100, (scoreVal / c.max) * 100);
      const barColor = pct > 66 ? '#ff4444' : pct > 33 ? '#ff8800' : '#22c55e';
      item.innerHTML = `
        <div style="display:flex; justify-content:space-between; margin-bottom:0.3rem;">
          <span class="spec-label">${c.name}</span>
          <span class="spec-value code">${scoreVal.toFixed(2)} / ${c.max}</span>
        </div>
        <div class="progress-bar-container" style="height:6px;">
          <div class="progress-bar-fill" style="width: ${pct}%; background: ${barColor};"></div>
        </div>
      `;
    }
    breakdownContainer.appendChild(item);
  });
}

function renderReFindings(manifest) {
  const sections = [
    { listId: 'reCryptoList', items: manifest.resolved_crypto_configs || [] },
    { listId: 'reDclList', items: manifest.resolved_dcl_targets || [] },
    { listId: 'reWebviewList', items: manifest.resolved_webview_bridges || [] },
    { listId: 'reNativeList', items: manifest.resolved_native_bridges || [] },
  ];

  let total = 0;
  sections.forEach(({ listId, items }) => {
    const container = document.getElementById(listId);
    if (!container) return;
    container.innerHTML = '';
    total += items.length;
    if (items.length === 0) {
      container.innerHTML = '<span class="re-empty">None found</span>';
      return;
    }
    items.forEach(finding => {
      const item = document.createElement('div');
      item.className = 're-finding-item';
      // WEAK: flags a real risk — highlight it distinctly rather than blending
      // it into the same neutral text as an ordinary resolved finding.
      item.classList.toggle('re-finding-weak', finding.includes('WEAK:'));
      item.textContent = finding;
      container.appendChild(item);
    });
  });

  const countEl = document.getElementById('reFindingsCount');
  if (countEl) countEl.textContent = total;
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
    const barColor = t.probability > 0.66 ? '#ff4444' : t.probability > 0.33 ? '#ff8800' : '#22c55e';
    const item = document.createElement('div');
    item.className = 'mitre-item';
    item.innerHTML = `
      <div class="mitre-item-header">
        <span class="mitre-id">${t.technique_id}</span>
        <span class="mitre-name">${t.name || 'Unknown Technique'}</span>
        <span class="mitre-tactic">${t.tactic || 'Unknown Tactic'}</span>
      </div>
      <div class="progress-bar-container" style="height:6px; margin: 0.4rem 0;">
        <div class="progress-bar-fill" style="width: ${pct}%; background: ${barColor};"></div>
      </div>
      <div class="mitre-item-footer">
        <span class="spec-value code">${pct}% confidence</span>
        ${t.description ? `<p class="mitre-description">${t.description}</p>` : ''}
      </div>
    `;
    container.appendChild(item);
  });
}

function renderRelatedSamples(manifest) {
  const container = document.getElementById('relatedSamplesList');
  if (!container) return;
  container.innerHTML = '';

  const related = manifest.related_samples || [];
  const countEl = document.getElementById('relatedCount');
  if (countEl) countEl.textContent = related.length;

  if (related.length === 0) {
    container.innerHTML = '<span class="re-empty">No overlapping samples in the graph yet</span>';
    return;
  }

  related.forEach(r => {
    const item = document.createElement('div');
    item.className = 'related-sample-item';
    const sharedTech = (r.shared_techniques || []).map(t => `<span class="chip">${t}</span>`).join('');
    const sharedC2 = (r.shared_c2 || []).map(c => `<span class="chip chip-danger">${c}</span>`).join('');
    item.innerHTML = `
      <div class="related-sample-header">
        <span class="mitre-name">${r.app_name || r.sha256}</span>
        ${r.family ? `<span class="mitre-tactic">${r.family}</span>` : ''}
        ${r.risk_score !== null && r.risk_score !== undefined ? `<span class="spec-value code" style="margin-left:auto;">score ${Number(r.risk_score).toFixed(1)}</span>` : ''}
      </div>
      ${sharedTech ? `<div class="related-sample-row"><span class="spec-label">Shared techniques:</span> ${sharedTech}</div>` : ''}
      ${sharedC2 ? `<div class="related-sample-row"><span class="spec-label">Shared C2 infrastructure:</span> ${sharedC2}</div>` : ''}
    `;
    container.appendChild(item);
  });
}

let cyInstance = null;
let cyLandscapeInstance = null;

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
    layout: { name: 'cose', animate: false, padding: 30, nodeRepulsion: 8000, idealEdgeLength: 80 }
  });

  // Tighter initial framing than the default fit — the raw layout leaves a lot
  // of dead space around a graph this size, which makes it look smaller/emptier
  // than it is at a glance.
  cyLandscapeInstance.ready(() => {
    cyLandscapeInstance.fit(undefined, 20);
  });

  cyLandscapeInstance.on('tap', 'node', function (evt) {
    const node = evt.target;
    console.log(`${node.data('type')}: ${node.data('label')}`);

    const neighborhood = node.closedNeighborhood();
    cyLandscapeInstance.elements().not(neighborhood).addClass('landscape-faded').removeClass('landscape-highlighted');
    neighborhood.removeClass('landscape-faded').addClass('landscape-highlighted');
  });

  // Tap on empty canvas background clears the isolation.
  cyLandscapeInstance.on('tap', function (evt) {
    if (evt.target === cyLandscapeInstance) {
      cyLandscapeInstance.elements().removeClass('landscape-faded landscape-highlighted');
    }
  });
}

function relayoutLandscape(layoutName) {
  if (cyLandscapeInstance) {
    cyLandscapeInstance.layout({ name: layoutName, animate: true, animationDuration: 500, padding: 30 }).run();
  }
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

<<<<<<< HEAD
  const obf = manifest.obfuscation || {};
  const outlierNodes = obf.flattening_outlier_nodes || [];
  const subgraphs = manifest.behavioral_subgraphs || [];

  const outlierDetails = obf.flattening_outlier_details || [];

  const elements = [];
  const nodeSet = new Set();

  function addNode(id, label, type, tooltip, parent) {
    if (!nodeSet.has(id)) {
      nodeSet.add(id);
      const data = { id, label, type, tooltip };
      if (parent) data.parent = parent;
      elements.push({ data });
=======
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
>>>>>>> c47d6df938ca58831f1efa56b8729a19d1141dbd
    }
  }
  function addEdge(source, target, label) {
    elements.push({
      data: { id: `e_${source}_${target}_${Math.random().toString(36).slice(2, 6)}`, source, target, label },
    });
  }

<<<<<<< HEAD
  // Every node drawn below is a real basic block from the backend's induced
  // subgraph, and every edge is a real control transition. Behavior flag and
  // matched API are properties *of* a block, not nodes of their own.
  //
  // Subgraphs are merged per method first. Several anchors in one method produce
  // overlapping 4-hop windows over the SAME CFG, so their block ids are identical
  // by construction. Drawing them as separate components made the later ones
  // dedupe to nothing — an empty compound box — and stole the purple styling from
  // their anchors, which the earlier window had already added as plain blocks.
  const byMethod = new Map();

  subgraphs.forEach(sg => {
    const topo = sg.topology;
    if (!topo || !(topo.nodes || []).length) return;

    const key = sg.method_signature || shortenMethodSig(sg);
    let m = byMethod.get(key);
    if (!m) {
      m = {
        label: shortenMethodSig(sg),
        signature: sg.method_signature || '',
        nodes: new Map(),
        edges: new Map(),
        anchorFlags: new Map(),
        matched: new Set()
      };
      byMethod.set(key, m);
    }

    (sg.matched_apis || []).forEach(a => m.matched.add(a));

    (topo.nodes || []).forEach(n => {
      const prev = m.nodes.get(n.id);
      if (prev) {
        // Same block seen through another window: keep whichever view found it
        // interesting rather than letting the first arrival win.
        prev.is_anchor = prev.is_anchor || n.is_anchor;
        prev.is_outlier = prev.is_outlier || n.is_outlier;
      } else {
        m.nodes.set(n.id, Object.assign({}, n));
      }
      if (n.is_anchor) {
        if (!m.anchorFlags.has(n.id)) m.anchorFlags.set(n.id, new Set());
        m.anchorFlags.get(n.id).add(sg.primary_behavior_flag || 'ANCHOR');
      }
    });

    (topo.edges || []).forEach(e => m.edges.set(`${e.source}->${e.target}`, e));
  });

  const drawnMethods = new Set();
  let groupIdx = 0;

  byMethod.forEach(m => {
    const groupId = `grp_${groupIdx++}`;
    addNode(groupId, m.label, 'group', m.signature || m.label);
    if (m.signature) drawnMethods.add(m.signature);

    m.nodes.forEach(n => {
      const flags = m.anchorFlags.get(n.id);
      let type = 'normal';
      if (n.is_anchor && n.is_outlier) type = 'anchor_outlier';
      else if (n.is_anchor) type = 'anchor';
      else if (n.is_outlier) type = 'outlier';
      else if ((n.api_calls || []).some(a => m.matched.has(a))) type = 'api_block';

      const offsetHex = `0x${(n.block_offset || 0).toString(16)}`;
      // The compound parent already names the method, so an anchor shows only what
      // it anchors. Repeating the method here is what overflowed the labels.
      const label = flags ? [...flags].join('\n') : (n.label || offsetHex);

      const tipLines = [];
      if (flags) tipLines.push(`Anchor block ${offsetHex} — ${[...flags].join(', ')}`);
      else tipLines.push(`Basic block ${offsetHex}`);
      if (m.signature) tipLines.push(m.signature);
      if (n.is_outlier) tipLines.push('Flattening dispatcher (high-degree block)');
      (n.api_calls || []).forEach(a => tipLines.push(`calls ${a}`));
      (n.string_literals || []).forEach(s => tipLines.push(`"${s}"`));

      addNode(n.id, label, type, tipLines.join(' | '), groupId);
    });

    m.edges.forEach(e => {
      // Only draw transitions whose endpoints both survived the backend node cap.
      if (nodeSet.has(e.source) && nodeSet.has(e.target)) {
        addEdge(e.source, e.target, '');
      }
    });
  });

  // Flattening dispatchers in methods that produced no anchor subgraph. These have
  // no topology to sit inside, so they are drawn standalone. `node_id` is
  // method-qualified, so same-offset blocks in different classes stay distinct.
  // A real APK yields hundreds of these; they are supporting context, not the
  // subject of the panel, so take only the most dispatcher-like by degree.
  outlierDetails
    .filter(o => !drawnMethods.has(o.method_signature))
    .sort((a, b) => (b.degree || 0) - (a.degree || 0))
    .slice(0, MAX_STANDALONE_OUTLIERS)
    .forEach(o => {
      addNode(
        o.node_id,
        shortenMethodSig(o),
        'outlier',
        `Flattening dispatcher @0x${(o.block_offset || 0).toString(16)} (degree ${o.degree}) — ${o.method_signature}`
      );
    });

  // Pre-`flattening_outlier_details` responses (cached records) only carry bare
  // offsets. Nothing can be attributed from those, so label them as such.
  if (!outlierDetails.length && outlierNodes.length && !drawnMethods.size) {
    outlierNodes.forEach(nodeNum => {
      addNode(
        `outlier_${nodeNum}`,
        `block 0x${Number(nodeNum).toString(16)}`,
        'outlier',
        `Flattening dispatcher at block offset ${nodeNum} (method not recorded)`
      );
    });
=======
  const sampleId = 'sample:current';
  const sampleLabel = manifest.target_package || (manifest.sha256 || 'this sample').slice(0, 16);
  addNode(sampleId, sampleLabel, 'Sample');

  if (manifest.predicted_family) {
    const famId = `family:${manifest.predicted_family}`;
    addNode(famId, manifest.predicted_family, 'MalwareFamily');
    addEdge(sampleId, famId, 'CLASSIFIED_AS_FAMILY');
>>>>>>> c47d6df938ca58831f1efa56b8729a19d1141dbd
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
<<<<<<< HEAD
          'border-color': '#1e293b',
          'transition-property': 'background-color, line-color, target-arrow-color',
          'transition-duration': '0.3s'
        }
      },
      {
        selector: 'node[type="outlier"]',
        style: {
          'background-color': '#f43f5e',
          'border-color': '#881337',
          'border-width': 3,
          'width': 34,
          'height': 34,
          'font-weight': 'bold',
          'color': '#fda4af'
        }
      },
      {
        selector: 'node[type="anchor"]',
        style: {
          'background-color': '#a855f7',
          'border-color': '#581c87',
          'border-width': 2,
          'width': 34,
          'height': 34,
          'color': '#d8b4fe',
          'text-wrap': 'wrap',
          'text-max-width': '140px',
          'font-weight': 'bold'
        }
      },
      {
        // Anchor that is also a flattening dispatcher: suspicious behavior sitting
        // inside obfuscated control flow. Purple fill keeps it readable as an
        // anchor, red border marks the corroboration.
        selector: 'node[type="anchor_outlier"]',
        style: {
          'background-color': '#a855f7',
          'border-color': '#f43f5e',
          'border-width': 5,
          'width': 38,
          'height': 38,
          'color': '#d8b4fe',
          'text-wrap': 'wrap',
          'text-max-width': '140px',
          'font-weight': 'bold'
        }
      },
      {
        selector: 'node[type="api_block"]',
        style: {
          'background-color': '#0ea5e9',
          'border-color': '#0369a1',
          'border-width': 2,
          'width': 26,
          'height': 26,
          'color': '#7dd3fc'
=======
          'border-color': 'rgba(255,255,255,0.15)',
>>>>>>> c47d6df938ca58831f1efa56b8729a19d1141dbd
        }
      },
      {
        selector: 'node[type="group"]',
        style: {
          'background-color': 'rgba(30, 41, 59, 0.45)',
          'background-opacity': 0.45,
          'border-color': 'rgba(148, 163, 184, 0.35)',
          'border-width': 1,
          'shape': 'round-rectangle',
          'label': 'data(label)',
          'text-valign': 'top',
          'text-halign': 'center',
          'text-margin-y': -6,
          'font-size': '11px',
          'font-weight': 'bold',
          'color': '#94a3b8',
          // Obfuscated class names run to 30+ characters. Wrap them instead of
          // letting adjacent group titles overrun each other.
          'text-wrap': 'wrap',
          'text-max-width': '150px',
          'padding': '22px'
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
    const node = evt.target;
    console.log(`${node.data('type')}: ${node.data('label')}`);
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

function switchTab(tabId) {
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
  document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

  event.currentTarget.classList.add('active');
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

function copyAiReport() {
  if (currentReportData && currentReportData.narrative_report) {
    navigator.clipboard.writeText(currentReportData.narrative_report);
    alert('AI Threat Narrative Report copied to clipboard!');
  }
}
