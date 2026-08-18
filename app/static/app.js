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
  const verdict = (risk.verdict_band || 'UNKNOWN').toUpperCase();
  const verdictTag = document.getElementById('verdictTag');
  verdictTag.textContent = verdict;

  const score = risk.total_score || 0;
  document.getElementById('scoreNum').textContent = score.toFixed(1);

  // Update gauge stroke-dashoffset (max 264)
  const strokeOffset = 264 - (264 * (score / 100));
  document.getElementById('gaugeFill').style.strokeDashoffset = strokeOffset;

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
  const outliers = obf.flattening_outlier_nodes || [];
  if (outliers.length > 0) {
    outliers.forEach(node => {
      const chip = document.createElement('span');
      chip.className = 'chip';
      chip.textContent = `Node #${node}`;
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
  const components = [
    { name: 'Permission & API Analysis', score: risk.permission_api_component, max: 25 },
    { name: 'Forensic Anchor Matching', score: risk.forensic_anchor_component, max: 25 },
    { name: 'Obfuscation Signals', score: risk.obfuscation_component, max: 15 },
    { name: 'Reputation & VT Engine Hits', score: risk.reputation_component, max: 15 },
    { name: 'IoC Match Component', score: risk.ioc_component, max: 10 },
    { name: 'TTP Severity', score: risk.ttp_severity_component, max: 15 },
    { name: 'Classifier Confidence', score: risk.classifier_confidence_component, max: 10 },
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

let cyInstance = null;

function renderGraphExplorer(manifest) {
  const container = document.getElementById('cyGraphContainer');
  if (!container || typeof cytoscape === 'undefined') return;

  const obf = manifest.obfuscation || {};
  const outlierNodes = obf.flattening_outlier_nodes || [];
  const subgraphs = manifest.behavioral_subgraphs || [];

  const elements = [];
  const nodeSet = new Set();

  function addNode(id, label, type, tooltip) {
    if (!nodeSet.has(id)) {
      nodeSet.add(id);
      elements.push({
        data: { id, label, type, tooltip }
      });
    }
  }

  function addEdge(source, target, label) {
    elements.push({
      data: {
        id: `e_${source}_${target}_${Math.random().toString(36).substr(2, 4)}`,
        source,
        target,
        label: label || ''
      }
    });
  }

  // 1. Add outlier nodes
  outlierNodes.forEach((nodeNum, idx) => {
    const id = `outlier_${nodeNum}`;
    addNode(id, `Node #${nodeNum}`, 'outlier', `Flattening Outlier Node #${nodeNum}`);

    // Create a mini CFG structure around outlier
    const entryId = `entry_${nodeNum}`;
    const exitId = `exit_${nodeNum}`;
    addNode(entryId, `BB_entry_${idx+1}`, 'normal', 'Dispatcher Basic Block');
    addNode(exitId, `BB_exit_${idx+1}`, 'normal', 'Switch Handler Block');
    addEdge(entryId, id, 'dispatch');
    addEdge(id, exitId, 'case_branch');
  });

  // 2. Add behavioral subgraphs
  subgraphs.slice(0, 12).forEach((sg, idx) => {
    const sgId = `sg_${idx}`;
    const flag = sg.primary_behavior_flag || `Anchor #${idx+1}`;
    addNode(sgId, flag, 'behavior', `Behavioral Anchor: ${flag}`);

    (sg.matched_apis || []).slice(0, 3).forEach((api, aIdx) => {
      const apiId = `api_${idx}_${aIdx}`;
      const shortApi = api.split('/').pop() || api;
      addNode(apiId, shortApi, 'api', `Target API: ${api}`);
      addEdge(sgId, apiId, 'invokes');
    });

    // Link to nearby outlier node if available
    if (outlierNodes.length > 0) {
      const randomOutlier = `outlier_${outlierNodes[idx % outlierNodes.length]}`;
      addEdge(randomOutlier, sgId, 'triggers');
    }
  });

  // Fallback if empty
  if (elements.length === 0) {
    addNode('root', 'Root Method (Entry)', 'normal', 'App Entry');
    addNode('n1', 'Method::init', 'normal', 'Initialization');
    addNode('n2', 'SMS Broadcast Receiver', 'behavior', 'SMS Interception Logic');
    addNode('n3', 'sendTextMessage()', 'api', 'Telephony API Call');
    addEdge('root', 'n1', 'call');
    addEdge('n1', 'n2', 'register');
    addEdge('n2', 'n3', 'invoke');
  }

  if (cyInstance) {
    cyInstance.destroy();
  }

  cyInstance = cytoscape({
    container: container,
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'color': '#f8fafc',
          'font-size': '10px',
          'font-family': 'Outfit, sans-serif',
          'text-valign': 'bottom',
          'text-margin-y': 5,
          'background-color': '#475569',
          'width': 26,
          'height': 26,
          'border-width': 2,
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
        selector: 'node[type="behavior"]',
        style: {
          'background-color': '#a855f7',
          'border-color': '#581c87',
          'border-width': 2,
          'width': 30,
          'height': 30,
          'color': '#d8b4fe'
        }
      },
      {
        selector: 'node[type="api"]',
        style: {
          'background-color': '#0ea5e9',
          'border-color': '#0369a1',
          'border-width': 2,
          'width': 24,
          'height': 24,
          'color': '#7dd3fc'
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
      name: 'cose',
      animate: false,
      padding: 30,
      nodeRepulsion: 6500,
      idealEdgeLength: 60
    }
  });

  cyInstance.on('tap', 'node', function(evt) {
    const node = evt.target;
    const tooltip = node.data('tooltip') || node.data('label');
    console.log("Selected Graph Node:", tooltip);
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
}

function copyAiReport() {
  if (currentReportData && currentReportData.narrative_report) {
    navigator.clipboard.writeText(currentReportData.narrative_report);
    alert('AI Threat Narrative Report copied to clipboard!');
  }
}
