// ============================================================
// Navigation
// ============================================================
function renderSteps() {
  const steps = getSteps();
  const maxReachable = maxReachableStep();
  const nav = document.getElementById('steps-nav');
  nav.innerHTML = steps.map((name, i) => {
    const cls = i === state.step ? 'active' : (i < state.step ? 'done' : '');
    const enabled = (i <= state.step) || (i <= maxReachable);
    const numContent = i < state.step ? '&#10003;' : (i + 1);
    return (i > 0 ? '<span class="step-arrow">\u203a</span>' : '') +
      `<button class="step-btn ${cls}" onclick="goToStep(${i})" ${enabled ? '' : 'disabled'}>` +
      `<span class="step-num">${numContent}</span><span>${name}</span></button>`;
  }).join('');
}

function maxReachableStep() {
  const steps = getSteps();
  // Furthest step index that can be reached via sequential validation from step 0.
  let i = 0;
  while (i < steps.length - 1 && !validateStep(i)) i++;
  return i;
}

function validateStep(stepIdx) {
  if (stepIdx === 0) {
    if (state.dns.defaultNs.length === 0 && state.dns.nameservers.length === 0) {
      return t('errAddDnsBoth');
    }
    if (state.dns.defaultNs.length === 0) {
      return t('errAddDefaultNs');
    }
    if (state.dns.nameservers.length === 0) {
      return t('errAddNs');
    }
  }
  if (stepIdx === 1) {
    if (state.proxies.length === 0 && state.proxyProviders.length === 0) {
      return t('errAddProxyOrSub');
    }
  }
  return '';
}

function setFooterError(msg) {
  const el = document.getElementById('footer-error');
  if (el) el.textContent = msg || '';
  const nextBtn = document.getElementById('btn-next');
  if (nextBtn) nextBtn.disabled = !!msg;
}

function updateFooterValidation() {
  const steps = getSteps();
  // Only validate on steps that have "Next" button.
  if (state.step >= steps.length - 1) { setFooterError(''); renderSteps(); return; }
  setFooterError(validateStep(state.step));
  renderSteps();
}

function goToStep(n) {
  const steps = getSteps();
  if (n < 0 || n >= steps.length) return;
  if (n > state.step) {
    // Prevent skipping ahead via breadcrumbs when earlier steps are invalid.
    for (let i = state.step; i < n; i++) {
      const msg = validateStep(i);
      if (msg) { setFooterError(msg); return; }
    }
  }
  state.step = n;
  document.querySelectorAll('.step-content').forEach(el => {
    el.classList.toggle('active', parseInt(el.dataset.step) === n);
  });
  renderSteps();
  document.getElementById('btn-prev').style.visibility = n === 0 ? 'hidden' : 'visible';
  const nextBtn = document.getElementById('btn-next');
  nextBtn.style.display = n === steps.length - 1 ? 'none' : '';
  if (n === 3) { renderDevices(); renderPreview(); }
  updateFooterValidation();
  window.scrollTo({top: 0, behavior: 'smooth'});
}

function nextStep() {
  const msg = validateStep(state.step);
  if (msg) { setFooterError(msg); return; }
  goToStep(state.step + 1);
}
function prevStep() { goToStep(state.step - 1); }

// ============================================================
// DNS (Step 1)
// ============================================================
function isDnsPresetActive(type, id) {
  const presets = type === 'default' ? DNS_DEFAULT_PRESETS : DNS_NS_PRESETS;
  const list = type === 'default' ? state.dns.defaultNs : state.dns.nameservers;
  return presets[id].servers.every(s => list.includes(s));
}

function renderDnsPresets(type) {
  const presets = type === 'default' ? DNS_DEFAULT_PRESETS : DNS_NS_PRESETS;
  const containerId = type === 'default' ? 'dns-default-presets' : 'dns-ns-presets';
  document.getElementById(containerId).innerHTML = Object.entries(presets).map(([id, p]) =>
    `<button class="preset-btn ${isDnsPresetActive(type, id) ? 'active' : ''}" onclick="toggleDnsPreset('${type}','${id}')">${p.label}</button>`
  ).join('');
}

function toggleDnsPreset(type, id) {
  const presets = type === 'default' ? DNS_DEFAULT_PRESETS : DNS_NS_PRESETS;
  const key = type === 'default' ? 'defaultNs' : 'nameservers';
  const servers = presets[id].servers;

  if (isDnsPresetActive(type, id)) {
    state.dns[key] = state.dns[key].filter(s => !servers.includes(s));
  } else {
    for (const s of servers) {
      if (!state.dns[key].includes(s)) state.dns[key].push(s);
    }
  }
  renderDnsPresets(type);
  renderDnsList(type);
}

function renderDnsList(type) {
  const listId = type === 'default' ? 'dns-default-list' : 'dns-ns-list';
  const arr = type === 'default' ? state.dns.defaultNs : state.dns.nameservers;
  document.getElementById(listId).innerHTML = arr.length === 0
    ? `<div class="empty">${t('emptyServers')}</div>`
    : arr.map((s, i) =>
      `<div class="list-item">` +
      `<span class="list-item-text">${escHtml(s)}</span>` +
      `<button class="remove-btn" onclick="removeDnsServer('${type}',${i})" title="${escHtml(t('removeTitle'))}">&times;</button>` +
      `</div>`
    ).join('');
  updateFooterValidation();
}

function addDnsServer(type) {
  const inputId = type === 'default' ? 'dns-default-input' : 'dns-ns-input';
  const key = type === 'default' ? 'defaultNs' : 'nameservers';
  const input = document.getElementById(inputId);
  const val = input.value.trim();
  if (!val) return;
  if (!state.dns[key].includes(val)) {
    state.dns[key].push(val);
  }
  input.value = '';
  renderDnsPresets(type);
  renderDnsList(type);
}

function removeDnsServer(type, index) {
  const key = type === 'default' ? 'defaultNs' : 'nameservers';
  state.dns[key].splice(index, 1);
  renderDnsPresets(type);
  renderDnsList(type);
}

// ============================================================
// Proxies UI (Step 2)
// ============================================================
function addProxiesFromUrls() {
  const ta = document.getElementById('proxy-urls');
  const lines = ta.value.split('\n').filter(l => l.trim());
  if (!lines.length) return;
  let added = 0, addedSubs = 0, failed = 0;
  for (const line of lines) {
    const proxy = parseProxyUrl(line);
    if (proxy) {
      proxy.name = uniqueServerName(proxy.name);
      state.proxies.push(proxy);
      added++;
      continue;
    }
    const sub = parseSubscriptionUrl(line);
    if (sub) {
      sub.name = uniqueServerName(sub.name);
      state.proxyProviders.push(sub);
      addedSubs++;
      continue;
    }
    if (!proxy) {
      failed++;
    }
  }
  ta.value = '';
  renderProxies();
  if (added) toast(t('addedServersToast', {count: added}), 'success');
  if (addedSubs) toast(t('addedSubsToast', {count: addedSubs}), 'success');
  if (failed) toast(t('failedParseToast', {count: failed}), 'error');
}

function addProxyFromFile(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    const proxy = parseWireGuardConfig(reader.result);
    if (proxy && proxy.error) {
      toast(t('proxyAddFailed'), 'error');
    } else if (proxy) {
      proxy.name = uniqueServerName(proxy.name);
      state.proxies.push(proxy);
      renderProxies();
      const isAwg = !!proxy['amnezia-wg-option'];
      const label = isAwg ? `AmneziaWG ${proxy.awgVersion || ''}`.trim() : 'WireGuard';
      toast(t('proxyAddedToast', {type: label, name: proxy.name}), 'success');
    } else {
      toast(t('proxyFileParseFailed'), 'error');
    }
    input.value = '';
  };
  reader.readAsText(file);
}

function removeProxy(index) {
  state.proxies.splice(index, 1);
  renderProxies();
}

function removeProxyProvider(index) {
  state.proxyProviders.splice(index, 1);
  renderProxies();
}

function openSubscriptionEditor(index) {
  const sub = state.proxyProviders[index];
  if (!sub) return;
  document.getElementById('subscription-edit-index').value = String(index);
  document.getElementById('subscription-edit-name').textContent = sub.name;
  document.getElementById('subscription-edit-filter').value = sub.filter || '';
  document.getElementById('subscription-edit-exclude-filter').value = sub['exclude-filter'] || '';
  document.getElementById('subscription-modal').classList.add('show');
}

function closeSubscriptionEditor() {
  document.getElementById('subscription-modal').classList.remove('show');
}

function saveSubscriptionEditor() {
  const idx = +document.getElementById('subscription-edit-index').value;
  const sub = state.proxyProviders[idx];
  if (!sub) return;
  sub.filter = document.getElementById('subscription-edit-filter').value.trim();
  sub['exclude-filter'] = document.getElementById('subscription-edit-exclude-filter').value.trim();
  closeSubscriptionEditor();
  renderProxies();
  toast(t('subUpdatedToast', {name: sub.name}), 'success');
}

function clearProxies() {
  state.proxies = [];
  state.proxyProviders = [];
  renderProxies();
}

function renderProxies() {
  const card = document.getElementById('proxy-list-card');
  const tbody = document.getElementById('proxy-tbody');
  const title = document.getElementById('proxy-list-title');
  const total = state.proxies.length + state.proxyProviders.length;
  card.style.display = total ? '' : 'none';
  if (title) title.textContent = t('proxyListTitle', {count: total});
  const proxyRows = state.proxies.map((p, i) =>
    `<tr>` +
    `<td>${escHtml(p.name)}</td>` +
    `<td><span class="type-badge type-${p.type}">${escHtml(p.type === 'wireguard' && p.awgVersion ? ('amneziawg ' + p.awgVersion) : p.type)}</span></td>` +
    `<td>${escHtml(p.server)}</td>` +
    `<td>${p.port}</td>` +
    `<td><button class="remove-btn" onclick="removeProxy(${i})" title="${escHtml(t('removeTitle'))}">&times;</button></td>` +
    `</tr>`
  );
  const subRows = state.proxyProviders.map((p, i) =>
    `<tr>` +
    `<td>${escHtml(p.name)}</td>` +
    `<td><span class="type-badge">${escHtml(t('subscriptionType'))}</span></td>` +
    `<td>${escHtml(p.url)}</td>` +
    `<td>-</td>` +
    `<td class="proxy-actions">` +
    `<button class="remove-btn edit-btn" onclick="openSubscriptionEditor(${i})" title="${escHtml(t('editTitle'))}" aria-label="${escHtml(t('editTitle'))}">&#9998;</button>` +
    `<button class="remove-btn" onclick="removeProxyProvider(${i})" title="${escHtml(t('removeTitle'))}">&times;</button>` +
    `</td>` +
    `</tr>`
  );
  tbody.innerHTML = [...proxyRows, ...subRows].join('');
  renderTargetSelects();
  updateFooterValidation();
}

// ============================================================
// Rules (Step 3)
// ============================================================
function buildTargetOptions(currentValue, includeReject) {
  let opts = '<option value="Proxy">Proxy</option>';
  for (const p of state.proxies) {
    opts += `<option value="${escHtml(p.name)}">${escHtml(p.name)}</option>`;
  }
  opts += `<option value="DIRECT">${escHtml(t('directOption'))}</option>`;
  if (includeReject) opts += `<option value="REJECT">${escHtml(t('rejectOption'))}</option>`;
  return opts;
}

function renderTargetSelects() {
  const ruleTarget = document.getElementById('rule-target');
  const matchTarget = document.getElementById('match-target');
  const prevRule = ruleTarget.value || 'Proxy';
  const prevMatch = matchTarget.value || state.matchTarget;

  ruleTarget.innerHTML = buildTargetOptions(prevRule, true);
  matchTarget.innerHTML = buildTargetOptions(prevMatch, false);

  ruleTarget.value = prevRule;
  matchTarget.value = prevMatch;
  // If previous value no longer exists, fallback to defaults
  if (!ruleTarget.value) ruleTarget.value = 'Proxy';
  if (!matchTarget.value) { matchTarget.value = 'DIRECT'; state.matchTarget = 'DIRECT'; }
}

function renderAllPresets() {
  const labelOf = p => p.labelKey ? t(p.labelKey) : p.label;
  document.getElementById('presets-services').innerHTML = Object.entries(SERVICE_PRESETS).map(([id, p]) =>
    `<button class="preset-btn ${state.activeServicePresets.has(id)?'active':''}" onclick="togglePreset('services','${id}')">${escHtml(labelOf(p))}</button>`
  ).join('');

  document.getElementById('presets-cdn').innerHTML = CDN_PROVIDERS.map(p =>
    `<button class="preset-btn ${state.activeCdnProviders.has(p.id)?'active':''}" onclick="toggleCdn('${p.id}')">${escHtml(labelOf(p))}</button>`
  ).join('');

  document.getElementById('presets-other').innerHTML = Object.entries(OTHER_PRESETS).map(([id, p]) =>
    `<button class="preset-btn ${state.activeOtherPresets.has(id)?'active':''}" onclick="togglePreset('other','${id}')">${escHtml(labelOf(p))}</button>`
  ).join('');
}

function togglePreset(category, id) {
  const presets = category === 'services' ? SERVICE_PRESETS : OTHER_PRESETS;
  const activeSet = category === 'services' ? state.activeServicePresets : state.activeOtherPresets;

  if (activeSet.has(id)) {
    activeSet.delete(id);
    const presetRules = presets[id].rules;
    state.rules = state.rules.filter(r =>
      !presetRules.some(pr => pr.type === r.type && pr.payload === r.payload && pr.target === r.target)
    );
  } else {
    activeSet.add(id);
    for (const r of presets[id].rules) {
      if (!state.rules.some(er => er.type === r.type && er.payload === r.payload)) {
        state.rules.push({...r});
      }
    }
  }
  renderAllPresets();
  renderRules();
}

function toggleCdn(id) {
  if (state.activeCdnProviders.has(id)) {
    state.activeCdnProviders.delete(id);
    state.rules = state.rules.filter(r => !(r.type === 'RULE-SET' && r.payload === 'cdn-' + id));
  } else {
    if (id === 'all') {
      // Remove all individual CDN rules
      for (const p of CDN_PROVIDERS) {
        if (p.id !== 'all') state.activeCdnProviders.delete(p.id);
      }
      state.rules = state.rules.filter(r => !(r.type === 'RULE-SET' && r.payload.startsWith('cdn-') && r.payload !== 'cdn-all'));
    } else if (state.activeCdnProviders.has('all')) {
      // Switching from "all" to individual — remove "all" first
      state.activeCdnProviders.delete('all');
      state.rules = state.rules.filter(r => !(r.type === 'RULE-SET' && r.payload === 'cdn-all'));
    }
    state.activeCdnProviders.add(id);
    state.rules.push({type: 'RULE-SET', payload: 'cdn-' + id, target: 'Proxy'});
  }
  renderAllPresets();
  renderRules();
}

function cdnProviderUrl(id) {
  const suffix = state.ipv6 ? '_plain.txt' : '_plain_ipv4.txt';
  return `https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/${id}/${id}${suffix}`;
}

function telegramProviderUrl() {
  const suffix = state.ipv6 ? '_plain.txt' : '_plain_ipv4.txt';
  return `https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/telegram/telegram${suffix}`;
}

function ruBlockedProviderUrl() {
  return 'https://cdn.jsdelivr.net/gh/shvchk/unblock-net/lists/clash/ru-blocked';
}

function addRule() {
  const type = document.getElementById('rule-type').value;
  const payload = document.getElementById('rule-payload').value.trim();
  const target = document.getElementById('rule-target').value;
  if (!payload) { toast(t('ruleValueRequired'), 'error'); return; }
  state.rules.push({type, payload, target});
  document.getElementById('rule-payload').value = '';
  renderRules();
}

function removeRule(index) {
  const removed = state.rules[index];
  state.rules.splice(index, 1);
  if (removed.type === 'RULE-SET' && removed.payload.startsWith('cdn-')) {
    state.activeCdnProviders.delete(removed.payload.slice(4));
    renderAllPresets();
  }
  renderRules();
}

function moveRule(index, dir) {
  const newIdx = index + dir;
  if (newIdx < 0 || newIdx >= state.rules.length) return;
  [state.rules[index], state.rules[newIdx]] = [state.rules[newIdx], state.rules[index]];
  renderRules();
}

function prioritizeTelegramRules() {
  const isTelegramRule = r => r.type === 'RULE-SET' && r.payload === 'telegram';
  const telegramRules = state.rules.filter(isTelegramRule);
  if (!telegramRules.length) return;
  const otherRules = state.rules.filter(r => !isTelegramRule(r));
  state.rules = [...telegramRules, ...otherRules];
}

function renderRules() {
  prioritizeTelegramRules();
  const list = document.getElementById('rules-list');
  if (!state.rules.length) {
    list.innerHTML = `<div class="empty">${escHtml(t('emptyRules'))}</div>`;
    return;
  }
  list.innerHTML = state.rules.map((r, i) => {
    const opts = buildTargetOptions(r.target, true);
    return `<div class="rule-item">` +
      `<span class="rule-text">${escHtml(r.type)},${escHtml(r.payload)}</span>` +
      `<select class="rule-target-select" onchange="changeRuleTarget(${i},this.value)">${opts}</select>` +
      `<div class="rule-actions">` +
      `<button onclick="moveRule(${i},-1)" title="${escHtml(t('moveUpTitle'))}">&#8593;</button>` +
      `<button onclick="moveRule(${i},1)" title="${escHtml(t('moveDownTitle'))}">&#8595;</button>` +
      `<button onclick="removeRule(${i})" title="${escHtml(t('removeTitle'))}">&times;</button>` +
      `</div></div>`;
  }).join('');
  // Set selected values after innerHTML is set
  state.rules.forEach((r, i) => {
    const sel = list.querySelectorAll('.rule-target-select')[i];
    if (sel) { sel.value = r.target; sel.style.color = targetColor(r.target); }
  });
}

function targetColor(v) {
  if (v === 'REJECT') return '#e74c5e';
  if (v === 'DIRECT') return '#34c77b';
  return '#267cff';
}

function changeRuleTarget(index, value) {
  state.rules[index].target = value;
  const sel = document.querySelectorAll('#rules-list .rule-target-select')[index];
  if (sel) sel.style.color = targetColor(value);
}
