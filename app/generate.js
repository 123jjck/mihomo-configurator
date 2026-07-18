// ============================================================
// Config Generation (Step 4)
// ============================================================

const YAML_DUMP_OPTS = {
  lineWidth: -1,
  noRefs: true,
  quotingType: '"',
  forceQuotes: false
};

function stripProxyForExport(proxy) {
  const copy = { ...proxy };
  delete copy.awgVersion;
  return copy;
}

function ruleSetFlags() {
  return {
    telegram: state.rules.some(r => r.type === 'RULE-SET' && r.payload === 'telegram'),
    discordVoice: state.rules.some(r => r.type === 'RULE-SET' && r.payload === 'discord-voice'),
    ruBlocked: state.rules.some(r => r.type === 'RULE-SET' && r.payload === 'ru-blocked')
  };
}

function geositeProviderNames() {
  return [...new Set(
    state.rules
      .filter(r => r.type === 'RULE-SET' && r.payload.startsWith('geosite-'))
      .map(r => r.payload)
  )];
}

/** Auto-generated rule-providers for geosite / CDN / telegram / discord-voice / ru-blocked. */
function buildAutoRuleProviders() {
  const flags = ruleSetFlags();
  const providers = {};

  for (const name of geositeProviderNames()) {
    const siteName = name.slice('geosite-'.length);
    providers[name] = {
      behavior: 'domain',
      type: 'http',
      url: `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/${siteName}.yaml`,
      interval: 86400
    };
  }

  for (const id of state.activeCdnProviders) {
    providers['cdn-' + id] = {
      behavior: 'ipcidr',
      type: 'http',
      url: cdnProviderUrl(id),
      interval: 86400,
      format: 'text'
    };
  }

  if (flags.telegram) {
    providers.telegram = {
      behavior: 'ipcidr',
      type: 'http',
      url: telegramProviderUrl(),
      interval: 86400,
      format: 'text'
    };
  }

  if (flags.discordVoice) {
    providers['discord-voice'] = {
      behavior: 'ipcidr',
      type: 'http',
      url: discordVoiceProviderUrl(),
      interval: 86400,
      format: 'text'
    };
  }

  if (flags.ruBlocked) {
    providers['ru-blocked'] = {
      behavior: 'domain',
      type: 'http',
      url: ruBlockedProviderUrl(),
      interval: 86400,
      format: 'text'
    };
  }

  return providers;
}

function buildRulesList() {
  const rules = state.rules.map(r => `${r.type},${r.payload},${r.target}`);
  if (state.matchTarget === 'Proxy') {
    for (const r of PRIVATE_NETWORK_RULES) rules.push(r);
  }
  rules.push(`MATCH,${state.matchTarget}`);
  return rules;
}

function buildHttpProxyProviders() {
  const providers = {};
  for (const p of state.proxyProviders) {
    providers[p.name] = {
      type: 'http',
      url: p.url,
      interval: p.interval || 3600
    };
    if (p.filter) providers[p.name].filter = p.filter;
    if (p['exclude-filter']) providers[p.name]['exclude-filter'] = p['exclude-filter'];
  }
  return providers;
}

function buildProxySelectGroup() {
  const proxyNames = state.proxies.map(p => p.name);
  const providerNames = state.proxyProviders.map(p => p.name);
  const group = { name: 'Proxy', type: 'select', proxies: [...proxyNames] };
  if (!providerNames.length) group.proxies.push('DIRECT');
  if (providerNames.length) group.use = [...providerNames];
  return group;
}

function buildSnifferConfig(telegramEnabled) {
  const sniffer = {
    enable: true,
    'force-dns-mapping': true,
    'parse-pure-ip': true,
    'override-destination': false,
    sniff: {
      HTTP: { ports: [80, '8080-8880'], 'override-destination': false },
      TLS: { ports: [443, 8443], 'override-destination': false },
      QUIC: { ports: [443, 8443], 'override-destination': false }
    },
    'skip-domain': [
      'Mijia Cloud',
      '+.lan',
      '+.local',
      '+.push.apple.com',
      '+.apple.com',
      '+.msftconnecttest.com',
      '+.3gppnetwork'
    ]
  };
  if (telegramEnabled) {
    sniffer['skip-dst-address'] = [...TELEGRAM_SNIFFER_SKIP_DST];
  }
  return sniffer;
}

/** Dump config object to YAML with blank lines between top-level multi-line sections. */
function dumpYamlConfig(config) {
  const raw = jsyaml.dump(config, YAML_DUMP_OPTS);
  const lines = raw.split('\n');
  const result = [];
  let prevBlockWasMultiLine = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isTopLevel = line.length > 0 && /^\S/.test(line);
    if (isTopLevel && i > 0) {
      const nextIsChild = i + 1 < lines.length && /^[ -]/.test(lines[i + 1]);
      if (prevBlockWasMultiLine || nextIsChild) {
        if (result.length > 0 && result[result.length - 1] !== '') {
          result.push('');
        }
      }
    }
    if (isTopLevel) {
      prevBlockWasMultiLine = i + 1 < lines.length && /^[ -]/.test(lines[i + 1]);
    }
    result.push(line);
  }
  return result.join('\n');
}

function generateConfig() {
  if (state.importedRawConfig) return generateFromImported();
  return generateFresh();
}

function keepAliveForDevice() {
  const isMobile = state.device === 'android' || state.device === 'ios';
  return isMobile
    ? { idle: 600, interval: 30 }
    : { idle: 30, interval: 15 };
}

function generateFresh() {
  const flags = ruleSetFlags();
  const isRouterConfig = state.device === 'router';
  const keepAlive = keepAliveForDevice();
  const autoRuleProviders = buildAutoRuleProviders();

  const config = {
    mode: 'rule',
    ipv6: state.ipv6,
    'log-level': 'error',
    'allow-lan': false,
    'unified-delay': true,
    'tcp-concurrent': true,
    'external-controller': `${isRouterConfig ? '0.0.0.0' : '127.0.0.1'}:9090`
  };

  if (isRouterConfig) {
    config['external-ui'] = './ui';
    config['external-ui-url'] = 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip';
    config['tproxy-port'] = 7894;
    config['routing-mark'] = 2;
  }

  config.dns = {
    enable: true,
    listen: '127.0.0.1:7874',
    ipv6: state.ipv6
  };
  if (state.dns.defaultNs.length) {
    config.dns['default-nameserver'] = [...state.dns.defaultNs];
  }
  if (state.dns.nameservers.length) {
    config.dns.nameserver = [...state.dns.nameservers];
  }

  config['keep-alive-idle'] = keepAlive.idle;
  config['keep-alive-interval'] = keepAlive.interval;

  config.profile = {
    'store-selected': true,
    tracing: false
  };

  config.sniffer = buildSnifferConfig(flags.telegram);

  config.proxies = state.proxies.map(stripProxyForExport);

  if (state.proxyProviders.length) {
    config['proxy-providers'] = buildHttpProxyProviders();
  }

  if (state.proxies.length || state.proxyProviders.length) {
    config['proxy-groups'] = [buildProxySelectGroup()];
  } else {
    config['proxy-groups'] = [];
  }

  if (Object.keys(autoRuleProviders).length) {
    config['rule-providers'] = autoRuleProviders;
  }

  config.rules = buildRulesList();

  return dumpYamlConfig(config);
}

function generateFromImported() {
  const config = structuredClone(state.importedRawConfig);
  const flags = ruleSetFlags();
  const keepAlive = keepAliveForDevice();

  config.ipv6 = state.ipv6;
  config['external-controller'] = state.device === 'router' ? '0.0.0.0:9090' : '127.0.0.1:9090';
  config['keep-alive-idle'] = keepAlive.idle;
  config['keep-alive-interval'] = keepAlive.interval;

  if (!config.dns) config.dns = {};
  config.dns.ipv6 = state.ipv6;
  if (state.dns.defaultNs.length) {
    config.dns['default-nameserver'] = [...state.dns.defaultNs];
  } else {
    delete config.dns['default-nameserver'];
  }
  if (state.dns.nameservers.length) {
    config.dns.nameserver = [...state.dns.nameservers];
  } else {
    delete config.dns.nameserver;
  }

  config.proxies = state.proxies.map(stripProxyForExport);

  // Rebuild proxy-providers: preserve non-HTTP from original + current state HTTP providers
  const originalProviders = state.importedRawConfig['proxy-providers'] || {};
  const newProviders = {};
  for (const [name, pp] of Object.entries(originalProviders)) {
    if (pp.type !== 'http' || !pp.url) {
      newProviders[name] = structuredClone(pp);
    }
  }
  Object.assign(newProviders, buildHttpProxyProviders());
  if (Object.keys(newProviders).length) {
    config['proxy-providers'] = newProviders;
  } else {
    delete config['proxy-providers'];
  }

  // Update the "Proxy" select group; preserve all other groups
  if (Array.isArray(config['proxy-groups'])) {
    const proxyGroup = config['proxy-groups'].find(g => g.name === 'Proxy');
    if (proxyGroup) {
      const updated = buildProxySelectGroup();
      proxyGroup.proxies = updated.proxies;
      if (updated.use) {
        proxyGroup.use = updated.use;
      } else {
        delete proxyGroup.use;
      }
    }
  } else if (state.proxies.length || state.proxyProviders.length) {
    config['proxy-groups'] = [buildProxySelectGroup()];
  }

  // Rebuild rule-providers: preserve original non-auto ones + auto-generated
  const originalRuleProviders = state.importedRawConfig['rule-providers'] || {};
  const newRuleProviders = {};
  const knownAutoNames = new Set();
  for (const p of CDN_PROVIDERS) knownAutoNames.add('cdn-' + p.id);
  knownAutoNames.add('telegram');
  knownAutoNames.add('discord-voice');
  knownAutoNames.add('ru-blocked');

  for (const [name, rp] of Object.entries(originalRuleProviders)) {
    if (!knownAutoNames.has(name) && !name.startsWith('geosite-')) {
      newRuleProviders[name] = structuredClone(rp);
    }
  }
  Object.assign(newRuleProviders, buildAutoRuleProviders());

  if (Object.keys(newRuleProviders).length) {
    config['rule-providers'] = newRuleProviders;
  } else {
    delete config['rule-providers'];
  }

  config.rules = buildRulesList();

  if (config.sniffer) {
    if (flags.telegram) {
      config.sniffer['skip-dst-address'] = [...TELEGRAM_SNIFFER_SKIP_DST];
    } else {
      delete config.sniffer['skip-dst-address'];
    }
  }

  return dumpYamlConfig(config);
}

const DEVICES = {
  desktop: {
    labelKey: 'deviceDesktopLabel',
    hintKey: 'deviceDesktopHintHtml'
  },
  android: {
    labelKey: 'deviceAndroidLabel',
    hintKey: 'deviceAndroidHintHtml'
  },
  ios: {
    labelKey: 'deviceIosLabel',
    hintKey: 'deviceIosHintHtml'
  },
  router: {
    labelKey: 'deviceRouterLabel',
    hintKey: 'deviceRouterHintHtml'
  }
};

function renderDevices() {
  const labelOf = d => d.labelKey ? t(d.labelKey) : d.label;
  const hintOf = d => d.hintKey ? t(d.hintKey) : d.hint;
  document.getElementById('device-presets').innerHTML = Object.entries(DEVICES).map(([id, d]) =>
    `<button class="preset-btn ${state.device === id ? 'active' : ''}" onclick="selectDevice('${id}')">${escHtml(labelOf(d))}</button>`
  ).join('');
  document.getElementById('device-hint').innerHTML = hintOf(DEVICES[state.device]);
}

function selectDevice(id) {
  state.device = id;
  renderDevices();
  renderPreview();
}

function renderPreview() {
  document.getElementById('config-preview').textContent = generateConfig();
}

function copyConfig() {
  navigator.clipboard.writeText(generateConfig()).then(
    () => toast(t('copySuccess'), 'success'),
    () => toast(t('copyFail'), 'error')
  );
}

function downloadConfig() {
  const yaml = generateConfig();
  const blob = new Blob([yaml], {type: 'application/x-yaml'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'config.yaml';
  a.click();
  URL.revokeObjectURL(url);
  toast(t('downloadSuccess'), 'success');
}

// ============================================================
// Import Config
// ============================================================
function handleImportFile(input) {
  const file = input.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    try {
      importConfig(reader.result);
      toast(t('importSuccess'), 'success');
    } catch (e) {
      console.error('Import failed:', e);
      toast(t('importFail'), 'error');
    }
    input.value = '';
  };
  reader.readAsText(file);
}

function importConfig(yamlText) {
  const doc = jsyaml.load(yamlText);
  if (!doc || typeof doc !== 'object') throw new Error('Invalid YAML');

  state.importedRawConfig = doc;

  // IPv6
  if (typeof doc.ipv6 === 'boolean') {
    state.ipv6 = doc.ipv6;
    const toggle = document.getElementById('ipv6-toggle');
    if (toggle) toggle.value = String(state.ipv6);
  }

  // DNS
  if (doc.dns) {
    if (Array.isArray(doc.dns['default-nameserver'])) {
      state.dns.defaultNs = doc.dns['default-nameserver'].map(String);
    }
    if (Array.isArray(doc.dns.nameserver)) {
      state.dns.nameservers = doc.dns.nameserver.map(String);
    }
  }

  // Device detection
  if (doc['tproxy-port']) {
    state.device = 'router';
  }

  // Proxies
  if (Array.isArray(doc.proxies)) {
    state.proxies = doc.proxies.map(p => {
      const proxy = {...p};
      if (!proxy.name) proxy.name = proxy.type + '-' + proxy.server;
      return proxy;
    });
  }

  // Proxy providers (http type with url)
  state.proxyProviders = [];
  if (doc['proxy-providers'] && typeof doc['proxy-providers'] === 'object') {
    for (const [name, pp] of Object.entries(doc['proxy-providers'])) {
      if (pp.type === 'http' && pp.url) {
        state.proxyProviders.push({
          name: name,
          type: 'http',
          url: pp.url,
          interval: pp.interval || 3600,
          filter: pp.filter || '',
          'exclude-filter': pp['exclude-filter'] || ''
        });
      }
    }
  }

  // Rules
  state.rules = [];
  state.matchTarget = 'DIRECT';
  if (Array.isArray(doc.rules)) {
    for (const ruleStr of doc.rules) {
      const parts = String(ruleStr).split(',');
      if (parts.length >= 2) {
        const type = parts[0].trim();
        if (type === 'MATCH') {
          state.matchTarget = parts[1].trim();
          continue;
        }
        // Skip private network rules (they're auto-added)
        if (type === 'IP-CIDR' && ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12', '127.0.0.0/8'].includes(parts[1].trim()) && parts[2] && parts[2].trim() === 'DIRECT') {
          continue;
        }
        if (parts.length >= 3) {
          state.rules.push({
            type: type,
            payload: parts[1].trim(),
            target: parts.slice(2).join(',').trim()
          });
        } else {
          state.rules.push({
            type: type,
            payload: parts[1].trim(),
            target: 'Proxy'
          });
        }
      }
    }
  }

  detectActivePresets();

  document.getElementById('import-btn').style.display = 'none';
  document.getElementById('import-reset-btn').style.display = '';

  renderAll();

  const matchEl = document.getElementById('match-target');
  if (matchEl) matchEl.value = state.matchTarget;
}

function detectActivePresets() {
  state.activeServicePresets = new Set();
  state.activeExceptionPresets = new Set();
  state.activeOtherPresets = new Set();
  state.activeCdnProviders = new Set();

  for (const [presets, activeSet] of [
    [SERVICE_PRESETS, state.activeServicePresets],
    [EXCEPTION_PRESETS, state.activeExceptionPresets],
    [OTHER_PRESETS, state.activeOtherPresets]
  ]) {
    for (const [id, preset] of Object.entries(presets)) {
      const allMatch = preset.rules.every(pr =>
        state.rules.some(r => r.type === pr.type && r.payload === pr.payload && r.target === pr.target)
      );
      if (allMatch) activeSet.add(id);
    }
  }

  for (const p of CDN_PROVIDERS) {
    if (state.rules.some(r => r.type === 'RULE-SET' && r.payload === 'cdn-' + p.id)) {
      state.activeCdnProviders.add(p.id);
    }
  }
}

function resetImport() {
  const lang = state.lang;
  const step = state.step;
  Object.assign(state, initialState());
  state.lang = lang;
  state.step = step;

  const toggle = document.getElementById('ipv6-toggle');
  if (toggle) toggle.value = 'false';

  document.getElementById('import-btn').style.display = '';
  document.getElementById('import-reset-btn').style.display = 'none';

  renderAll();
}

// ============================================================
// Init
// ============================================================
function init() {
  const switcher = document.getElementById('lang-switch');
  if (switcher) {
    switcher.addEventListener('change', e => setLanguage(e.target.value));
  }
  state.lang = browserLanguage();
  setLanguage(state.lang, false);
}

init();
