// ============================================================
// Config Generation (Step 4)
// ============================================================
function q(s) {
  if (s === undefined || s === null) return '""';
  s = String(s);
  if (s === '' || /[:#{}[\],&*?|>!%@`'"\\\n\r\t]/.test(s) ||
      /^(true|false|yes|no|on|off|null|~)$/i.test(s) ||
      s !== s.trim() || (s.length > 0 && s === String(Number(s)))) {
    return '"' + s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n') + '"';
  }
  return s;
}

function proxyToYaml(p) {
  let y = `  - name: ${q(p.name)}\n`;
  y += `    type: ${p.type}\n`;
  y += `    server: ${q(p.server)}\n`;
  y += `    port: ${p.port}\n`;

  switch (p.type) {
    case 'vless':
      y += `    uuid: ${p.uuid}\n`;
      y += `    network: ${p.network || 'tcp'}\n`;
      if (p.tls) y += `    tls: true\n`;
      y += `    udp: true\n`;
      if (p.servername) y += `    servername: ${q(p.servername)}\n`;
      if (p['client-fingerprint']) y += `    client-fingerprint: ${p['client-fingerprint']}\n`;
      if (p.flow) y += `    flow: ${p.flow}\n`;
      if (p['reality-opts']) {
        y += `    reality-opts:\n`;
        if (p['reality-opts']['public-key']) y += `      public-key: ${p['reality-opts']['public-key']}\n`;
        if (p['reality-opts']['short-id']) y += `      short-id: ${q(p['reality-opts']['short-id'])}\n`;
      }
      if (p['ws-opts']) {
        y += `    ws-opts:\n`;
        y += `      path: ${q(p['ws-opts'].path)}\n`;
        if (p['ws-opts'].headers) {
          y += `      headers:\n`;
          for (const [k, v] of Object.entries(p['ws-opts'].headers))
            y += `        ${k}: ${q(v)}\n`;
        }
      }
      if (p['grpc-opts']) {
        y += `    grpc-opts:\n`;
        y += `      grpc-service-name: ${q(p['grpc-opts']['grpc-service-name'])}\n`;
      }
      if (p['h2-opts']) {
        y += `    h2-opts:\n`;
        y += `      path: ${q(p['h2-opts'].path)}\n`;
        y += `      host:\n`;
        for (const h of p['h2-opts'].host) y += `        - ${q(h)}\n`;
      }
      break;

    case 'vmess':
      y += `    uuid: ${p.uuid}\n`;
      y += `    alterId: ${p.alterId || 0}\n`;
      y += `    cipher: ${p.cipher || 'auto'}\n`;
      if (p.tls) y += `    tls: true\n`;
      y += `    udp: true\n`;
      if (p.servername) y += `    servername: ${q(p.servername)}\n`;
      if (p.network) {
        y += `    network: ${p.network}\n`;
        if (p['ws-opts']) {
          y += `    ws-opts:\n`;
          y += `      path: ${q(p['ws-opts'].path)}\n`;
          if (p['ws-opts'].headers) {
            y += `      headers:\n`;
            for (const [k, v] of Object.entries(p['ws-opts'].headers))
              y += `        ${k}: ${q(v)}\n`;
          }
        }
        if (p['grpc-opts']) {
          y += `    grpc-opts:\n`;
          y += `      grpc-service-name: ${q(p['grpc-opts']['grpc-service-name'])}\n`;
        }
      }
      break;

    case 'ss':
      y += `    cipher: ${p.cipher}\n`;
      y += `    password: ${q(p.password)}\n`;
      y += `    udp: true\n`;
      break;

    case 'trojan':
      y += `    password: ${q(p.password)}\n`;
      y += `    udp: true\n`;
      if (p.sni) y += `    sni: ${q(p.sni)}\n`;
      if (p['skip-cert-verify']) y += `    skip-cert-verify: true\n`;
      if (p.network) {
        y += `    network: ${p.network}\n`;
        if (p['ws-opts']) {
          y += `    ws-opts:\n`;
          y += `      path: ${q(p['ws-opts'].path)}\n`;
          if (p['ws-opts'].headers) {
            y += `      headers:\n`;
            for (const [k, v] of Object.entries(p['ws-opts'].headers))
              y += `        ${k}: ${q(v)}\n`;
          }
        }
        if (p['grpc-opts']) {
          y += `    grpc-opts:\n`;
          y += `      grpc-service-name: ${q(p['grpc-opts']['grpc-service-name'])}\n`;
        }
      }
      break;

    case 'hysteria2':
      y += `    password: ${q(p.password)}\n`;
      if (p.sni) y += `    sni: ${q(p.sni)}\n`;
      if (p['skip-cert-verify']) y += `    skip-cert-verify: true\n`;
      if (p.obfs) y += `    obfs: ${p.obfs}\n`;
      if (p['obfs-password']) y += `    obfs-password: ${q(p['obfs-password'])}\n`;
      break;

    case 'tuic':
      y += `    uuid: ${p.uuid}\n`;
      y += `    password: ${q(p.password)}\n`;
      if (p.sni) y += `    sni: ${q(p.sni)}\n`;
      if (p.alpn) {
        y += `    alpn:\n`;
        for (const a of p.alpn) y += `      - ${a}\n`;
      }
      if (p['congestion-controller']) y += `    congestion-controller: ${p['congestion-controller']}\n`;
      if (p['udp-relay-mode']) y += `    udp-relay-mode: ${p['udp-relay-mode']}\n`;
      break;

    case 'wireguard':
      y += `    ip: ${p.ip}\n`;
      y += `    private-key: ${p['private-key']}\n`;
      y += `    public-key: ${p['public-key']}\n`;
      y += `    udp: true\n`;
      if (p.mtu) y += `    mtu: ${p.mtu}\n`;
      if (p['pre-shared-key']) y += `    pre-shared-key: ${p['pre-shared-key']}\n`;
      if (p.dns) {
        y += `    dns:\n`;
        for (const d of p.dns) y += `      - ${d}\n`;
      }
      if (p['amnezia-wg-option']) {
        y += `    amnezia-wg-option:\n`;
        for (const [k, v] of Object.entries(p['amnezia-wg-option'])) {
          if (typeof v === 'number') {
            y += `      ${k}: ${v}\n`;
          } else {
            y += `      ${k}: ${q(v)}\n`;
          }
        }
      }
      break;
  }
  return y;
}

function generateConfig() {
  if (state.importedRawConfig) return generateFromImported();
  return generateFresh();
}

function generateFresh() {
  let y = '';
  const telegramEnabled = state.rules.some(r => r.type === 'RULE-SET' && r.payload === 'telegram');
  const ruBlockedEnabled = state.rules.some(r => r.type === 'RULE-SET' && r.payload === 'ru-blocked');
  const isRouterConfig = state.device === 'router';

  // General
  y += `mode: rule\n`;
  y += `ipv6: ${state.ipv6}\n`;
  y += `log-level: error\n`;
  y += `allow-lan: false\n`;
  y += `unified-delay: true\n`;
  y += `tcp-concurrent: true\n`;
  y += `external-controller: 127.0.0.1:9090\n`;
  if (isRouterConfig) {
    y += `external-ui: ./ui\n`;
    y += `external-ui-url: "https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip"\n`;
    y += `tproxy-port: 7894\n`;
    y += `routing-mark: 2\n`;
  }
  y += `\n`;

  // DNS
  y += `dns:\n`;
  y += `  enable: true\n`;
  y += `  listen: 127.0.0.1:7874\n`;
  y += `  ipv6: ${state.ipv6}\n`;
  if (state.dns.defaultNs.length) {
    y += `  default-nameserver:\n`;
    for (const ns of state.dns.defaultNs) y += `    - ${ns}\n`;
  }
  if (state.dns.nameservers.length) {
    y += `  nameserver:\n`;
    for (const ns of state.dns.nameservers) y += `    - ${q(ns)}\n`;
  }
  y += `\n`;

  // Keep-alive
  y += `keep-alive-idle: 15\n`;
  y += `keep-alive-interval: 15\n`;
  y += `\n`;

  // Profile
  y += `profile:\n`;
  y += `  store-selected: true\n`;
  y += `  tracing: false\n`;
  y += `\n`;

  // Sniffer
  y += `sniffer:\n`;
  y += `  enable: true\n`;
  y += `  force-dns-mapping: true\n`;
  y += `  parse-pure-ip: true\n`;
  y += `  sniff:\n`;
  y += `    HTTP:\n`;
  y += `      ports: [80, 8080-8880]\n`;
  y += `      override-destination: true\n`;
  y += `    TLS:\n`;
  y += `      ports: [443, 8443]\n`;
  y += `  skip-domain:\n`;
  y += `    - "Mijia Cloud"\n`;
  y += `    - '+.lan'\n`;
  y += `    - '+.local'\n`;
  y += `    - '+.push.apple.com'\n`;
  y += `    - '+.apple.com'\n`;
  y += `    - '+.msftconnecttest.com'\n`;
  y += `    - '+.3gppnetwork'\n`;
  if (telegramEnabled) {
    y += `  skip-dst-address:\n`;
    for (const cidr of TELEGRAM_SNIFFER_SKIP_DST) y += `    - ${cidr}\n`;
  }
  y += `\n`;

  // Proxies and providers
  if (state.proxies.length) {
    y += `proxies:\n`;
    for (const p of state.proxies) y += proxyToYaml(p);
    y += `\n`;
  } else {
    y += `proxies:\n`;
    y += `\n`;
  }

  if (state.proxyProviders.length) {
    y += `proxy-providers:\n`;
    for (const p of state.proxyProviders) {
      y += `  ${q(p.name)}:\n`;
      y += `    type: http\n`;
      y += `    url: ${q(p.url)}\n`;
      y += `    interval: 3600\n`;
      if (p.filter) y += `    filter: ${q(p.filter)}\n`;
      if (p['exclude-filter']) y += `    exclude-filter: ${q(p['exclude-filter'])}\n`;
    }
    y += `\n`;
  }

  if (state.proxies.length || state.proxyProviders.length) {
    const names = state.proxies.map(p => q(p.name));
    const providerNames = state.proxyProviders.map(p => q(p.name));
    y += `proxy-groups:\n`;
    y += `  - name: Proxy\n`;
    y += `    type: select\n`;
    y += `    proxies:\n`;
    for (const n of names) y += `      - ${n}\n`;
    if (!providerNames.length) y += `      - DIRECT\n`;
    if (providerNames.length) {
      y += `    use:\n`;
      for (const n of providerNames) y += `      - ${n}\n`;
    }
  } else {
    y += `proxy-groups:\n`;
  }
  y += `\n`;

  // Rule providers (geosite + CDN + Telegram + ru-blocked)
  const needTelegram = telegramEnabled;
  const needRuBlocked = ruBlockedEnabled;
  const geositeProviders = [...new Set(
    state.rules
      .filter(r => r.type === 'RULE-SET' && r.payload.startsWith('geosite-'))
      .map(r => r.payload)
  )];
  const hasProviders = state.activeCdnProviders.size > 0 || needTelegram || needRuBlocked || geositeProviders.length > 0;
  if (hasProviders) {
    y += `rule-providers:\n`;
    for (const name of geositeProviders) {
      const siteName = name.slice('geosite-'.length);
      y += `  ${name}:\n`;
      y += `    behavior: domain\n`;
      y += `    type: http\n`;
      y += `    url: "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/${siteName}.yaml"\n`;
      y += `    interval: 86400\n`;
    }
    for (const id of state.activeCdnProviders) {
      y += `  cdn-${id}:\n`;
      y += `    behavior: ipcidr\n`;
      y += `    type: http\n`;
      y += `    url: "${cdnProviderUrl(id)}"\n`;
      y += `    interval: 86400\n`;
      y += `    format: text\n`;
    }
    if (needTelegram) {
      y += `  telegram:\n`;
      y += `    behavior: ipcidr\n`;
      y += `    type: http\n`;
      y += `    url: "${telegramProviderUrl()}"\n`;
      y += `    interval: 86400\n`;
      y += `    format: text\n`;
    }
    if (needRuBlocked) {
      y += `  ru-blocked:\n`;
      y += `    behavior: domain\n`;
      y += `    type: http\n`;
      y += `    url: "${ruBlockedProviderUrl()}"\n`;
      y += `    interval: 86400\n`;
      y += `    format: text\n`;
    }
    y += `\n`;
  }

  // Rules
  y += `rules:\n`;
  for (const r of state.rules) {
    y += `  - ${r.type},${r.payload},${r.target}\n`;
  }
  if (state.matchTarget === 'Proxy') {
    for (const r of PRIVATE_NETWORK_RULES) y += `  - ${r}\n`;
  }
  y += `  - MATCH,${state.matchTarget}\n`;

  return y;
}

function generateFromImported() {
  const config = structuredClone(state.importedRawConfig);
  const telegramEnabled = state.rules.some(r => r.type === 'RULE-SET' && r.payload === 'telegram');
  const ruBlockedEnabled = state.rules.some(r => r.type === 'RULE-SET' && r.payload === 'ru-blocked');

  // Update editable top-level fields
  config.ipv6 = state.ipv6;

  // Update DNS
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

  // Rebuild proxies — strip internal fields like awgVersion
  config.proxies = state.proxies.map(p => {
    const copy = {...p};
    delete copy.awgVersion;
    return copy;
  });

  // Rebuild proxy-providers: current state providers + preserved non-HTTP providers from original
  const originalProviders = state.importedRawConfig['proxy-providers'] || {};
  const newProviders = {};
  // Keep non-HTTP providers from original
  for (const [name, pp] of Object.entries(originalProviders)) {
    if (pp.type !== 'http' || !pp.url) {
      newProviders[name] = structuredClone(pp);
    }
  }
  // Add current state providers
  for (const p of state.proxyProviders) {
    newProviders[p.name] = {
      type: 'http',
      url: p.url,
      interval: p.interval || 3600
    };
    if (p.filter) newProviders[p.name].filter = p.filter;
    if (p['exclude-filter']) newProviders[p.name]['exclude-filter'] = p['exclude-filter'];
  }
  if (Object.keys(newProviders).length) {
    config['proxy-providers'] = newProviders;
  } else {
    delete config['proxy-providers'];
  }

  // Update the "Proxy" select group in proxy-groups with current proxy/provider names
  // Preserve all other groups
  if (Array.isArray(config['proxy-groups'])) {
    const proxyGroup = config['proxy-groups'].find(g => g.name === 'Proxy');
    if (proxyGroup) {
      const proxyNames = state.proxies.map(p => p.name);
      const providerNames = state.proxyProviders.map(p => p.name);
      proxyGroup.proxies = [...proxyNames];
      if (!providerNames.length) proxyGroup.proxies.push('DIRECT');
      if (providerNames.length) {
        proxyGroup.use = [...providerNames];
      } else {
        delete proxyGroup.use;
      }
    }
  } else if (state.proxies.length || state.proxyProviders.length) {
    const proxyNames = state.proxies.map(p => p.name);
    const providerNames = state.proxyProviders.map(p => p.name);
    const proxyGroup = { name: 'Proxy', type: 'select', proxies: [...proxyNames] };
    if (!providerNames.length) proxyGroup.proxies.push('DIRECT');
    if (providerNames.length) proxyGroup.use = [...providerNames];
    config['proxy-groups'] = [proxyGroup];
  }

  // Rebuild rule-providers: preserve original ones + add/remove auto-generated ones
  const geositeProvidersImported = [...new Set(
    state.rules
      .filter(r => r.type === 'RULE-SET' && r.payload.startsWith('geosite-'))
      .map(r => r.payload)
  )];
  const autoGeneratedProviderNames = new Set();
  // geosite providers
  for (const name of geositeProvidersImported) autoGeneratedProviderNames.add(name);
  // CDN providers
  for (const id of state.activeCdnProviders) {
    autoGeneratedProviderNames.add('cdn-' + id);
  }
  if (telegramEnabled) autoGeneratedProviderNames.add('telegram');
  if (ruBlockedEnabled) autoGeneratedProviderNames.add('ru-blocked');

  const originalRuleProviders = state.importedRawConfig['rule-providers'] || {};
  const newRuleProviders = {};

  // Preserved original rule-providers that aren't auto-generated types
  const knownAutoNames = new Set();
  // Collect all possible auto-generated names
  for (const p of CDN_PROVIDERS) knownAutoNames.add('cdn-' + p.id);
  knownAutoNames.add('telegram');
  knownAutoNames.add('ru-blocked');

  for (const [name, rp] of Object.entries(originalRuleProviders)) {
    if (!knownAutoNames.has(name) && !name.startsWith('geosite-')) {
      newRuleProviders[name] = structuredClone(rp);
    }
  }

  // Add auto-generated rule-providers
  for (const name of geositeProvidersImported) {
    const siteName = name.slice('geosite-'.length);
    newRuleProviders[name] = {
      behavior: 'domain',
      type: 'http',
      url: `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/${siteName}.yaml`,
      interval: 86400
    };
  }
  for (const id of state.activeCdnProviders) {
    newRuleProviders['cdn-' + id] = {
      behavior: 'ipcidr', type: 'http',
      url: cdnProviderUrl(id), interval: 86400, format: 'text'
    };
  }
  if (telegramEnabled) {
    newRuleProviders.telegram = {
      behavior: 'ipcidr', type: 'http',
      url: telegramProviderUrl(), interval: 86400, format: 'text'
    };
  }
  if (ruBlockedEnabled) {
    newRuleProviders['ru-blocked'] = {
      behavior: 'domain', type: 'http',
      url: ruBlockedProviderUrl(), interval: 86400, format: 'text'
    };
  }

  if (Object.keys(newRuleProviders).length) {
    config['rule-providers'] = newRuleProviders;
  } else {
    delete config['rule-providers'];
  }

  // Rebuild rules
  const rules = [];
  for (const r of state.rules) {
    rules.push(`${r.type},${r.payload},${r.target}`);
  }
  if (state.matchTarget === 'Proxy') {
    for (const r of PRIVATE_NETWORK_RULES) rules.push(r);
  }
  rules.push(`MATCH,${state.matchTarget}`);
  config.rules = rules;

  // Handle sniffer skip-dst-address for telegram
  if (config.sniffer) {
    if (telegramEnabled) {
      config.sniffer['skip-dst-address'] = [...TELEGRAM_SNIFFER_SKIP_DST];
    } else {
      delete config.sniffer['skip-dst-address'];
    }
  }

  const raw = jsyaml.dump(config, {
    lineWidth: -1,
    noRefs: true,
    quotingType: '"',
    forceQuotes: false
  });

  // Insert blank lines between top-level sections (multi-line blocks)
  const lines = raw.split('\n');
  const result = [];
  let prevBlockWasMultiLine = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const isTopLevel = line.length > 0 && /^\S/.test(line);
    if (isTopLevel && i > 0) {
      // Check if the NEXT line after this top-level key is indented (making it a section start)
      const nextIsChild = i + 1 < lines.length && /^[ -]/.test(lines[i + 1]);
      // Add blank line if previous block had children OR this new key starts a section
      if (prevBlockWasMultiLine || nextIsChild) {
        if (result.length > 0 && result[result.length - 1] !== '') {
          result.push('');
        }
      }
    }
    if (isTopLevel) {
      // Determine if this top-level key has children
      prevBlockWasMultiLine = i + 1 < lines.length && /^[ -]/.test(lines[i + 1]);
    }
    result.push(line);
  }
  return result.join('\n');
}

const DEVICES = {
  pc: {
    labelKey: 'devicePcLabel',
    hintKey: 'devicePcHintHtml'
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
      // Ensure required fields
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
          // Two-part rule like MATCH,target (already handled above)
          state.rules.push({
            type: type,
            payload: parts[1].trim(),
            target: 'Proxy'
          });
        }
      }
    }
  }

  // Detect active presets
  detectActivePresets();

  // Update UI
  document.getElementById('import-btn').style.display = 'none';
  document.getElementById('import-reset-btn').style.display = '';

  renderDnsPresets('default');
  renderDnsPresets('ns');
  renderDnsList('default');
  renderDnsList('ns');
  renderProxies();
  renderAllPresets();
  renderRules();
  renderTargetSelects();
  updateFooterValidation();

  // Set match target dropdown
  const matchEl = document.getElementById('match-target');
  if (matchEl) matchEl.value = state.matchTarget;
}

function detectActivePresets() {
  state.activeServicePresets = new Set();
  state.activeOtherPresets = new Set();
  state.activeCdnProviders = new Set();

  // Check service presets
  for (const [id, preset] of Object.entries(SERVICE_PRESETS)) {
    const allMatch = preset.rules.every(pr =>
      state.rules.some(r => r.type === pr.type && r.payload === pr.payload && r.target === pr.target)
    );
    if (allMatch) state.activeServicePresets.add(id);
  }

  // Check other presets
  for (const [id, preset] of Object.entries(OTHER_PRESETS)) {
    const allMatch = preset.rules.every(pr =>
      state.rules.some(r => r.type === pr.type && r.payload === pr.payload && r.target === pr.target)
    );
    if (allMatch) state.activeOtherPresets.add(id);
  }

  // Check CDN providers
  for (const p of CDN_PROVIDERS) {
    if (state.rules.some(r => r.type === 'RULE-SET' && r.payload === 'cdn-' + p.id)) {
      state.activeCdnProviders.add(p.id);
    }
  }
}

function resetImport() {
  state.importedRawConfig = null;
  state.ipv6 = false;
  state.dns.defaultNs = ['9.9.9.9', '149.112.112.112'];
  state.dns.nameservers = ['https://dns.quad9.net/dns-query', 'tls://dns.quad9.net'];
  state.proxies = [];
  state.proxyProviders = [];
  state.rules = [];
  state.activeServicePresets = new Set();
  state.activeOtherPresets = new Set();
  state.activeCdnProviders = new Set();
  state.matchTarget = 'DIRECT';
  state.device = 'pc';

  const toggle = document.getElementById('ipv6-toggle');
  if (toggle) toggle.value = 'false';

  document.getElementById('import-btn').style.display = '';
  document.getElementById('import-reset-btn').style.display = 'none';

  renderDnsPresets('default');
  renderDnsPresets('ns');
  renderDnsList('default');
  renderDnsList('ns');
  renderProxies();
  renderAllPresets();
  renderRules();
  renderTargetSelects();
  updateFooterValidation();
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
