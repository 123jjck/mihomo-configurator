// ============================================================
// State
// ============================================================
const state = {
  step: 0,
  ipv6: false,
  dns: {
    defaultNs: ['9.9.9.9', '149.112.112.112'],
    nameservers: ['https://dns.quad9.net/dns-query', 'tls://dns.quad9.net']
  },
  proxies: [],
  proxyProviders: [],
  rules: [],
  activeServicePresets: new Set(),
  activeOtherPresets: new Set(),
  activeCdnProviders: new Set(),
  matchTarget: 'DIRECT',
  device: 'pc',
  lang: 'ru'
};

const SUPPORTED_LANGS = ['ru', 'en'];
const I18N = {
  ru: {
    appTitle: 'Mihomo Configurator',
    appSubtitleHtml: 'Конструктор конфигурации <a href="https://github.com/MetaCubeX/mihomo" target="_blank" style="color:#267cff">mihomo</a>',
    languageLabel: 'Язык',
    languageRu: 'Русский',
    languageEn: 'English',
    steps: ['DNS', 'Серверы', 'Правила', 'Скачать'],
    dnsTitle: 'Настройка DNS',
    dnsDesc: 'Настройте DNS-серверы для резолвинга доменов',
    dnsMainHint: 'Не рекомендуется что-либо менять на этой странице, если вы не понимаете, что делаете.',
    ipv6Label: 'IPv6',
    ipv6Disabled: 'Отключен',
    ipv6Enabled: 'Включен',
    dnsDefaultTitle: 'Default Nameservers',
    dnsDefaultHint: 'DNS-серверы (IP), через которые резолвятся адреса основных nameserver',
    dnsDefaultAdd: 'Добавить',
    dnsNsTitle: 'Nameservers',
    dnsNsHint: 'Основные DNS-серверы (DoH / DoT) для резолвинга доменов',
    dnsNsAdd: 'Добавить',
    serversTitle: 'Добавление серверов',
    serversDesc: 'Добавьте прокси-серверы из ссылок или файлов конфигурации',
    serversHint: 'Все данные обрабатываются локально в вашем браузере и никуда не передаются.',
    linksTitle: 'Из ссылок',
    linksHint: 'Вставьте ссылки по одной на строку: vless://, vmess://, ss://, trojan://, hysteria2://, hy2://, tuic:// или URL подписки https://...',
    linksAdd: 'Добавить из ссылок',
    fileTitle: 'Из файла (WireGuard / AmneziaWG)',
    fileHint: 'Загрузите .conf файл. AmneziaWG определяется автоматически.',
    proxyListTitle: 'Добавленные серверы и подписки ({count})',
    proxyClear: 'Очистить все',
    proxyThName: 'Имя',
    proxyThType: 'Тип',
    proxyThServer: 'Сервер',
    proxyThPort: 'Порт',
    rulesTitle: 'Правила маршрутизации',
    rulesDesc: 'Настройте, какой трафик проксировать, а какой направлять напрямую',
    rulesServicesTitle: 'Популярные сервисы',
    rulesCdnTitle: 'CDN',
    rulesCdnHint: 'IP-диапазоны CDN-провайдеров для проксирования',
    rulesOtherTitle: 'Прочее',
    ruleManualTitle: 'Добавить правило вручную',
    ruleAddBtn: 'Добавить',
    rulesCurrentTitle: 'Текущие правила',
    matchLabel: 'Остальной трафик (MATCH) →',
    downloadTitle: 'Скачивание конфига',
    downloadDesc: 'Выберите устройство и скачайте файл конфигурации',
    deviceTitle: 'Устройство',
    previewTitle: 'Предпросмотр',
    copyBtn: 'Копировать',
    downloadBtn: 'Скачать config.yaml',
    prevBtn: 'Назад',
    nextBtn: 'Далее',
    subModalTitle: 'Параметры подписки',
    subEditLabel: 'Подписка:',
    subFilterLabel: 'Добавить сервера со словами в названии:',
    subExcludeLabel: 'Исключить сервера со словами в названии:',
    cancelBtn: 'Отмена',
    saveBtn: 'Сохранить',
    errAddDnsBoth: 'Добавьте DNS-серверы, чтобы продолжить.',
    errAddDefaultNs: 'Добавьте Default Nameservers, чтобы продолжить.',
    errAddNs: 'Добавьте Nameservers (DoH/DoT), чтобы продолжить.',
    errAddProxyOrSub: 'Добавьте прокси-сервер или подписку, чтобы продолжить.',
    emptyServers: 'Нет серверов',
    emptyRules: 'Нет правил. Добавьте пресеты или создайте вручную.',
    removeTitle: 'Удалить',
    editTitle: 'Редактировать',
    moveUpTitle: 'Вверх',
    moveDownTitle: 'Вниз',
    directOption: 'Напрямую',
    rejectOption: 'Блокировать',
    ruleValueRequired: 'Введите значение правила',
    addedServersToast: 'Добавлено серверов: {count}',
    addedSubsToast: 'Добавлено подписок: {count}',
    failedParseToast: 'Не удалось распознать: {count}',
    proxyAddFailed: 'Не удалось добавить сервер',
    proxyAddedToast: 'Добавлен {type} сервер: {name}',
    proxyFileParseFailed: 'Не удалось распознать файл конфигурации',
    subUpdatedToast: 'Параметры подписки обновлены: {name}',
    copySuccess: 'Скопировано в буфер обмена',
    copyFail: 'Не удалось скопировать',
    downloadSuccess: 'Файл config.yaml скачан',
    subscriptionType: 'подписка',
    presetDirectRu: 'RU трафик напрямую',
    presetAllCdn: 'Все CDN',
    devicePcLabel: 'PC / Android / iOS',
    devicePcHintHtml: 'Клиент: <a href="https://github.com/pluralplay/FlClashX/releases" target="_blank" style="color:#267cff">FlClashX</a> (Windows / macOS / Linux / Android) · iOS: <a href="https://apps.apple.com/us/app/clash-mi/id6744321968" target="_blank" style="color:#267cff">Clash Mi</a>',
    deviceRouterLabel: 'Роутер (OpenWRT)',
    deviceRouterHintHtml: 'Клиент: <a href="https://ssclash.notion.site/SSClash-OpenWrt-15989188f6b4804b8e4bcc15ef00b890" target="_blank" style="color:#267cff">SSClash</a>'
  },
  en: {
    appTitle: 'Mihomo Configurator',
    appSubtitleHtml: 'Configuration builder for <a href="https://github.com/MetaCubeX/mihomo" target="_blank" style="color:#267cff">mihomo</a>',
    languageLabel: 'Language',
    languageRu: 'Russian',
    languageEn: 'English',
    steps: ['DNS', 'Servers', 'Rules', 'Download'],
    dnsTitle: 'DNS Setup',
    dnsDesc: 'Configure DNS servers for domain resolution',
    dnsMainHint: 'Changing settings on this page is not recommended unless you understand what you are doing.',
    ipv6Label: 'IPv6',
    ipv6Disabled: 'Disabled',
    ipv6Enabled: 'Enabled',
    dnsDefaultTitle: 'Default Nameservers',
    dnsDefaultHint: 'IP DNS servers used to resolve primary nameserver addresses',
    dnsDefaultAdd: 'Add',
    dnsNsTitle: 'Nameservers',
    dnsNsHint: 'Primary DNS servers (DoH / DoT) for domain resolution',
    dnsNsAdd: 'Add',
    serversTitle: 'Add Servers',
    serversDesc: 'Add proxy servers from links or configuration files',
    serversHint: 'All data is processed locally in your browser and is not sent anywhere.',
    linksTitle: 'From Links',
    linksHint: 'Paste one link per line: vless://, vmess://, ss://, trojan://, hysteria2://, hy2://, tuic://, or subscription URL https://...',
    linksAdd: 'Add from links',
    fileTitle: 'From File (WireGuard / AmneziaWG)',
    fileHint: 'Upload a .conf file. AmneziaWG is detected automatically.',
    proxyListTitle: 'Added servers and subscriptions ({count})',
    proxyClear: 'Clear all',
    proxyThName: 'Name',
    proxyThType: 'Type',
    proxyThServer: 'Server',
    proxyThPort: 'Port',
    rulesTitle: 'Routing Rules',
    rulesDesc: 'Configure which traffic goes through proxy and which goes directly',
    rulesServicesTitle: 'Popular Services',
    rulesCdnTitle: 'CDN',
    rulesCdnHint: 'CDN IP ranges for proxy routing',
    rulesOtherTitle: 'Other',
    ruleManualTitle: 'Add Rule Manually',
    ruleAddBtn: 'Add',
    rulesCurrentTitle: 'Current Rules',
    matchLabel: 'Remaining traffic (MATCH) →',
    downloadTitle: 'Download Config',
    downloadDesc: 'Choose a device and download the configuration file',
    deviceTitle: 'Device',
    previewTitle: 'Preview',
    copyBtn: 'Copy',
    downloadBtn: 'Download config.yaml',
    prevBtn: 'Back',
    nextBtn: 'Next',
    subModalTitle: 'Subscription Settings',
    subEditLabel: 'Subscription:',
    subFilterLabel: 'Include servers containing words in name:',
    subExcludeLabel: 'Exclude servers containing words in name:',
    cancelBtn: 'Cancel',
    saveBtn: 'Save',
    errAddDnsBoth: 'Add DNS servers to continue.',
    errAddDefaultNs: 'Add Default Nameservers to continue.',
    errAddNs: 'Add Nameservers (DoH/DoT) to continue.',
    errAddProxyOrSub: 'Add a proxy server or subscription to continue.',
    emptyServers: 'No servers',
    emptyRules: 'No rules. Add presets or create one manually.',
    removeTitle: 'Remove',
    editTitle: 'Edit',
    moveUpTitle: 'Up',
    moveDownTitle: 'Down',
    directOption: 'Direct',
    rejectOption: 'Block',
    ruleValueRequired: 'Enter rule value',
    addedServersToast: 'Servers added: {count}',
    addedSubsToast: 'Subscriptions added: {count}',
    failedParseToast: 'Failed to parse: {count}',
    proxyAddFailed: 'Failed to add server',
    proxyAddedToast: '{type} server added: {name}',
    proxyFileParseFailed: 'Failed to parse configuration file',
    subUpdatedToast: 'Subscription parameters updated: {name}',
    copySuccess: 'Copied to clipboard',
    copyFail: 'Failed to copy',
    downloadSuccess: 'config.yaml downloaded',
    subscriptionType: 'subscription',
    presetDirectRu: 'RU traffic direct',
    presetAllCdn: 'All CDNs',
    devicePcLabel: 'PC / Android / iOS',
    devicePcHintHtml: 'Client: <a href="https://github.com/pluralplay/FlClashX/releases" target="_blank" style="color:#267cff">FlClashX</a> (Windows / macOS / Linux / Android) · iOS: <a href="https://apps.apple.com/us/app/clash-mi/id6744321968" target="_blank" style="color:#267cff">Clash Mi</a>',
    deviceRouterLabel: 'Router (OpenWRT)',
    deviceRouterHintHtml: 'Client: <a href="https://ssclash.notion.site/SSClash-OpenWrt-15989188f6b4804b8e4bcc15ef00b890" target="_blank" style="color:#267cff">SSClash</a>'
  }
};

function browserLanguage() {
  try {
    const saved = localStorage.getItem('ui-lang');
    if (SUPPORTED_LANGS.includes(saved)) return saved;
  } catch {}
  const lang = (navigator.language || '').toLowerCase();
  return lang.startsWith('ru') ? 'ru' : 'en';
}

function formatText(template, vars = {}) {
  return String(template).replace(/\{(\w+)\}/g, (_, key) => (vars[key] !== undefined ? vars[key] : `{${key}}`));
}

function t(key, vars = {}) {
  const langPack = I18N[state.lang] || I18N.ru;
  const fallback = I18N.ru;
  const raw = langPack[key] !== undefined ? langPack[key] : fallback[key];
  return formatText(raw !== undefined ? raw : key, vars);
}

function setText(id, key, vars = {}) {
  const el = document.getElementById(id);
  if (el) el.textContent = t(key, vars);
}

function setHtml(id, key, vars = {}) {
  const el = document.getElementById(id);
  if (el) el.innerHTML = t(key, vars);
}

function setPlaceholder(id, key) {
  const el = document.getElementById(id);
  if (el) el.placeholder = t(key);
}

function getSteps() {
  return (I18N[state.lang] || I18N.ru).steps;
}

function localizeStaticUI() {
  document.documentElement.lang = state.lang;
  document.title = t('appTitle');
  setText('app-title', 'appTitle');
  setHtml('app-subtitle', 'appSubtitleHtml');
  setText('lang-switch-label', 'languageLabel');
  setText('lang-option-ru', 'languageRu');
  setText('lang-option-en', 'languageEn');
  setText('dns-title', 'dnsTitle');
  setText('dns-desc', 'dnsDesc');
  setText('dns-main-hint', 'dnsMainHint');
  setText('ipv6-label', 'ipv6Label');
  setText('ipv6-off', 'ipv6Disabled');
  setText('ipv6-on', 'ipv6Enabled');
  setText('dns-default-title', 'dnsDefaultTitle');
  setText('dns-default-hint', 'dnsDefaultHint');
  setText('dns-default-add-btn', 'dnsDefaultAdd');
  setText('dns-ns-title', 'dnsNsTitle');
  setText('dns-ns-hint', 'dnsNsHint');
  setText('dns-ns-add-btn', 'dnsNsAdd');
  setText('servers-title', 'serversTitle');
  setText('servers-desc', 'serversDesc');
  setText('servers-hint', 'serversHint');
  setText('links-title', 'linksTitle');
  setText('links-hint', 'linksHint');
  setText('links-add-btn', 'linksAdd');
  setText('file-title', 'fileTitle');
  setText('file-hint', 'fileHint');
  setText('proxy-clear-btn', 'proxyClear');
  setText('proxy-th-name', 'proxyThName');
  setText('proxy-th-type', 'proxyThType');
  setText('proxy-th-server', 'proxyThServer');
  setText('proxy-th-port', 'proxyThPort');
  setText('rules-title', 'rulesTitle');
  setText('rules-desc', 'rulesDesc');
  setText('rules-services-title', 'rulesServicesTitle');
  setText('rules-cdn-title', 'rulesCdnTitle');
  setText('rules-cdn-hint', 'rulesCdnHint');
  setText('rules-other-title', 'rulesOtherTitle');
  setText('rule-manual-title', 'ruleManualTitle');
  setText('rule-add-btn', 'ruleAddBtn');
  setText('rules-current-title', 'rulesCurrentTitle');
  setText('match-label', 'matchLabel');
  setText('download-title', 'downloadTitle');
  setText('download-desc', 'downloadDesc');
  setText('device-title', 'deviceTitle');
  setText('preview-title', 'previewTitle');
  setText('copy-btn', 'copyBtn');
  setText('download-btn', 'downloadBtn');
  setText('sub-modal-title', 'subModalTitle');
  setText('subscription-edit-label', 'subEditLabel');
  setText('sub-filter-label', 'subFilterLabel');
  setText('sub-exclude-label', 'subExcludeLabel');
  setText('sub-cancel-btn', 'cancelBtn');
  setText('sub-save-btn', 'saveBtn');
  const prevBtn = document.getElementById('btn-prev');
  if (prevBtn) prevBtn.textContent = `\u2190 ${t('prevBtn')}`;
  const nextBtn = document.getElementById('btn-next');
  if (nextBtn) nextBtn.textContent = `${t('nextBtn')} \u2192`;
}

function setLanguage(lang, persist = true) {
  const normalized = SUPPORTED_LANGS.includes(lang) ? lang : 'ru';
  state.lang = normalized;
  if (persist) {
    try { localStorage.setItem('ui-lang', normalized); } catch {}
  }
  const switcher = document.getElementById('lang-switch');
  if (switcher) switcher.value = normalized;
  localizeStaticUI();
  renderSteps();
  renderDnsPresets('default');
  renderDnsPresets('ns');
  renderDnsList('default');
  renderDnsList('ns');
  renderProxies();
  renderAllPresets();
  renderRules();
  renderTargetSelects();
  renderDevices();
  updateFooterValidation();
  if (state.step === getSteps().length - 1) renderPreview();
}

// ============================================================
// DNS Presets
// ============================================================
const DNS_DEFAULT_PRESETS = {
  quad9:      { label: 'Quad9',      servers: ['9.9.9.9', '149.112.112.112'] },
  cloudflare: { label: 'Cloudflare', servers: ['1.1.1.1', '1.0.0.1'] },
  google:     { label: 'Google',     servers: ['8.8.8.8', '8.8.4.4'] }
};

const DNS_NS_PRESETS = {
  quad9:      { label: 'Quad9 DoH/DoT',      servers: ['https://dns.quad9.net/dns-query', 'tls://dns.quad9.net'] },
  cloudflare: { label: 'Cloudflare DoH/DoT', servers: ['https://cloudflare-dns.com/dns-query', 'tls://1dot1dot1dot1.cloudflare-dns.com'] },
  google:     { label: 'Google DoH/DoT',     servers: ['https://dns.google/dns-query', 'tls://dns.google'] }
};

// ============================================================
// Rule Presets
// ============================================================
const SERVICE_PRESETS = {
  telegram:  { label: 'Telegram',  rules: [{type:'RULE-SET',payload:'telegram',target:'Proxy'}] },
  youtube:   { label: 'YouTube',   rules: [{type:'GEOSITE',payload:'youtube',target:'Proxy'}] },
  twitter:   { label: 'Twitter',   rules: [{type:'GEOSITE',payload:'twitter',target:'Proxy'}] },
  facebook:  { label: 'Facebook',  rules: [{type:'GEOSITE',payload:'facebook',target:'Proxy'}] },
  whatsapp:  { label: 'WhatsApp',  rules: [{type:'GEOSITE',payload:'whatsapp',target:'Proxy'}] },
  instagram: { label: 'Instagram', rules: [{type:'GEOSITE',payload:'instagram',target:'Proxy'}] },
  chatgpt:   { label: 'ChatGPT',   rules: [{type:'GEOSITE',payload:'openai',target:'Proxy'}] }
};

const OTHER_PRESETS = {
  directRU:  { labelKey: 'presetDirectRu', rules: [{type:'GEOIP',payload:'RU',target:'DIRECT'}] },
  ruBlocked: { label: 'ru-blocked', rules: [{type:'RULE-SET',payload:'ru-blocked',target:'Proxy'}] }
};

const CDN_PROVIDERS = [
  { id: 'all',          labelKey: 'presetAllCdn' },
  { id: 'akamai',       label: 'Akamai' },
  { id: 'aws',          label: 'AWS' },
  { id: 'cdn77',        label: 'CDN77' },
  { id: 'cloudflare',   label: 'Cloudflare' },
  { id: 'cogent',       label: 'Cogent' },
  { id: 'constant',     label: 'Constant' },
  { id: 'contabo',      label: 'Contabo' },
  { id: 'datacamp',     label: 'Datacamp' },
  { id: 'digitalocean', label: 'DigitalOcean' },
  { id: 'fastly',       label: 'Fastly' },
  { id: 'hetzner',      label: 'Hetzner' },
  { id: 'oracle',       label: 'Oracle' },
  { id: 'ovh',          label: 'OVH' },
  { id: 'roblox',       label: 'Roblox' },
  { id: 'scaleway',     label: 'Scaleway' },
  { id: 'vercel',       label: 'Vercel' }
];

const PRIVATE_NETWORK_RULES = [
  'IP-CIDR,192.168.0.0/16,DIRECT',
  'IP-CIDR,10.0.0.0/8,DIRECT',
  'IP-CIDR,172.16.0.0/12,DIRECT',
  'IP-CIDR,127.0.0.0/8,DIRECT'
];

// Telegram: improve connection stability by excluding known Telegram dst ranges from sniffing.
const TELEGRAM_SNIFFER_SKIP_DST = [
  '5.28.192.0/18',
  '91.105.192.0/23',
  '91.108.4.0/22',
  '91.108.8.0/21',
  '91.108.16.0/21',
  '91.108.56.0/22',
  '95.161.64.0/20',
  '109.239.140.0/24',
  '149.154.160.0/20',
  '185.76.151.0/24',
  '2001:67c:4e8::/48',
  '2001:b28:f23c::/47',
  '2001:b28:f23f::/48',
  '2a0a:f280::/32'
];

// ============================================================
// Helpers
// ============================================================
function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ============================================================
// Toast
// ============================================================
function toast(msg, type = 'success') {
  const el = document.createElement('div');
  el.className = 'toast toast-' + type;
  el.textContent = msg;
  document.getElementById('toasts').appendChild(el);
  requestAnimationFrame(() => el.classList.add('show'));
  setTimeout(() => {
    el.classList.remove('show');
    setTimeout(() => el.remove(), 300);
  }, 2800);
}

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
// Proxy Parsers (Step 2)
// ============================================================
function parseVless(url) {
  const m = url.match(/^vless:\/\/([^@]+)@([^:]+):(\d+)\??([^#]*)(?:#(.*))?$/);
  if (!m) return null;
  const [, uuid, server, port, qs, rawName] = m;
  const p = new URLSearchParams(qs);
  const name = rawName ? decodeURIComponent(rawName) : 'vless-' + server;
  const proxy = { name, type: 'vless', server, port: +port, uuid, udp: true };

  const net = p.get('type') || 'tcp';
  proxy.network = net;

  const sec = p.get('security') || '';
  if (sec === 'tls' || sec === 'reality') proxy.tls = true;
  if (p.get('sni')) proxy.servername = p.get('sni');
  if (p.get('fp')) {
    proxy['client-fingerprint'] = p.get('fp');
  } else if (sec === 'tls' || sec === 'reality') {
    // Auto-add default client-fingerprint for TLS/reality connections
    proxy['client-fingerprint'] = 'chrome';
  }
  if (p.get('flow')) proxy.flow = p.get('flow');

  if (sec === 'reality') {
    proxy['reality-opts'] = {};
    if (p.get('pbk')) proxy['reality-opts']['public-key'] = p.get('pbk');
    if (p.get('sid')) proxy['reality-opts']['short-id'] = p.get('sid');
  }

  if (net === 'ws') {
    proxy['ws-opts'] = { path: p.get('path') || '/' };
    if (p.get('host')) proxy['ws-opts'].headers = { Host: p.get('host') };
  } else if (net === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': p.get('serviceName') || '' };
  } else if (net === 'h2') {
    proxy['h2-opts'] = { path: p.get('path') || '/', host: [p.get('host') || server] };
  }
  return proxy;
}

function parseVmess(url) {
  const b64 = url.replace(/^vmess:\/\//, '');
  let json;
  try { json = JSON.parse(atob(b64.replace(/-/g,'+').replace(/_/g,'/'))); } catch { return null; }
  const name = json.ps || 'vmess-' + json.add;
  const proxy = {
    name, type: 'vmess', server: json.add, port: +json.port,
    uuid: json.id, alterId: +(json.aid || 0), cipher: json.scy || 'auto', udp: true
  };
  if (json.tls === 'tls') proxy.tls = true;
  if (json.sni) proxy.servername = json.sni;
  const net = json.net || 'tcp';
  if (net !== 'tcp') proxy.network = net;
  if (net === 'ws') {
    proxy['ws-opts'] = { path: json.path || '/' };
    if (json.host) proxy['ws-opts'].headers = { Host: json.host };
  } else if (net === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': json.path || '' };
  }
  return proxy;
}

function parseSS(url) {
  const raw = url.replace(/^ss:\/\//, '');
  let method, password, server, port, name;
  const hashIdx = raw.indexOf('#');
  name = hashIdx >= 0 ? decodeURIComponent(raw.slice(hashIdx + 1)) : '';
  const main = hashIdx >= 0 ? raw.slice(0, hashIdx) : raw;

  const atIdx = main.indexOf('@');
  if (atIdx >= 0) {
    const userInfo = main.slice(0, atIdx);
    const hostPort = main.slice(atIdx + 1);
    let decoded;
    try { decoded = atob(userInfo.replace(/-/g,'+').replace(/_/g,'/')); } catch { decoded = userInfo; }
    const colonIdx = decoded.indexOf(':');
    if (colonIdx < 0) return null;
    method = decoded.slice(0, colonIdx);
    password = decoded.slice(colonIdx + 1);
    const hpMatch = hostPort.match(/^([^:]+):(\d+)/);
    if (!hpMatch) return null;
    server = hpMatch[1];
    port = +hpMatch[2];
  } else {
    let decoded;
    try { decoded = atob(main.replace(/-/g,'+').replace(/_/g,'/')); } catch { return null; }
    const m2 = decoded.match(/^([^:]+):([^@]+)@([^:]+):(\d+)$/);
    if (!m2) return null;
    method = m2[1]; password = m2[2]; server = m2[3]; port = +m2[4];
  }
  if (!name) name = 'ss-' + server;
  return { name, type: 'ss', server, port, cipher: method, password, udp: true };
}

function parseTrojan(url) {
  const m = url.match(/^trojan:\/\/([^@]+)@([^:]+):(\d+)\??([^#]*)(?:#(.*))?$/);
  if (!m) return null;
  const [, password, server, port, qs, rawName] = m;
  const p = new URLSearchParams(qs);
  const name = rawName ? decodeURIComponent(rawName) : 'trojan-' + server;
  const proxy = { name, type: 'trojan', server, port: +port, password: decodeURIComponent(password), udp: true };
  if (p.get('sni')) proxy.sni = p.get('sni');
  if (p.get('allowInsecure') === '1' || p.get('insecure') === '1') proxy['skip-cert-verify'] = true;
  const net = p.get('type') || 'tcp';
  if (net !== 'tcp') {
    proxy.network = net;
    if (net === 'ws') {
      proxy['ws-opts'] = { path: p.get('path') || '/' };
      if (p.get('host')) proxy['ws-opts'].headers = { Host: p.get('host') };
    } else if (net === 'grpc') {
      proxy['grpc-opts'] = { 'grpc-service-name': p.get('serviceName') || '' };
    }
  }
  return proxy;
}

function parseHysteria2(url) {
  const m = url.match(/^(?:hysteria2|hy2):\/\/([^@]+)@([^:]+):(\d+)\??([^#]*)(?:#(.*))?$/);
  if (!m) return null;
  const [, password, server, port, qs, rawName] = m;
  const p = new URLSearchParams(qs);
  const name = rawName ? decodeURIComponent(rawName) : 'hy2-' + server;
  const proxy = { name, type: 'hysteria2', server, port: +port, password: decodeURIComponent(password) };
  if (p.get('sni')) proxy.sni = p.get('sni');
  if (p.get('insecure') === '1') proxy['skip-cert-verify'] = true;
  if (p.get('obfs') && p.get('obfs') !== 'none') {
    proxy.obfs = p.get('obfs');
    if (p.get('obfs-password')) proxy['obfs-password'] = p.get('obfs-password');
  }
  return proxy;
}

function parseTuic(url) {
  const m = url.match(/^tuic:\/\/([^:]+):([^@]+)@([^:]+):(\d+)\??([^#]*)(?:#(.*))?$/);
  if (!m) return null;
  const [, uuid, password, server, port, qs, rawName] = m;
  const p = new URLSearchParams(qs);
  const name = rawName ? decodeURIComponent(rawName) : 'tuic-' + server;
  const proxy = {
    name, type: 'tuic', server, port: +port,
    uuid: decodeURIComponent(uuid), password: decodeURIComponent(password)
  };
  if (p.get('sni')) proxy.sni = p.get('sni');
  if (p.get('alpn')) proxy.alpn = p.get('alpn').split(',');
  if (p.get('congestion_control')) proxy['congestion-controller'] = p.get('congestion_control');
  if (p.get('udp_relay_mode')) proxy['udp-relay-mode'] = p.get('udp_relay_mode');
  return proxy;
}

function parseWireGuardConfig(text) {
  function normalizeWgValue(v) {
    v = String(v ?? '').trim();
    if (v === '""' || v === "''") return '';
    return v;
  }
  function getKey(obj, k) {
    return obj[k] ?? obj[k.toUpperCase()] ?? obj[k.toLowerCase()];
  }
  function hasKey(obj, k) {
    return getKey(obj, k) !== undefined;
  }
  function toIntMaybe(v) {
    v = normalizeWgValue(v);
    if (!v) return null;
    if (!/^\d+$/.test(v)) return null;
    return +v;
  }
  function toIntOrRangeMaybe(v) {
    v = normalizeWgValue(v);
    if (!v) return null;
    if (/^\d+$/.test(v)) return +v;
    const m = v.match(/^(\d+)\s*-\s*(\d+)$/);
    if (!m) return null;
    return `${m[1]}-${m[2]}`;
  }
  function hasAnyAwgKey(obj) {
    // Detect AmneziaWG even when only v1.5 CPS fields are present (e.g. just i1).
    const keys = [
      'Jc','Jmin','Jmax',
      'S1','S2','S3','S4',
      'H1','H2','H3','H4',
      'I1','I2','I3','I4','I5',
      'J1','J2','J3',
      'Itime'
    ];
    for (const k of keys) {
      if (hasKey(obj, k)) return true;
    }
    return false;
  }

  const lines = text.split(/\r?\n/);
  const iface = {}, peer = {};
  let section = null;
  for (let line of lines) {
    line = line.trim();
    if (!line || line.startsWith('#')) continue;
    if (/^\[Interface\]/i.test(line)) { section = 'i'; continue; }
    if (/^\[Peer\]/i.test(line)) { section = 'p'; continue; }
    const kv = line.match(/^(\w+)\s*=\s*(.+)$/);
    if (!kv) continue;
    (section === 'i' ? iface : peer)[kv[1].trim()] = kv[2].trim();
  }
  const privateKey = getKey(iface, 'PrivateKey');
  const publicKey = getKey(peer, 'PublicKey');
  const endpoint = getKey(peer, 'Endpoint');
  if (!privateKey || !publicKey || !endpoint) return null;
  const ep = endpoint.match(/^([^:]+):(\d+)$/);
  if (!ep) return null;
  const server = ep[1], port = +ep[2];
  const address = getKey(iface, 'Address');
  const ip = address ? address.split('/')[0] : '10.0.0.2';
  const isAmnezia = hasAnyAwgKey(iface);

  const proxy = {
    name: (isAmnezia ? 'awg-' : 'wg-') + server,
    type: 'wireguard', server, port, ip,
    'private-key': privateKey,
    'public-key': publicKey,
    udp: true
  };
  const mtu = toIntMaybe(getKey(iface, 'MTU'));
  if (mtu !== null) proxy.mtu = mtu;
  const psk = getKey(peer, 'PresharedKey');
  if (psk) proxy['pre-shared-key'] = psk;
  const dns = getKey(iface, 'DNS');
  if (dns) proxy.dns = [dns.split(',')[0].trim()];
  if (isAmnezia) {
    const h1 = toIntOrRangeMaybe(getKey(iface, 'H1'));
    const h2 = toIntOrRangeMaybe(getKey(iface, 'H2'));
    const h3 = toIntOrRangeMaybe(getKey(iface, 'H3'));
    const h4 = toIntOrRangeMaybe(getKey(iface, 'H4'));
    const hasV20 =
      hasKey(iface, 'S3') || hasKey(iface, 'S4') ||
      [h1, h2, h3, h4].some(v => typeof v === 'string');
    const hasV15 = hasKey(iface, 'I1');

    const o = {};
    // Fill missing fields with zeros for predictable output.
    o.jc = toIntMaybe(getKey(iface, 'Jc')) ?? 0;
    o.jmin = toIntMaybe(getKey(iface, 'Jmin')) ?? 0;
    o.jmax = toIntMaybe(getKey(iface, 'Jmax')) ?? 0;
    o.s1 = toIntMaybe(getKey(iface, 'S1')) ?? 0;
    o.s2 = toIntMaybe(getKey(iface, 'S2')) ?? 0;
    o.s3 = toIntMaybe(getKey(iface, 'S3')) ?? 0;
    o.s4 = toIntMaybe(getKey(iface, 'S4')) ?? 0;
    o.h1 = h1 ?? 0;
    o.h2 = h2 ?? 0;
    o.h3 = h3 ?? 0;
    o.h4 = h4 ?? 0;

    // AmneziaWG v1.5 additional options.
    // v1.5 is detected by presence of I1 (case-insensitive). If I1 is absent, it behaves as v1.0.
    if (hasV15) {
      const i1 = normalizeWgValue(getKey(iface, 'I1'));
      const i2 = normalizeWgValue(getKey(iface, 'I2'));
      const i3 = normalizeWgValue(getKey(iface, 'I3'));
      const i4 = normalizeWgValue(getKey(iface, 'I4'));
      const i5 = normalizeWgValue(getKey(iface, 'I5'));
      const j1 = normalizeWgValue(getKey(iface, 'J1'));
      const j2 = normalizeWgValue(getKey(iface, 'J2'));
      const j3 = normalizeWgValue(getKey(iface, 'J3'));
      const itimeRaw = getKey(iface, 'Itime');
      const itime = toIntMaybe(itimeRaw) ?? 0;

      // CPS strings: default to empty string when omitted.
      o.i1 = i1;
      o.i2 = hasKey(iface, 'I2') ? i2 : '';
      o.i3 = hasKey(iface, 'I3') ? i3 : '';
      o.i4 = hasKey(iface, 'I4') ? i4 : '';
      o.i5 = hasKey(iface, 'I5') ? i5 : '';
      o.j1 = hasKey(iface, 'J1') ? j1 : '';
      o.j2 = hasKey(iface, 'J2') ? j2 : '';
      o.j3 = hasKey(iface, 'J3') ? j3 : '';
      o.itime = itime;
    }
    proxy.awgVersion = hasV20 ? '2.0' : (hasV15 ? '1.5' : '1.0');
    proxy['amnezia-wg-option'] = o;
  }
  return proxy;
}

function parseProxyUrl(line) {
  line = line.trim();
  if (!line) return null;
  if (line.startsWith('vless://')) return parseVless(line);
  if (line.startsWith('vmess://')) return parseVmess(line);
  if (line.startsWith('ss://')) return parseSS(line);
  if (line.startsWith('trojan://')) return parseTrojan(line);
  if (line.startsWith('hysteria2://') || line.startsWith('hy2://')) return parseHysteria2(line);
  if (line.startsWith('tuic://')) return parseTuic(line);
  return null;
}

function parseSubscriptionUrl(line) {
  line = line.trim();
  if (!/^https?:\/\//i.test(line)) return null;
  let url;
  try {
    url = new URL(line);
  } catch {
    return null;
  }
  const base = (url.hostname || 'subscription').replace(/[^\w.-]/g, '-');
  return {
    name: 'sub-' + base,
    type: 'http',
    url: line,
    interval: 3600,
    filter: '',
    'exclude-filter': ''
  };
}

function uniqueServerName(name) {
  const existing = new Set([
    ...state.proxies.map(p => p.name),
    ...state.proxyProviders.map(p => p.name)
  ]);
  if (!existing.has(name)) return name;
  let i = 2;
  while (existing.has(name + '-' + i)) i++;
  return name + '-' + i;
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

  // Geodata
  y += `geodata-mode: true\n`;
  y += `geox-url:\n`;
  y += `  geoip: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat"\n`;
  y += `  geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"\n`;
  y += `  mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb"\n`;
  y += `  asn: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"\n`;
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

  // Rule providers (CDN + Telegram + ru-blocked)
  const needTelegram = telegramEnabled;
  const needRuBlocked = ruBlockedEnabled;
  const hasProviders = state.activeCdnProviders.size > 0 || needTelegram || needRuBlocked;
  if (hasProviders) {
    y += `rule-providers:\n`;
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
