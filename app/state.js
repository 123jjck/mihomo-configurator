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
  lang: 'ru',
  importedRawConfig: null
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
    deviceRouterHintHtml: 'Клиент: <a href="https://ssclash.notion.site/SSClash-OpenWrt-15989188f6b4804b8e4bcc15ef00b890" target="_blank" style="color:#267cff">SSClash</a>',
    importBtn: 'Импортировать конфиг',
    importSuccess: 'Конфиг импортирован',
    importFail: 'Не удалось импортировать конфиг',
    importResetBtn: 'Сбросить импорт'
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
    deviceRouterHintHtml: 'Client: <a href="https://ssclash.notion.site/SSClash-OpenWrt-15989188f6b4804b8e4bcc15ef00b890" target="_blank" style="color:#267cff">SSClash</a>',
    importBtn: 'Import config',
    importSuccess: 'Config imported',
    importFail: 'Failed to import config',
    importResetBtn: 'Reset import'
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
  setText('import-btn', 'importBtn');
  setText('import-reset-btn', 'importResetBtn');
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
