// ============================================================
// State
// ============================================================
function initialState() {
  return {
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
    activeExceptionPresets: new Set(),
    activeOtherPresets: new Set(),
    activeCdnProviders: new Set(),
    matchTarget: 'DIRECT',
    device: 'desktop',
    lang: 'ru',
    importedRawConfig: null
  };
}

const state = initialState();

const SUPPORTED_LANGS = ['ru', 'en'];
const I18N = {
  ru: {
    appTitle: 'Mihomo Configurator',
    appSubtitleHtml: 'Конструктор конфигурации <a href="https://github.com/MetaCubeX/mihomo" target="_blank">mihomo</a>',
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
    linksHint: 'Вставьте ссылки по одной на строку: vless://, vmess://, ss://, trojan://, hysteria2://, hy2://, tuic://, vpn:// (из Amnezia: AmneziaWG/WireGuard/VLESS) или URL подписки https://...',
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
    rulesExceptionsTitle: 'Исключения',
    rulesExceptionsHint: 'Используйте при проксировании CDN: адреса этих сервисов могут пересекаться с диапазонами CDN, хотя сами сервисы не заблокированы и доступны напрямую.',
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
    proxyModalTitle: 'Параметры сервера',
    proxyEditLabel: 'Сервер:',
    dialerProxyLabel: 'Подключаться через другой сервер',
    dialerProxyHint: 'Выбранный сервер будет использоваться для подключения к этому серверу.',
    dialerProxyNone: 'Не использовать',
    dialerProxyVia: 'Через: {name}',
    dialerProxyCycle: 'Нельзя создать циклическую цепочку серверов.',
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
    proxyUpdatedToast: 'Параметры сервера обновлены: {name}',
    copySuccess: 'Скопировано в буфер обмена',
    copyFail: 'Не удалось скопировать',
    downloadSuccess: 'Файл config.yaml скачан',
    subscriptionType: 'подписка',
    presetDirectRu: 'RU трафик напрямую',
    presetRuBlocked: 'Заблокированные сайты',
    presetAllCdn: 'Все CDN',
    deviceDesktopLabel: 'Windows / macOS / Linux',
    deviceDesktopHintHtml: 'Клиент: <a href="https://github.com/pluralplay/FlClashX/releases" target="_blank">FlClashX</a>',
    deviceAndroidLabel: 'Android',
    deviceAndroidHintHtml: 'Клиент: <a href="https://github.com/pluralplay/FlClashX/releases" target="_blank">FlClashX</a>',
    deviceIosLabel: 'iOS',
    deviceIosHintHtml: 'Клиент: <a href="https://apps.apple.com/us/app/clash-mi/id6744321968" target="_blank">Clash Mi</a>',
    deviceRouterLabel: 'Роутер (OpenWRT)',
    deviceRouterHintHtml: 'Клиент: <a href="https://ssclash.notion.site/SSClash-OpenWrt-15989188f6b4804b8e4bcc15ef00b890" target="_blank">SSClash</a>',
    importBtn: 'Импортировать конфиг',
    importSuccess: 'Конфиг импортирован',
    importFail: 'Не удалось импортировать конфиг',
    importResetBtn: 'Сбросить импорт'
  },
  en: {
    appTitle: 'Mihomo Configurator',
    appSubtitleHtml: 'Configuration builder for <a href="https://github.com/MetaCubeX/mihomo" target="_blank">mihomo</a>',
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
    linksHint: 'Paste one link per line: vless://, vmess://, ss://, trojan://, hysteria2://, hy2://, tuic://, vpn:// (from Amnezia: AmneziaWG/WireGuard/VLESS), or subscription URL https://...',
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
    rulesExceptionsTitle: 'Exceptions',
    rulesExceptionsHint: 'Use with CDN proxying: these services may share address ranges with CDNs, although they may not be blocked in your region.',
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
    proxyModalTitle: 'Server Settings',
    proxyEditLabel: 'Server:',
    dialerProxyLabel: 'Connect through another server',
    dialerProxyHint: 'The selected server will be used to establish a connection to this server.',
    dialerProxyNone: 'Do not use',
    dialerProxyVia: 'Via: {name}',
    dialerProxyCycle: 'A circular server chain cannot be created.',
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
    proxyUpdatedToast: 'Server parameters updated: {name}',
    copySuccess: 'Copied to clipboard',
    copyFail: 'Failed to copy',
    downloadSuccess: 'config.yaml downloaded',
    subscriptionType: 'subscription',
    presetDirectRu: 'RU traffic direct',
    presetRuBlocked: 'Blocked sites',
    presetAllCdn: 'All CDNs',
    deviceDesktopLabel: 'Windows / macOS / Linux',
    deviceDesktopHintHtml: 'Client: <a href="https://github.com/pluralplay/FlClashX/releases" target="_blank">FlClashX</a>',
    deviceAndroidLabel: 'Android',
    deviceAndroidHintHtml: 'Client: <a href="https://github.com/pluralplay/FlClashX/releases" target="_blank">FlClashX</a>',
    deviceIosLabel: 'iOS',
    deviceIosHintHtml: 'Client: <a href="https://apps.apple.com/us/app/clash-mi/id6744321968" target="_blank">Clash Mi</a>',
    deviceRouterLabel: 'Router (OpenWRT)',
    deviceRouterHintHtml: 'Client: <a href="https://ssclash.notion.site/SSClash-OpenWrt-15989188f6b4804b8e4bcc15ef00b890" target="_blank">SSClash</a>',
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

function getSteps() {
  return (I18N[state.lang] || I18N.ru).steps;
}

function localizeStaticUI() {
  document.documentElement.lang = state.lang;
  document.title = t('appTitle');

  document.querySelectorAll('[data-i18n]').forEach(el => {
    el.textContent = t(el.getAttribute('data-i18n'));
  });
  document.querySelectorAll('[data-i18n-html]').forEach(el => {
    el.innerHTML = t(el.getAttribute('data-i18n-html'));
  });

  // Nav buttons keep directional arrows around the translated label
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
  renderAll({ includeDevices: true, includePreview: state.step === getSteps().length - 1 });
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
  google:     { label: 'Google DoH/DoT',     servers: ['https://8.8.8.8/dns-query', 'tls://8.8.8.8'] }
};

// ============================================================
// Rule Presets
// ============================================================
const SERVICE_PRESETS = {
  telegram:  { label: 'Telegram',  rules: [{type:'RULE-SET',payload:'telegram',target:'Proxy'}] },
  discord:   { label: 'Discord',   rules: [
    {type:'RULE-SET',payload:'geosite-discord',target:'Proxy'},
    {type:'RULE-SET',payload:'discord-voice',target:'Proxy'}
  ] },
  youtube:   { label: 'YouTube',   rules: [{type:'RULE-SET',payload:'geosite-youtube',target:'Proxy'}] },
  twitter:   { label: 'X (Twitter) + Grok', rules: [{type:'RULE-SET',payload:'geosite-x',target:'Proxy'}] },
  facebook:  { label: 'Facebook',  rules: [{type:'RULE-SET',payload:'geosite-facebook',target:'Proxy'}] },
  whatsapp:  { label: 'WhatsApp',  rules: [{type:'RULE-SET',payload:'geosite-whatsapp',target:'Proxy'}] },
  instagram: { label: 'Instagram', rules: [{type:'RULE-SET',payload:'geosite-instagram',target:'Proxy'}] },
  chatgpt:   { label: 'ChatGPT',   rules: [{type:'RULE-SET',payload:'geosite-openai',target:'Proxy'}] },
  gemini:    { label: 'Gemini',    rules: [{type:'RULE-SET',payload:'geosite-google-gemini',target:'Proxy'}] },
  claude:    { label: 'Claude',    rules: [{type:'RULE-SET',payload:'geosite-anthropic',target:'Proxy'}] }
};

const OTHER_PRESETS = {
  ruBlocked: { labelKey: 'presetRuBlocked', rules: [{type:'RULE-SET',payload:'ru-blocked',target:'Proxy'}] },
  directRU:  { labelKey: 'presetDirectRu', rules: [{type:'GEOIP',payload:'RU',target:'DIRECT'}] }
};

const EXCEPTION_PRESETS = {
  steam:     { label: 'Steam', rules: [{type:'RULE-SET',payload:'geosite-steam',target:'DIRECT'}] },
  mihoyo:    { label: 'miHoYo', rules: [{type:'RULE-SET',payload:'geosite-mihoyo',target:'DIRECT'}] },
  kurogames: { label: 'Kuro Games (Wuthering Waves)', rules: [{type:'RULE-SET',payload:'geosite-kurogames',target:'DIRECT'}] },
  twitch:    { label: 'Twitch', rules: [{type:'RULE-SET',payload:'geosite-twitch',target:'DIRECT'}] }
};

const CDN_PROVIDERS = [
  { id: 'all',          labelKey: 'presetAllCdn' },
  { id: 'akamai',       label: 'Akamai' },
  { id: 'aws',          label: 'AWS' },
  { id: 'buyvm',        label: 'BuyVM' },
  { id: 'bunny',        label: 'BunnyCDN' },
  { id: 'cdn77',        label: 'CDN77' },
  { id: 'cloudflare',   label: 'Cloudflare' },
  { id: 'cogent',       label: 'Cogent' },
  { id: 'constant',     label: 'Constant' },
  { id: 'contabo',      label: 'Contabo' },
  { id: 'datacamp',     label: 'Datacamp' },
  { id: 'digitalocean', label: 'DigitalOcean' },
  { id: 'fastly',       label: 'Fastly' },
  { id: 'gcore',        label: 'GCore' },
  { id: 'glesys',       label: 'GleSYS' },
  { id: 'gthost',       label: 'GTHost' },
  { id: 'hetzner',      label: 'Hetzner' },
  { id: 'melbicom',     label: 'MelBiCom' },
  { id: 'oracle',       label: 'Oracle' },
  { id: 'ovh',          label: 'OVH' },
  { id: 'scalaxy',      label: 'Scalaxy' },
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
