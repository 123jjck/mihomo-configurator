// ============================================================
// Proxy Parsers (Step 2)
// ============================================================
function parseXHTTPExtra(extra, opts) {
  const xmuxToReuse = (xmux) => {
    if (!xmux || typeof xmux !== 'object' || Array.isArray(xmux)) return null;
    const reuse = {};
    const mapField = (src, dst) => {
      const value = xmux[src];
      if (typeof value === 'string' && value) reuse[dst] = value;
      else if (typeof value === 'number' && Number.isFinite(value)) reuse[dst] = String(Math.trunc(value));
    };
    mapField('maxConnections', 'max-connections');
    mapField('maxConcurrency', 'max-concurrency');
    mapField('cMaxReuseTimes', 'c-max-reuse-times');
    mapField('hMaxRequestTimes', 'h-max-request-times');
    mapField('hMaxReusableSecs', 'h-max-reusable-secs');
    return Object.keys(reuse).length > 0 ? reuse : null;
  };
  const toHeaderMap = (headers) => {
    if (!headers || typeof headers !== 'object' || Array.isArray(headers)) return null;
    const mapped = {};
    for (const [key, value] of Object.entries(headers)) {
      if (!key) continue;
      if (typeof value === 'string' && value) mapped[key] = value;
      else if (typeof value === 'number' || typeof value === 'boolean') mapped[key] = String(value);
    }
    return Object.keys(mapped).length > 0 ? mapped : null;
  };

  if (extra.noGRPCHeader === true) opts['no-grpc-header'] = true;
  if (typeof extra.xPaddingBytes === 'string' && extra.xPaddingBytes)
    opts['x-padding-bytes'] = extra.xPaddingBytes;
  const rootReuse = xmuxToReuse(extra.xmux);
  if (rootReuse) opts['reuse-settings'] = rootReuse;
  const headers = toHeaderMap(extra.headers);
  if (headers) opts.headers = headers;
  if (extra.downloadSettings && typeof extra.downloadSettings === 'object') {
    const ds = extra.downloadSettings;
    const dsOpts = {};
    if (typeof ds.address === 'string' && ds.address) dsOpts['server'] = ds.address;
    if (typeof ds.port === 'number') dsOpts['port'] = Math.trunc(ds.port);
    if (typeof ds.security === 'string' && ds.security.toLowerCase() === 'tls') dsOpts['tls'] = true;
    if (ds.tlsSettings && typeof ds.tlsSettings === 'object') {
      const tls = ds.tlsSettings;
      if (typeof tls.serverName === 'string' && tls.serverName) dsOpts['servername'] = tls.serverName;
      if (typeof tls.fingerprint === 'string' && tls.fingerprint) dsOpts['client-fingerprint'] = tls.fingerprint;
      if (tls.allowInsecure === true) dsOpts['skip-cert-verify'] = true;
      if (Array.isArray(tls.alpn) && tls.alpn.length > 0)
        dsOpts['alpn'] = tls.alpn.filter(a => typeof a === 'string');
    }
    if (ds.xhttpSettings && typeof ds.xhttpSettings === 'object') {
      const xh = ds.xhttpSettings;
      if (typeof xh.path === 'string' && xh.path) dsOpts['path'] = xh.path;
      if (typeof xh.host === 'string' && xh.host) dsOpts['host'] = xh.host;
      const downloadHeaders = toHeaderMap(xh.headers);
      if (downloadHeaders) dsOpts.headers = downloadHeaders;
      if (xh.noGRPCHeader === true) dsOpts['no-grpc-header'] = true;
      if (typeof xh.xPaddingBytes === 'string' && xh.xPaddingBytes) dsOpts['x-padding-bytes'] = xh.xPaddingBytes;
      const nestedReuse = xmuxToReuse(xh.extra?.xmux);
      if (nestedReuse) dsOpts['reuse-settings'] = nestedReuse;
    }
    if (Object.keys(dsOpts).length > 0) opts['download-settings'] = dsOpts;
  }
}

const MIHOMO_SHARE_LINK_USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36';

function buildMihomoShareWsHeaders(host = '', includeHost = true) {
  const headers = { 'User-Agent': MIHOMO_SHARE_LINK_USER_AGENT };
  if (includeHost) headers.Host = String(host ?? '');
  return headers;
}

function parseBase64HostUrl(rawUrl) {
  const u = parseUrlOrNull(rawUrl);
  if (!u) return null;
  const decodedHost = decodeBase64Compat(u.host);
  if (!decodedHost) return u;
  try {
    u.host = decodedHost;
  } catch {
    return u;
  }
  return u;
}

function parseMihomoVShareLink(rawUrl, scheme, { decodeBase64Host = false } = {}) {
  const u = decodeBase64Host ? parseBase64HostUrl(rawUrl) : parseUrlOrNull(rawUrl);
  if (!u || u.protocol !== `${scheme}:`) return null;

  const server = u.hostname;
  const port = Number(u.port);
  const uuid = decodeURIComponentSafe(u.username);
  if (!server || !Number.isFinite(port) || !uuid) return null;

  const p = u.searchParams;
  const proxy = {
    name: u.hash ? decodeURIComponentSafe(u.hash.slice(1)) : `${scheme}-${server}`,
    type: scheme,
    server,
    port,
    uuid,
    udp: true
  };

  const security = String(p.get('security') || '').toLowerCase();
  if (security.endsWith('tls') || security === 'reality') {
    proxy.tls = true;
    proxy['client-fingerprint'] = p.get('fp') || 'chrome';
    const alpn = parseCsv(p.get('alpn'));
    if (alpn.length) proxy.alpn = alpn;
    if (p.get('pcs')) proxy.fingerprint = p.get('pcs');
  }
  if (p.get('sni')) proxy.servername = p.get('sni');
  if (p.get('pbk')) {
    proxy['reality-opts'] = {
      'public-key': p.get('pbk'),
      'short-id': p.get('sid') || ''
    };
  }

  switch (String(p.get('packetEncoding') || '').toLowerCase()) {
    case 'none':
      break;
    case 'packet':
      proxy['packet-addr'] = true;
      break;
    default:
      proxy.xudp = true;
      break;
  }

  let network = String(p.get('type') || 'tcp').toLowerCase();
  const fakeType = String(p.get('headerType') || '').toLowerCase();
  if (fakeType === 'http') {
    network = 'http';
  } else if (network === 'http') {
    network = 'h2';
  }
  proxy.network = network;

  switch (network) {
    case 'tcp':
      if (fakeType !== 'none') {
        proxy['http-opts'] = { path: [p.get('path') || '/'], headers: {} };
        if (p.get('host')) proxy['http-opts'].headers.Host = [p.get('host')];
        if (p.get('method')) proxy['http-opts'].method = p.get('method');
      }
      break;
    case 'http':
      proxy['h2-opts'] = { path: [p.get('path') || '/'], headers: {} };
      if (p.get('host')) proxy['h2-opts'].host = [p.get('host')];
      break;
    case 'ws':
    case 'httpupgrade': {
      proxy['ws-opts'] = {
        path: p.get('path') || '',
        headers: buildMihomoShareWsHeaders(p.get('host') || '')
      };
      const earlyData = p.get('ed');
      if (earlyData) {
        const size = Number(earlyData);
        if (Number.isFinite(size) && size >= 0) {
          if (network === 'ws') {
            proxy['ws-opts']['max-early-data'] = size;
            proxy['ws-opts']['early-data-header-name'] = 'Sec-WebSocket-Protocol';
          } else {
            proxy['ws-opts']['v2ray-http-upgrade-fast-open'] = true;
          }
        }
      }
      if (p.get('eh')) proxy['ws-opts']['early-data-header-name'] = p.get('eh');
      break;
    }
    case 'grpc':
      proxy['grpc-opts'] = { 'grpc-service-name': p.get('serviceName') || '' };
      break;
    case 'xhttp':
      proxy['xhttp-opts'] = {};
      if (p.get('path')) proxy['xhttp-opts'].path = p.get('path');
      if (p.get('host')) proxy['xhttp-opts'].host = p.get('host');
      if (p.get('mode')) proxy['xhttp-opts'].mode = p.get('mode');
      try {
        const extra = JSON.parse(p.get('extra') || 'null');
        if (extra && typeof extra === 'object' && !Array.isArray(extra)) {
          parseXHTTPExtra(extra, proxy['xhttp-opts']);
        }
      } catch {
        // Ignore malformed xhttp extra payloads.
      }
      break;
    default:
      break;
  }

  return proxy;
}
function buildVlessProxy({
  name,
  server,
  port,
  uuid,
  network = 'tcp',
  security = '',
  servername = '',
  flow = '',
  skipCertVerify = false,
  alpn = [],
  fingerprint = '',
  tlsFingerprint = '',
  realityPublicKey = '',
  realityShortId = '',
  wsPath = '/',
  wsHost = '',
  grpcServiceName = '',
  h2Path = '/',
  h2Host = [],
  packetEncoding = '',
  xhttpPath = '',
  xhttpHost = '',
  xhttpMode = '',
  xhttpExtra = null
}) {
  if (!name || !server || !Number.isFinite(+port) || !uuid) return null;

  const proxy = { name, type: 'vless', server, port: +port, uuid, udp: true };
  const rawNet = String(network || 'tcp').toLowerCase();
  const isHttpUpgrade = rawNet === 'httpupgrade' || rawNet === 'http-upgrade';
  const isXhttp = rawNet === 'xhttp' || rawNet === 'splithttp';
  const net = isHttpUpgrade ? 'ws' : isXhttp ? 'xhttp' : rawNet;
  proxy.network = net;

  const sec = security || '';
  if (sec === 'tls' || sec === 'reality') proxy.tls = true;
  if (servername) proxy.servername = servername;
  if (flow) proxy.flow = flow;
  if (skipCertVerify) proxy['skip-cert-verify'] = true;
  const alpnList = (Array.isArray(alpn) ? alpn : [alpn]).map(v => String(v).trim()).filter(Boolean);
  if (alpnList.length) proxy.alpn = alpnList;
  switch (String(packetEncoding || '').toLowerCase()) {
    case 'none':
      break;
    case 'packet':
      proxy['packet-addr'] = true;
      break;
    default:
      proxy.xudp = true;
      break;
  }

  if (fingerprint) {
    proxy['client-fingerprint'] = fingerprint;
  } else if (proxy.tls) {
    proxy['client-fingerprint'] = 'chrome';
  }
  if (tlsFingerprint) proxy.fingerprint = tlsFingerprint;

  if (sec === 'reality') {
    proxy['reality-opts'] = {};
    if (realityPublicKey) proxy['reality-opts']['public-key'] = realityPublicKey;
    if (realityShortId !== undefined && realityShortId !== null && String(realityShortId) !== '') {
      proxy['reality-opts']['short-id'] = String(realityShortId);
    }
  }

  if (net === 'ws') {
    proxy['ws-opts'] = { path: wsPath || '/' };
    if (isHttpUpgrade) proxy['ws-opts']['v2ray-http-upgrade'] = true;
    if (wsHost) proxy['ws-opts'].headers = { Host: wsHost };
  } else if (net === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': grpcServiceName || '' };
  } else if (net === 'h2' || net === 'http') {
    const host = Array.isArray(h2Host) ? h2Host : [h2Host || server];
    proxy['h2-opts'] = { path: h2Path || '/', host: host.filter(Boolean) };
  } else if (net === 'xhttp') {
    proxy['xhttp-opts'] = {};
    if (xhttpPath) proxy['xhttp-opts'].path = xhttpPath;
    if (xhttpHost) proxy['xhttp-opts'].host = xhttpHost;
    if (xhttpMode) proxy['xhttp-opts'].mode = xhttpMode;
    if (xhttpExtra && typeof xhttpExtra === 'object') {
      parseXHTTPExtra(xhttpExtra, proxy['xhttp-opts']);
    }
    if (proxy['xhttp-opts'].mode === 'stream-one') {
      delete proxy['xhttp-opts']['download-settings'];
    }
  }

  return proxy;
}

function parseUrlOrNull(raw) {
  try {
    return new URL(raw);
  } catch {
    return null;
  }
}

function decodeURIComponentSafe(value) {
  const s = String(value ?? '');
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function decodeBase64Compat(value) {
  let b64 = String(value ?? '').trim();
  if (!b64) return null;
  b64 = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  try {
    return atob(b64);
  } catch {
    return null;
  }
}

function parseBoolish(value) {
  const v = String(value ?? '').trim().toLowerCase();
  if (!v) return false;
  return ['1', 'true', 't', 'yes', 'y', 'on'].includes(v);
}

function parseCsv(value) {
  return String(value ?? '').split(',').map(v => v.trim()).filter(Boolean);
}

function parseRelativePathQuery(pathValue) {
  const raw = String(pathValue ?? '');
  const qm = raw.indexOf('?');
  if (qm < 0) return { path: raw, query: new URLSearchParams() };
  return {
    path: raw.slice(0, qm) || '/',
    query: new URLSearchParams(raw.slice(qm + 1))
  };
}

function parseVless(rawUrl) {
  const proxy = parseMihomoVShareLink(rawUrl, 'vless', { decodeBase64Host: true });
  if (!proxy) return null;
  const u = parseBase64HostUrl(rawUrl);
  const p = u?.searchParams;
  if (!p) return proxy;
  if (parseBoolish(p.get('allowInsecure')) || parseBoolish(p.get('insecure'))) proxy['skip-cert-verify'] = true;
  const flow = p.get('flow');
  if (flow) proxy.flow = flow.toLowerCase();
  const encryption = p.get('encryption');
  if (encryption) proxy.encryption = encryption;
  return proxy;
}

function parseVmessLegacyFromJson(json) {
  const server = String(json.add || '').trim();
  const port = Number(json.port);
  const uuid = String(json.id || '').trim();
  if (!server || !Number.isFinite(port) || !uuid) return null;

  const name = String(json.ps || '').trim() || `vmess-${server}`;
  const proxy = {
    name,
    type: 'vmess',
    server,
    port,
    uuid,
    alterId: Number(json.aid || 0),
    cipher: json.scy || 'auto',
    udp: true,
    xudp: true
  };

  const tls = String(json.tls || '').toLowerCase();
  if (tls.endsWith('tls')) {
    proxy.tls = true;
    if (json.alpn) proxy.alpn = parseCsv(json.alpn);
  }
  if (json.sni) proxy.servername = String(json.sni);
  if (json.fp) proxy['client-fingerprint'] = String(json.fp);
  if (parseBoolish(json.allowInsecure) || parseBoolish(json.insecure)) proxy['skip-cert-verify'] = true;

  let network = String(json.net || 'tcp').toLowerCase();
  if (String(json.type || '').toLowerCase() === 'http') {
    network = 'http';
  } else if (network === 'http') {
    network = 'h2';
  }
  proxy.network = network;

  if (network === 'http') {
    const hostList = parseCsv(json.host);
    proxy['http-opts'] = { path: [json.path || '/'], headers: {} };
    if (hostList.length) proxy['http-opts'].headers = { Host: hostList };
  } else if (network === 'h2') {
    proxy['h2-opts'] = { path: json.path || '', headers: {} };
    const hostList = parseCsv(json.host);
    if (hostList.length) proxy['h2-opts'].headers = { Host: hostList };
  } else if (network === 'ws' || network === 'httpupgrade') {
    proxy['ws-opts'] = {
      path: '/',
      headers: {}
    };
    if (json.host) proxy['ws-opts'].headers.Host = String(json.host);
    if (json.path) {
      let path = String(json.path);
      const parsedPath = parseRelativePathQuery(path);
      const earlyData = parsedPath.query.get('ed');
      if (earlyData) {
        const size = Number(earlyData);
        if (Number.isFinite(size)) {
          if (network === 'ws') {
            proxy['ws-opts']['max-early-data'] = size;
            proxy['ws-opts']['early-data-header-name'] = 'Sec-WebSocket-Protocol';
          } else {
            proxy['ws-opts']['v2ray-http-upgrade-fast-open'] = true;
          }
          parsedPath.query.delete('ed');
          path = parsedPath.path + (parsedPath.query.toString() ? `?${parsedPath.query.toString()}` : '');
        }
      }
      const earlyHeader = parsedPath.query.get('eh');
      if (earlyHeader) proxy['ws-opts']['early-data-header-name'] = earlyHeader;
      proxy['ws-opts'].path = path;
    }
  } else if (network === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': json.path || '' };
  }

  return proxy;
}

function parseVmessUrl(rawUrl) {
  const proxy = parseMihomoVShareLink(rawUrl, 'vmess');
  if (!proxy) return null;
  const u = parseUrlOrNull(rawUrl);
  const p = u?.searchParams;
  if (p && (parseBoolish(p.get('allowInsecure')) || parseBoolish(p.get('insecure')))) {
    proxy['skip-cert-verify'] = true;
  }
  proxy.alterId = 0;
  proxy.cipher = p?.get('encryption') || 'auto';
  return proxy;
}

function parseVmess(rawUrl) {
  const b64 = rawUrl.replace(/^vmess:\/\//i, '');
  const decoded = decodeBase64Compat(b64);
  if (decoded) {
    try {
      const json = JSON.parse(decoded);
      const legacy = parseVmessLegacyFromJson(json);
      if (legacy) return legacy;
    } catch {
      // vmess may be URL-style, fallback below.
    }
  }
  return parseVmessUrl(rawUrl);
}

function parseSS(rawUrl) {
  let u = parseUrlOrNull(rawUrl);
  if (!u || u.protocol !== 'ss:') return null;

  if (!u.port) {
    const decoded = decodeBase64Compat(u.host);
    if (!decoded) return null;
    const rebuilt = parseUrlOrNull(`ss://${decoded}${u.search}${u.hash}`);
    if (!rebuilt) return null;
    u = rebuilt;
  }

  const server = u.hostname;
  const port = Number(u.port);
  if (!server || !Number.isFinite(port)) return null;

  let cipher = decodeURIComponentSafe(u.username);
  let password = decodeURIComponentSafe(u.password);
  if (!password) {
    const decoded = decodeBase64Compat(cipher);
    if (!decoded) return null;
    const idx = decoded.indexOf(':');
    if (idx < 0) return null;
    cipher = decoded.slice(0, idx);
    password = decoded.slice(idx + 1);
  }
  if (!cipher) return null;

  const name = u.hash ? decodeURIComponentSafe(u.hash.slice(1)) : `ss-${server}`;
  const proxy = { name, type: 'ss', server, port, cipher, password, udp: true };
  const q = u.searchParams;
  if (parseBoolish(q.get('udp-over-tcp')) || q.get('uot') === '1') proxy['udp-over-tcp'] = true;

  const plugin = q.get('plugin') || '';
  if (plugin.includes(';')) {
    const pluginInfo = new URLSearchParams(`pluginName=${plugin.replace(/;/g, '&')}`);
    const pluginName = (pluginInfo.get('pluginName') || '').toLowerCase();
    if (pluginName.includes('obfs')) {
      proxy.plugin = 'obfs';
      proxy['plugin-opts'] = {
        mode: pluginInfo.get('obfs') || '',
        host: pluginInfo.get('obfs-host') || ''
      };
    } else if (pluginName.includes('v2ray-plugin')) {
      proxy.plugin = 'v2ray-plugin';
      proxy['plugin-opts'] = {
        mode: pluginInfo.get('mode') || '',
        host: pluginInfo.get('host') || '',
        path: pluginInfo.get('path') || '',
        tls: /(?:^|;)tls(?:;|$)/.test(plugin)
      };
    }
  }
  return proxy;
}

function parseTrojan(rawUrl) {
  const u = parseUrlOrNull(rawUrl);
  if (!u || u.protocol !== 'trojan:') return null;
  const server = u.hostname;
  const port = Number(u.port);
  const password = decodeURIComponentSafe(u.username);
  if (!server || !Number.isFinite(port) || !password) return null;

  const p = u.searchParams;
  const proxy = {
    name: u.hash ? decodeURIComponentSafe(u.hash.slice(1)) : `trojan-${server}`,
    type: 'trojan',
    server,
    port,
    password,
    udp: true
  };
  if (p.get('sni')) proxy.sni = p.get('sni');
  if (parseBoolish(p.get('allowInsecure')) || parseBoolish(p.get('insecure'))) proxy['skip-cert-verify'] = true;
  const alpn = parseCsv(p.get('alpn'));
  if (alpn.length) proxy.alpn = alpn;
  proxy['client-fingerprint'] = p.get('fp') || 'chrome';
  if (p.get('pcs')) proxy.fingerprint = p.get('pcs');

  const network = String(p.get('type') || '').toLowerCase();
  if (network) {
    proxy.network = network;
    if (network === 'ws') {
      proxy['ws-opts'] = {
        path: p.get('path') || '',
        headers: buildMihomoShareWsHeaders('', false)
      };
    } else if (network === 'grpc') {
      proxy['grpc-opts'] = { 'grpc-service-name': p.get('serviceName') || '' };
    }
  }
  return proxy;
}

function parseHysteria2(rawUrl) {
  const u = parseUrlOrNull(rawUrl);
  if (!u || (u.protocol !== 'hysteria2:' && u.protocol !== 'hy2:')) return null;
  const server = u.hostname;
  const port = Number(u.port || 443);
  if (!server || !Number.isFinite(port)) return null;

  const p = u.searchParams;
  const proxy = {
    name: u.hash ? decodeURIComponentSafe(u.hash.slice(1)) : `hy2-${server}`,
    type: 'hysteria2',
    server,
    port
  };
  const password = decodeURIComponentSafe(u.username);
  if (password) proxy.password = password;
  if (p.get('sni')) proxy.sni = p.get('sni');
  if (parseBoolish(p.get('insecure'))) proxy['skip-cert-verify'] = true;
  const obfs = p.get('obfs');
  if (obfs && obfs !== 'none') {
    proxy.obfs = obfs;
    if (p.get('obfs-password')) proxy['obfs-password'] = p.get('obfs-password');
  }
  const alpn = parseCsv(p.get('alpn'));
  if (alpn.length) proxy.alpn = alpn;
  if (p.get('pinSHA256')) proxy.fingerprint = p.get('pinSHA256');
  if (p.get('up')) proxy.up = p.get('up');
  if (p.get('down')) proxy.down = p.get('down');
  return proxy;
}

function parseTuic(rawUrl) {
  const u = parseUrlOrNull(rawUrl);
  if (!u || u.protocol !== 'tuic:') return null;
  const server = u.hostname;
  const port = Number(u.port);
  if (!server || !Number.isFinite(port)) return null;

  const p = u.searchParams;
  const proxy = {
    name: u.hash ? decodeURIComponentSafe(u.hash.slice(1)) : `tuic-${server}`,
    type: 'tuic',
    server,
    port,
    udp: true
  };

  const username = decodeURIComponentSafe(u.username);
  const password = decodeURIComponentSafe(u.password);
  if (password) {
    proxy.uuid = username;
    proxy.password = password;
  } else if (username) {
    proxy.token = username;
  } else {
    return null;
  }

  if (p.get('sni')) proxy.sni = p.get('sni');
  const alpn = parseCsv(p.get('alpn'));
  if (alpn.length) proxy.alpn = alpn;
  if (p.get('congestion_control')) proxy['congestion-controller'] = p.get('congestion_control');
  if (p.get('udp_relay_mode')) proxy['udp-relay-mode'] = p.get('udp_relay_mode');
  if (parseBoolish(p.get('disable_sni'))) proxy['disable-sni'] = true;
  return proxy;
}

function parseJsonObject(text) {
  if (typeof text !== 'string') return null;
  try {
    const obj = JSON.parse(text);
    if (!obj || Array.isArray(obj) || typeof obj !== 'object') return null;
    return obj;
  } catch {
    return null;
  }
}

function parseJsonObjectMaybe(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) return value;
  return parseJsonObject(String(value ?? ''));
}

function decodeBase64UrlToBytes(input) {
  let b64 = String(input ?? '').trim();
  if (!b64) return null;
  b64 = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  let bin;
  try {
    bin = atob(b64);
  } catch {
    return null;
  }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function decodeUtf8(bytes) {
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    return '';
  }
}

function withTimeoutOrNull(promise, timeoutMs) {
  return new Promise(resolve => {
    const timer = setTimeout(() => resolve(null), timeoutMs);
    Promise.resolve(promise)
      .then(value => {
        clearTimeout(timer);
        resolve(value);
      })
      .catch(() => {
        clearTimeout(timer);
        resolve(null);
      });
  });
}

async function inflateZlib(bytes) {
  if (!bytes || !bytes.length) return null;
  if (typeof DecompressionStream === 'undefined') return null;
  return withTimeoutOrNull((async () => {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate'));
    const inflated = await new Response(stream).arrayBuffer();
    return new Uint8Array(inflated);
  })(), 5000);
}

function normalizeAwgValue(v) {
  v = String(v ?? '').trim();
  if (v === '""' || v === "''") return '';
  return v;
}

function getAwgKey(obj, k) {
  return obj?.[k] ?? obj?.[k.toUpperCase()] ?? obj?.[k.toLowerCase()];
}

function hasAwgKey(obj, k) {
  return getAwgKey(obj, k) !== undefined;
}

function toIntMaybe(v) {
  v = normalizeAwgValue(v);
  if (!v || !/^\d+$/.test(v)) return null;
  return +v;
}

function toIntOrRangeMaybe(v) {
  v = normalizeAwgValue(v);
  if (!v) return null;
  if (/^\d+$/.test(v)) return +v;
  const m = v.match(/^(\d+)\s*-\s*(\d+)$/);
  if (!m) return null;
  return `${m[1]}-${m[2]}`;
}

function normalizeAwgVersion(rawVersion, hasV20, hasV15) {
  const v = String(rawVersion ?? '').trim().toLowerCase();
  if (v === '2' || v === '2.0') return '2.0';
  if (v === '1.5') return '1.5';
  if (v === '1' || v === '1.0') return '1.0';
  return hasV20 ? '2.0' : (hasV15 ? '1.5' : '1.0');
}

function hasAnyAwgKey(obj) {
  const keys = [
    'Jc','Jmin','Jmax',
    'S1','S2','S3','S4',
    'H1','H2','H3','H4',
    'I1','I2','I3','I4','I5',
    'J1','J2','J3',
    'Itime'
  ];
  for (const k of keys) {
    if (hasAwgKey(obj, k)) return true;
  }
  return false;
}

function collectAwgOptions(obj) {
  const h1 = toIntOrRangeMaybe(getAwgKey(obj, 'H1'));
  const h2 = toIntOrRangeMaybe(getAwgKey(obj, 'H2'));
  const h3 = toIntOrRangeMaybe(getAwgKey(obj, 'H3'));
  const h4 = toIntOrRangeMaybe(getAwgKey(obj, 'H4'));
  const hasV20 =
    hasAwgKey(obj, 'S3') || hasAwgKey(obj, 'S4') ||
    [h1, h2, h3, h4].some(v => typeof v === 'string');
  const hasV15 = hasAwgKey(obj, 'I1');

  const awg = {};
  if (hasAwgKey(obj, 'Jc')) awg.jc = toIntMaybe(getAwgKey(obj, 'Jc')) ?? 0;
  if (hasAwgKey(obj, 'Jmin')) awg.jmin = toIntMaybe(getAwgKey(obj, 'Jmin')) ?? 0;
  if (hasAwgKey(obj, 'Jmax')) awg.jmax = toIntMaybe(getAwgKey(obj, 'Jmax')) ?? 0;
  if (hasAwgKey(obj, 'S1')) awg.s1 = toIntMaybe(getAwgKey(obj, 'S1')) ?? 0;
  if (hasAwgKey(obj, 'S2')) awg.s2 = toIntMaybe(getAwgKey(obj, 'S2')) ?? 0;
  if (hasAwgKey(obj, 'S3')) awg.s3 = toIntMaybe(getAwgKey(obj, 'S3')) ?? 0;
  if (hasAwgKey(obj, 'S4')) awg.s4 = toIntMaybe(getAwgKey(obj, 'S4')) ?? 0;
  if (hasAwgKey(obj, 'H1')) awg.h1 = h1 ?? 0;
  if (hasAwgKey(obj, 'H2')) awg.h2 = h2 ?? 0;
  if (hasAwgKey(obj, 'H3')) awg.h3 = h3 ?? 0;
  if (hasAwgKey(obj, 'H4')) awg.h4 = h4 ?? 0;

  if (hasV15) {
    awg.i1 = normalizeAwgValue(getAwgKey(obj, 'I1'));
    if (hasAwgKey(obj, 'I2')) awg.i2 = normalizeAwgValue(getAwgKey(obj, 'I2'));
    if (hasAwgKey(obj, 'I3')) awg.i3 = normalizeAwgValue(getAwgKey(obj, 'I3'));
    if (hasAwgKey(obj, 'I4')) awg.i4 = normalizeAwgValue(getAwgKey(obj, 'I4'));
    if (hasAwgKey(obj, 'I5')) awg.i5 = normalizeAwgValue(getAwgKey(obj, 'I5'));
    if (hasAwgKey(obj, 'J1')) awg.j1 = normalizeAwgValue(getAwgKey(obj, 'J1'));
    if (hasAwgKey(obj, 'J2')) awg.j2 = normalizeAwgValue(getAwgKey(obj, 'J2'));
    if (hasAwgKey(obj, 'J3')) awg.j3 = normalizeAwgValue(getAwgKey(obj, 'J3'));
    if (hasAwgKey(obj, 'Itime')) awg.itime = toIntMaybe(getAwgKey(obj, 'Itime')) ?? 0;
  }

  return { awg, hasV20, hasV15 };
}

function parseAmneziaWireGuardBaseProxy(serverConfig, protocolConfig, clientConfig, namePrefix) {
  const server = String(clientConfig.hostName || serverConfig.hostName || '').trim();
  const port = Number(clientConfig.port ?? protocolConfig.port);
  const privateKey = String(clientConfig.client_priv_key || '').trim();
  const publicKey = String(clientConfig.server_pub_key || '').trim();
  if (!server || !Number.isFinite(port) || !privateKey || !publicKey) return null;

  const ipRaw = String(clientConfig.client_ip || '').trim();
  const ip = (ipRaw ? ipRaw.split(',')[0] : '10.0.0.2').split('/')[0].trim() || '10.0.0.2';
  const name = String(serverConfig.description || '').trim() || `${namePrefix}-${server}`;

  const proxy = {
    name,
    type: 'wireguard',
    server,
    port,
    ip,
    'private-key': privateKey,
    'public-key': publicKey,
    udp: true
  };

  const psk = String(clientConfig.psk_key || '').trim();
  if (psk) proxy['pre-shared-key'] = psk;
  const mtu = toIntMaybe(clientConfig.mtu);
  if (mtu !== null) proxy.mtu = mtu;

  const dns1 = String(serverConfig.dns1 || '').trim();
  if (dns1) {
    proxy.dns = [dns1];
  } else {
    const cfgText = String(clientConfig.config || '');
    const mDns = cfgText.match(/^\s*DNS\s*=\s*([^\r\n]+)/im);
    if (mDns && mDns[1]) {
      const firstDns = mDns[1].split(',')[0].trim();
      if (firstDns) proxy.dns = [firstDns];
    }
  }

  return proxy;
}

function parseAmneziaWireGuardProxy(serverConfig, container) {
  const protocolConfig = parseJsonObjectMaybe(container?.wireguard);
  if (!protocolConfig) return null;
  const clientConfig = parseJsonObjectMaybe(protocolConfig?.last_config);
  if (!clientConfig) return null;
  return parseAmneziaWireGuardBaseProxy(serverConfig, protocolConfig, clientConfig, 'wg');
}

function parseAmneziaAwgProxy(serverConfig, container) {
  const protocolConfig = parseJsonObjectMaybe(container?.awg);
  if (!protocolConfig) return null;
  const clientConfig = parseJsonObjectMaybe(protocolConfig?.last_config);
  if (!clientConfig) return null;
  const proxy = parseAmneziaWireGuardBaseProxy(serverConfig, protocolConfig, clientConfig, 'awg');
  if (!proxy) return null;

  const { awg, hasV20, hasV15 } = collectAwgOptions(clientConfig);
  const awgVersion = normalizeAwgVersion(protocolConfig.protocol_version, hasV20, hasV15);
  proxy.awgVersion = awgVersion;
  proxy['amnezia-wg-option'] = awg;

  return proxy;
}

function parseAmneziaVlessProxy(serverConfig, container) {
  const protocolConfig = parseJsonObjectMaybe(container?.xray);
  if (!protocolConfig) return null;
  const lastConfig = parseJsonObjectMaybe(protocolConfig?.last_config);
  if (!lastConfig) return null;

  const outbounds = Array.isArray(lastConfig.outbounds) ? lastConfig.outbounds : [];
  const outbound = outbounds.find(o => o && o.protocol === 'vless') || outbounds[0];
  if (!outbound || outbound.protocol !== 'vless') return null;

  const vnext = outbound.settings?.vnext?.[0];
  const user = vnext?.users?.[0];
  const server = String(vnext?.address || serverConfig.hostName || '').trim();
  const port = Number(vnext?.port);
  const uuid = String(user?.id || '').trim();
  if (!server || !Number.isFinite(port) || !uuid) return null;

  const stream = outbound.streamSettings || {};
  const reality = stream.realitySettings || {};
  const tls = stream.tlsSettings || {};
  const ws = stream.wsSettings || {};
  const grpc = stream.grpcSettings || {};
  const http = stream.httpSettings || {};

  return buildVlessProxy({
    name: String(serverConfig.description || '').trim() || `vless-${server}`,
    server,
    port,
    uuid,
    network: stream.network || 'tcp',
    security: stream.security || '',
    servername: reality.serverName || tls.serverName || '',
    flow: user?.flow || '',
    skipCertVerify: !!tls.allowInsecure || !!reality.allowInsecure,
    alpn: Array.isArray(tls.alpn) ? tls.alpn : (tls.alpn ? [tls.alpn] : []),
    fingerprint: reality.fingerprint || tls.fingerprint || '',
    realityPublicKey: reality.publicKey || '',
    realityShortId: reality.shortId,
    wsPath: ws.path || '/',
    wsHost: ws.headers?.Host || ws.headers?.host || '',
    grpcServiceName: grpc.serviceName || '',
    h2Path: http.path || '/',
    h2Host: Array.isArray(http.host) ? http.host : [http.host || server]
  });
}

function parseAmneziaVpnJson(serverConfig) {
  if (!serverConfig || typeof serverConfig !== 'object') return null;
  const containers = Array.isArray(serverConfig.containers) ? serverConfig.containers : [];
  if (!containers.length) return null;

  const orderedContainers = [];
  const defaultContainer = String(serverConfig.defaultContainer || '').toLowerCase();
  if (defaultContainer) {
    const preferred = containers.find(c => String(c?.container || '').toLowerCase() === defaultContainer);
    if (preferred) orderedContainers.push(preferred);
  }
  for (const container of containers) {
    if (!orderedContainers.includes(container)) orderedContainers.push(container);
  }

  for (const container of orderedContainers) {
    const containerName = String(container?.container || '').toLowerCase();
    if (containerName === 'amnezia-awg' || containerName === 'amnezia-awg2') {
      const awgProxy = parseAmneziaAwgProxy(serverConfig, container);
      if (awgProxy) return awgProxy;
      continue;
    }
    if (containerName === 'amnezia-wireguard') {
      const wireGuardProxy = parseAmneziaWireGuardProxy(serverConfig, container);
      if (wireGuardProxy) return wireGuardProxy;
      continue;
    }
    if (containerName === 'amnezia-xray') {
      const vlessProxy = parseAmneziaVlessProxy(serverConfig, container);
      if (vlessProxy) return vlessProxy;
    }
  }
  return null;
}

async function parseAmneziaVpnLink(line) {
  const encoded = line.replace(/^vpn:\/\//i, '').trim();
  if (!encoded) return null;

  const raw = decodeBase64UrlToBytes(encoded);
  if (!raw) return null;

  let serverConfig = parseJsonObject(decodeUtf8(raw));

  if (!serverConfig) {
    let inflated = null;
    if (raw.length > 4) {
      inflated = await inflateZlib(raw.slice(4));
    }
    if (!inflated) {
      inflated = await inflateZlib(raw);
    }
    if (!inflated) return null;
    serverConfig = parseJsonObject(decodeUtf8(inflated));
  }

  if (!serverConfig) return null;
  return parseAmneziaVpnJson(serverConfig);
}

function parseWireGuardConfig(text) {
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
  const privateKey = getAwgKey(iface, 'PrivateKey');
  const publicKey = getAwgKey(peer, 'PublicKey');
  const endpoint = getAwgKey(peer, 'Endpoint');
  if (!privateKey || !publicKey || !endpoint) return null;
  const ep = endpoint.match(/^([^:]+):(\d+)$/);
  if (!ep) return null;
  const server = ep[1], port = +ep[2];
  const address = getAwgKey(iface, 'Address');
  let ip = '10.0.0.2';
  let ipv6 = null;
  if (address) {
    const addrs = address.split(',').map(a => a.trim().split('/')[0].trim());
    const v4 = addrs.find(a => /^\d{1,3}(\.\d{1,3}){3}$/.test(a));
    const v6 = addrs.find(a => a.includes(':'));
    if (v4) ip = v4;
    if (v6) ipv6 = v6;
  }
  const isAmnezia = hasAnyAwgKey(iface);

  const proxy = {
    name: (isAmnezia ? 'awg-' : 'wg-') + server,
    type: 'wireguard', server, port, ip,
    'private-key': privateKey,
    'public-key': publicKey,
    udp: true
  };
  if (ipv6) proxy.ipv6 = ipv6;
  const mtu = toIntMaybe(getAwgKey(iface, 'MTU'));
  if (mtu !== null) proxy.mtu = mtu;
  const psk = getAwgKey(peer, 'PresharedKey');
  if (psk) proxy['pre-shared-key'] = psk;
  const dns = getAwgKey(iface, 'DNS');
  if (dns) proxy.dns = [dns.split(',')[0].trim()];
  if (isAmnezia) {
    const { awg, hasV20, hasV15 } = collectAwgOptions(iface);
    proxy.awgVersion = normalizeAwgVersion('', hasV20, hasV15);
    proxy['amnezia-wg-option'] = awg;
  }
  return proxy;
}

async function parseProxyUrl(line) {
  line = line.trim();
  if (!line) return null;
  const lower = line.toLowerCase();
  if (lower.startsWith('vpn://')) return await withTimeoutOrNull(parseAmneziaVpnLink(line), 10000);
  if (lower.startsWith('vless://')) return parseVless(line);
  if (lower.startsWith('vmess://')) return parseVmess(line);
  if (lower.startsWith('ss://')) return parseSS(line);
  if (lower.startsWith('trojan://')) return parseTrojan(line);
  if (lower.startsWith('hysteria2://') || lower.startsWith('hy2://')) return parseHysteria2(line);
  if (lower.startsWith('tuic://')) return parseTuic(line);
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
