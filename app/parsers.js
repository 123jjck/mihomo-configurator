// ============================================================
// Proxy Parsers (Step 2)
// ============================================================
function parseXHTTPExtra(extra, opts) {
  const xmuxToReuse = (xmux) => {
    if (!xmux || typeof xmux !== 'object' || Array.isArray(xmux)) return null;
    const reuse = {};
    const mapStr = (src, dst) => {
      const value = xmux[src];
      if (typeof value === 'string' && value) reuse[dst] = value;
      else if (typeof value === 'number' && Number.isFinite(value)) reuse[dst] = String(Math.trunc(value));
    };
    mapStr('maxConnections', 'max-connections');
    mapStr('maxConcurrency', 'max-concurrency');
    mapStr('cMaxReuseTimes', 'c-max-reuse-times');
    mapStr('hMaxRequestTimes', 'h-max-request-times');
    mapStr('hMaxReusableSecs', 'h-max-reusable-secs');
    // hKeepAlivePeriod is a number in Go, stored as int
    if (typeof xmux['hKeepAlivePeriod'] === 'number' && Number.isFinite(xmux['hKeepAlivePeriod']))
      reuse['h-keep-alive-period'] = Math.trunc(xmux['hKeepAlivePeriod']);
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
  const setStr = (src, dst) => {
    if (typeof extra[src] === 'string' && extra[src]) opts[dst] = extra[src];
  };
  const setNum = (src, dst) => {
    if (typeof extra[src] === 'number' && Number.isFinite(extra[src])) opts[dst] = Math.trunc(extra[src]);
  };

  if (extra.noGRPCHeader === true) opts['no-grpc-header'] = true;
  setStr('xPaddingBytes', 'x-padding-bytes');
  if (typeof extra.xPaddingObfsMode === 'boolean') opts['x-padding-obfs-mode'] = extra.xPaddingObfsMode;
  setStr('xPaddingKey', 'x-padding-key');
  setStr('xPaddingHeader', 'x-padding-header');
  setStr('xPaddingPlacement', 'x-padding-placement');
  setStr('xPaddingMethod', 'x-padding-method');
  setStr('uplinkHttpMethod', 'uplink-http-method');
  setStr('sessionPlacement', 'session-placement');
  setStr('sessionKey', 'session-key');
  setStr('seqPlacement', 'seq-placement');
  setStr('seqKey', 'seq-key');
  setStr('uplinkDataPlacement', 'uplink-data-placement');
  setStr('uplinkDataKey', 'uplink-data-key');
  setNum('uplinkChunkSize', 'uplink-chunk-size');
  setNum('scMaxEachPostBytes', 'sc-max-each-post-bytes');
  setNum('scMinPostsIntervalMs', 'sc-min-posts-interval-ms');

  const rootReuse = xmuxToReuse(extra.xmux);
  if (rootReuse) opts['reuse-settings'] = rootReuse;
  const headers = toHeaderMap(extra.headers);
  if (headers) opts.headers = headers;

  if (extra.downloadSettings && typeof extra.downloadSettings === 'object') {
    const ds = extra.downloadSettings;
    const dsOpts = {};
    if (typeof ds.address === 'string' && ds.address) dsOpts['server'] = ds.address;
    if (typeof ds.port === 'number') dsOpts['port'] = Math.trunc(ds.port);
    const sec = typeof ds.security === 'string' ? ds.security.toLowerCase() : '';
    if (sec === 'tls' || sec === 'reality') {
      dsOpts['tls'] = true;
      if (ds.tlsSettings && typeof ds.tlsSettings === 'object') {
        const tls = ds.tlsSettings;
        if (typeof tls.serverName === 'string' && tls.serverName) dsOpts['servername'] = tls.serverName;
        if (typeof tls.fingerprint === 'string' && tls.fingerprint) dsOpts['client-fingerprint'] = tls.fingerprint;
        if (tls.allowInsecure === true) dsOpts['skip-cert-verify'] = true;
        if (Array.isArray(tls.alpn) && tls.alpn.length > 0)
          dsOpts['alpn'] = tls.alpn.filter(a => typeof a === 'string');
      }
      if (sec === 'reality' && ds.realitySettings && typeof ds.realitySettings === 'object') {
        const r = ds.realitySettings;
        const realityOpts = {};
        if (typeof r.publicKey === 'string' && r.publicKey) realityOpts['public-key'] = r.publicKey;
        if (typeof r.shortId === 'string' && r.shortId) realityOpts['short-id'] = r.shortId;
        if (Object.keys(realityOpts).length > 0) dsOpts['reality-opts'] = realityOpts;
      }
    }
    if (ds.xhttpSettings && typeof ds.xhttpSettings === 'object') {
      const xh = ds.xhttpSettings;
      if (typeof xh.path === 'string' && xh.path) dsOpts['path'] = xh.path;
      if (typeof xh.host === 'string' && xh.host) dsOpts['host'] = xh.host;
      if (xh.headers && typeof xh.headers === 'object' && !Array.isArray(xh.headers)) {
        const dsHeaders = toHeaderMap(xh.headers);
        if (dsHeaders) dsOpts.headers = dsHeaders;
      }
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
    name: shareLinkName(u, `${scheme}-${server}`),
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

  if (parseBoolish(p.get('allowInsecure')) || parseBoolish(p.get('insecure'))) {
    proxy['skip-cert-verify'] = true;
  }
  if (scheme === 'vless') {
    const flow = p.get('flow');
    if (flow) proxy.flow = flow.toLowerCase();
    const encryption = p.get('encryption');
    if (encryption) proxy.encryption = encryption;
  } else if (scheme === 'vmess') {
    proxy.alterId = 0;
    proxy.cipher = p.get('encryption') || 'auto';
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
    case 'httpupgrade':
      proxy['ws-opts'] = {
        path: p.get('path') || '',
        headers: buildMihomoShareWsHeaders(p.get('host') || '')
      };
      applyWsEarlyData(proxy['ws-opts'], network, p.get('ed'), p.get('eh'));
      break;
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
      if (proxy['xhttp-opts'].mode === 'stream-one') {
        delete proxy['xhttp-opts']['download-settings'];
      }
      break;
    default:
      break;
  }

  return proxy;
}
/**
 * Build a mihomo VLESS proxy from already-extracted Xray outbound settings.
 * Only Amnezia `.vpn` payloads use this path, so it covers exactly the stream
 * types their xray container emits — xhttp stream settings are not mapped.
 */
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
  realityPublicKey = '',
  realityShortId = '',
  wsPath = '/',
  wsHost = '',
  grpcServiceName = '',
  h2Path = '/',
  h2Host = []
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
  // Amnezia payloads carry no packetEncoding field; mihomo's default for VLESS is xudp.
  proxy.xudp = true;

  if (fingerprint) {
    proxy['client-fingerprint'] = fingerprint;
  } else if (proxy.tls) {
    proxy['client-fingerprint'] = 'chrome';
  }

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

function normalizeBase64(value) {
  let b64 = String(value ?? '').trim();
  if (!b64) return null;
  b64 = b64.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  b64 += '='.repeat((4 - (b64.length % 4)) % 4);
  return b64;
}

function decodeBase64Compat(value) {
  const b64 = normalizeBase64(value);
  if (!b64) return null;
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

/** Display name taken from the URL fragment, falling back to a generated label. */
function shareLinkName(u, fallback) {
  return u.hash ? decodeURIComponentSafe(u.hash.slice(1)) : fallback;
}

/**
 * Shared prologue for `<scheme>://[user[:pass]@]host[:port][?query][#name]` share links.
 * Returns null when the URL is unparsable, uses a different scheme, or has no host.
 * `namePrefix` picks the fallback name shape: `prefix-host` when set, `host:port` otherwise.
 */
function parseShareLinkBase(rawUrl, schemes, { namePrefix = '', defaultPort = '', requirePort = false } = {}) {
  const u = parseUrlOrNull(rawUrl);
  if (!u) return null;
  if (!schemes.includes(u.protocol.slice(0, -1).toLowerCase())) return null;

  const server = u.hostname;
  if (!server) return null;
  const portStr = u.port || String(defaultPort);
  if (requirePort && !portStr) return null;
  const port = Number(portStr);
  if (!Number.isFinite(port)) return null;

  return {
    url: u,
    params: u.searchParams,
    server,
    port,
    portStr,
    name: shareLinkName(u, namePrefix ? `${namePrefix}-${server}` : `${server}:${portStr}`),
    username: decodeURIComponentSafe(u.username),
    password: decodeURIComponentSafe(u.password)
  };
}

/**
 * Apply v2ray early-data hints to ws-opts. `ed` carries the max early-data size,
 * `eh` overrides the header name. Returns whether `ed` was accepted, so callers
 * that inherit it from a path query know to strip it.
 */
function applyWsEarlyData(wsOpts, network, edValue, ehValue) {
  let applied = false;
  const size = Number(edValue);
  if (edValue && Number.isFinite(size) && size >= 0) {
    if (network === 'ws') {
      wsOpts['max-early-data'] = size;
      wsOpts['early-data-header-name'] = 'Sec-WebSocket-Protocol';
    } else {
      wsOpts['v2ray-http-upgrade-fast-open'] = true;
    }
    applied = true;
  }
  if (ehValue) wsOpts['early-data-header-name'] = ehValue;
  return applied;
}

function parseVless(rawUrl) {
  return parseMihomoVShareLink(rawUrl, 'vless', { decodeBase64Host: true });
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
      // Legacy vmess smuggles `ed` / `eh` inside the path query; strip `ed` once consumed.
      const applied = applyWsEarlyData(
        proxy['ws-opts'],
        network,
        parsedPath.query.get('ed'),
        parsedPath.query.get('eh')
      );
      if (applied) {
        parsedPath.query.delete('ed');
        path = parsedPath.path + (parsedPath.query.toString() ? `?${parsedPath.query.toString()}` : '');
      }
      proxy['ws-opts'].path = path;
    }
  } else if (network === 'grpc') {
    proxy['grpc-opts'] = { 'grpc-service-name': json.path || '' };
  }

  return proxy;
}

function parseVmessUrl(rawUrl) {
  return parseMihomoVShareLink(rawUrl, 'vmess');
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

  const name = shareLinkName(u, `ss-${server}`);
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
      // fall back to obfs/obfs-host params (some share link generators use them)
      const mode = pluginInfo.get('mode') || pluginInfo.get('obfs') || '';
      const host = pluginInfo.get('host') || pluginInfo.get('obfs-host') || '';
      proxy.plugin = 'v2ray-plugin';
      proxy['plugin-opts'] = {
        mode,
        host,
        path: pluginInfo.get('path') || '',
        tls: /(?:^|;)tls(?:;|$)/.test(plugin)
      };
    }
  }
  return proxy;
}

function parseTrojan(rawUrl) {
  const base = parseShareLinkBase(rawUrl, ['trojan'], { namePrefix: 'trojan' });
  if (!base || !base.username) return null;

  const { params: p, server, port } = base;
  const proxy = {
    name: base.name,
    type: 'trojan',
    server,
    port,
    password: base.username,
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
  const base = parseShareLinkBase(rawUrl, ['hysteria2', 'hy2'], { namePrefix: 'hy2', defaultPort: 443 });
  if (!base) return null;

  const { params: p } = base;
  const proxy = {
    name: base.name,
    type: 'hysteria2',
    server: base.server,
    port: base.port
  };
  if (base.username) proxy.password = base.username;
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
  const base = parseShareLinkBase(rawUrl, ['tuic'], { namePrefix: 'tuic' });
  if (!base) return null;

  const { params: p, username, password } = base;
  const proxy = {
    name: base.name,
    type: 'tuic',
    server: base.server,
    port: base.port,
    udp: true
  };

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
  const bin = decodeBase64Compat(input);
  if (bin == null) return null;
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

/**
 * Build a case-insensitive key lookup over a WireGuard/AmneziaWG section.
 * The index is built once per section instead of rescanning the keys on every
 * lookup, and exact matches still win over case-folded ones — this handles
 * variants like PresharedKey / PreSharedKey / PRESHAREDKEY.
 */
function awgLookup(obj) {
  const byLower = new Map();
  for (const [key, value] of Object.entries(obj || {})) {
    const lower = key.toLowerCase();
    if (!byLower.has(lower)) byLower.set(lower, value);
  }
  return key => (obj && key in obj) ? obj[key] : byLower.get(key.toLowerCase());
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

/**
 * Resolve the AmneziaWG generation. An explicit version from the source wins;
 * otherwise it is inferred from which knobs are present. A source that declares
 * plain "3" still reports 3.1 when it carries a 3.1-only knob, because the two
 * releases share one wire protocol and differ only by these extra options.
 */
function normalizeAwgVersion(rawVersion, flags) {
  const v = String(rawVersion ?? '').trim().toLowerCase();
  if (v === '3.1') return '3.1';
  if (v === '3' || v === '3.0') return flags.hasV31 ? '3.1' : '3.0';
  if (v === '2' || v === '2.0') return '2.0';
  if (v === '1.5') return '1.5';
  if (v === '1' || v === '1.0') return '1.0';
  if (flags.hasV31) return '3.1';
  if (flags.hasV3) return '3.0';
  return flags.hasV20 ? '2.0' : (flags.hasV15 ? '1.5' : '1.0');
}

const asAwgInt = v => toIntMaybe(v) ?? 0;
const asAwgIntOrRange = v => toIntOrRangeMaybe(v) ?? 0;
const asAwgBool = v => /^(1|true|yes|on)$/i.test(normalizeAwgValue(v));

/**
 * AmneziaWG obfuscation knobs, in the order mihomo expects them.
 * `v15` marks fields that only exist from protocol 1.5 onward. This list is the
 * single definition of which keys count as AmneziaWG — see hasAnyAwgKey().
 *
 * `legacyOnly` and `v3` mark the knobs each protocol generation owns
 * exclusively: v3 dropped the controlled-junk/itime handshake knobs and added
 * header protection plus the handshake timers. `v31` marks the two options
 * AmneziaWG 3.1 added on top of 3.0.
 */
const AWG_FIELD_SPECS = [
  { key: 'Jc',    out: 'jc',    parse: asAwgInt },
  { key: 'Jmin',  out: 'jmin',  parse: asAwgInt },
  { key: 'Jmax',  out: 'jmax',  parse: asAwgInt },
  { key: 'S1',    out: 's1',    parse: asAwgInt },
  { key: 'S2',    out: 's2',    parse: asAwgInt },
  { key: 'S3',    out: 's3',    parse: asAwgInt },
  { key: 'S4',    out: 's4',    parse: asAwgInt },
  { key: 'H1',    out: 'h1',    parse: asAwgIntOrRange },
  { key: 'H2',    out: 'h2',    parse: asAwgIntOrRange },
  { key: 'H3',    out: 'h3',    parse: asAwgIntOrRange },
  { key: 'H4',    out: 'h4',    parse: asAwgIntOrRange },
  { key: 'I1',    out: 'i1',    parse: normalizeAwgValue, v15: true },
  { key: 'I2',    out: 'i2',    parse: normalizeAwgValue, v15: true },
  { key: 'I3',    out: 'i3',    parse: normalizeAwgValue, v15: true },
  { key: 'I4',    out: 'i4',    parse: normalizeAwgValue, v15: true },
  { key: 'I5',    out: 'i5',    parse: normalizeAwgValue, v15: true },
  { key: 'J1',    out: 'j1',    parse: normalizeAwgValue, v15: true, legacyOnly: true },
  { key: 'J2',    out: 'j2',    parse: normalizeAwgValue, v15: true, legacyOnly: true },
  { key: 'J3',    out: 'j3',    parse: normalizeAwgValue, v15: true, legacyOnly: true },
  { key: 'Itime', out: 'itime', parse: asAwgInt,          v15: true, legacyOnly: true },

  { key: 'HeaderProtectionKey',    out: 'header-protection-key',    parse: normalizeAwgValue, v3: true },
  { key: 'ContentPaddingAddition', out: 'content-padding-addition', parse: asAwgIntOrRange,   v3: true },
  { key: 'RekeyAfterTime',         out: 'rekey-after-time',         parse: asAwgIntOrRange,   v3: true },
  { key: 'RekeyTimeout',           out: 'rekey-timeout',            parse: asAwgIntOrRange,   v3: true },
  { key: 'RejectAfterTime',        out: 'reject-after-time',        parse: asAwgIntOrRange,   v3: true },
  { key: 'KeepaliveTimeout',       out: 'keepalive-timeout',        parse: asAwgIntOrRange,   v3: true },
  { key: 'MaxHandshakeAttempts',   out: 'max-handshake-attempts',   parse: asAwgIntOrRange,   v3: true },
  { key: 'RandomTrailers',         out: 'random-trailers',          parse: asAwgBool, v3: true, v31: true },
  { key: 'DisableCookies',         out: 'disable-cookies',          parse: asAwgBool, v3: true, v31: true }
];

function hasAnyAwgKey(get) {
  return AWG_FIELD_SPECS.some(spec => get(spec.key) !== undefined);
}

/**
 * Keep only the knobs the resolved generation accepts, and pin `version` for
 * v3. mihomo hands `version: 3` to the AmneziaWG v3 device and every other
 * value to the legacy one; each rejects the other's exclusive keys outright, so
 * an unfiltered knob — or a missing `version` — is a startup failure rather
 * than a harmless no-op.
 */
function buildAwgOption(parsed, version) {
  const v3 = version.startsWith('3');
  const awg = v3 ? { version: 3 } : {};
  for (const spec of AWG_FIELD_SPECS) {
    if (!(spec.out in parsed)) continue;
    if (v3 ? spec.legacyOnly : spec.v3) continue;
    awg[spec.out] = parsed[spec.out];
  }
  return awg;
}

function collectAwgOptions(get, rawVersion) {
  const hasV15 = get('I1') !== undefined;

  const parsed = {};
  for (const spec of AWG_FIELD_SPECS) {
    if (spec.v15 && !hasV15) continue;
    const raw = get(spec.key);
    if (raw !== undefined) parsed[spec.out] = spec.parse(raw);
  }

  // Protocol 2.0 is implied by the S3/S4 knobs or by a header given as a range.
  const hasV20 =
    's3' in parsed || 's4' in parsed ||
    ['h1', 'h2', 'h3', 'h4'].some(k => typeof parsed[k] === 'string');
  const hasV3 = AWG_FIELD_SPECS.some(spec => spec.v3 && spec.out in parsed);
  const hasV31 = AWG_FIELD_SPECS.some(spec => spec.v31 && spec.out in parsed);

  const version = normalizeAwgVersion(rawVersion, { hasV31, hasV3, hasV20, hasV15 });
  return { awg: buildAwgOption(parsed, version), version };
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

  const { awg, version } = collectAwgOptions(awgLookup(clientConfig), protocolConfig.protocol_version);
  proxy.awgVersion = version;
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
  const ifaceGet = awgLookup(iface);
  const peerGet = awgLookup(peer);

  const privateKey = ifaceGet('PrivateKey');
  const publicKey = peerGet('PublicKey');
  const endpoint = peerGet('Endpoint');
  if (!privateKey || !publicKey || !endpoint) return null;
  const ep = endpoint.match(/^([^:]+):(\d+)$/);
  if (!ep) return null;
  const server = ep[1], port = +ep[2];
  const address = ifaceGet('Address');
  let ip = '10.0.0.2';
  let ipv6 = null;
  if (address) {
    const addrs = address.split(',').map(a => a.trim().split('/')[0].trim());
    const v4 = addrs.find(a => /^\d{1,3}(\.\d{1,3}){3}$/.test(a));
    const v6 = addrs.find(a => a.includes(':'));
    if (v4) ip = v4;
    if (v6) ipv6 = v6;
  }
  const isAmnezia = hasAnyAwgKey(ifaceGet);

  const proxy = {
    name: (isAmnezia ? 'awg-' : 'wg-') + server,
    type: 'wireguard', server, port, ip,
    'private-key': privateKey,
    'public-key': publicKey,
    udp: true
  };
  if (ipv6) proxy.ipv6 = ipv6;
  const mtu = toIntMaybe(ifaceGet('MTU'));
  if (mtu !== null) proxy.mtu = mtu;
  const psk = peerGet('PresharedKey');
  if (psk) proxy['pre-shared-key'] = psk;
  const dns = ifaceGet('DNS');
  if (dns) proxy.dns = [dns.split(',')[0].trim()];
  if (isAmnezia) {
    const { awg, version } = collectAwgOptions(ifaceGet, '');
    proxy.awgVersion = version;
    proxy['amnezia-wg-option'] = awg;
  }
  return proxy;
}

// ============================================================
// Hysteria v1
// ============================================================
function parseHysteria(rawUrl) {
  const base = parseShareLinkBase(rawUrl, ['hysteria'], { namePrefix: 'hysteria' });
  if (!base) return null;

  const { params: p } = base;
  const proxy = {
    name: base.name,
    type: 'hysteria',
    server: base.server,
    port: base.port
  };
  const peer = p.get('peer');
  if (peer) proxy.sni = peer;
  const obfs = p.get('obfs');
  if (obfs) proxy.obfs = obfs;
  const alpn = parseCsv(p.get('alpn'));
  if (alpn.length) proxy.alpn = alpn;
  const auth = p.get('auth');
  if (auth) proxy.auth_str = auth;
  const protocol = p.get('protocol');
  if (protocol) proxy.protocol = protocol;
  const up = p.get('up') || p.get('upmbps');
  const down = p.get('down') || p.get('downmbps');
  if (up) proxy.up = up;
  if (down) proxy.down = down;
  if (parseBoolish(p.get('insecure'))) proxy['skip-cert-verify'] = true;
  return proxy;
}

// ============================================================
// SSR (ShadowsocksR)
// ============================================================
function parseSsr(rawUrl) {
  const b64 = rawUrl.replace(/^ssr:\/\//i, '');
  const decoded = decodeBase64Compat(b64);
  if (!decoded) return null;

  const qmark = decoded.indexOf('/?');
  const before = qmark >= 0 ? decoded.slice(0, qmark) : decoded;
  const after  = qmark >= 0 ? decoded.slice(qmark + 2) : '';

  // ssr://host:port:protocol:method:obfs:base64pass
  const parts = before.split(':');
  if (parts.length < 6) return null;
  const host     = parts[0];
  const port     = parts[1];
  const protocol = parts[2];
  const method   = parts[3];
  const obfs     = parts[4];
  // password may contain colons after base64 decoding, join remaining
  const pwdB64   = parts.slice(5).join(':');
  const password = decodeBase64Compat(pwdB64) || pwdB64;

  if (!host || !port || !password) return null;

  let remarks = '', obfsParam = '', protocolParam = '';
  if (after) {
    // Query values are URL-safe base64 (no padding); use decodeBase64Compat
    const params = new URLSearchParams(after);
    const rb64 = params.get('remarks');
    if (rb64) remarks = decodeBase64Compat(rb64) || '';
    const ob64 = params.get('obfsparam');
    if (ob64) obfsParam = decodeBase64Compat(ob64) || '';
    const pb64 = params.get('protoparam');
    if (pb64) protocolParam = decodeBase64Compat(pb64) || '';
  }

  const proxy = {
    name: remarks || `ssr-${host}`,
    type: 'ssr',
    server: host,
    port: +port,
    cipher: method,
    password,
    obfs,
    protocol,
    udp: true
  };
  if (obfsParam) proxy['obfs-param'] = obfsParam;
  if (protocolParam) proxy['protocol-param'] = protocolParam;
  return proxy;
}

// ============================================================
// SOCKS5 plain proxies (socks:// socks5:// socks5h://)
// NOTE: http:// and https:// are intentionally excluded here —
// those URLs are treated as subscription links by the configurator.
// ============================================================
function parseSocks(rawUrl) {
  const base = parseShareLinkBase(rawUrl, ['socks', 'socks5', 'socks5h'], { requirePort: true });
  if (!base) return null;

  // Credentials may be plain or base64-encoded (concat as "user:pass" then try decode)
  let { username, password } = base;
  if (username && !password) {
    const decoded = decodeBase64Compat(base.url.username);
    if (decoded) {
      const idx = decoded.indexOf(':');
      if (idx >= 0) { username = decoded.slice(0, idx); password = decoded.slice(idx + 1); }
      else { username = decoded; }
    }
  }

  return {
    name: base.name,
    type: 'socks5',
    server: base.server,
    port: base.port,
    username,
    password,
    'skip-cert-verify': true
  };
}

// ============================================================
// AnyTLS
// https://github.com/anytls/anytls-go/blob/main/docs/uri_scheme.md
// ============================================================
function parseAnyTls(rawUrl) {
  const base = parseShareLinkBase(rawUrl, ['anytls'], { requirePort: true });
  if (!base) return null;

  const { params: p, username } = base;
  return {
    name: base.name,
    type: 'anytls',
    server: base.server,
    port: base.port,
    username,
    password: base.password || username,
    sni: p.get('sni') || '',
    fingerprint: p.get('hpkp') || '',
    'skip-cert-verify': p.get('insecure') === '1',
    udp: true
  };
}

// ============================================================
// Mieru
// ============================================================
function parseMieru(rawUrl) {
  const base = parseShareLinkBase(rawUrl, ['mierus']);
  if (!base) return null;

  const { params: p, server, username, password } = base;
  const portList     = p.getAll('port');
  const protocolList = p.getAll('protocol');
  if (!portList.length || portList.length !== protocolList.length) return null;

  // Take first port/protocol pair (same as first iteration in Go)
  const port     = portList[0];
  const protocol = protocolList[0];
  // Mieru carries its ports in the query string, so the name is built here rather than by the base helper.
  const baseName = shareLinkName(base.url, p.get('profile') || server);
  const name = `${baseName}:${port}/${protocol}`;

  const proxy = {
    name,
    type: 'mieru',
    server,
    transport: protocol,
    udp: true,
    username,
    password
  };
  if (port.includes('-')) {
    proxy['port-range'] = port;
  } else {
    proxy.port = +port;
  }
  const multiplexing = p.get('multiplexing');
  if (multiplexing) proxy.multiplexing = multiplexing;
  const handshakeMode = p.get('handshake-mode');
  if (handshakeMode) proxy['handshake-mode'] = handshakeMode;
  const trafficPattern = p.get('traffic-pattern');
  if (trafficPattern) proxy['traffic-pattern'] = trafficPattern;
  return proxy;
}

/**
 * Supported share-link schemes. `http`/`https` are deliberately absent —
 * the configurator treats those as subscription URLs, not proxies.
 */
const PROXY_URL_PARSERS = {
  vpn: line => withTimeoutOrNull(parseAmneziaVpnLink(line), 10000),
  vless: parseVless,
  vmess: parseVmess,
  ss: parseSS,
  ssr: parseSsr,
  trojan: parseTrojan,
  hysteria2: parseHysteria2,
  hy2: parseHysteria2,
  hysteria: parseHysteria,
  tuic: parseTuic,
  anytls: parseAnyTls,
  mierus: parseMieru,
  socks: parseSocks,
  socks5: parseSocks,
  socks5h: parseSocks
};

async function parseProxyUrl(line) {
  line = line.trim();
  const scheme = (line.match(/^([a-z][a-z0-9+.-]*):\/\//i)?.[1] || '').toLowerCase();
  const parse = Object.prototype.hasOwnProperty.call(PROXY_URL_PARSERS, scheme)
    ? PROXY_URL_PARSERS[scheme]
    : null;
  return parse ? await parse(line) : null;
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
