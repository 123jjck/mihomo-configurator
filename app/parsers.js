// ============================================================
// Proxy Parsers (Step 2)
// ============================================================
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
  const net = isHttpUpgrade ? 'ws' : rawNet;
  proxy.network = net;

  const sec = security || '';
  if (sec === 'tls' || sec === 'reality') proxy.tls = true;
  if (servername) proxy.servername = servername;
  if (flow) proxy.flow = flow;
  if (skipCertVerify) proxy['skip-cert-verify'] = true;
  const alpnList = (Array.isArray(alpn) ? alpn : [alpn]).map(v => String(v).trim()).filter(Boolean);
  if (alpnList.length) proxy.alpn = alpnList;

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

function parseVless(url) {
  const m = url.match(/^vless:\/\/([^@]+)@([^:]+):(\d+)\??([^#]*)(?:#(.*))?$/);
  if (!m) return null;
  const [, uuid, server, port, qs, rawName] = m;
  const p = new URLSearchParams(qs);
  const boolish = value => ['1', 'true', 'yes'].includes(String(value || '').trim().toLowerCase());
  const alpn = (p.get('alpn') || '').split(',').map(v => v.trim()).filter(Boolean);
  const name = rawName ? decodeURIComponent(rawName) : 'vless-' + server;
  return buildVlessProxy({
    name,
    server,
    port: +port,
    uuid,
    network: p.get('type') || 'tcp',
    security: p.get('security') || '',
    servername: p.get('sni') || '',
    flow: p.get('flow') || '',
    skipCertVerify: boolish(p.get('allowInsecure')) || boolish(p.get('insecure')),
    alpn,
    fingerprint: p.get('fp') || '',
    realityPublicKey: p.get('pbk') || '',
    realityShortId: p.get('sid') || '',
    wsPath: p.get('path') || '/',
    wsHost: p.get('host') || '',
    grpcServiceName: p.get('serviceName') || '',
    h2Path: p.get('path') || '/',
    h2Host: [p.get('host') || server]
  });
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
  if (/^vpn:\/\//i.test(line)) return await withTimeoutOrNull(parseAmneziaVpnLink(line), 10000);
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
