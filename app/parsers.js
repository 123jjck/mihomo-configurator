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
