import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp, encodeBase64Url } from '../helpers/app-context.mjs';

let ctx;
let app;

beforeEach(() => {
  ctx = createApp();
  app = ctx.app;
});

afterEach(() => {
  ctx.close();
});

describe('proxy share-link parsers', () => {
  it('parses VLESS reality websocket links with mihomo-compatible TLS and packet options', () => {
    const proxy = app.parseVless(
      'vless://11111111-1111-4111-8111-111111111111@edge.example.com:443' +
      '?type=ws&security=reality&sni=cdn.example.com&fp=chrome&pbk=publicKey&sid=abcd' +
      '&path=%2Fws&host=front.example.com&alpn=h2,http/1.1&packetEncoding=packet' +
      '#VLESS%20Reality%20WS'
    );

    expect(proxy).toMatchObject({
      name: 'VLESS Reality WS',
      type: 'vless',
      server: 'edge.example.com',
      port: 443,
      uuid: '11111111-1111-4111-8111-111111111111',
      network: 'ws',
      tls: true,
      servername: 'cdn.example.com',
      'client-fingerprint': 'chrome',
      'packet-addr': true,
      'reality-opts': {
        'public-key': 'publicKey',
        'short-id': 'abcd'
      }
    });
    expect(proxy.alpn).toEqual(['h2', 'http/1.1']);
    expect(proxy['ws-opts'].headers).toMatchObject({
      Host: 'front.example.com',
      'User-Agent': expect.stringContaining('Chrome/')
    });
  });

  it('maps XHTTP extra fields, padding, headers, xmux reuse, and download settings', () => {
    const extra = encodeURIComponent(JSON.stringify({
      noGRPCHeader: true,
      xPaddingBytes: '100-200',
      xPaddingObfsMode: true,
      headers: { 'X-Test': 'ok', Numeric: 42 },
      xmux: { maxConnections: 2, hKeepAlivePeriod: 30 },
      downloadSettings: {
        address: 'download.example.com',
        port: 8443,
        security: 'reality',
        tlsSettings: {
          serverName: 'download-sni.example.com',
          fingerprint: 'firefox',
          allowInsecure: true,
          alpn: ['h2']
        },
        realitySettings: { publicKey: 'downPublic', shortId: '01' },
        xhttpSettings: {
          path: '/download',
          host: 'download-host.example.com',
          headers: { Down: true },
          extra: { xmux: { maxConcurrency: 8 } }
        }
      }
    }));

    const proxy = app.parseVless(
      `vless://22222222-2222-4222-8222-222222222222@xhttp.example.com:443?type=xhttp&security=tls&path=%2Fup&host=up.example.com&mode=stream-up&extra=${extra}#XHTTP`
    );

    expect(proxy['xhttp-opts']).toMatchObject({
      path: '/up',
      host: 'up.example.com',
      mode: 'stream-up',
      'no-grpc-header': true,
      'x-padding-bytes': '100-200',
      'x-padding-obfs-mode': true,
      headers: {
        'X-Test': 'ok',
        Numeric: '42'
      },
      'reuse-settings': {
        'max-connections': '2',
        'h-keep-alive-period': 30
      },
      'download-settings': {
        server: 'download.example.com',
        port: 8443,
        tls: true,
        servername: 'download-sni.example.com',
        'client-fingerprint': 'firefox',
        'skip-cert-verify': true,
        alpn: ['h2'],
        'reality-opts': {
          'public-key': 'downPublic',
          'short-id': '01'
        },
        path: '/download',
        host: 'download-host.example.com',
        headers: { Down: 'true' },
        'reuse-settings': {
          'max-concurrency': '8'
        }
      }
    });
  });

  it('drops xhttp download-settings for stream-one mode in vless share links', () => {
    const extra = encodeURIComponent(JSON.stringify({
      downloadSettings: {
        address: 'download.example.com',
        port: 8443,
        security: 'tls'
      }
    }));

    const proxy = app.parseVless(
      `vless://22222222-2222-4222-8222-222222222222@xhttp.example.com:443?type=xhttp&security=tls&path=%2Fup&mode=stream-one&extra=${extra}#XHTTP`
    );

    expect(proxy['xhttp-opts'].mode).toBe('stream-one');
    expect(proxy['xhttp-opts']['download-settings']).toBeUndefined();
  });

  it('parses legacy vmess base64 JSON with websocket early data', () => {
    const payload = Buffer.from(JSON.stringify({
      ps: 'Legacy VMess',
      add: 'vmess.example.com',
      port: '443',
      id: '33333333-3333-4333-8333-333333333333',
      aid: 0,
      scy: 'auto',
      net: 'ws',
      tls: 'tls',
      sni: 'sni.example.com',
      fp: 'safari',
      path: '/socket?ed=2048&eh=X-Early',
      host: 'host.example.com'
    })).toString('base64');

    const proxy = app.parseVmess(`vmess://${payload}`);

    expect(proxy).toMatchObject({
      name: 'Legacy VMess',
      type: 'vmess',
      network: 'ws',
      tls: true,
      servername: 'sni.example.com',
      'client-fingerprint': 'safari'
    });
    expect(proxy['ws-opts']).toMatchObject({
      path: '/socket?eh=X-Early',
      headers: { Host: 'host.example.com' },
      'max-early-data': 2048,
      'early-data-header-name': 'X-Early'
    });
  });

  it('parses Shadowsocks SIP002 links with obfs plugin options', () => {
    const creds = Buffer.from('chacha20-ietf-poly1305:secret').toString('base64url');
    const plugin = encodeURIComponent('obfs-local;obfs=tls;obfs-host=cdn.example.com');
    const proxy = app.parseSS(`ss://${creds}@ss.example.com:8388?plugin=${plugin}&uot=1#SS%20Obfs`);

    expect(proxy).toMatchObject({
      name: 'SS Obfs',
      type: 'ss',
      server: 'ss.example.com',
      port: 8388,
      cipher: 'chacha20-ietf-poly1305',
      password: 'secret',
      'udp-over-tcp': true,
      plugin: 'obfs',
      'plugin-opts': {
        mode: 'tls',
        host: 'cdn.example.com'
      }
    });
  });

  it('parses trojan websocket links, hysteria2 links, and tuic links', () => {
    expect(app.parseTrojan(
      'trojan://pass@trojan.example.com:443?type=ws&sni=sni.example.com&path=%2Ftr&alpn=h2&allowInsecure=1#Trojan'
    )).toMatchObject({
      name: 'Trojan',
      type: 'trojan',
      sni: 'sni.example.com',
      'skip-cert-verify': true,
      network: 'ws',
      alpn: ['h2']
    });

    expect(app.parseHysteria2(
      'hy2://hy-pass@hy.example.com:8443?sni=hy-sni.example.com&obfs=salamander&obfs-password=obfs-pass&pinSHA256=sha256&up=20Mbps&down=100Mbps#HY2'
    )).toMatchObject({
      name: 'HY2',
      type: 'hysteria2',
      password: 'hy-pass',
      obfs: 'salamander',
      'obfs-password': 'obfs-pass',
      fingerprint: 'sha256',
      up: '20Mbps',
      down: '100Mbps'
    });

    expect(app.parseTuic(
      'tuic://44444444-4444-4444-8444-444444444444:tuic-pass@tuic.example.com:443?sni=tuic-sni.example.com&alpn=h3&congestion_control=bbr&udp_relay_mode=native&disable_sni=1#TUIC'
    )).toMatchObject({
      name: 'TUIC',
      type: 'tuic',
      uuid: '44444444-4444-4444-8444-444444444444',
      password: 'tuic-pass',
      sni: 'tuic-sni.example.com',
      alpn: ['h3'],
      'congestion-controller': 'bbr',
      'udp-relay-mode': 'native',
      'disable-sni': true
    });
  });

  it('parses WireGuard and AmneziaWG config files', () => {
    const proxy = app.parseWireGuardConfig(`
[Interface]
PrivateKey = private
Address = 10.7.0.2/32, fd00::2/128
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280
Jc = 4
S1 = 111
H1 = 1-2

[Peer]
PublicKey = public
PresharedKey = psk
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0
`);

    expect(proxy).toMatchObject({
      name: 'awg-wg.example.com',
      type: 'wireguard',
      server: 'wg.example.com',
      port: 51820,
      ip: '10.7.0.2',
      ipv6: 'fd00::2',
      mtu: 1280,
      dns: ['1.1.1.1'],
      awgVersion: '2.0',
      'amnezia-wg-option': {
        jc: 4,
        s1: 111,
        h1: '1-2'
      }
    });
  });

  it('parses AmneziaWG 3.0 and 3.1 config files', () => {
    const v3Interface = `
[Interface]
PrivateKey = private
Address = 10.7.0.2/32
Jc = 4
S1 = 30
S2 = 40
S3 = 50
S4 = 20
H1 = 1000000001-1000000005
I1 = <b 0xf6ab><t><r 10>
J1 = <b 0xffffffff><c>
Itime = 60
HeaderProtectionKey = aGVhZGVyLXByb3RlY3Rpb24ta2V5LTMyLWJ5dGVzIQ==
ContentPaddingAddition = 0-32
RekeyAfterTime = 120
RekeyTimeout = 5
RejectAfterTime = 180
KeepaliveTimeout = 10
MaxHandshakeAttempts = 18
`;
    const peer = `
[Peer]
PublicKey = public
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0
`;

    const v30 = app.parseWireGuardConfig(v3Interface + peer);
    expect(v30).toMatchObject({
      awgVersion: '3.0',
      'amnezia-wg-option': {
        // mihomo routes the proxy to its AmneziaWG v3 device on this field alone.
        version: 3,
        jc: 4,
        s1: 30,
        h1: '1000000001-1000000005',
        i1: '<b 0xf6ab><t><r 10>',
        'header-protection-key': 'aGVhZGVyLXByb3RlY3Rpb24ta2V5LTMyLWJ5dGVzIQ==',
        'content-padding-addition': '0-32',
        'rekey-after-time': 120,
        'rekey-timeout': 5,
        'reject-after-time': 180,
        'keepalive-timeout': 10,
        'max-handshake-attempts': 18
      }
    });
    // v3 dropped the controlled-junk knobs; its device rejects them outright.
    expect(v30['amnezia-wg-option']).not.toHaveProperty('j1');
    expect(v30['amnezia-wg-option']).not.toHaveProperty('itime');
    expect(v30['amnezia-wg-option']).not.toHaveProperty('random-trailers');

    const v31 = app.parseWireGuardConfig(
      v3Interface + 'RandomTrailers = true\nDisableCookies = true\n' + peer
    );
    expect(v31).toMatchObject({
      awgVersion: '3.1',
      'amnezia-wg-option': {
        version: 3,
        'random-trailers': true,
        'disable-cookies': true
      }
    });
  });

  it('keeps AmneziaWG 1.x and 2.x free of v3-only fields', () => {
    const legacy = app.parseWireGuardConfig(`
[Interface]
PrivateKey = private
Address = 10.7.0.2/32
Jc = 4
Jmin = 40
Jmax = 70
S1 = 30
S2 = 40
S3 = 50
S4 = 20
H1 = 1000000001-1000000005
I1 = <b 0xf6ab><t><r 10>
J1 = <b 0xffffffff><c>
Itime = 60

[Peer]
PublicKey = public
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0
`);

    expect(legacy).toMatchObject({
      awgVersion: '2.0',
      'amnezia-wg-option': {
        jc: 4,
        i1: '<b 0xf6ab><t><r 10>',
        j1: '<b 0xffffffff><c>',
        itime: 60
      }
    });
    // The legacy device knows none of these, so they must never leak into a v1/v2 proxy.
    expect(legacy['amnezia-wg-option']).not.toHaveProperty('version');
    expect(legacy['amnezia-wg-option']).not.toHaveProperty('header-protection-key');
    expect(legacy['amnezia-wg-option']).not.toHaveProperty('random-trailers');
  });

  it('recognizes subscription URLs, unique names, and unsupported input safely', async () => {
    app.state.proxies.push({ name: 'Node', type: 'ss', server: 'one.example.com', port: 443 });
    app.state.proxyProviders.push({ name: 'Node-2', type: 'http', url: 'https://sub.example.com' });

    expect(app.parseSubscriptionUrl('https://sub.example.com/path?token=abc')).toMatchObject({
      name: 'sub-sub.example.com',
      type: 'http',
      interval: 3600
    });
    expect(app.uniqueServerName('Node')).toBe('Node-3');
    await expect(app.parseProxyUrl('ftp://example.com')).resolves.toBeNull();
  });
});
