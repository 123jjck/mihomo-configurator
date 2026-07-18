import yaml from 'js-yaml';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createApp } from '../helpers/app-context.mjs';

let ctx;
let app;

beforeEach(() => {
  ctx = createApp();
  app = ctx.app;
});

afterEach(() => {
  ctx.close();
});

describe('mihomo YAML generation', () => {
  it('generates parseable desktop config with DNS, proxies, groups, providers, and rules', async () => {
    app.state.proxies = [
      await app.parseProxyUrl('vless://11111111-1111-4111-8111-111111111111@edge.example.com:443?type=ws&security=tls&sni=sni.example.com&path=%2Fws&host=front.example.com#VLESS'),
      await app.parseProxyUrl('ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss.example.com:8388#SS')
    ];
    app.state.proxyProviders = [{
      name: 'sub-main',
      type: 'http',
      url: 'https://sub.example.com/config.yaml',
      interval: 3600,
      filter: 'HK|SG',
      'exclude-filter': 'trial'
    }];
    app.state.rules = [
      { type: 'RULE-SET', payload: 'telegram', target: 'Proxy' },
      { type: 'RULE-SET', payload: 'geosite-youtube', target: 'Proxy' },
      { type: 'DOMAIN-SUFFIX', payload: 'example.org', target: 'DIRECT' }
    ];
    app.state.activeCdnProviders = new Set(['cloudflare']);
    app.state.matchTarget = 'Proxy';

    const doc = yaml.load(app.generateConfig());

    expect(doc.mode).toBe('rule');
    expect(doc.ipv6).toBe(false);
    expect(doc['keep-alive-idle']).toBe(30);
    expect(doc['keep-alive-interval']).toBe(15);
    expect(doc.dns).toMatchObject({
      enable: true,
      listen: '127.0.0.1:7874',
      ipv6: false,
      'default-nameserver': ['9.9.9.9', '149.112.112.112'],
      nameserver: ['https://dns.quad9.net/dns-query', 'tls://dns.quad9.net']
    });
    expect(doc.sniffer['skip-dst-address']).toEqual(app.TELEGRAM_SNIFFER_SKIP_DST);
    expect(doc.proxies).toHaveLength(2);
    expect(doc['proxy-providers']['sub-main']).toMatchObject({
      type: 'http',
      url: 'https://sub.example.com/config.yaml',
      interval: 3600,
      filter: 'HK|SG',
      'exclude-filter': 'trial'
    });
    expect(doc['proxy-groups'][0]).toMatchObject({
      name: 'Proxy',
      type: 'select',
      proxies: ['VLESS', 'SS'],
      use: ['sub-main']
    });
    expect(doc['rule-providers'].telegram).toMatchObject({
      behavior: 'ipcidr',
      type: 'http',
      format: 'text'
    });
    expect(doc['rule-providers']['cdn-cloudflare']).toMatchObject({
      behavior: 'ipcidr',
      type: 'http',
      format: 'text'
    });
    expect(doc['rule-providers']['geosite-youtube']).toMatchObject({
      behavior: 'domain',
      type: 'http'
    });
    expect(doc.rules).toEqual([
      'RULE-SET,telegram,Proxy',
      'RULE-SET,geosite-youtube,Proxy',
      'DOMAIN-SUFFIX,example.org,DIRECT',
      'IP-CIDR,192.168.0.0/16,DIRECT',
      'IP-CIDR,10.0.0.0/8,DIRECT',
      'IP-CIDR,172.16.0.0/12,DIRECT',
      'IP-CIDR,127.0.0.0/8,DIRECT',
      'MATCH,Proxy'
    ]);
  });

  it('generates router-specific fields documented by mihomo config examples', async () => {
    app.state.device = 'router';
    app.state.proxies = [
      await app.parseProxyUrl('trojan://pass@trojan.example.com:443?sni=sni.example.com#Trojan')
    ];

    const doc = yaml.load(app.generateConfig());

    expect(doc).toMatchObject({
      'external-controller': '0.0.0.0:9090',
      'keep-alive-idle': 30,
      'keep-alive-interval': 15,
      'external-ui': './ui',
      'external-ui-url': 'https://github.com/Zephyruso/zashboard/releases/latest/download/dist-cdn-fonts.zip',
      'tproxy-port': 7894,
      'routing-mark': 2
    });
  });

  it.each(['android', 'ios'])('uses mobile keep-alive values for %s', device => {
    app.state.device = device;

    const doc = yaml.load(app.generateConfig());

    expect(doc['keep-alive-idle']).toBe(600);
    expect(doc['keep-alive-interval']).toBe(30);
  });

  it('writes dialer-proxy for an edited server', async () => {
    const exit = await app.parseProxyUrl('ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@exit.example.com:8388#Exit');
    const dialer = await app.parseProxyUrl('trojan://pass@dialer.example.com:443#Dialer');
    exit['dialer-proxy'] = dialer.name;
    app.state.proxies = [exit, dialer];

    const doc = yaml.load(app.generateConfig());

    expect(doc.proxies[0]['dialer-proxy']).toBe('Dialer');
  });

  it('adds Discord Voice rules and provider when the Discord preset is selected', () => {
    app.togglePreset('services', 'discord');

    const doc = yaml.load(app.generateConfig());

    expect(doc['rule-providers']['discord-voice']).toEqual({
      behavior: 'ipcidr',
      type: 'http',
      url: 'https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/discord-voice/discord-voice_plain_ipv4.txt',
      interval: 86400,
      format: 'text'
    });
    expect(doc.rules).toContain('RULE-SET,discord-voice,Proxy');
  });

  it('uses the BunnyCDN IPv4 range for IPv4 configs', () => {
    app.toggleCdn('bunny');

    const doc = yaml.load(app.generateConfig());

    expect(doc['rule-providers']['cdn-bunny'].url).toBe(
      'https://raw.githubusercontent.com/123jjck/cdn-ip-ranges/refs/heads/main/bunny/bunny_plain_ipv4.txt'
    );
  });

  it.each([
    ['steam', 'geosite-steam', 'steam'],
    ['mihoyo', 'geosite-mihoyo', 'mihoyo'],
    ['kurogames', 'geosite-kurogames', 'kurogames'],
    ['twitch', 'geosite-twitch', 'twitch']
  ])('adds the %s CDN exception as a direct geosite provider', (presetId, providerName, siteName) => {
    app.togglePreset('exceptions', presetId);

    const doc = yaml.load(app.generateConfig());

    expect(doc['rule-providers'][providerName]).toEqual({
      behavior: 'domain',
      type: 'http',
      url: `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/refs/heads/meta/geo/geosite/${siteName}.yaml`,
      interval: 86400
    });
    expect(doc.rules).toContain(`RULE-SET,${providerName},DIRECT`);
  });

  it('serializes tricky proxy names safely via js-yaml dump/load roundtrip', async () => {
    app.state.proxies = [
      await app.parseProxyUrl('ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss.example.com:8388#true'),
      await app.parseProxyUrl('ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss2.example.com:8388#1'),
      await app.parseProxyUrl('ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpzZWNyZXQ@ss3.example.com:8388#value:with:colon')
    ];
    // Force distinct names that stress YAML scalar rules
    app.state.proxies[0].name = 'true';
    app.state.proxies[1].name = '1';
    app.state.proxies[2].name = 'value:with:colon';

    const doc = yaml.load(app.generateConfig());
    expect(doc.proxies.map(p => p.name)).toEqual(['true', '1', 'value:with:colon']);
  });

  it('imports existing YAML, preserves non-generated providers, and regenerates editable sections', async () => {
    app.importConfig(`
mode: rule
ipv6: true
dns:
  default-nameserver:
    - 1.1.1.1
  nameserver:
    - https://dns.example.com/dns-query
proxies:
  - name: Old
    type: ss
    server: old.example.com
    port: 8388
    cipher: chacha20-ietf-poly1305
    password: old
proxy-providers:
  file-provider:
    type: file
    path: ./providers.yaml
  remote:
    type: http
    url: https://sub.example.com
proxy-groups:
  - name: Proxy
    type: select
    proxies:
      - Old
  - name: Manual
    type: select
    proxies:
      - DIRECT
rule-providers:
  manual-provider:
    behavior: classical
    type: file
    path: ./rules.yaml
rules:
  - DOMAIN-SUFFIX,old.example.com,Proxy
  - MATCH,DIRECT
`);

    app.state.proxies = [
      await app.parseProxyUrl('ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpuZXc@new.example.com:8388#New')
    ];
    app.state.proxyProviders = [];
    app.state.rules = [{ type: 'RULE-SET', payload: 'ru-blocked', target: 'Proxy' }];

    const doc = yaml.load(app.generateConfig());

    expect(doc['proxy-providers']).toEqual({
      'file-provider': {
        type: 'file',
        path: './providers.yaml'
      }
    });
    expect(doc['proxy-groups']).toEqual([
      {
        name: 'Proxy',
        type: 'select',
        proxies: ['New', 'DIRECT']
      },
      {
        name: 'Manual',
        type: 'select',
        proxies: ['DIRECT']
      }
    ]);
    expect(doc['rule-providers']['manual-provider']).toMatchObject({
      behavior: 'classical',
      type: 'file'
    });
    expect(doc['rule-providers']['ru-blocked']).toMatchObject({
      behavior: 'domain',
      type: 'http',
      format: 'text'
    });
    expect(doc.rules).toEqual(['RULE-SET,ru-blocked,Proxy', 'MATCH,DIRECT']);
  });
});
