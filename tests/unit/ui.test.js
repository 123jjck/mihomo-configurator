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

describe('UI state helpers', () => {
  it('validates DNS and proxy requirements for the stepper', () => {
    app.setLanguage('ru', false);
    app.state.dns.defaultNs = [];
    app.state.dns.nameservers = [];
    expect(app.validateStep(0)).toBe('Добавьте DNS-серверы, чтобы продолжить.');

    app.state.dns.defaultNs = ['9.9.9.9'];
    expect(app.validateStep(0)).toBe('Добавьте Nameservers (DoH/DoT), чтобы продолжить.');

    app.state.dns.nameservers = ['https://dns.quad9.net/dns-query'];
    expect(app.validateStep(0)).toBe('');
    expect(app.validateStep(1)).toBe('Добавьте прокси-сервер или подписку, чтобы продолжить.');

    app.state.proxyProviders = [{ name: 'sub-main', url: 'https://sub.example.com' }];
    expect(app.validateStep(1)).toBe('');
  });

  it('uses individual CDN rules when partially selected and cdn-all when fully selected', () => {
    app.toggleCdn('cloudflare');
    app.toggleCdn('aws');

    expect([...app.state.activeCdnProviders].sort()).toEqual(['aws', 'cloudflare']);
    expect(app.state.rules.map(rule => rule.payload).sort()).toEqual(['cdn-aws', 'cdn-cloudflare']);

    app.toggleCdn('cloudflare');
    expect([...app.state.activeCdnProviders]).toEqual(['aws']);

    app.togglePresetGroup('services', 'cdn');
    expect([...app.state.activeCdnProviders]).toEqual(['all']);
    expect(app.state.rules.map(rule => rule.payload)).toEqual(['cdn-all']);

    app.toggleCdn('cloudflare');
    expect(app.state.activeCdnProviders.has('all')).toBe(false);
    expect(app.state.activeCdnProviders.has('cloudflare')).toBe(false);
    expect(app.state.activeCdnProviders.size).toBe(app.CDN_PROVIDERS.length - 1);
    expect(app.state.rules.some(r => r.payload === 'cdn-all')).toBe(false);
  });

  it('exposes BunnyCDN and the updated popular service list', () => {
    expect(app.CDN_PROVIDERS).toContainEqual({ id: 'bunny', label: 'BunnyCDN' });
    expect(app.SERVICE_PRESETS.twitter.label).toBe('X (Twitter)');
    expect(app.SERVICE_PRESETS.twitter.rules[0].payload).toBe('geosite-twitter');
    expect(app.SERVICE_PRESETS.grok.rules[0].payload).toBe('geosite-xai');
    expect(app.SERVICE_GROUPS.find(g => g.id === 'ai').items).toEqual(['chatgpt', 'claude', 'gemini', 'grok']);
    expect(app.SERVICE_PRESETS.roblox).toBeUndefined();
  });

  it('renders grouped services and exceptions and keeps RU direct last', () => {
    app.setLanguage('ru', false);

    const serviceLabels = [...ctx.document.querySelectorAll('#presets-services .preset-group-main, #presets-services > .preset-btn')]
      .map(button => button.textContent);
    const exceptionLabels = [...ctx.document.querySelectorAll('#presets-exceptions .preset-group-main, #presets-exceptions > .preset-btn')]
      .map(button => button.textContent);
    const otherLabels = [...ctx.document.querySelectorAll('#presets-other button')].map(button => button.textContent);

    expect(serviceLabels).toEqual(['Мессенджеры', 'YouTube', 'Соц. сети', 'Нейросети', 'CDN']);
    expect(exceptionLabels).toEqual(['Игры', 'Apple', 'Twitch']);
    expect(otherLabels).toEqual(['Заблокированные сайты', 'RU трафик напрямую']);
    expect(ctx.document.getElementById('rules-services-title').textContent).toBe('Популярное');
    expect(ctx.document.getElementById('rules-exceptions-hint').textContent).toContain('проксировании CDN');
    expect(ctx.document.getElementById('presets-cdn')).toBeNull();
  });

  it('toggles cdn-all from the CDN group button', () => {
    app.togglePresetGroup('services', 'cdn');
    expect([...app.state.activeCdnProviders]).toEqual(['all']);
    expect(app.state.rules.map(r => r.payload)).toEqual(['cdn-all']);

    app.togglePresetGroup('services', 'cdn');
    expect([...app.state.activeCdnProviders]).toEqual([]);
    expect(app.state.rules).toEqual([]);
  });

  it('toggles all presets in a group and supports partial selection', () => {
    app.togglePresetGroup('exceptions', 'games');

    expect([...app.state.activeExceptionPresets].sort()).toEqual(
      ['ea', 'epicgames', 'kurogames', 'mihoyo', 'nintendo', 'steam']
    );
    expect(app.state.rules.filter(r => r.payload.startsWith('geosite-')).map(r => r.payload).sort()).toEqual([
      'geosite-ea',
      'geosite-epicgames',
      'geosite-kurogames',
      'geosite-mihoyo',
      'geosite-nintendo',
      'geosite-steam'
    ]);

    app.togglePreset('exceptions', 'steam');
    expect(ctx.document.querySelector('#presets-exceptions .preset-group-btn').classList.contains('partial')).toBe(true);

    app.togglePresetGroup('exceptions', 'games');
    expect([...app.state.activeExceptionPresets].sort()).toEqual(
      ['ea', 'epicgames', 'kurogames', 'mihoyo', 'nintendo', 'steam']
    );

    app.togglePresetGroup('exceptions', 'games');
    expect([...app.state.activeExceptionPresets]).toEqual([]);
  });

  it('places a selected exception before existing CDN rules', () => {
    app.toggleCdn('cloudflare');
    app.togglePreset('exceptions', 'steam');

    expect(app.state.rules).toEqual([
      { type: 'RULE-SET', payload: 'geosite-steam', target: 'DIRECT' },
      { type: 'RULE-SET', payload: 'cdn-cloudflare', target: 'Proxy' }
    ]);
  });

  it('prioritizes Telegram rule rendering before other rules for stable sniffing config', () => {
    app.state.rules = [
      { type: 'DOMAIN-SUFFIX', payload: 'example.com', target: 'DIRECT' },
      { type: 'RULE-SET', payload: 'telegram', target: 'Proxy' }
    ];

    app.renderRules();

    expect(app.state.rules[0]).toMatchObject({ type: 'RULE-SET', payload: 'telegram' });
    expect(ctx.document.querySelector('#rules-list .rule-text').textContent).toBe('RULE-SET,telegram');
  });

  it('renders proxy names in rule target selectors and falls back when removed', () => {
    app.state.proxies = [
      { name: 'First', type: 'ss', server: 'first.example.com', port: 443 },
      { name: 'Second', type: 'ss', server: 'second.example.com', port: 443 }
    ];
    ctx.document.getElementById('rule-target').value = 'Second';
    app.renderTargetSelects();

    expect([...ctx.document.querySelectorAll('#rule-target option')].map(option => option.value)).toEqual([
      'Proxy',
      'First',
      'Second',
      'DIRECT',
      'REJECT'
    ]);

    app.state.proxies = [{ name: 'First', type: 'ss', server: 'first.example.com', port: 443 }];
    app.renderTargetSelects();

    expect(ctx.document.getElementById('rule-target').value).toBe('Proxy');
  });

  it('edits a server dialer-proxy and clears references when the dialer is removed', () => {
    app.state.proxies = [
      { name: 'Exit', type: 'ss', server: 'exit.example.com', port: 443 },
      { name: 'Dialer', type: 'ss', server: 'dialer.example.com', port: 443 }
    ];
    app.renderProxies();

    app.openProxyEditor(0);
    const select = ctx.document.getElementById('proxy-edit-dialer-proxy');
    expect([...select.options].map(option => option.value)).toEqual(['', 'Dialer']);
    select.value = 'Dialer';
    app.saveProxyEditor();

    expect(app.state.proxies[0]['dialer-proxy']).toBe('Dialer');
    expect(ctx.document.querySelector('.proxy-chain').textContent).toContain('Dialer');

    app.removeProxy(1);
    expect(app.state.proxies[0]['dialer-proxy']).toBeUndefined();
  });

  it('prevents circular dialer-proxy chains', () => {
    app.state.proxies = [
      { name: 'First', type: 'ss', server: 'first.example.com', port: 443, 'dialer-proxy': 'Second' },
      { name: 'Second', type: 'ss', server: 'second.example.com', port: 443 }
    ];

    app.openProxyEditor(1);

    expect(ctx.document.querySelector('#proxy-edit-dialer-proxy option[value="First"]').disabled).toBe(true);
  });

  it('changes server order without breaking dialer-proxy references', () => {
    app.state.proxies = [
      { name: 'Exit', type: 'ss', server: 'exit.example.com', port: 443, 'dialer-proxy': 'Dialer' },
      { name: 'Dialer', type: 'ss', server: 'dialer.example.com', port: 443 }
    ];

    app.moveProxy(0, 1);

    expect(app.state.proxies.map(proxy => proxy.name)).toEqual(['Dialer', 'Exit']);
    expect(app.state.proxies[1]['dialer-proxy']).toBe('Dialer');
    expect(ctx.document.querySelectorAll('.proxy-actions-cell')).toHaveLength(2);
    expect(ctx.document.querySelectorAll('.proxy-actions-cell')[0].querySelectorAll('button')).toHaveLength(4);
  });

  it('switches localization and updates static labels', () => {
    app.setLanguage('en', false);

    expect(app.state.lang).toBe('en');
    expect(ctx.document.getElementById('servers-title').textContent).toBe('Add Servers');
    expect(ctx.document.getElementById('btn-next').textContent).toContain('Next');
  });

  it('renders separate desktop, Android, iOS, and router device choices', () => {
    app.state.step = 3;
    app.setLanguage('en', false);

    const labels = [...ctx.document.querySelectorAll('#device-presets button')].map(button => button.textContent);
    expect(labels).toEqual(['Windows / macOS / Linux', 'Android', 'iOS', 'Router (OpenWRT)']);
  });
});
