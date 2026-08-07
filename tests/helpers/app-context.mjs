import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';
import { JSDOM } from 'jsdom';

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const scriptPaths = [
  'app/state.js',
  'app/parsers.js',
  'app/ui.js',
  'app/generate.js'
];

const exportedNames = [
  'state',
  'I18N',
  'DNS_DEFAULT_PRESETS',
  'DNS_NS_PRESETS',
  'SERVICE_PRESETS',
  'SERVICE_GROUPS',
  'EXCEPTION_PRESETS',
  'EXCEPTION_GROUPS',
  'OTHER_PRESETS',
  'CDN_PROVIDERS',
  'PRIVATE_NETWORK_RULES',
  'TELEGRAM_SNIFFER_SKIP_DST',
  'dumpYamlConfig',
  'buildAutoRuleProviders',
  'initialState',
  'renderAll',
  'generateConfig',
  'generateFresh',
  'generateFromImported',
  'importConfig',
  'resetImport',
  'parseProxyUrl',
  'parseVless',
  'parseVmess',
  'parseSS',
  'parseTrojan',
  'parseHysteria2',
  'parseHysteria',
  'parseTuic',
  'parseWireGuardConfig',
  'parseSubscriptionUrl',
  'uniqueServerName',
  'validateStep',
  'maxReachableStep',
  'toggleCdn',
  'togglePreset',
  'togglePresetGroup',
  'togglePresetDropdown',
  'renderAllPresets',
  'renderProxies',
  'renderRules',
  'renderTargetSelects',
  'buildTargetOptions',
  'openProxyEditor',
  'closeProxyEditor',
  'saveProxyEditor',
  'createsDialerProxyCycle',
  'removeProxy',
  'moveProxy',
  'removeRule',
  'moveRule',
  'changeRuleTarget',
  'setLanguage'
];

export function createApp() {
  const html = fs.readFileSync(path.join(rootDir, 'index.html'), 'utf8');
  const dom = new JSDOM(html, {
    runScripts: 'outside-only',
    url: 'http://127.0.0.1/'
  });

  const { window } = dom;
  window.jsyaml = yaml;
  window.console = console;
  window.structuredClone = globalThis.structuredClone;
  window.TextDecoder = globalThis.TextDecoder;
  window.TextEncoder = globalThis.TextEncoder;
  window.requestAnimationFrame = callback => setTimeout(callback, 0);
  window.navigator.clipboard = {
    writeText: () => Promise.resolve()
  };
  window.scrollTo = () => {};

  const appSource = scriptPaths
    .map(relativePath => {
      const source = fs.readFileSync(path.join(rootDir, relativePath), 'utf8');
      return `\n// ${relativePath}\n${source}`;
    })
    .join('\n');

  window.eval(`${appSource}

    window.__app = {
      ${exportedNames.map(name => `${name}: typeof ${name} !== 'undefined' ? ${name} : undefined`).join(',\n      ')}
    };
  `);

  return {
    window,
    document: window.document,
    app: window.__app,
    close: () => window.close()
  };
}

export function encodeBase64Url(value) {
  return Buffer.from(value, 'utf8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}
