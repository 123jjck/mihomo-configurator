**🌐 Language / Язык:** [English](README.md) | [Русский](README.ru.md)

# Mihomo Configurator

A browser-based configurator for generating `mihomo` YAML configs.

Live demo (GitHub Pages): https://123jjck.github.io/mihomo-configurator/

## Features

- Add proxies from links: `vless`, `vmess`, `ss`, `trojan`, `hysteria2`/`hy2`, `tuic`
- Add WireGuard / AmneziaWG proxies from `.conf` files
- Add subscription providers from `https://...` URLs
- Build routing rules with presets (services, CDN providers, Telegram, `ru-blocked`) and manual rules
- Generate platform-oriented configs:
  - `PC / Android / iOS` (FlClashX + Clash Mi)
  - `Router (OpenWRT)` profile for SSClash
- UI localization: Russian and English
  - Default language is detected from browser language
  - Language can be changed via the switcher in the header

## Usage

1. Open `index.html` in a browser.
2. Go through steps:
   - DNS
   - Servers
   - Rules
   - Download
3. Copy generated YAML or download `config.yaml`.

## Project Structure

- `index.html` - UI markup
- `style.css` - styles
- `app.js` - app logic, parsers, config generation, and localization
