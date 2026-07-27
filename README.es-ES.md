**🌐 Language / Язык:** [English](README.md) | [Русский](README.ru.md) | [Español](README.es.md)

# Mihomo Configurator

Un configurador basado en el navegador para generar configuraciones YAML de `mihomo`.

Demo en vivo (GitHub Pages): https://123jjck.github.io/mihomo-configurator/

## Características

- Agregar proxies desde enlaces: `vless`, `vmess`, `ss`, `trojan`, `hysteria2`/`hy2`, `tuic`, `vpn://`
- Agregar proxies WireGuard / AmneziaWG desde archivos `.conf`
- Agregar proveedores de suscripción desde URLs `https://...`
- Crear reglas de enrutamiento con ajustes preestablecidos (servicios, proveedores de CDN, Telegram, `ru-blocked`) y reglas manuales
- Generar configuraciones orientadas a plataformas:
  - `PC / Android / iOS` (FlClashX + Clash Mi)
  - Perfil de `Router (OpenWRT)` para SSClash
- Localización de la interfaz: Ruso e Inglés
  - El idioma predeterminado se detecta según el idioma del navegador
  - El idioma se puede cambiar mediante el selector en el encabezado

## Uso

1. Abre `index.html` en un navegador.
2. Sigue los pasos:
   - DNS
   - Servidores (Servers)
   - Reglas (Rules)
   - Descargar (Download)
3. Copia el YAML generado o descarga `config.yaml`.

## Pruebas (Testing)

```bash
npm install
npm run test:unit
npm run test:e2e
npm run build
```

- Las pruebas unitarias cubren los analizadores (parsers) de enlaces de proxy, el análisis de configuraciones de WireGuard / AmneziaWG, la generación de YAML, la regeneración de importaciones y los ayudantes de estado de la UI.
- Las pruebas de humo (smoke tests) del navegador ejecutan la aplicación estática con Playwright y verifican el flujo principal de construcción de la configuración.
- El flujo de trabajo de GitHub Actions ejecuta las pruebas, construye `dist` y lo despliega en GitHub Pages desde la rama `main`.

## Estructura del Proyecto

- `index.html` - Marcado de la UI
- `app/style.css` - Estilos
- `app/state.js` - Estado, localización, presets y ayudantes compartidos
- `app/parsers.js` - Analizadores de proxy/suscripción/WireGuard
- `app/ui.js` - Renderizado de la UI y transiciones de estado
- `app/generate.js` - Generación de YAML de mihomo y manejo de importaciones
- `tests/unit` - Pruebas unitarias del analizador, generador y estado de la UI
- `tests/e2e` - Pruebas de humo del navegador con Playwright
- `.github/workflows/test-and-deploy.yml` - CI y despliegue en GitHub Pages
