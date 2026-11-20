// @ts-check
import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'
import starlightLinksValidator from 'starlight-links-validator'
import { LOCALES, t } from './locales.mjs'

// A project page of the organisation's GitHub Pages: `oxidestack.github.io` is shared by every project of the
// organisation, so this site lives under `/mock-server/`, and every internal link carries that base. The staging
// script writes the links with it (scripts/stage.mjs, BASE), and the validator below fails a link without it.
export default defineConfig({
  site: 'https://oxidestack.github.io',
  base: process.env.SITE_BASE || '/mock-server',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'mock-server',
      // PLACEHOLDER: no logo or favicon yet; they go here
      // (`logo: { src: './src/assets/<mark>.svg' }`, `favicon`) once the artwork exists.
      description: 'A drop-in for MockServer, written in Rust: the same API, the same clients, one static binary and no JVM.',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/oxidestack/mock-server' }],
      // Each staged page sets its own editUrl to its source file: the default would point at the staged copy,
      // which the next build deletes.
      editLink: { baseUrl: 'https://github.com/oxidestack/mock-server/edit/main/' },
      // English at the root, every other language under its directory (locales.mjs, site/README.md "Languages").
      defaultLocale: 'root',
      locales: LOCALES,
      sidebar: [
        {
          ...t('Getting started', 'Начало работы', '入门', 'Primeros pasos'),
          items: [
            { ...t('Introduction', 'Введение', '简介', 'Introducción'), slug: 'index' },
            { ...t('Installation', 'Установка', '安装', 'Instalación'), slug: 'installation' },
            { ...t('Upgrading', 'Обновление', '升级', 'Actualización'), slug: 'upgrading' },
          ],
        },
        { ...t('API reference', 'Справочник API', 'API 参考', 'Referencia de la API'), slug: 'api' },
        { ...t('Configuration', 'Конфигурация', '配置', 'Configuración'), slug: 'configuration' },
        { ...t('Operations', 'Эксплуатация', '运维', 'Operación'), slug: 'operations' },
        { ...t('Troubleshooting', 'Устранение неполадок', '故障排除', 'Solución de problemas'), slug: 'troubleshooting' },
        // Generated from public/benchmarks/results.json by scripts/benchmarks.mjs, in English only.
        { ...t('Benchmarks', 'Бенчмарки', '基准测试', 'Pruebas de rendimiento'), slug: 'benchmarks' },
      ],
      plugins: [
        // A broken internal link or anchor fails the build: every page is staged from a file of the repository, so a
        // link that stops resolving is a heading or a file renamed there, and the build is where to hear of it. A
        // translation's link to a page not translated yet is to that page's English fallback in its language.
        starlightLinksValidator({ errorOnRelativeLinks: true, errorOnInvalidHashes: true, errorOnFallbackPages: false }),
      ],
    }),
  ],
})
