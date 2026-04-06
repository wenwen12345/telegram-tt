import 'dotenv/config';

import { execSync } from 'child_process';
import { statSync } from 'fs';
import path from 'path';
import type { Plugin } from 'vite';
import { defineConfig } from 'vite';
import { nodePolyfills } from 'vite-plugin-node-polyfills';

import { PRODUCTION_URL } from './src/config.ts';
import { version as appVersion } from './package.json' with { type: 'json' };

function getAppRevision(appEnv: string, head: string) {
  try {
    const branch = head || execSync('git branch --show-current').toString().trim();
    const commit = execSync('git rev-parse --short HEAD').toString().trim().substring(0, 7);
    const shouldDisplayOnlyCommit = appEnv === 'staging' || !branch || branch === 'HEAD';
    return shouldDisplayOnlyCommit ? commit : `${branch}#${commit}`;
  } catch {
    return 'unknown';
  }
}

export default defineConfig((_env) => {
  const {
    APP_ENV = 'production',
    APP_MOCKED_CLIENT = '',
    HTTPS_CERT_PATH = '',
    HTTPS_KEY_PATH = '',
    HEAD = '',
    APP_NAME,
    TELEGRAM_API_ID,
    TELEGRAM_API_HASH,
    TEST_SESSION,
    CSP_CONNECT_DOMAIN,
  } = process.env;

  process.env.BASE_URL = process.env.BASE_URL || PRODUCTION_URL;

  const {
    BASE_URL,
    API_BASE_URL = '.web.telegram.org',
    APP_TITLE = `Telegram${APP_ENV !== 'production' ? ' Beta' : ''}`,
  } = process.env;

  const cspConnectDomain = CSP_CONNECT_DOMAIN ?? API_BASE_URL;

  const CSP = `
    default-src 'self';
    connect-src 'self' wss://*${cspConnectDomain} blob: http: https: ${APP_ENV === 'development' ? 'wss: ipc:' : ''};
    script-src 'self' 'wasm-unsafe-eval' https://t.me/_websync_ https://telegram.me/_websync_;
     style-src 'self' 'unsafe-inline';
     font-src 'self' data:;
     img-src 'self' data: blob: https://ss3.4sqi.net/img/categories_v2/;
    media-src 'self' blob: data:;
    object-src 'none';
    frame-src http: https:
      bitkeep: bnc: bybitapp: echooo: imtokenv2: mytonwallet-tc:
      nicegram-tc: safepal-tc: tonkeeper-pro-tc: tonkeeper-tc:;
    base-uri 'none';
    form-action 'none';`
    .replace(/\s+/g, ' ').trim();

  const CHANGELOG_PATH = path.resolve(__dirname, 'src/versionNotification.txt');
  const __dirname_config = path.dirname(new URL(import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));

  const appRevision = getAppRevision(APP_ENV, HEAD);
  const changelogDatetime = statSync(CHANGELOG_PATH, { throwIfNoEntry: false })?.mtime.getTime();

  const httpsOptions = HTTPS_CERT_PATH && HTTPS_KEY_PATH
    ? { key: HTTPS_KEY_PATH, cert: HTTPS_CERT_PATH }
    : undefined;

  const appleIcon = APP_ENV === 'production' ? 'apple-touch-icon' : 'apple-touch-icon-dev';
  const mainIcon = APP_ENV === 'production' ? 'icon-192x192' : 'icon-dev-192x192';
  const manifest = APP_ENV === 'production' ? 'site.webmanifest' : 'site_dev.webmanifest';

  const htmlTransformPlugin: Plugin = {
    name: 'html-transform',
    transformIndexHtml: {
      order: 'pre',
      handler(html: string) {
        return html
          .replace(/__APP_TITLE__/g, APP_TITLE)
          .replace(/__APPLE_ICON__/g, appleIcon)
          .replace(/__MAIN_ICON__/g, mainIcon)
          .replace(/__MANIFEST__/g, manifest)
          .replace(/__BASE_URL__/g, BASE_URL ?? '')
          .replace(/__CSP__/g, CSP);
      },
    },
  };

  return {
    root: './src',
    publicDir: path.resolve(__dirname, 'public'),

    define: {
      'process.env.APP_ENV': JSON.stringify(APP_ENV),
      'process.env.APP_MOCKED_CLIENT': JSON.stringify(APP_MOCKED_CLIENT),
      'process.env.APP_NAME': JSON.stringify(APP_NAME),
      'process.env.APP_TITLE': JSON.stringify(APP_TITLE),
      'process.env.TELEGRAM_API_ID': JSON.stringify(TELEGRAM_API_ID),
      'process.env.TELEGRAM_API_HASH': JSON.stringify(TELEGRAM_API_HASH),
      'process.env.TEST_SESSION': JSON.stringify(TEST_SESSION),
      'process.env.BASE_URL': JSON.stringify(BASE_URL),
      'process.env.API_BASE_URL': JSON.stringify(API_BASE_URL),
      APP_VERSION: JSON.stringify(appVersion),
      APP_REVISION: JSON.stringify(appRevision),
      CHANGELOG_DATETIME: JSON.stringify(changelogDatetime),
    },

    resolve: {
      alias: [
        // "@teact" bare (no slash) → teact.ts
        { find: /^@teact$/, replacement: path.resolve(__dirname, './src/lib/teact/teact.ts') },
        // "@teact/xxx" → src/lib/teact/xxx
        { find: /^@teact\/(.+)$/, replacement: path.resolve(__dirname, './src/lib/teact/$1') },
      ],
      extensions: ['.js', '.cjs', '.mjs', '.ts', '.tsx'],
    },

    css: {
      modules: {
        localsConvention: 'camelCase',
        generateScopedName: APP_ENV === 'production'
          ? '[hash:base64:8]'
          : '[name]__[local]',
      },
    },

    plugins: [
      nodePolyfills({
        include: ['path', 'os', 'buffer'],
        globals: {
          Buffer: true,
        },
      }),
      htmlTransformPlugin,
    ],

    esbuild: {
      jsx: 'automatic',
      jsxImportSource: '@teact',
    },

    server: {
      port: 1234,
      host: '0.0.0.0',
      https: httpsOptions,
      hmr: false,
      headers: {
        'Content-Security-Policy': CSP,
      },
      fs: {
        allow: [
          '.',
          './node_modules/emoji-data-ios',
          './node_modules/opus-recorder/dist',
          './src/lib/rlottie',
          './src/lib/secret-sauce',
        ],
      },
    },

    build: {
      outDir: path.resolve(__dirname, 'dist'),
      emptyOutDir: true,
      sourcemap: true,
      rollupOptions: {
        output: {
          entryFileNames: '[name].[hash].js',
          chunkFileNames: '[name].[hash].js',
          assetFileNames: '[name].[hash][extname]',
          manualChunks(id: string) {
            if (id.includes('/src/components/ui/')) {
              return 'shared-components';
            }
            return undefined;
          },
        },
        onwarn(warning, warn) {
          if (warning.code === 'CIRCULAR_DEPENDENCY') return;
          warn(warning);
        },
      },
    },

    assetsInclude: ['**/*.tgs', '**/*.tl', '**/*.strings', '**/*.wasm'],

    optimizeDeps: {
      exclude: ['opus-recorder'],
    },

    worker: {
      format: 'es',
      plugins: () => [
        nodePolyfills({
          include: ['path', 'os', 'buffer'],
          globals: {
            Buffer: true,
          },
        }),
      ],
    },
  };
});
