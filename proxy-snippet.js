/**
 * Cloudflare Snippet — Telegram Web Proxy
 *
 * 路由规则（基于子域名，Snippet 挂在通配符域名 *.tgweb.example.com 上）：
 *   tgweb.example.com          → Cloudflare Pages 静态网页（经 Cloudflare Access 保护）
 *   zws1-tgweb.example.com     → wss://zws1.web.telegram.org  (DC1 普通)
 *   zws1-1-tgweb.example.com   → wss://zws1-1.web.telegram.org (DC1 下载)
 *   zws2-tgweb.example.com     → wss://zws2.web.telegram.org  ...以此类推
 *
 * 子域名前缀提取规则：
 *   请求 Host 去掉 TGWEB_DOMAIN 后缀，剩余部分即为 DC 前缀。
 *   例：Host = zws1-tgweb.example.com，TGWEB_DOMAIN = tgweb.example.com
 *       前缀 = "zws1-"，目标 = zws1.web.telegram.org
 *
 * 环境变量（Cloudflare Dashboard → Snippets → Environment Variables）：
 *   PASSWORD               必填  访问密码
 *   TGWEB_DOMAIN           必填  主域名，如 tgweb.example.com（不含协议和斜杠）
 *   PAGES_URL              必填  Cloudflare Pages 源站域名，如 your-project.pages.dev
 *   CF_CLIENT_ID           必填  Cloudflare Access Service Token 的 Client ID
 *   CF_CLIENT_SECRET       必填  Cloudflare Access Service Token 的 Client Secret
 *   DC_TARGET              可选  DC 目标域名后缀，默认 .web.telegram.org
 *
 * Pages 侧配置：
 *   在 Pages 项目对应的 Cloudflare Access 应用中启用 Service Token 策略，
 *   并将 read_service_tokens_from_header 设置为 "Authorization"（通过 API/Terraform）。
 *   首次请求用 Service Token 双头认证，Access 返回 CF_Authorization cookie；
 *   后续请求直接带该 cookie，避免每次都用 token 头；cookie 失效后自动重新认证。
 */

// ─── 常量 ────────────────────────────────────────────────────────────────────

// 匹配 DC 子域名前缀，如 "zws1-" 或 "zws1-1-"（用于子域名模式：zws1-tgweb.example.com 的 .tgweb.example.com 后缀）
const DC_PREFIX_RE = /^(zws\d(?:-1)?)-$/;
// 匹配 DC 直接前缀模式：zws2-tweb.example.com（即 zws2- 直接拼在主域名前，无点分隔）
const DC_DIRECT_PREFIX_RE = /^(zws\d(?:-1)?)-/;

// AES-256-GCM 解密参数
// 环境变量 AES_KEY：64 个十六进制字符（256-bit）
// 加密文件格式：[0..2] "ENC" 魔数 | [3..14] IV(12B) | [15..30] AuthTag(16B) | [31..] ciphertext
const ENC_MAGIC = new Uint8Array([0x45, 0x4e, 0x43]); // "ENC"

/** 将 64 位 hex 字符串转为 CryptoKey（AES-256-GCM） */
async function getAesKey() {
  const hex = AES_KEY;
  const raw = new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, ['decrypt']);
}

/**
 * 若 body 以 "ENC" 魔数开头则解密，否则原样返回。
 * @param {ArrayBuffer} buf
 * @returns {Promise<ArrayBuffer>}
 */
async function maybeDecrypt(buf) {
  const view = new Uint8Array(buf);
  if (view.length < 31
    || view[0] !== ENC_MAGIC[0]
    || view[1] !== ENC_MAGIC[1]
    || view[2] !== ENC_MAGIC[2]) {
    return buf;
  }
  const iv = view.slice(3, 15);          // 12 bytes
  const authTag = view.slice(15, 31);    // 16 bytes
  const ciphertext = view.slice(31);

  // Web Crypto 要求 authTag 附在密文末尾
  const ciphertextWithTag = new Uint8Array(ciphertext.length + authTag.length);
  ciphertextWithTag.set(ciphertext);
  ciphertextWithTag.set(authTag, ciphertext.length);

  const key = await getAesKey();
  return crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertextWithTag);
}
const AUTH_COOKIE = 'tgweb_auth';
// Cookie 有效期：7 天
const COOKIE_MAX_AGE = 7 * 24 * 60 * 60;

// ─── 入口 ────────────────────────────────────────────────────────────────────

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const host = url.hostname;
    const suffix = `.${TGWEB_DOMAIN}`;
    const isApexOrWww = host === TGWEB_DOMAIN || host === `www.${TGWEB_DOMAIN}`;

    // 处理 CORS 预检（主域名和 DC 子域名均需处理）
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, PATCH, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    // DC 子域名不做密码保护，直接反代
    // 模式1（子域名）：zws1-tgweb.example.com（TGWEB_DOMAIN = tgweb.example.com）
    if (!isApexOrWww && host.endsWith(suffix)) {
      const prefix = host.slice(0, host.length - suffix.length + 1);
      const dcMatch = prefix.match(DC_PREFIX_RE);
      if (dcMatch) {
        return proxyDC(request, url, dcMatch[1]);
      }
    }
    // 模式2（直接前缀）：zws2-tweb.example.com（TGWEB_DOMAIN = tweb.example.com）
    if (!isApexOrWww) {
      const directMatch = host.match(DC_DIRECT_PREFIX_RE);
      if (directMatch && host.slice(directMatch[0].length) === TGWEB_DOMAIN) {
        return proxyDC(request, url, directMatch[1]);
      }
    }

    // 主域名：公开路径直接放行，无需密码验证
    // 包含所有 webmanifest、图标、robots.txt 等静态资源
    if (!isPublicPath(url.pathname)) {
      const authResult = await checkAuth(request, url);
      if (authResult) return authResult;
    }

    return proxyPages(request);
  },
};

// ─── 公开路径判断 ─────────────────────────────────────────────────────────────

/**
 * 无需密码验证的公开路径：
 *   - /*.webmanifest         网页清单（PWA）
 *   - /favicon*              各尺寸图标
 *   - /icon-*                各尺寸图标
 *   - /apple-touch-icon*     Apple 触摸图标
 *   - /robots.txt            爬虫协议
 *   - /__auth                密码表单提交端点（自身）
 */
function isPublicPath(pathname) {
  return (
    pathname.endsWith('.webmanifest')
    || pathname.startsWith('/favicon')
    || pathname.startsWith('/icon-')
    || pathname.startsWith('/apple-touch-icon')
    || pathname === '/robots.txt'
    || pathname === '/__auth'
  );
}

// ─── 密码验证 ─────────────────────────────────────────────────────────────────

/**
 * 返回 Response 表示需要拦截（显示密码页 / 重定向）；
 * 返回 undefined 表示已通过验证，继续处理请求。
 */
async function checkAuth(request, url) {
  // POST /__auth — 处理密码表单提交
  if (request.method === 'POST' && url.pathname === '/__auth') {
    return handleAuthPost(request, url);
  }

  // 验证 Cookie
  const cookie = parseCookie(request.headers.get('Cookie') || '');
  const token = cookie[AUTH_COOKIE];
  if (token && await verifyToken(token)) return undefined;

  // 未通过：展示密码输入页
  return renderPasswordPage(url, false);
}

async function handleAuthPost(request, url) {
  let body;
  try {
    body = await request.formData();
  } catch {
    return renderPasswordPage(url, true);
  }

  const password = body.get('password') || '';
  if (!timingSafeEqual(password, PASSWORD)) {
    return renderPasswordPage(url, true);
  }

  // 密码正确：签发 Cookie，重定向回原始页面
  const redirect = url.searchParams.get('redirect') || '/';
  const token = await signToken();
  return new Response(null, {
    status: 302,
    headers: {
      'Location': redirect,
      'Set-Cookie': `${AUTH_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`,
      'Cache-Control': 'no-store',
    },
  });
}

// ─── HMAC Token ──────────────────────────────────────────────────────────────

async function getHmacKey() {
  const raw = new TextEncoder().encode(PASSWORD);
  return crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signToken() {
  const key = await getHmacKey();
  // payload = 过期时间戳（秒）
  const exp = Math.floor(Date.now() / 1000) + COOKIE_MAX_AGE;
  const payload = String(exp);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(payload));
  const sigHex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, '0')).join('');
  return `${payload}.${sigHex}`;
}

async function verifyToken(token) {
  const dot = token.lastIndexOf('.');
  if (dot < 0) return false;
  const payload = token.slice(0, dot);
  const sigHex = token.slice(dot + 1);

  const exp = Number(payload);
  if (!Number.isFinite(exp) || Math.floor(Date.now() / 1000) > exp) return false;

  const key = await getHmacKey();
  const sigBytes = new Uint8Array(sigHex.match(/../g).map(h => parseInt(h, 16)));
  return crypto.subtle.verify('HMAC', key, sigBytes, new TextEncoder().encode(payload));
}

// ─── 密码页 HTML ──────────────────────────────────────────────────────────────

function renderPasswordPage(url, isError) {
  const redirect = encodeURIComponent(url.pathname + url.search);
  const errorHtml = isError
    ? '<p class="error">密码错误，请重试</p>'
    : '';
  const html = `<!DOCTYPE html>
<html lang="zh">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Telegram Web</title>
  <style>
    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      min-height: 100dvh;
      display: flex;
      align-items: center;
      justify-content: center;
      background: #1c2733;
      font-family: system-ui, sans-serif;
      color: #e8eaed;
    }
    .card {
      width: min(340px, 92vw);
      background: #242f3d;
      border-radius: 16px;
      padding: 2rem;
      display: flex;
      flex-direction: column;
      gap: 1.25rem;
      box-shadow: 0 8px 32px #0006;
    }
    .logo {
      text-align: center;
      font-size: 2.5rem;
      line-height: 1;
    }
    h1 {
      text-align: center;
      font-size: 1.1rem;
      font-weight: 600;
      color: #fff;
    }
    label { font-size: 0.85rem; color: #8e9aaa; }
    input[type=password] {
      width: 100%;
      padding: 0.65rem 0.85rem;
      border: 1.5px solid #3a4b5c;
      border-radius: 10px;
      background: #1c2733;
      color: #e8eaed;
      font-size: 1rem;
      outline: none;
      transition: border-color .15s;
    }
    input[type=password]:focus { border-color: #2ea6ff; }
    button {
      width: 100%;
      padding: 0.7rem;
      background: #2ea6ff;
      color: #fff;
      border: none;
      border-radius: 10px;
      font-size: 1rem;
      font-weight: 600;
      cursor: pointer;
      transition: background .15s;
    }
    button:hover { background: #44b3ff; }
    .error {
      color: #ff6b6b;
      font-size: 0.85rem;
      text-align: center;
    }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">✈️</div>
    <h1>Telegram Web</h1>
    <form method="POST" action="/__auth?redirect=${redirect}">
      <div style="display:flex;flex-direction:column;gap:.5rem">
        <label for="pw">访问密码</label>
        <input id="pw" type="password" name="password" autofocus autocomplete="current-password" placeholder="请输入密码">
      </div>
      <br>
      <button type="submit">进入</button>
    </form>
    ${errorHtml}
  </div>
</body>
</html>`;

  return new Response(html, {
    status: isError ? 403 : 401,
    headers: {
      'Content-Type': 'text/html; charset=UTF-8',
      'Cache-Control': 'no-store',
    },
  });
}

// ─── DC WebSocket 反代 ───────────────────────────────────────────────────────

async function proxyDC(request, url, dcPrefix) {
  const dcTargetSuffix = (typeof DC_TARGET !== 'undefined' ? DC_TARGET : '.web.telegram.org');
  const targetHost = `${dcPrefix}${dcTargetSuffix}`;

  const targetUrl = new URL(request.url);
  targetUrl.hostname = targetHost;
  targetUrl.protocol = url.protocol;

  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader?.toLowerCase() === 'websocket') {
    return fetch(targetUrl.toString(), request);
  }

  const response = await fetch(new Request(targetUrl.toString(), {
    method: request.method,
    headers: stripHopByHopHeaders(request.headers),
    body: request.body,
    redirect: 'follow',
  }));

  const respHeaders = new Headers(response.headers);
  respHeaders.set('Access-Control-Allow-Origin', '*');
  respHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  respHeaders.set('Access-Control-Allow-Headers', '*');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: respHeaders,
  });
}

// ─── Pages 静态资源反代 ──────────────────────────────────────────────────────

// 内存缓存 CF_Authorization cookie，避免每次都用 token 头
let cfAuthCookie = undefined;

async function proxyPages(request) {
  const targetUrl = new URL(request.url);
  targetUrl.hostname = PAGES_URL.replace(/^https?:\/\//, '').split('/')[0];
  targetUrl.protocol = 'https:';

  console.log(`[pages] ${request.method} ${targetUrl.toString()}`);

  const response = await fetchWithCfAuth(targetUrl, request);

  // 若 Access 返回了新的 CF_Authorization cookie，更新缓存
  const setCookie = response.headers.get('Set-Cookie') || '';
  const match = setCookie.match(/CF_Authorization=([^;]+)/);
  if (match) cfAuthCookie = match[1];

  const respHeaders = new Headers(response.headers);
  respHeaders.delete('X-Powered-By');
  respHeaders.delete('Server');
  // 不把 CF_Authorization Set-Cookie 透传给浏览器
  respHeaders.delete('Set-Cookie');
  respHeaders.set('X-Robots-Tag', 'noindex, nofollow');
  respHeaders.set('Access-Control-Allow-Origin', '*');
  respHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  respHeaders.set('Access-Control-Allow-Headers', '*');

  console.log(`[pages] response ${response.status}`);

  // 对加密文件（魔数 "ENC" 开头）进行 AES-256-GCM 解密后再返回
  if (response.status === 200 && typeof AES_KEY !== 'undefined' && AES_KEY) {
    const raw = await response.arrayBuffer();
    const decrypted = await maybeDecrypt(raw);
    // 若确实发生了解密，移除 Content-Encoding 避免浏览器二次解压
    if (decrypted !== raw) {
      respHeaders.delete('Content-Encoding');
      respHeaders.set('Content-Length', String(decrypted.byteLength));
    }
    return new Response(decrypted, {
      status: response.status,
      statusText: response.statusText,
      headers: respHeaders,
    });
  }

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: respHeaders,
  });
}

async function fetchWithCfAuth(targetUrl, request) {
  const headers = stripHopByHopHeaders(request.headers);
  headers.delete('Authorization');
  headers.delete('Referer');

  if (cfAuthCookie) {
    // 有缓存 cookie，优先用 cookie 认证
    console.log('[cf-auth] using cached CF_Authorization cookie');
    headers.set('Cookie', `CF_Authorization=${cfAuthCookie}`);
    const response = await fetch(new Request(targetUrl.toString(), {
      method: request.method,
      headers,
      body: request.body,
      redirect: 'manual',
    }));
    console.log(`[cf-auth] cookie request status: ${response.status}`);
    // 302 说明 cookie 已过期，回退到 token 头重新认证
    if (response.status !== 302) return response;
    console.log('[cf-auth] cookie expired, falling back to service token');
    cfAuthCookie = undefined;
  }

  // 用 Service Token 头做首次 / 重新认证，禁止跟随重定向
  // （跟随重定向会导致 token 头丢失，Access 改走邮箱验证码流程）
  console.log('[cf-auth] authenticating with service token');
  headers.set('CF-Access-Client-Id', CF_CLIENT_ID);
  headers.set('CF-Access-Client-Secret', CF_CLIENT_SECRET);
  headers.delete('Cookie');
  const tokenResp = await fetch(new Request(targetUrl.toString(), {
    method: request.method,
    headers,
    body: request.body,
    redirect: 'manual',
  }));
  console.log(`[cf-auth] token request status: ${tokenResp.status}`);

  // Access 认证成功后会 302 到原始 URL，同时在 Set-Cookie 里带 CF_Authorization
  // 此时跟随这一次重定向，并把 token 缓存起来供后续请求使用
  if (tokenResp.status === 302) {
    const location = tokenResp.headers.get('Location');
    const setCookie = tokenResp.headers.get('Set-Cookie') || '';
    const match = setCookie.match(/CF_Authorization=([^;]+)/);
    if (match) {
      cfAuthCookie = match[1];
      console.log('[cf-auth] CF_Authorization cookie cached');
    } else {
      console.warn('[cf-auth] 302 received but no CF_Authorization in Set-Cookie');
    }

    if (location) {
      console.log(`[cf-auth] following redirect to ${location}`);
      const redirectHeaders = stripHopByHopHeaders(request.headers);
      redirectHeaders.delete('Authorization');
      redirectHeaders.delete('Referer');
      if (cfAuthCookie) {
        redirectHeaders.set('Cookie', `CF_Authorization=${cfAuthCookie}`);
      }
      return fetch(new Request(location, {
        method: 'GET',
        headers: redirectHeaders,
        redirect: 'follow',
      }));
    }
  }

  return tokenResp;
}

// ─── 工具 ────────────────────────────────────────────────────────────────────

function stripHopByHopHeaders(headers) {
  const result = new Headers(headers);
  for (const h of ['connection', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']) {
    result.delete(h);
  }
  return result;
}

function parseCookie(cookieHeader) {
  return Object.fromEntries(
    cookieHeader.split(';').map(s => s.trim().split('=')).filter(p => p.length === 2).map(([k, v]) => [k.trim(), v.trim()])
  );
}

/** 防时序攻击的字符串比较 */
function timingSafeEqual(a, b) {
  let diff = 0;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    diff |= (a.charCodeAt(i % a.length) ^ b.charCodeAt(i % b.length));
  }
  return diff === 0 && a.length === b.length;
}
