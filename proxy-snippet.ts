/**
 * Cloudflare Snippet — Telegram Web Proxy
 *
 * 路由规则（基于子域名，Snippet 挂在通配符域名 *.tgweb.example.com 上）：
 *   tgweb.example.com          → Cloudflare Pages 静态网页
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
 *   PASSWORD      必填  Basic Auth 密码（用户名任意）
 *   TGWEB_DOMAIN  必填  主域名，如 tgweb.example.com（不含协议和斜杠）
 *   PAGES_URL     必填  Cloudflare Pages 源站域名，如 your-project.pages.dev
 *   PAGES_SECRET  必填  随机长字符串，转发到 Pages 时注入 X-Internal-Secret 头
 *                       在 Pages 项目 Cloudflare Access Policy 中用同一值做保护
 *   DC_TARGET     可选  DC 目标域名后缀，默认 .web.telegram.org
 */

declare const PASSWORD: string;
declare const TGWEB_DOMAIN: string;
declare const PAGES_URL: string;
declare const PAGES_SECRET: string;
declare const DC_TARGET: string | undefined;

// ─── 常量 ────────────────────────────────────────────────────────────────────

// 匹配 DC 子域名前缀，如 "zws1-" 或 "zws1-1-"
// 对应 Utils.ts getDC() 生成的 zws1.web.telegram.org / zws1-1.web.telegram.org
const DC_PREFIX_RE = /^(zws\d(?:-1)?)-$/;

// ─── 入口 ────────────────────────────────────────────────────────────────────

export default {
  async fetch(request: Request): Promise<Response> {
    // 1. Basic Auth 验证
    const authError = checkAuth(request);
    if (authError) return authError;

    const url = new URL(request.url);
    const host = url.hostname; // 不含端口

    // 2. 提取子域名前缀
    //    host = "zws1-tgweb.example.com", TGWEB_DOMAIN = "tgweb.example.com"
    //    → prefix = "zws1-"
    const suffix = `.${TGWEB_DOMAIN}`;
    const isApexOrWww = host === TGWEB_DOMAIN || host === `www.${TGWEB_DOMAIN}`;

    if (!isApexOrWww && host.endsWith(suffix)) {
      const prefix = host.slice(0, host.length - suffix.length + 1); // 保留末尾的 "-"
      const dcMatch = prefix.match(DC_PREFIX_RE);
      if (dcMatch) {
        return proxyDC(request, url, dcMatch[1]);
      }
    }

    // 3. 主域名 / 其他路径 → Cloudflare Pages
    return proxyPages(request, url);
  },
};

// ─── Basic Auth ──────────────────────────────────────────────────────────────

function checkAuth(request: Request): Response | undefined {
  const header = request.headers.get('Authorization') || '';
  if (header.startsWith('Basic ')) {
    const decoded = atob(header.slice(6));
    const colonIdx = decoded.indexOf(':');
    const password = colonIdx >= 0 ? decoded.slice(colonIdx + 1) : decoded;
    if (timingSafeEqual(password, PASSWORD)) return undefined;
  }
  return new Response('Unauthorized', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Telegram Web", charset="UTF-8"',
      'Cache-Control': 'no-store',
    },
  });
}

/** 防时序攻击的字符串比较 */
function timingSafeEqual(a: string, b: string): boolean {
  // 先走完整循环再返回，避免提前退出泄露长度差异
  let diff = 0;
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    diff |= (a.charCodeAt(i % a.length) ^ b.charCodeAt(i % b.length));
  }
  return diff === 0 && a.length === b.length;
}

// ─── DC WebSocket 反代 ───────────────────────────────────────────────────────

async function proxyDC(
  request: Request,
  url: URL,
  dcPrefix: string, // e.g. "zws1" or "zws1-1"
): Promise<Response> {
  const dcTargetSuffix = (typeof DC_TARGET !== 'undefined' ? DC_TARGET : '.web.telegram.org');
  const targetHost = `${dcPrefix}${dcTargetSuffix}`;

  const targetUrl = new URL(request.url);
  targetUrl.hostname = targetHost;
  targetUrl.protocol = url.protocol; // 保留 wss: 或 https:

  const upgradeHeader = request.headers.get('Upgrade');
  if (upgradeHeader?.toLowerCase() === 'websocket') {
    // WebSocket 升级请求直接透传
    return fetch(targetUrl.toString(), request);
  }

  // 普通 HTTP 兜底
  return fetch(new Request(targetUrl.toString(), {
    method: request.method,
    headers: stripHopByHopHeaders(request.headers),
    body: request.body,
    redirect: 'follow',
  }));
}

// ─── Pages 静态资源反代 ──────────────────────────────────────────────────────

async function proxyPages(request: Request, url: URL): Promise<Response> {
  const targetUrl = new URL(request.url);
  targetUrl.hostname = PAGES_URL.replace(/^https?:\/\//, '').split('/')[0];
  targetUrl.protocol = 'https:';

  const headers = new Headers(request.headers);
  headers.set('X-Internal-Secret', PAGES_SECRET);
  headers.delete('Referer');

  const response = await fetch(new Request(targetUrl.toString(), {
    method: request.method,
    headers: stripHopByHopHeaders(headers),
    body: request.body,
    redirect: 'follow',
  }));

  const respHeaders = new Headers(response.headers);
  respHeaders.delete('X-Powered-By');
  respHeaders.delete('Server');
  respHeaders.set('X-Robots-Tag', 'noindex, nofollow');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: respHeaders,
  });
}

// ─── 工具 ────────────────────────────────────────────────────────────────────

function stripHopByHopHeaders(headers: Headers): Headers {
  const result = new Headers(headers);
  for (const h of ['connection', 'keep-alive', 'proxy-authenticate',
    'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade']) {
    result.delete(h);
  }
  return result;
}
