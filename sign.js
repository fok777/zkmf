#!/usr/bin/env node
/**
 * MT论坛 (bbs.binmt.cc) 自动签到脚本 (Node.js) —— 修复版
 * 部署到 GitHub Actions 每天自动运行
 *
 * 本版修复的问题：
 *  1. 【取不到 formhash】登录页被 ESA WAF 挑战页顶掉时，旧版 vm 沙箱缺 setTimeout/window 等全局，
 *     脚本跑不完就取不到 document.cookie，于是把「挑战页」当成登录页解析，必然没有 formhash。
 *     现在 = vm 沙箱（补全全局）+ 算法解算（移植自 as257259/MT）双路，任一成功即可。
 *  2. 【被 WAF 拦死】挑战识别只看 `<script>` 字面量，且解不出就直接返回挑战页。
 *     现在改为按 arg1 特征识别、最多解 5 次、两种解算方式轮换。
 *  3. 【Cookie 串被污染】旧版把多个 Set-Cookie 用 ';' 拼接后再按 ';' 切开，
 *     把 expires / path / HttpOnly 这些属性也当成 cookie 发给了服务端。现在用真正的 Set-Cookie 解析。
 *  4. 【海外 IP 被风控】新增代理支持（HTTPS_PROXY / PROXIES），默认不配就直连，行为不变。
 *
 * 容错：
 *  - 强制 IPv4（论坛 IPv6 链路不通）
 *  - 单次请求超时 120s，自动重试 4 次（重试时轮换代理）
 *  - 整体最多 4 轮，间隔 30s / 60s / 120s
 *  - 密码错误即停，不做无意义重试
 *  - 定时触发随机延迟打散时间特征，手动触发跳过
 *
 * 配置（环境变量）：
 *  ACCOUNTS      - 每行 "用户名:密码"，必填（与 BBS_COOKIE 二选一）
 *  BBS_COOKIE    - 可选。给了就跳过登录直接签到
 *  HTTPS_PROXY   - 可选。单个代理，如 http://user:pass@1.2.3.4:8080
 *  PROXIES       - 可选。代理池，每行一个，失败自动轮换（推荐，参照 as257259/MT）
 *  MT_DEBUG      - 设为 0 关闭调试快照，默认把每次响应存到 debug/ 目录
 *  MT_SMOKE      - 设为 1 只做连通性自检，不签到（排查 WAF/代理问题时用）
 */

const https = require('https');
const http = require('http');
const tls = require('tls');
const vm = require('vm');
const zlib = require('zlib');
const fs = require('fs');
const path = require('path');
const { URLSearchParams } = require('url');

const BASE = (process.env.MT_BASE_URL || 'https://bbs.binmt.cc').replace(/\/+$/, '');
const UA = 'Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36';

const REQ_TIMEOUT = 120000;
const REQ_RETRIES = 4;
const FLOW_ATTEMPTS = 4;
const FLOW_DELAYS = [30000, 60000, 120000];
const WAF_MAX_ROUNDS = 5;
const DEBUG_DIR = process.env.MT_DEBUG_DIR || 'debug';

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ============================================================
// 调试快照：把每次响应原样存盘，方便 Actions 里下载下来看
// ============================================================
function dump(tag, body) {
  if (process.env.MT_DEBUG === '0') return;
  try {
    fs.mkdirSync(DEBUG_DIR, { recursive: true });
    const safe = String(tag).replace(/[^a-zA-Z0-9._-]/g, '_').slice(0, 60);
    fs.writeFileSync(path.join(DEBUG_DIR, `${Date.now()}-${safe}.html`), body);
  } catch (e) { /* 忽略 */ }
}

function snippet(s, n = 200) {
  return String(s || '').replace(/\s+/g, ' ').trim().slice(0, n);
}

function maskUser(u) {
  if (/^1[3-9]\d{9}$/.test(u)) return `${u.slice(0, 3)}****${u.slice(-4)}`;
  return u.slice(0, 2) + '***' + u.slice(-1);
}

// ============================================================
// Cookie 罐
// ============================================================
class Jar {
  constructor(str = '') {
    this.m = new Map();
    if (str) this.mergeStr(str);
  }
  mergeStr(str) {
    for (let part of String(str || '').split(';')) {
      part = part.trim();
      if (!part) continue;
      const eq = part.indexOf('=');
      if (eq <= 0) continue;
      const k = part.slice(0, eq).trim();
      let v = part.slice(eq + 1).trim();
      if (v.length > 1 && v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      if (!k) continue;
      if (v === '' || /^(deleted|null)$/i.test(v)) { this.m.delete(k); continue; }
      this.m.set(k, v);
    }
    return this;
  }
  // 只吃每个 Set-Cookie 的第一段 name=value，属性（expires/path/HttpOnly）一律丢弃
  absorb(setCookieArr) {
    const arr = Array.isArray(setCookieArr) ? setCookieArr : (setCookieArr ? [setCookieArr] : []);
    for (const raw of arr) {
      const one = String(raw);
      const pair = one.split(';')[0];
      const eq = pair.indexOf('=');
      if (eq <= 0) continue;
      const k = pair.slice(0, eq).trim();
      let v = pair.slice(eq + 1).trim();
      if (v.length > 1 && v.startsWith('"') && v.endsWith('"')) v = v.slice(1, -1);
      if (!k) continue;
      if (v === '' || /^(deleted|null)$/i.test(v)) { this.m.delete(k); continue; }
      // 站点下发的「删除型」cookie：1970 年过期 或 max-age=0
      if (/expires\s*=\s*[a-z]{3},\s*\d{2}[\s-][a-z]{3}[\s-]19(?:6[0-9]|70)/i.test(one) && !/max-age\s*=\s*[1-9]/i.test(one)) {
        this.m.delete(k); continue;
      }
      if (/max-age\s*=\s*0+(?:;|$)/i.test(one)) { this.m.delete(k); continue; }
      this.m.set(k, v);
    }
    return this;
  }
  has(...names) {
    return names.some(n => this.m.has(n));
  }
  get(k) { return this.m.get(k) || ''; }
  toString() {
    const out = [];
    for (const [k, v] of this.m) out.push(k + '=' + v);
    return out.join('; ');
  }
  clone() {
    const j = new Jar();
    j.m = new Map(this.m);
    return j;
  }
}

// ============================================================
// 代理：http/https 代理走 CONNECT 隧道
// ============================================================
function parseProxy(p) {
  let s = String(p || '').trim();
  if (!s) return null;
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = 'http://' + s;
  let u;
  try { u = new URL(s); } catch (e) { return null; }
  if (!/^https?:$/.test(u.protocol)) {
    console.log(`⚠️ 暂不支持 ${u.protocol} 代理：${s}`);
    return null;
  }
  return {
    host: u.hostname,
    port: parseInt(u.port, 10) || (u.protocol === 'https:' ? 443 : 80),
    user: u.username ? decodeURIComponent(u.username) : '',
    pass: u.password ? decodeURIComponent(u.password) : '',
    label: s.replace(/\/\/[^@]*@/, '//***@'),
  };
}

function connectTunnel(proxy, host, port) {
  return new Promise((resolve, reject) => {
    const headers = { Host: `${host}:${port}` };
    if (proxy.user) {
      headers['Proxy-Authorization'] = 'Basic ' + Buffer.from(`${proxy.user}:${proxy.pass}`).toString('base64');
    }
    const req = http.request({
      host: proxy.host, port: proxy.port, method: 'CONNECT',
      path: `${host}:${port}`, headers, family: 4, timeout: 30000,
    });
    req.once('connect', (res, socket) => {
      if (res.statusCode !== 200) {
        socket.destroy();
        return reject(new Error(`代理 CONNECT 返回 ${res.statusCode}`));
      }
      resolve(socket);
    });
    req.once('timeout', () => req.destroy(new Error('代理连接超时')));
    req.once('error', reject);
    req.end();
  });
}

const agentCache = new Map();
function tunnelAgent(proxy) {
  const key = `${proxy.host}:${proxy.port}:${proxy.user}`;
  if (agentCache.has(key)) return agentCache.get(key);
  const agent = new https.Agent({ keepAlive: false });
  agent.createConnection = function (options, cb) {
    connectTunnel(proxy, options.host, options.port || 443)
      .then(socket => {
        const t = tls.connect({
          socket, servername: options.host,
          host: options.host, port: options.port || 443,
        });
        t.on('error', () => { /* 交给上层 request 的 error 事件 */ });
        cb(null, t);
      })
      .catch(e => cb(e));
  };
  agentCache.set(key, agent);
  return agent;
}

function buildProxyList() {
  const out = [];
  const seen = new Set();
  const push = s => {
    const p = parseProxy(s);
    if (p && !seen.has(p.host + ':' + p.port + p.user)) {
      seen.add(p.host + ':' + p.port + p.user);
      out.push(p);
    }
  };
  const list = (process.env.PROXIES || process.env.MT_PROXIES || '').replace(/\r/g, '');
  for (const line of list.split('\n')) push(line.trim());
  push(process.env.HTTPS_PROXY || process.env.https_proxy || '');
  push(process.env.HTTP_PROXY || process.env.http_proxy || '');
  return out;
}

// ============================================================
// HTTP 请求
// ============================================================
function requestOnce(url, jar, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url, BASE);
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? https : http;
    const headers = Object.assign({
      'User-Agent': UA,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept-Language': 'zh-CN,zh;q=0.9',
      'Referer': opts.referer || BASE + '/',
      'Connection': 'close',
    }, opts.headers || {});
    const ck = jar ? jar.toString() : '';
    if (ck) headers['Cookie'] = ck;

    let payload = null;
    if (opts.form) {
      payload = Buffer.from(new URLSearchParams(opts.form).toString(), 'utf8');
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      headers['Content-Length'] = payload.length;
      headers['Origin'] = BASE;
    }

    const reqOpts = {
      host: u.hostname,
      port: u.port || (isHttps ? 443 : 80),
      path: u.pathname + u.search,
      method: payload ? 'POST' : (opts.method || 'GET'),
      headers,
    };
    if (opts.proxy) reqOpts.agent = tunnelAgent(opts.proxy);
    else reqOpts.family = 4;

    const t0 = Date.now();
    const reqObj = mod.request(reqOpts, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        let buf = Buffer.concat(chunks);
        const enc = (res.headers['content-encoding'] || '').toLowerCase();
        try {
          if (enc.includes('gzip')) buf = zlib.gunzipSync(buf);
          else if (enc.includes('deflate')) buf = zlib.inflateSync(buf);
          else if (enc.includes('br')) buf = zlib.brotliDecompressSync(buf);
        } catch (e) { /* 解不开就保留原文 */ }
        resolve({
          status: res.statusCode,
          body: buf.toString('utf8'),
          setCookie: res.headers['set-cookie'] || [],
          headers: res.headers,
          url: u.toString(),
          ms: Date.now() - t0,
        });
      });
    });
    reqObj.setTimeout(opts.timeout || REQ_TIMEOUT, () => {
      reqObj.destroy(Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }));
    });
    reqObj.on('error', err => { err.reqMs = Date.now() - t0; reject(err); });
    if (payload) reqObj.write(payload);
    reqObj.end();
  });
}

// 单请求重试，每次换一个代理（代理池用完了就回第一个）
async function requestWithRetry(url, jar, opts = {}, retries = REQ_RETRIES) {
  const pool = opts.proxyPool && opts.proxyPool.length ? opts.proxyPool : [opts.proxy || null];
  // 有代理池时少在同一条链路上死磕，赶紧换下一个出口
  const tries = pool.length > 1 ? Math.min(retries, 2) : retries;
  const FAST = /ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EAI_AGAIN|EPROTO|EPIPE/i;
  let lastErr = null;
  for (let i = 0; i < tries; i++) {
    const proxy = pool[i % pool.length];
    try {
      return await requestOnce(url, jar, Object.assign({}, opts, { proxy }));
    } catch (e) {
      lastErr = e;
      if (i === tries - 1) break;
      // 连接级错误说明这条链路根本不通，没必要干等，直接换
      if (!FAST.test(e.code || '')) await sleep(5000);
      console.log(`⚠️ 请求失败(${e.message} code=${e.code || '-'} ${e.reqMs || '?'}ms) 代理=${proxy ? proxy.label : '直连'}，第 ${i + 1} 次重试...`);
    }
  }
  throw lastErr;
}

// ============================================================
// 阿里云 ESA WAF (acw_sc__v2) 挑战解算
// ============================================================
const ACW_B64 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=';
const ACW_ARR = [
  0xf, 0x23, 0x1d, 0x18, 0x21, 0x10, 0x1, 0x26, 0xa, 0x9, 0x13, 0x1f,
  0x28, 0x1b, 0x16, 0x17, 0x19, 0xd, 0x6, 0xb, 0x27, 0x12, 0x14, 0x8,
  0xe, 0x15, 0x20, 0x1a, 0x2, 0x1e, 0x7, 0x4, 0x11, 0x5, 0x3, 0x1c,
  0x22, 0x25, 0xc, 0x24,
];
const ACW_FALLBACK = '3000176000856006061501533003690027800375';
let ACW_KEY_CACHE = null;

function acwDecode(s) {
  const out = [];
  let bits = 0, nb = 0;
  for (const ch of String(s)) {
    if (ch === '=') break;
    const v = ACW_B64.indexOf(ch);
    if (v < 0) continue;
    bits = (bits << 6) | v;
    nb += 6;
    while (nb >= 8) { nb -= 8; out.push((bits >> nb) & 0xff); }
  }
  return Buffer.from(out).toString('utf8');
}

function acwKey(html) {
  if (ACW_KEY_CACHE) return ACW_KEY_CACHE;
  const m = html.match(/function\s+a0i\s*\(\s*\)\s*\{\s*var\s+N\s*=\s*\[([\s\S]*?)\]/);
  if (m) {
    for (const s of m[1].match(/'([^']*)'/g) || []) {
      const d = acwDecode(s.slice(1, -1));
      if (d.length === 40 && /^[0-9a-fA-F]{40}$/.test(d)) {
        ACW_KEY_CACHE = d;
        console.log('   · WAF 密钥动态提取成功');
        return d;
      }
    }
  }
  ACW_KEY_CACHE = ACW_FALLBACK;
  return ACW_KEY_CACHE;
}

// 移植自 as257259/MT 的算法解算：排列还原 + 异或
function acwSolveByAlgo(html) {
  const am = html.match(/arg1\s*=\s*['"]([0-9A-Fa-f]{40})['"]/);
  if (!am) return null;
  const arg1 = am[1];

  let arr = null;
  const pm = html.match(/for\s*\(\s*var\s+m\s*=\s*\[([^\]]+)\]/);
  if (pm) {
    const found = (pm[1].match(/0x([0-9a-fA-F]+)/g) || []).map(x => parseInt(x, 16));
    if (found.length === 40) arr = found;
  }
  if (!arr) arr = ACW_ARR;

  const q = new Array(40).fill(null);
  for (let x = 0; x < 40; x++) {
    for (let z = 0; z < 40; z++) {
      if (arr[z] === x + 1) q[z] = arg1[x];
    }
  }
  if (q.some(v => v === null)) return null;

  const key = acwKey(html);
  let res = '';
  for (let i = 0; i < 40; i++) {
    res += ((parseInt(q[i], 16) ^ parseInt(key[i], 16)) & 0xf).toString(16);
  }
  return `acw_sc__v2=${res}; max-age=3600; path=/`;
}

// vm 沙箱：把 WAF 的混淆 JS 真跑一遍，靠拦截 document.cookie 取值
function acwSolveByVm(html) {
  const blocks = [];
  for (const m of html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/gi)) blocks.push(m[1]);
  const js = blocks.find(b => /arg1\s*=/.test(b));
  if (!js) return null;

  let cookieVal = '';
  let timerCalls = 0;
  const sandbox = {
    location: { reload() {}, href: BASE + '/', hrefs: [] },
    navigator: { userAgent: UA, platform: 'Linux x86_64', appVersion: UA },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    sessionStorage: { getItem: () => null, setItem: () => {} },
    Date, Math, RegExp, String, Array, Object, Number, Boolean, JSON,
    parseInt, parseFloat, isNaN, encodeURIComponent, decodeURIComponent,
    setTimeout(fn) {
      // WAF 脚本常用定时器兜底调用 reload，这里直接同步执行（限次防死循环）
      if (timerCalls++ > 5) return 0;
      try {
        if (typeof fn === 'string') new Function(fn).call(sandbox);
        else if (typeof fn === 'function') fn();
      } catch (e) { /* 忽略 */ }
      return 0;
    },
    clearTimeout() {}, setInterval() { return 0; }, clearInterval() {},
    console,
  };
  const doc = {
    cookie: '',
    createElement: () => ({ style: {}, setAttribute() {}, appendChild() {} }),
    getElementsByTagName: () => [],
    getElementById: () => null,
    body: { appendChild() {} },
    write() {}, writeln() {}, referrer: BASE + '/',
  };
  Object.defineProperty(doc, 'cookie', {
    get() { return cookieVal; },
    set(v) { cookieVal = String(v); },
  });
  sandbox.document = doc;

  try {
    vm.createContext(sandbox);
    sandbox.window = sandbox;
    sandbox.self = sandbox;
    sandbox.top = sandbox;
    vm.runInContext(js, sandbox, { timeout: 8000 });
  } catch (e) { /* 跑挂了就看有没有半路写进 cookie */ }

  if (cookieVal && cookieVal.includes('acw_sc__v2')) {
    return cookieVal.includes(';') ? cookieVal : `${cookieVal}; max-age=3600; path=/`;
  }
  return null;
}

function isChallenge(body) {
  if (!body) return false;
  // arg1 是挑战页的标志；页面里带 acw_sc__v* 字面量，或页面很小（挑战页通常不到 20KB），都判定为挑战
  if (!/arg1\s*=\s*['"][0-9A-Fa-f]{20,}['"]/.test(body)) return false;
  return /acw_sc__v\d/i.test(body) || body.length < 20000;
}

// 每轮换一种解算方式：算法解不出就上沙箱，反之亦然
function solveAcw(html, round) {
  const a = acwSolveByAlgo(html);
  const b = acwSolveByVm(html);
  const order = round % 2 === 0 ? [a, b] : [b, a];
  for (const v of order) {
    if (v && /acw_sc__v2=[0-9a-fA-F]{16,}/.test(v)) return v;
  }
  return null;
}

// 带 WAF 绕过的请求；follow=false 时不跟重定向（登录 POST 用）
async function fetchPage(url, jar, opts = {}) {
  const pool = opts.proxyPool && opts.proxyPool.length ? opts.proxyPool : [opts.proxy || null];
  let cur = jar || new Jar();
  const baseOpts = Object.assign({}, opts, { proxyPool: pool });

  for (let round = 0; round < WAF_MAX_ROUNDS; round++) {
    let r;
    try {
      r = await requestWithRetry(url, cur, baseOpts);
    } catch (e) {
      throw e;
    }
    cur = cur.clone().absorb(r.setCookie);
    dump(`r${round}-${path.basename(new URL(r.url).pathname)}`, r.body);

    if (!isChallenge(r.body)) {
      return { res: r, jar: cur };
    }

    console.log(`   · 第 ${round + 1} 次遇到 WAF 挑战（HTTP ${r.status}, ${r.body.length}B）`);
    const acw = solveAcw(r.body, round);
    if (!acw) {
      console.log('   · 挑战识别到了但没解出来，响应片段: ' + snippet(r.body.replace(/<[^>]+>/g, ' '), 160));
      return { res: r, jar: cur, challenged: true };
    }
    // 只吃第一段 name=value，别把 max-age / path 这些属性也当成 cookie 塞进去
    cur = cur.clone().mergeStr(String(acw).split(';')[0]);
    console.log('   · 挑战已破解，带 cookie 重新请求');
    await sleep(1000);
  }
  return { res: null, jar: cur, challenged: true };
}

// ============================================================
// HTML 取值：Discuz 用 inajax=1 时把 HTML 塞进 <![CDATA[...]]>，
// 里面的引号会转成 &quot; / &#39;，必须先反转义才匹配得上
// ============================================================
function decodeEntities(s) {
  return String(s)
    .replace(/&quot;/g, '"')
    .replace(/&#0*34;/g, '"')
    .replace(/&#x0*22;/gi, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#0*39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

function unwrapCdata(body) {
  const m = String(body).match(/<!\[CDATA\[([\s\S]*?)\]\]>/);
  return m ? m[1] : body;
}

function stripCdata(body) {
  let s = String(body)
    .replace(/^<\?xml[\s\S]*?<root><!\[CDATA\[/, '')
    .replace(/\]\]><\/root>[\s\S]*$/, '')
    .replace(/<\/?root>/g, '')
    .trim();
  if (!s) s = String(body).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  return s;
}

function pickFormhash(rawHtml) {
  const raw = String(rawHtml || '');
  const candidates = [raw, unwrapCdata(raw), decodeEntities(unwrapCdata(raw)), decodeEntities(raw)];
  const pats = [
    /name=["']?formhash["']?\s+value=["']([A-Za-z0-9]{4,16})["']/i,
    /value=["']([A-Za-z0-9]{4,16})["']\s+name=["']?formhash["']?/i,
    /name=["']?formhash["']?[^>]{0,60}?value=["']([A-Za-z0-9]{4,16})/i,
    /formhash=([A-Za-z0-9]{6,10})/i,
    /formhash["']?\s*[:=]\s*["']?([A-Za-z0-9]{4,16})/i,
    /"formhash"\s*:\s*"([A-Za-z0-9]{4,16})"/i,
  ];
  for (const c of candidates) {
    if (!c) continue;
    for (const p of pats) {
      const m = c.match(p);
      if (m && m[1]) return m[1];
    }
  }
  return null;
}

function pickLoginhash(rawHtml) {
  const raw = String(rawHtml || '');
  const candidates = [raw, unwrapCdata(raw), decodeEntities(unwrapCdata(raw))];
  const pats = [
    /name=["']?loginhash["']?[^>]{0,60}?value=["']([A-Za-z0-9]{4,10})/i,
    /value=["']([A-Za-z0-9]{4,10})["']\s+name=["']?loginhash["']?/i,
    /name=["']?loginhash["']?\s+value=["']([A-Za-z0-9]{4,10})["']/i,
    /loginhash[^>]{0,40}?=\s*["']?([A-Za-z0-9]{4,10})/i,
    /loginhash=([A-Za-z0-9]{4,8})/i,
    /action=login&loginhash=([A-Za-z0-9]+)/i,
    /"loginhash"\s*:\s*"([A-Za-z0-9]{4,8})"/i,
  ];
  for (const c of candidates) {
    if (!c) continue;
    for (const p of pats) {
      const m = c.match(p);
      if (m && m[1]) return m[1];
    }
  }
  return '';
}

function parseResult(respBody) {
  const text = stripCdata(respBody) || String(respBody).replace(/<[^>]+>/g, '').trim();
  if (/今日已签|今天已签|已签到|已经签到|请不要重复/.test(text)) return { kind: 'already', text };
  if (/签到成功|成功.*签|恭喜|获得.*(金币|积分|奖励)/.test(text)) return { kind: 'success', text };
  if (/请(先)?登录|需要先登录|未登录|尚未登录|您还不是|游客|登录后才/.test(text)) return { kind: 'expired', text };
  if (/失败|错误|异常|未开启|不存在|已禁用/.test(text)) return { kind: 'fail', text };
  return { kind: 'unknown', text };
}

// ============================================================
// 登录
// ============================================================
const LOGIN_PAGES = [
  '/member.php?mod=logging&action=login&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login',
  '/member.php?mod=logging&action=login&infloat=yes&handlekey=login',
  '/member.php?mod=logging&action=login',
];

async function login(user, pwd, proxy, proxyPool) {
  let formhash = null;
  let loginhash = '';
  let jar = new Jar();

  for (const page of LOGIN_PAGES) {
    const got = await fetchPage(page, jar, { proxy, proxyPool });
    if (!got.res) continue;
    jar = got.jar;
    const fh = pickFormhash(got.res.body);
    console.log(`登录页 ${page.slice(0, 52)}... -> HTTP ${got.res.status} ${got.res.ms}ms ${got.res.body.length}B formhash=${fh || '无'}`);
    if (fh) {
      formhash = fh;
      loginhash = pickLoginhash(got.res.body);
      break;
    }
    console.log(`   └ 响应片段: ${snippet(stripCdata(got.res.body), 160)}`);
  }

  if (!formhash) return { ok: false, msg: '登录页未取到 formhash（已试 3 个候选页，多半还是 WAF 挑战页）' };
  console.log(`✅ 取到 formhash=${formhash} loginhash=${loginhash || '-'}`);

  const loginUrl = `/member.php?mod=logging&action=login&loginsubmit=yes&handlekey=login&loginhash=${loginhash}&inajax=1`;
  const form = {
    formhash,
    referer: BASE + '/k_misign-sign.html',
    fastloginfield: 'username',
    username: user,
    password: pwd,
    questionid: '0',
    answer: '',
    agreebbrule: '',
    cookietime: '2592000',
  };

  let r;
  try {
    r = await requestWithRetry(loginUrl, jar, {
      form, proxy, proxyPool,
      referer: BASE + LOGIN_PAGES[0],
      headers: { 'X-Requested-With': 'XMLHttpRequest' },
    });
  } catch (e) {
    return { ok: false, msg: `登录请求失败: ${e.message}` };
  }
  jar = jar.clone().absorb(r.setCookie);
  dump('login-result', r.body);
  console.log(`登录接口: HTTP ${r.status} ${r.ms}ms`);

  const text = stripCdata(r.body);
  if (/登录失败|密码错误|用户名.*?不正确|密码.*?不正确|账号不存在|安全提问|尝试次数过多|您的账号/.test(text + r.body)) {
    return { ok: false, fatal: true, msg: `账号或密码有误：${snippet(text, 120)}` };
  }

  // Discuz 登录成功会下发 saltkey / auth
  const logged = jar.has('saltkey', 'auth', 'EeqY_2132_auth', 'htVD_2132_auth') ||
    /登录成功|欢迎您回来/.test(r.body);
  if (!logged) {
    return { ok: false, msg: `登录未确认（没拿到会话 Cookie）：${snippet(text, 120)}` };
  }
  console.log('✅ 登录成功，已取得会话 Cookie');
  return { ok: true, jar };
}

// ============================================================
// 签到
// ============================================================
async function attemptSign(jar, proxy, proxyPool) {
  const signUrl = BASE + '/k_misign-sign.html';
  const sf = await fetchPage(signUrl, jar, { proxy, proxyPool });
  if (!sf.res) return { ok: false, msg: '签到页多次请求仍被 WAF 拦截' };
  const html = sf.res.body;
  const jar2 = sf.jar;
  console.log(`签到页: HTTP ${sf.res.status} ${sf.res.ms}ms, ${html.length}B`);

  const formhash = pickFormhash(html);
  if (!formhash) {
    return {
      ok: false, fatal: true,
      msg: `未能从签到页取到 formhash（Cookie 可能没生效）响应片段: ${snippet(stripCdata(html), 160)}`,
    };
  }
  console.log('✅ formhash =', formhash);

  const qdUrl = `${BASE}/plugin.php?id=k_misign:sign&operation=qiandao&format=text&formhash=${formhash}`;
  const qd = await fetchPage(qdUrl, jar2, {
    proxy, proxyPool, referer: signUrl,
    headers: { 'X-Requested-With': 'XMLHttpRequest' },
  });
  if (!qd.res) return { ok: false, msg: '签到请求多次被 WAF 拦截' };
  console.log(`签到接口: HTTP ${qd.res.status} ${qd.res.ms}ms`);

  const result = parseResult(qd.res.body);
  if (result.kind === 'already') {
    console.log('📅 今日已签到过: ' + result.text);
    return { ok: true, text: result.text };
  }
  if (result.kind === 'success') {
    console.log('✅ ' + result.text);
    return { ok: true, text: result.text };
  }
  if (result.kind === 'expired') {
    console.log('❌ 会话失效（需要重新登录）: ' + result.text);
    return { ok: false, msg: '会话失效', text: result.text, relogin: true };
  }
  if (result.kind === 'fail') {
    console.log('❌ 签到未成功: ' + result.text);
    return { ok: false, msg: result.text };
  }
  console.log('ℹ️ 签到返回（按成功处理）: ' + result.text);
  return { ok: true, text: result.text };
}

// ============================================================
// 入口
// ============================================================
function parseAccounts() {
  const raw = (process.env.ACCOUNTS || '').replace(/\r/g, '');
  const out = [];
  for (const line of raw.split('\n')) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const u = line.slice(0, idx).trim();
    const p = line.slice(idx + 1).trim();
    if (u && p) out.push([u, p]);
  }
  return out;
}

// 连通性自检：不签到，只看出口 IP / WAF / 能否拿到页面
async function smokeTest(proxy, proxyPool) {
  console.log('🔧 自检模式（MT_SMOKE=1），不执行签到');
  for (const url of ['/k_misign-sign.html', '/forum.php']) {
    const jar = new Jar();
    try {
      const r = await fetchPage(url, jar, { proxy, proxyPool });
      if (!r.res) { console.log(`${url} -> 被 WAF 拦死`); continue; }
      const b = r.res.body;
      console.log(`${url} -> HTTP ${r.res.status} ${r.res.ms}ms ${b.length}B`);
      console.log('   formhash=' + (pickFormhash(b) || '无') +
        ' WAF挑战=' + (isChallenge(b) ? '是' : '否') +
        ' 需登录=' + (/请登录|需要先登录|游客/.test(b) ? '是' : '否'));
    } catch (e) {
      console.log(`${url} -> 请求失败: ${e.message} code=${e.code || '-'}`);
    }
  }
}

async function main() {
  const proxyPool = buildProxyList();
  const directCookie = (process.env.BBS_COOKIE || '').replace(/[;%\s]+$/, '').trim();
  const accounts = directCookie ? [] : parseAccounts();

  if (proxyPool.length) {
    console.log(`🌐 已加载 ${proxyPool.length} 个代理，失败自动轮换`);
  } else {
    console.log('🌐 未配置代理，直连（海外 IP 可能触发风控，建议配 PROXIES）');
  }

  if (process.env.MT_SMOKE === '1') {
    await smokeTest(proxyPool[0] || null, proxyPool);
    return;
  }

  if (!directCookie && !accounts.length) {
    console.log('❌ 缺少环境变量 ACCOUNTS（每行 用户名:密码），或直接给 BBS_COOKIE');
    process.exit(1);
  }
  console.log(directCookie ? '使用 BBS_COOKIE，跳过登录' : `共 ${accounts.length} 个账号`);

  const eventName = process.env.GITHUB_EVENT_NAME || '';
  if (eventName === 'schedule' && process.env.SKIP_DELAY !== '1') {
    const maxMin = Math.max(0, parseInt(process.env.MAX_DELAY_MIN || '15', 10) || 0);
    const delay = Math.floor(Math.random() * maxMin * 60 * 1000);
    console.log(`🎲 随机延迟 ${Math.round(delay / 60000)} 分钟后开始签到...`);
    const HEARTBEAT = 5 * 60 * 1000;
    let remaining = delay;
    while (remaining > 0) {
      const step = Math.min(remaining, HEARTBEAT);
      await sleep(step);
      remaining -= step;
      if (remaining > 0) console.log(`⏳ 剩余 ${Math.round(remaining / 60000)} 分钟...`);
    }
    console.log('⏰ 延迟结束，开始签到！');
  } else {
    console.log('🚀 手动触发，跳过随机延迟');
  }

  const targets = directCookie
    ? [['(BBS_COOKIE)', directCookie]]
    : accounts.map(([u, p]) => [u, p]);

  const failed = [];

  for (const [label, secret] of targets) {
    console.log(`\n========== 账号 ${maskUser(label)} ==========`);

    let jar = directCookie ? new Jar(directCookie) : null;
    let ok = false;

    for (let attempt = 1; attempt <= FLOW_ATTEMPTS; attempt++) {
      // 每轮换一个代理，把「换出口 IP」和「重试」合并成同一件事
      const proxy = proxyPool.length ? proxyPool[(attempt - 1) % proxyPool.length] : null;
      if (attempt > 1) {
        const delay = FLOW_DELAYS[attempt - 2] || 120000;
        console.log(`\n🔄 整体第 ${attempt} 轮（代理=${proxy ? proxy.label : '直连'}，等待 ${delay / 1000}s）...`);
        await sleep(delay);
      } else if (proxy) {
        console.log(`🌐 本轮代理: ${proxy.label}`);
      }

      try {
        if (!jar) {
          const lg = await login(label, secret, proxy, proxyPool);
          if (!lg.ok) {
            if (lg.fatal) {
              console.log(`❌ ${maskUser(label)} ${lg.msg}`);
              break;
            }
            console.log(`⚠️ ${maskUser(label)} ${lg.msg}`);
            continue;
          }
          jar = lg.jar;
        }

        const r = await attemptSign(jar, proxy, proxyPool);
        if (r.ok) {
          console.log('✅ 签到流程成功.');
          console.log('RESULT_BODY=' + JSON.stringify(r.text));
          ok = true;
          break;
        }
        if (r.relogin) jar = null;   // 会话掉了，下一轮重新登录
        console.log(`⚠️ 本轮未完成: ${r.msg}`);
      } catch (e) {
        console.log(`⚠️ 本轮异常: ${e.message} code=${e.code || '-'}`);
      }
    }

    if (ok) console.log(`✅ ${maskUser(label)} 签到完成`);
    else {
      console.log(`❌ ${maskUser(label)} 多次尝试均失败，签到未完成`);
      failed.push(maskUser(label));
    }
  }

  if (failed.length) {
    console.log(`\n❌ 以下账号签到失败: ${failed.join(', ')}`);
    process.exit(1);
  }
  console.log('\n✅ 全部账号签到完成');
}

main().catch(e => { console.error('❌ 出错:', e.message); process.exit(1); });
