#!/usr/bin/env node
/**
 * MT论坛 (bbs.binmt.cc) 自动签到脚本 (Node.js)
 *
 * 基于 Xingyan777/binmt-auto-signin 改造：
 *   - 登录方式由 Cookie 改为「账号 + 密码」，自动走登录流程拿 Cookie
 *   - 保留原版的 WAF 沙箱、强制 IPv4、重试策略
 *
 * 功能：
 *  1. 账号密码登录（自动提取 loginhash / formhash）
 *  2. 自动过阿里云 WAF (acw_sc__v2 JS 挑战)
 *  3. 调用 k_misign 插件签到接口
 *
 * 容错：
 *  - 强制 IPv4（论坛 IPv6 链路不通，会挂起到超时）
 *  - 单次请求超时 120s，自动重试 4 次
 *  - 整个流程整体重试最多 4 轮（应对海外 runner 到国内站网络波动）
 *  - 密码错误立即终止，不做无意义重试
 *
 * 配置（环境变量）：
 *  ACCOUNTS  - 多行 "user:pass"，必填
 */

const https = require('https');
const http = require('http');
const vm = require('vm');
const zlib = require('zlib');
const { URLSearchParams } = require('url');

const BASE = 'https://bbs.binmt.cc';
const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

const REQ_TIMEOUT = 120000;
const REQ_RETRIES = 4;
const FLOW_ATTEMPTS = 4;
const FLOW_DELAYS = [30000, 60000, 120000];

const sleep = ms => new Promise(r => setTimeout(r, ms));

// ---------- 基础请求 ----------
function request(url, cookieStr, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url, BASE);
    const mod = u.protocol === 'https:' ? https : http;
    const headers = Object.assign({
      'User-Agent': UA,
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      'Accept-Encoding': 'gzip, deflate',
      'Accept-Language': 'zh-CN,zh;q=0.9',
      'Origin': BASE,
      'Referer': BASE + '/',
      'Connection': 'close',
    }, opts.headers || {});
    if (cookieStr) headers['Cookie'] = cookieStr;

    let payload = null;
    if (opts.form) {
      payload = new URLSearchParams(opts.form).toString();
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      headers['Content-Length'] = Buffer.byteLength(payload);
    }

    const t0 = Date.now();
    // family:4 强制走 IPv4 —— 论坛 IPv6 链路不通，runner 有 IPv6 时会挂起到超时
    const reqObj = mod.request(u, { headers, family: 4, method: payload ? 'POST' : 'GET' }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        let buf = Buffer.concat(chunks);
        const enc = (res.headers['content-encoding'] || '').toLowerCase();
        try {
          if (enc.includes('gzip')) buf = zlib.gunzipSync(buf);
          else if (enc.includes('deflate')) buf = zlib.inflateSync(buf);
        } catch (e) { /* 保留原文 */ }
        const setCookie = (res.headers['set-cookie'] || []).map(c => c.split(';')[0]).join('; ');
        resolve({
          status: res.statusCode,
          body: buf.toString('utf8'),
          setCookie,
          headers: res.headers,
          ms: Date.now() - t0,
        });
      });
    });

    reqObj.setTimeout(REQ_TIMEOUT, () => reqObj.destroy(new Error('timeout')));
    reqObj.on('error', err => { err.reqMs = Date.now() - t0; reject(err); });
    if (payload) reqObj.write(payload);
    reqObj.end();
  });
}

async function requestWithRetry(url, cookieStr, opts = {}, retries = REQ_RETRIES) {
  for (let i = 0; i < retries; i++) {
    try {
      return await request(url, cookieStr, opts);
    } catch (e) {
      if (i === retries - 1) throw e;
      console.log(`⚠️ 请求失败(${e.message} code=${e.code || '-'} ${e.reqMs || '?'}ms)，第 ${i + 1} 次重试...`);
      await sleep(5000);
    }
  }
}

function mergeCookies(...cookStrs) {
  const map = new Map();
  for (const cs of cookStrs) {
    if (!cs) continue;
    for (let part of cs.split(';')) {
      part = part.trim();
      if (!part) continue;
      const eq = part.indexOf('=');
      if (eq === -1) continue;
      map.set(part.slice(0, eq).trim(), part.slice(eq + 1));
    }
  }
  return [...map].map(([k, v]) => `${k}=${v}`).join('; ');
}

// ---------- 阿里云 WAF (acw_sc__v2) ----------
function solveAcwChallenge(html) {
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  if (!m) return null;
  const js = m[1];
  if (!/arg1\s*=/.test(js)) return null;
  let cookieVal = '';
  const sandbox = {
    document: {},
    location: { reload() {}, href: BASE + '/' },
    navigator: { userAgent: UA, platform: 'Win32' },
    localStorage: { getItem: () => null, setItem: () => {} },
    Date, Math, RegExp, String, Array, Object, Number, Boolean,
    parseInt, parseFloat, isNaN, decodeURIComponent, encodeURIComponent,
    escape, unescape, setTimeout, console,
  };
  Object.defineProperty(sandbox.document, 'cookie', {
    get() { return cookieVal; },
    set(v) { cookieVal = v; },
  });
  try {
    vm.createContext(sandbox);
    vm.runInContext(js, sandbox, { timeout: 5000 });
  } catch (e) { /* 忽略，挑战脚本常带反调试 */ }
  if (cookieVal.includes('acw_sc__v2')) return cookieVal;
  // 少数版本直接把结果写在变量里
  try {
    const v = sandbox.acw_sc__v2 || sandbox.arg2;
    if (v) return `acw_sc__v2=${v}`;
  } catch (e) {}
  return null;
}

async function getWithWaf(url, cookie) {
  let c = cookie;
  for (let i = 0; i < 3; i++) {
    const r = await requestWithRetry(url, c);
    if (/acw_sc__v2/.test(r.body) && /<script>[\s\S]*arg1\s*=/.test(r.body)) {
      const acw = solveAcwChallenge(r.body);
      if (acw) {
        c = mergeCookies(c, acw, r.setCookie);
        continue;
      }
    }
    return { res: r, cookie: mergeCookies(c, r.setCookie) };
  }
  return null;
}

async function postWithWaf(url, cookie, form) {
  const r = await requestWithRetry(url, cookie, { form });
  return { res: r, cookie: mergeCookies(cookie, r.setCookie) };
}

// ---------- 页面解析 ----------
function pickFormhash(html) {
  const pats = [
    /name=["']formhash["']\s+value=["']([A-Za-z0-9]{4,16})["']/,
    /value=["']([A-Za-z0-9]{4,16})["']\s+name=["']formhash["']/,
    /formhash=([A-Za-z0-9]{8})/,
    /formhash["']?\s*[:=]\s*["']?([A-Za-z0-9]{4,16})/,
  ];
  for (const p of pats) {
    const m = html.match(p);
    if (m && m[1]) return m[1];
  }
  return null;
}

function pickLoginhash(html) {
  const pats = [
    /loginhash["']?\s*[:=]\s*["']?([A-Za-z0-9]{4,16})/,
    /loginhash=([A-Za-z0-9]{4,8})/,
    /action=login&loginhash=([A-Za-z0-9]+)/,
  ];
  for (const p of pats) {
    const m = html.match(p);
    if (m && m[1]) return m[1];
  }
  return '';
}

function stripCdata(body) {
  let s = body
    .replace(/^<\?xml[\s\S]*?<root><!\[CDATA\[/, '')
    .replace(/\]\]><\/root>[\s\S]*$/, '')
    .replace(/<\/?root>/g, '')
    .trim();
  if (!s) s = body.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
  return s.slice(0, 200);
}

function parseSignResult(raw) {
  const text = stripCdata(raw);
  if (/已签|今日已签|签到已完成|已经签到/.test(raw)) return { kind: 'already', text };
  if (/签到成功|成功.*获取|恭喜|success|qiandao_success|获得/.test(raw)) return { kind: 'success', text };
  if (/未登录|请登录|请先登录|非法|重新登录/.test(raw)) return { kind: 'needLogin', text };
  return { kind: 'unknown', text };
}

function maskUser(u) {
  if (/^1[3-9]\d{9}$/.test(u) && u.length === 11) return `${u.slice(0, 3)}****${u.slice(-4)}`;
  return u.slice(0, 2) + '***' + u.slice(-1);
}

// ---------- 登录 + 签到 ----------
async function attemptSign(user, pwd) {
  // 1) 登录页
  const loginPageUrl = '/member.php?mod=logging&action=login&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login';
  const lp = await getWithWaf(loginPageUrl, '');
  if (!lp) return { ok: false, msg: '登录页被 WAF 拦截' };
  const loginhash = pickLoginhash(lp.res.body);
  const formhash = pickFormhash(lp.res.body);
  if (!formhash) return { ok: false, msg: '未能从登录页取到 formhash' };
  console.log(`登录页 HTTP ${lp.res.status} ${lp.res.ms}ms | formhash=${formhash} loginhash=${loginhash || '-'}`);

  // 2) 提交登录
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
  };
  const lg = await postWithWaf(loginUrl, lp.cookie, form);
  const lgText = stripCdata(lg.res.body);
  if (/登录失败|密码错误|用户名.*?不正确|密码.*?不正确|账号不存在|安全提问|您的账号/.test(lg.res.body)) {
    return { ok: false, fatal: true, msg: `账号或密码有误：${lgText}` };
  }
  if (!/登录成功|欢迎您回来|succeed|location\.reload/.test(lg.res.body)) {
    console.log(`ℹ️ 登录响应未知: ${lgText}`);
  }
  let cookie = lg.cookie;
  const logged = /_saltkey|_|auth/.test(cookie) || /登录成功|欢迎您回来/.test(lg.res.body);
  if (!logged) {
    return { ok: false, msg: '登录未确认（未拿到会话 Cookie）' };
  }
  console.log('✅ 登录成功，已取得会话 Cookie');

  await sleep(1200);

  // 3) 签到页取 formhash
  const sp = await getWithWaf('/k_misign-sign.html', cookie);
  if (!sp) return { ok: false, msg: '签到页被 WAF 拦截' };
  cookie = sp.cookie;
  const sfh = pickFormhash(sp.res.body);
  if (!sfh) return { ok: false, msg: '未能从签到页取到 formhash（Cookie 可能无效）' };
  console.log(`签到页 HTTP ${sp.res.status} ${sp.res.ms}ms | formhash=${sfh}`);

  await sleep(1200);

  // 4) 调签到接口
  const qdUrl = `/plugin.php?id=k_misign:sign&operation=qiandao&format=text&formhash=${sfh}`;
  const qd = await getWithWaf(qdUrl, cookie);
  if (!qd) return { ok: false, msg: '签到接口被 WAF 拦截' };
  const result = parseSignResult(qd.res.body);
  console.log(`签到接口 HTTP ${qd.res.status} ${qd.res.ms}ms -> ${result.text}`);

  if (result.kind === 'already' || result.kind === 'success') {
    return { ok: true, text: result.text };
  }
  if (result.kind === 'needLogin') {
    return { ok: false, msg: '会话失效，签到时仍判定未登录' };
  }
  return { ok: false, msg: `签到未确认：${result.text}` };
}

// ---------- 主流程 ----------
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

async function main() {
  const accounts = parseAccounts();
  if (!accounts.length) {
    console.log('❌ 缺少环境变量 ACCOUNTS，格式：每行 user:pass');
    process.exit(1);
  }
  console.log(`共 ${accounts.length} 个账号`);

  // schedule 触发时随机延迟，打散时间特征；手动触发跳过
  // 上限由 MAX_DELAY_MIN 控制（默认 15 分钟），GitHub 的 schedule 本身会晚 5~30 分钟
  const eventName = process.env.GITHUB_EVENT_NAME || '';
  if (eventName === 'schedule' && process.env.SKIP_DELAY !== '1') {
    const maxMin = Math.max(0, parseInt(process.env.MAX_DELAY_MIN || '15', 10) || 0);
    const delay = Math.floor(Math.random() * maxMin * 60 * 1000);
    console.log(`🎲 随机延迟 ${Math.round(delay / 60000)} 分钟后开始签到`);
    const HEARTBEAT = 5 * 60 * 1000;
    let remaining = delay;
    while (remaining > 0) {
      const step = Math.min(remaining, HEARTBEAT);
      await sleep(step);
      remaining -= step;
      if (remaining > 0) console.log(`⏳ 剩余 ${Math.round(remaining / 60000)} 分钟...`);
    }
    console.log('⏰ 延迟结束，开始签到');
  } else {
    console.log('🚀 手动触发，跳过随机延迟');
  }

  const failed = [];
  for (const [user, pwd] of accounts) {
    console.log(`\n========== 账号 ${maskUser(user)} ==========`);
    let ok = false;
    for (let attempt = 1; attempt <= FLOW_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        const d = FLOW_DELAYS[attempt - 2] || 120000;
        console.log(`🔄 第 ${attempt} 轮（等待 ${d / 1000}s）...`);
        await sleep(d);
      }
      try {
        const r = await attemptSign(user, pwd);
        if (r.ok) {
          console.log(`✅ ${maskUser(user)} 签到完成: ${r.text}`);
          ok = true;
          break;
        }
        if (r.fatal) {
          console.log(`❌ ${maskUser(user)} ${r.msg}`);
          break;
        }
        console.log(`⚠️ ${maskUser(user)} 本轮未完成: ${r.msg}`);
      } catch (e) {
        console.log(`⚠️ ${maskUser(user)} 本轮异常: ${e.message} code=${e.code || '-'}`);
      }
    }
    if (!ok) failed.push(maskUser(user));
  }

  if (failed.length) {
    console.log(`\n❌ 以下账号签到失败: ${failed.join(', ')}`);
    process.exit(1);
  }
  console.log('\n✅ 全部账号签到完成');
  process.exit(0);
}

main().catch(e => { console.error('❌ 出错:', e.message); process.exit(1); });
