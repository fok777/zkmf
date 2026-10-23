#!/usr/bin/env node
/**
 * MT论坛 (bbs.binmt.cc) 自动签到脚本 (Node.js)
 * 部署到 GitHub Actions 每天自动运行
 *
 * 功能：
 *  1. 自动过阿里云 WAF (acw_sc__v2 JS 挑战)
 *  2. 动态获取 formhash
 *  3. 调用 k_misign 插件签到接口
 *
 * 容错：
 *  - 强制 IPv4（论坛 IPv6 链路不通，避免偶发快速超时）
 *  - 单次请求超时 120s
 *  - 单次请求自动重试 4 次
 *  - 整个签到流程整体重试最多 4 轮（应对海外 runner 到国内站网络波动）
 *
 * 配置（环境变量）：
 *  ACCOUNTS    - 每行 "用户名:密码"，必填（本版本新增，脚本自动登录取 Cookie）
 *  BBS_COOKIE  - 可选。给了就按 Xingyan777 原版方式直接签到，跳过登录
 */

const https = require('https');
const vm = require('vm');
const zlib = require('zlib');
const { URLSearchParams } = require('url');

const BASE = 'https://bbs.binmt.cc';
const UA = 'Mozilla/5.0 (Linux; Android 11; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116.0.0.0 Mobile Safari/537.36';

const REQ_TIMEOUT = 120000;
const REQ_RETRIES = 4;
const FLOW_ATTEMPTS = 4;
const FLOW_DELAYS = [30000, 60000, 120000];

const sleep = ms => new Promise(r => setTimeout(r, ms));

function request(url, cookieStr, opts = {}) {
  return new Promise((resolve, reject) => {
    const u = new URL(url, BASE);
    const isHttps = u.protocol === 'https:';
    const mod = isHttps ? https : require('http');
    const headers = Object.assign({
      'User-Agent': UA,
      'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
      'Accept-Encoding': 'gzip, deflate, br',
      'Accept-Language': 'zh-CN,zh;q=0.9',
      'Referer': BASE + '/',
      'Connection': 'close',
    }, opts.headers || {});
    if (cookieStr) headers['Cookie'] = cookieStr;

    // 唯一对原版 request() 的扩展：传 opts.form 时走 POST（登录要用）
    // 不传则与 Xingyan777 原版完全一致
    let payload = null;
    if (opts.form) {
      payload = new URLSearchParams(opts.form).toString();
      headers['Content-Type'] = 'application/x-www-form-urlencoded';
      headers['Content-Length'] = Buffer.byteLength(payload);
      headers['Origin'] = BASE;
    }

    const t0 = Date.now();
    // family:4 强制走 IPv4 —— bbs.binmt.cc 的 IPv6 链路不通（会挂起到超时），
    // GitHub runner 有 IPv6 地址，若不强制 IPv4 会偶发连接被丢弃导致快速 timeout
    const reqObj = mod.request(u, { headers, family: 4, method: payload ? 'POST' : 'GET' }, res => {
      const chunks = [];
      res.on('data', c => chunks.push(c));
      res.on('end', () => {
        let buf = Buffer.concat(chunks);
        const enc = (res.headers['content-encoding'] || '').toLowerCase();
        try {
          if (enc.includes('gzip')) buf = zlib.gunzipSync(buf);
          else if (enc.includes('deflate')) buf = zlib.inflateSync(buf);
          else if (enc.includes('br')) buf = zlib.brotliDecompressSync(buf);
        } catch (e) { /* 保留原文 */ }
        const setCookie = (res.headers['set-cookie'] || []).join('; ');
        resolve({
          status: res.statusCode,
          body: buf.toString(),
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
      const k = part.slice(0, eq).trim();
      const v = part.slice(eq + 1);
      map.set(k, v);
    }
  }
  const out = [];
  for (const [k, v] of map) out.push(k + '=' + v);
  return out.join('; ');
}

function solveAcwChallenge(html) {
  const m = html.match(/<script>([\s\S]*?)<\/script>/);
  if (!m) return null;
  const js = m[1];
  const arg1m = js.match(/arg1\s*=\s*'([0-9A-Fa-f]+)'/);
  if (!arg1m) return null;
  const arg1 = arg1m[1];
  let cookieVal = '';
  const sandbox = {
    document: {},
    location: { reload() {} },
    navigator: { userAgent: UA, platform: 'Linux x86_64' },
    localStorage: { getItem: () => null, setItem: () => {} },
    Date, Math, RegExp, String, Array, parseInt, parseFloat,
    decodeURIComponent, encodeURIComponent, console,
  };
  Object.defineProperty(sandbox.document, 'cookie', {
    get() { return cookieVal; },
    set(v) { cookieVal = v; },
  });
  try {
    vm.createContext(sandbox);
    vm.runInContext(js, sandbox, { timeout: 5000 });
  } catch (e) { /* 忽略 */ }
  if (cookieVal.includes('acw_sc__v2')) return cookieVal;
  return null;
}

async function getWithWaf(url, cookie) {
  let c = cookie;
  for (let i = 0; i < 3; i++) {
    const r = await requestWithRetry(url, c);
    if (r.body.includes('acw_sc__v2') && /<script>[\s\S]*arg1\s*=/.test(r.body)) {
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

function parseResult(respBody) {
  const clean = respBody
    .replace(/^<\?xml[\s\S]*?<root><!\[CDATA\[/, '')
    .replace(/\]\]><\/root>[\s\S]*$/, '')
    .replace(/^<\/?root>/, '')
    .trim();
  const text = clean || respBody.replace(/<[^>]+>/g, '').trim();
  if (/已签到|今日已签|今日已签到/.test(respBody)) return { kind: 'already', text };
  if (/签到成功|成功.*获取|签到.*成功/.test(respBody)) return { kind: 'success', text };
  if (respBody.includes('登录') && !respBody.includes('今日')) return { kind: 'expired', text };
  return { kind: 'unknown', text };
}

async function attemptSign(cookie) {
  const signUrl = BASE + '/k_misign-sign.html';
  const sf = await getWithWaf(signUrl, cookie);
  if (!sf) return { ok: false, msg: '多次请求仍被 WAF 拦截' };
  const html = sf.res.body;
  const cookieWithWaf = sf.cookie;
  console.log(`签到页: HTTP ${sf.res.status} ${sf.res.ms}ms, ${html.length}B`);

  const fh = html.match(/formhash=([a-f0-9]{8})/);
  if (!fh) return { ok: false, msg: '未能获取 formhash（cookie 可能已失效）' };
  const formhash = fh[1];
  console.log('✅ formhash =', formhash);

  const qdUrl = `${BASE}/plugin.php?id=k_misign:sign&operation=qiandao&format=text&formhash=${formhash}`;
  const qd = await getWithWaf(qdUrl, cookieWithWaf);
  if (!qd) return { ok: false, msg: '签到请求被 WAF 拦截' };
  console.log(`签到接口: HTTP ${qd.res.status} ${qd.res.ms}ms`);

  const respBody = qd.res.body;
  const result = parseResult(respBody);

  if (result.kind === 'already') {
    console.log('📅 今日已签到过: ' + result.text);
    return { ok: true, text: result.text };
  }
  if (result.kind === 'success') {
    console.log('✅ ' + result.text);
    return { ok: true, text: result.text };
  }
  if (result.kind === 'expired') {
    console.log('❌ Cookie 已失效，请更新 BBS_COOKIE');
    return { ok: false, fatal: true, msg: 'Cookie 已失效', text: result.text };
  }
  console.log('ℹ️ 签到返回: ' + result.text);
  return { ok: true, text: result.text };
}

// ============================================================
// 以下为本站唯一改动：登录方式
// Xingyan777 原版直接用环境变量 BBS_COOKIE 里的 Cookie 签到；
// 这里改为「账号 + 密码」，先走 Discuz 登录流程拿到 Cookie，
// 再把 Cookie 交给原版 attemptSign(cookie)，其余流程一字不动。
// ============================================================

// Discuz 用 inajax=1 时把 HTML 塞进 <![CDATA[...]]>，
// 里面的引号会被转成 &quot; / &#39;，必须先反转义才匹配得上
function decodeEntities(s) {
  return s
    .replace(/&quot;/g, '"')
    .replace(/&#0*34;/g, '"')
    .replace(/&#x0*22;/gi, '"')
    .replace(/&apos;/g, "'")
    .replace(/&#0*39;/g, "'")
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&amp;/g, '&');
}

// 把 CDATA 里的 HTML 掏出来（不去头尾，只剥壳）
function unwrapCdata(body) {
  const m = body.match(/<!\[CDATA\[([\s\S]*?)\]\]>/);
  return m ? m[1] : body;
}

function pickFormhash(rawHtml) {
  // 原始 + 剥 CDATA + 反转义，三份一起找
  const candidates = [
    rawHtml,
    unwrapCdata(rawHtml),
    decodeEntities(unwrapCdata(rawHtml)),
    decodeEntities(rawHtml),
  ];
  const pats = [
    /name=["']?formhash["']?\s+value=["']([A-Za-z0-9]{4,16})["']/i,
    /value=["']([A-Za-z0-9]{4,16})["']\s+name=["']?formhash["']?/i,
    /name=["']?formhash["']?[^>]{0,40}?value=["']([A-Za-z0-9]{4,16})/i,
    /formhash=([A-Za-z0-9]{8})/i,
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
  const candidates = [
    rawHtml,
    unwrapCdata(rawHtml),
    decodeEntities(unwrapCdata(rawHtml)),
  ];
  const pats = [
    /loginhash["']?\s*[:=]\s*["']?([A-Za-z0-9]{4,16})/i,
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
  return '';  // loginhash 取不到也能登录，Discuz 多数情况不校验
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

function maskUser(u) {
  if (/^1[3-9]\d{9}$/.test(u)) return `${u.slice(0, 3)}****${u.slice(-4)}`;
  return u.slice(0, 2) + '***' + u.slice(-1);
}

/**
 * 账号密码登录，返回可用于签到的 Cookie 串
 * 成功 -> { ok: true, cookie }
 * 失败 -> { ok: false, fatal?: true, msg }
 */
async function login(user, pwd) {
  // 1) 打开登录页（同样过 WAF），取 loginhash / formhash
  // 移动端 UA 下 Discuz 可能返回不同页，逐个候选页试，取到 formhash 就用
  const LOGIN_PAGES = [
    '/member.php?mod=logging&action=login&infloat=yes&handlekey=login&inajax=1&ajaxtarget=fwin_content_login',
    '/member.php?mod=logging&action=login&infloat=yes&handlekey=login',
    '/member.php?mod=logging&action=login',
  ];

  let lp = null;
  let formhash = null;
  let loginhash = '';

  for (const page of LOGIN_PAGES) {
    const got = await getWithWaf(page, '');
    if (!got) {
      console.log(`登录页 ${page} -> 被 WAF 拦截`);
      continue;
    }
    const fh = pickFormhash(got.res.body);
    console.log(`登录页 ${page} -> HTTP ${got.res.status} ${got.res.ms}ms ${got.res.body.length}B formhash=${fh || '无'}`);
    if (fh) {
      lp = got;
      formhash = fh;
      loginhash = pickLoginhash(got.res.body);
      break;
    }
    // 诊断：把没取到时的响应头部打出来，便于定位
    console.log(`   └ 响应片段: ${stripCdata(got.res.body).slice(0, 160)}`);
  }

  if (!formhash) return { ok: false, msg: '登录页未取到 formhash（已试 3 个候选页）' };
  console.log(`✅ 取到 formhash=${formhash} loginhash=${loginhash || '-'}`);

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

  let r;
  try {
    r = await requestWithRetry(loginUrl, lp.cookie, { form });
  } catch (e) {
    return { ok: false, msg: `登录请求失败: ${e.message}` };
  }
  console.log(`登录接口: HTTP ${r.status} ${r.ms}ms`);

  const text = stripCdata(r.body);
  if (/登录失败|密码错误|用户名.*?不正确|密码.*?不正确|账号不存在|安全提问|您的账号|尝试次数过多/.test(r.body)) {
    return { ok: false, fatal: true, msg: `账号或密码有误：${text}` };
  }

  const cookie = mergeCookies(lp.cookie, r.setCookie);
  // Discuz 登录成功会在 set-cookie 里下发 saltkey / auth
  const logged = /saltkey|auth/i.test(cookie) || /登录成功|欢迎您回来/.test(r.body);
  if (!logged) {
    return { ok: false, msg: `登录未确认（未拿到会话 Cookie）：${text}` };
  }
  console.log('✅ 登录成功，已取得会话 Cookie');
  return { ok: true, cookie };
}

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
  // 兼容 Xingyan777 原版：直接给了 BBS_COOKIE 就跳过登录
  let directCookie = (process.env.BBS_COOKIE || '').replace(/[;%\s]+$/, '').trim();

  let accounts = [];
  if (!directCookie) {
    accounts = parseAccounts();
    if (!accounts.length) {
      console.log('❌ 缺少环境变量 ACCOUNTS（每行 用户名:密码），或直接给 BBS_COOKIE');
      process.exit(1);
    }
    console.log(`共 ${accounts.length} 个账号`);
  } else {
    console.log('使用 BBS_COOKIE，跳过登录');
  }

  // 随机延迟：仅 schedule 触发时生效，workflow_dispatch（手动）跳过
  // 上限由 MAX_DELAY_MIN 控制，默认 15 分钟
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

    let cookie = null;
    if (directCookie) {
      cookie = directCookie;
    } else {
      // 登录这一步只做 1 次：密码错是 fatel，重试没意义；网络错交给下面的整体重试
      let lg = null;
      for (let li = 1; li <= 3 && !lg; li++) {
        if (li > 1) {
          console.log(`🔁 登录重试第 ${li} 次`);
          await sleep(5000);
        }
        try {
          const r = await login(label, secret);
          if (r.ok) { lg = r; break; }
          if (r.fatal) {
            console.log(`❌ ${maskUser(label)} ${r.msg}`);
            break;
          }
          console.log(`⚠️ ${maskUser(label)} ${r.msg}`);
        } catch (e) {
          console.log(`⚠️ ${maskUser(label)} 登录异常: ${e.message} code=${e.code || '-'}`);
        }
      }
      if (!lg) {
        failed.push(maskUser(label));
        continue;
      }
      cookie = lg.cookie;
    }

    // —— 以下与 Xingyan777 原版完全一致 ——
    let ok = false;
    for (let attempt = 1; attempt <= FLOW_ATTEMPTS; attempt++) {
      if (attempt > 1) {
        const delay = FLOW_DELAYS[attempt - 2] || 120000;
        console.log(`\n🔄 整体第 ${attempt} 轮尝试（等待 ${delay / 1000}s 后开始）...`);
        await sleep(delay);
      }
      try {
        const r = await attemptSign(cookie);
        if (r.ok) {
          console.log('✅ 签到流程成功.');
          console.log('RESULT_BODY=' + JSON.stringify(r.text));
          ok = true;
          break;
        }
        if (r.fatal) {
          console.log(`❌ ${r.msg}`);
          break;
        }
        console.log(`⚠️ 本轮未完成: ${r.msg}`);
      } catch (e) {
        console.log(`⚠️ 本轮异常: ${e.message} code=${e.code || '-'}`);
      }
    }

    if (ok) {
      console.log(`✅ ${maskUser(label)} 签到完成`);
    } else {
      console.log(`❌ ${maskUser(label)} 多次尝试均失败，签到未完成`);
      failed.push(maskUser(label));
    }
  }

  if (failed.length) {
    console.log(`\n❌ 以下账号签到失败: ${failed.join(', ')}`);
    process.exit(1);
  }
  console.log('\n✅ 全部账号签到完成');
  process.exit(0);
}

main().catch(e => { console.error('❌ 出错:', e.message); process.exit(1); });
