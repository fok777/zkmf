# zkmf — MT 论坛自动签到

Node.js 实现，GitHub Actions 定时运行。**账号密码登录**，不用抓 Cookie。

方案基于 [Xingyan777/binmt-auto-signin](https://github.com/Xingyan777/binmt-auto-signin) 改造：保留其 WAF 沙箱与强制 IPv4 策略，把登录方式从 Cookie 换成账号密码；WAF 解算部分参考了 [as257259/MT](https://github.com/as257259/MT) 的算法实现。

## 特性

- **账号密码登录**：自动提取 `loginhash` / `formhash` 并提交登录，无需手动抓 Cookie
- **WAF 双路解算**：先跑 Node `vm` 沙箱真执行 WAF 的混淆 JS（拦截 `document.cookie`），解不出再走算法解算（排列还原 + 异或），两条路轮换，抗算法变化能力强
- **代理支持**：`PROXIES` / `HTTPS_PROXY`，不配就直连，行为完全不变；配了代理池会在失败时自动轮换出口
- **正确的 Cookie 处理**：逐个解析 `Set-Cookie`，只取 `name=value`，不再把 `expires` / `path` / `HttpOnly` 当成 cookie 发回服务端
- **强制 IPv4**：论坛 IPv6 链路不通，runner 有 IPv6 时会挂起到超时，因此直连时固定 `family: 4`
- **多重重试**：单请求超时 120s × 重试 4 次；整体最多 4 轮（间隔 30s/60s/120s），每轮换一个出口
- **密码错误即停**：不做无意义重试
- **随机延迟**：定时触发时随机延迟打散时间特征，手动触发跳过
- **调试快照**：每次响应存一份到 `debug/`，Actions 里直接下载看

## 部署

1. Fork 或直接用本仓库
2. 进 **Settings → Secrets and variables → Actions → New repository secret**
   - 名称：`ACCOUNTS`
   - 值：每行一个账号，格式 `用户名:密码`

   ```
   user1:pass1
   user2:pass2
   ```
3. 进 **Actions** 页启用 workflow，点 **Run workflow** 手动试一次

## 环境变量

| 变量 | 位置 | 说明 |
|---|---|---|
| `ACCOUNTS` | Secret | 每行 `用户名:密码`。和 `BBS_COOKIE` 二选一 |
| `BBS_COOKIE` | Secret | 可选。给了就跳过登录直接签到 |
| `PROXIES` | Secret | 代理池，每行一个，失败自动轮换 |
| `HTTPS_PROXY` | Secret | 单个代理 |
| `USE_WARP` | Variable | 设为 `false` 可关掉 workflow 里的 Cloudflare WARP（配了代理时建议关） |
| `MT_DEBUG` | Variable | 设为 `0` 关闭调试快照 |
| `MAX_DELAY_MIN` | Variable | 定时触发的随机延迟上限（分钟），默认 15 |

代理写法：`http://user:pass@1.2.3.4:8080`、`1.2.3.4:8080` 都行，暂时不支持 socks。

## 定时

默认北京时间 **00:07** 和 **08:13** 各跑一次（cron 按 UTC 计）。

## 手动触发参数

| 参数 | 说明 |
|---|---|
| `skip_delay` | 跳过随机延迟，默认开（立即签到） |
| `use_warp` | 是否挂 Cloudflare WARP，默认开；配了代理就关掉 |
| `smoke` | 只做连通性自检不签到，排查 WAF / 代理时用 |

## 关于出口 IP

这是签到失败最常见的原因：MT 论坛对海外 IP 有风控（轻则弹滑动验证码，重则直接拒绝）。

- workflow 默认会尝试挂 Cloudflare WARP 换出口，但 WARP 出来的仍是海外 IP，只能解决丢包，解决不了风控
- 想稳定，最好是配一个**国内代理**填进 `PROXIES`，然后把 Variable `USE_WARP` 设成 `false`
- 只想排查网络，手动触发时把 `smoke` 勾上，脚本只测连通性和 WAF，不签到

失败时看「签到结果」步骤，它会直接给出原因（密码错 / 拿不到 formhash / WAF 没解开 / 代理不通 / 会话失效）。

## 免责

仅供学习交流，请遵守目标站点使用条款。
