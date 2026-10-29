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
- **默认立即签到**：不随机延迟，触发就签（想恢复抖动见下文 `SKIP_DELAY`）
- **调试快照**：每次响应存一份到 `debug/`，Actions 里直接下载看
- **每周清理**：每个 workflow 只留最新 1 条运行记录，缓存只留最新 1 个

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
| `MT_DEBUG` | Variable | 设为 `0` 关闭调试快照 |
| `SKIP_DELAY` | Variable | 默认跳过随机延迟立即签到；设 `false` 可恢复抖动 |
| `MAX_DELAY_MIN` | Variable | 恢复抖动后的延迟上限（分钟），默认 15 |

代理写法：`http://user:pass@1.2.3.4:8080`、`1.2.3.4:8080` 都行，暂时不支持 socks。

## 定时

默认北京时间 **00:07** 和 **08:13** 各跑一次（cron 按 UTC 计）。

## 手动触发参数

| 参数 | 说明 |
|---|---|
| `skip_delay` | 跳过随机延迟立即签到，默认开。取消勾选才走随机延迟 |
| `use_warp` | 挂 Cloudflare WARP 换出口 IP，默认开。取消勾选才跳过 |
| `smoke` | 只做连通性自检不签到，排查 WAF / 代理时用 |

## 关于出口 IP

这是签到失败最常见的原因：MT 论坛对海外 IP 有风控（轻则弹滑动验证码，重则直接拒绝）。

- WARP **默认常开**，把出口换成 Cloudflare 的 IP，能解决 runner 到目标站的丢包问题。但它出来的仍是海外 IP，解决不了风控本身
- 真想稳定，配一个**国内代理**填进 `PROXIES`；代理和 WARP 可以并存（先 WARP 出口，再走代理）
- 只想排查网络，手动触发时把 `smoke` 勾上，脚本只测连通性和 WAF，不签到

失败时看「签到结果」步骤，它会直接给出原因（密码错 / 拿不到 formhash / WAF 没解开 / 代理不通 / 会话失效）。

## 每周清理

北京时间每周日 03:00 跑一次，默认策略：

- **运行记录**：每个 workflow 只保留最新 1 条，其余全删
- **缓存**：只保留最近使用的 1 个，其余全删

手动触发可临时改：`keep_runs` / `keep_caches` 调保留条数，`retain_days` 设成大于 0 可额外保留最近 N 天的记录，`dry_run` 勾选只统计不删。

## 免责

仅供学习交流，请遵守目标站点使用条款。
