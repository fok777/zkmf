# zkmf — MT 论坛自动签到

Node.js 实现，GitHub Actions 定时运行。**账号密码登录**，不用抓 Cookie。

方案基于 [Xingyan777/binmt-auto-signin](https://github.com/Xingyan777/binmt-auto-signin) 改造：保留其 WAF 沙箱与强制 IPv4 策略，把登录方式从 Cookie 换成账号密码。

## 特性

- **账号密码登录**：自动提取 `loginhash` / `formhash` 并提交登录，无需手动抓 Cookie
- **过阿里云 ESA 挑战**：用 Node `vm` 沙箱真跑 WAF 的 JS，靠拦截 `document.cookie` 还原 `acw_sc__v2`，比正则提取更能抗算法变化
- **强制 IPv4**：论坛 IPv6 链路不通，runner 有 IPv6 时会挂起到超时，因此全部请求固定 `family: 4`
- **多重重试**：单请求超时 120s × 重试 4 次；整体最多 4 轮，间隔 30s/60s/120s
- **密码错误即停**：不做无意义重试
- **随机延迟**：定时触发时随机延迟 0~4 小时打散时间特征，手动触发跳过

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

## 定时

默认北京时间 **00:07** 和 **08:13** 各跑一次（cron 按 UTC 计）。

## 手动触发参数

| 参数 | 说明 |
|---|---|
| `cleanup` | 跑完是否清理旧运行记录与缓存，默认开 |
| `skip_delay` | 是否跳过随机延迟，默认开（立即签到） |

## 关于出口 IP

GitHub Runner 的 Azure 出口 IP 常被目标站丢包。workflow 里会尝试挂 Cloudflare WARP 把出口换成 Cloudflare 的 IP，失败则按原出口直连，不阻塞流程。

如果签到失败，看「签到结果」步骤——它会直接给出原因（密码错 / WAF 拦截 / 网络超时 / 会话失效），不用翻日志。

## 免责

仅供学习交流，请遵守目标站点使用条款。
