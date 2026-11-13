# 部署与更新

当前 Fork 已配置 Free Nodes 工作流，并已有一个 Secret Gist 用于保存订阅及报告；无需再创建重复 Gist。**Secret Gist 是不公开链接，不是访问控制；任何拿到订阅 URL 的人都能读取内容。**免费节点来源不可信，不要用它登录账号、支付或传输敏感信息。

## 必需的仓库 Secrets

在 GitHub 仓库 **Settings → Secrets and variables → Actions** 中确认 `GIST_ID`（现有 Secret Gist 的 ID），以及 `GIST_PAT`（可更新 Gist 的 PAT，建议只授予 `gist` 权限）。如果使用兼容的旧配置，也可用 `PUSH_TOKEN`；脚本先读 `GIST_PAT`，未设置时回退到 `PUSH_TOKEN`。

Token 只能放在仓库 Secrets，不能写进代码、README、提交记录或公开日志。轮换时只更新对应 Secret，不要把 Token 发在聊天或代码里。IPQuery 和 blocklist.de 均用公开 HTTPS 数据，不需要额外 API Key。

## 手动运行与状态

打开仓库 **Actions → Free Nodes → Run workflow → Run workflow** 可立即启动一次检查。成功时，Gist 会一次性更新 `clash.yaml`、`v2ray.txt`、`singbox.json` 和 `report.json`。工作流每 6 小时自动运行一次（UTC 每 6 小时的第 17 分钟）；README 顶部徽章显示最近状态。

## 检查与保护规则

四个订阅源分别抓取，单个节点源失败不会阻断其他源；对 HTTP 403、429 等拒绝或限流响应不重试，所有节点源都没有有效节点时整轮失败。另有一个必需的纯净度数据源：若黑名单快照下载或解析失败，整轮不发布，旧 Gist 保持不变。

只有通过 Mihomo 双网址测试的节点才继续检查：Google `generate_204` 与 YouTube 静态图片都必须通，两个延迟均不超过 5000ms。每个候选活节点通过节点出口查询公网 IP；出口 IP 缺失、无效或非公网会剔除。报告还记录国家、ASN、机房/移动/推测住宅分类、IPQuery 的代理/VPN/Tor 标签与风险分数，以及 Netflix/ChatGPT 解锁结果。

`blacklist_flag` 是出口 IP 是否精确命中 [blocklist.de 的 all.txt 名单](https://lists.blocklist.de/lists/all.txt)。官方说明该名单列出过去 48 小时向其或合作方报告的攻击 IP，并每 30 分钟生成；因此“未命中”仅表示未出现在这份近期名单中，不代表全网或所有威胁情报库都判定干净。该结果与 IPQuery 的 proxy/VPN/Tor 分类分开报告，不会因命中而自动删掉节点。

最后按两个测速中较高的延迟排序，最多保留 200 个节点。发布前必须通过 Clash YAML 解析、V2Ray Base64 解码和每条分享链接解析、Sing-box JSON 解析、Mihomo 配置检查与 `sing-box check`。少于 20 个节点，或低于上次保留数的一半（向上取整），旧结果都会保留；旧报告读不到、检查数据缺失或任一验证失败也不会更新。连续失败两次会在 Fork 仓库创建一条 Issue 提醒。

## 订阅地址

当前可用链接列在仓库根目录 README 的“订阅地址”表中。原始格式为：

- `https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/clash.yaml`
- `https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/v2ray.txt`
- `https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/singbox.json`
- `https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/report.json`
