# CSMP 免费节点聚合

每 6 小时自动抓取公开免费节点源，去重、Mihomo 双目标延迟检测、出口纯净度探测，只保留活节点，按延迟排序（最多 200 个），订阅保存在 GitHub Secret Gist。

> **安全提醒：**免费节点来源不可信，不要用它登录账号、支付或传输敏感信息。Secret Gist 是不公开链接而非访问控制；拿到链接的人都能读取。

## 订阅地址

以下链接对应仓库 Secrets 中的 `GIST_ID`，当前可直接使用：

| 格式 | 订阅链接 |
| --- | --- |
| Clash | `https://gist.githubusercontent.com/cesar699/24c6aea70f95c6f67a5cc66515e90081/raw/clash.yaml` |
| V2Ray | `https://gist.githubusercontent.com/cesar699/24c6aea70f95c6f67a5cc66515e90081/raw/v2ray.txt` |
| Sing-box | `https://gist.githubusercontent.com/cesar699/24c6aea70f95c6f67a5cc66515e90081/raw/singbox.json` |

纯净度报告：`https://gist.githubusercontent.com/cesar699/24c6aea70f95c6f67a5cc66515e90081/raw/report.json`。IPQuery 提供国家、ASN、机房/移动/推测住宅分类、代理/VPN/Tor 风险标记与风险分数；独立 `blacklist_flag` 是出口 IP 是否命中 [blocklist.de 公开名单](https://www.blocklist.de/en/export.html)，记录过去 48 小时被报告的攻击 IP。未命中不等于全网绝对干净，IPQuery 风险分数也不是黑名单判定。

## 一键导入 Shadowrocket

把订阅链接做 base64url 编码（去掉 `=` 填充）后拼在 `shadowrocket://add/sub://` 后面，例如 Clash 订阅：

```
shadowrocket://add/sub://<base64url(https://gist.githubusercontent.com/cesar699/24c6aea70f95c6f67a5cc66515e90081/raw/clash.yaml)>
```

```bash
# macOS / Linux
printf 'https://gist.githubusercontent.com/cesar699/24c6aea70f95c6f67a5cc66515e90081/raw/clash.yaml' \
  | base64 | tr '+/' '-_' | tr -d '=\n'
# 将输出拼成 shadowrocket://add/sub://<上面输出的结果>
```

## 运行状态与更新方法

![Free Nodes](https://github.com/cesar699/aggregator/actions/workflows/free-nodes.yaml/badge.svg)

- 定时：每 6 小时自动运行（UTC 每 6 小时的第 17 分钟）。
- 手动更新：GitHub 仓库 **Actions → Free Nodes → Run workflow → Run workflow**。
- 失败保护：少于 20 个节点或低于上次保留数的一半（向上取整）时不更新 Gist；检查或验证失败时保留上次结果，连续失败 2 次开 Issue 提醒。
- Secrets：`GIST_ID` 与 `GIST_PAT`（或兼容的 `PUSH_TOKEN`）只放在仓库 Actions Secrets，不能写入代码；IPQuery 和 blocklist.de 无需 API Key。

## 工作方式

1. 抓取四个公开节点源，单个源失效不影响其他源；没有任何源产生有效节点时整轮失败。
2. 去重；SSR 与不支持或配置无效的节点不进入测试。
3. Mihomo 通过 Google `generate_204` 与 YouTube 静态图片做双目标延迟测试，两项都通且均 ≤ 5000ms 才算活节点。
4. 逐个查询节点出口公网 IP；无效/非公网 IP 直接剔除。记录国家、ASN、机房/移动/推测住宅、IPQuery 代理/VPN/Tor 标记与分数、Netflix/ChatGPT 结果和 blocklist.de 精确名单命中。
5. 下载并解析黑名单快照；快照不可用或格式异常时不更新 Gist。生成三种订阅与 `report.json` 后，先完成 YAML、JSON、Base64/分享链接、Mihomo 与 Sing-box 校验，再一次性更新 Gist。

详见 [`free-nodes/SETUP.md`](free-nodes/SETUP.md)。
