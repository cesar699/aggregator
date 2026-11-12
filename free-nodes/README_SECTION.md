# CSMP 免费节点聚合

每 6 小时自动抓取公开免费节点源，去重、Mihomo 延迟检测、出口纯净度探测，只保留活节点，按延迟排序（最多 200 个），订阅保存在 GitHub Gist。

> **⚠️ 安全提醒：免费节点来源不可信，不要用它登录账号、支付或传输敏感信息。**

## 订阅地址

把下面链接中的 `<GIST_ID>` 换成实际的 Gist ID（见仓库 Secrets 中的 `GIST_ID`）：

| 格式 | 订阅链接 |
| --- | --- |
| Clash | `https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/clash.yaml` |
| V2Ray | `https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/v2ray.txt` |
| Sing-box | `https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/singbox.json` |

纯净度报告（出口国家 / ASN / 机房或住宅 / Netflix、ChatGPT 解锁）：`https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/report.json`

## 一键导入 Shadowrocket

把订阅链接做 base64url 编码（去掉 `=` 填充）后拼在 `shadowrocket://add/sub://` 后面，例如 Clash 订阅：

```
shadowrocket://add/sub://<base64url(https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/clash.yaml)>
```

生成方法（任选其一）：

```bash
# macOS / Linux
printf 'https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/clash.yaml' \
  | base64 | tr '+/' '-_' | tr -d '=\n'
# 再拼成 shadowrocket://add/sub://<上面输出的结果>
```

## 运行状态

![Free Nodes](https://github.com/cesar699/aggregator/actions/workflows/free-nodes.yaml/badge.svg)

- 定时：每 6 小时自动运行（Actions → Free Nodes）
- 手动更新：Actions → Free Nodes → Run workflow
- 失败策略：失败时保留上一次的 Gist 结果；新结果少于 20 个节点，或不到上次保留数的一半，也视为失败、不更新 Gist；连续失败 2 次会自动开 Issue 提醒。

## 工作方式

1. 抓取 4 个公开节点源（单个源失效不影响其他源；全部失效整轮失败）
2. 去重（按协议 + 服务器 + 端口 + 身份）；SSR 协议节点直接丢弃
3. Mihomo 延迟测试：节点同时请求 Google `generate_204` 和一个 YouTube 静态资源，两项都通、延迟 < 5000ms 才算活节点
4. 对活节点逐个做出口纯净度检查：出口 IP 的国家 / ASN / 机房或住宅 / 代理或黑名单标记，探测 Netflix、ChatGPT 是否解锁；查不到出口 IP 的节点直接剔除
5. 生成 Clash / V2Ray / Sing-box 三份订阅 + `report.json`，更新到 Gist

详见 [`free-nodes/SETUP.md`](free-nodes/SETUP.md)。
