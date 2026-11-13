# 部署与更新

本项目有两种运行方式：GitHub Actions（现有默认方案，发布到 Gist）和服务器自托管（Docker 运行，原子保存到服务器本地）。两种方式共用相同的抓取、测速、出口检查、格式验证和节点数量保护规则。

> 免费节点由第三方运营，配置和流量都不可信。不要用它登录账号、支付或传输敏感信息。Secret Gist 只是“不公开链接”，不是访问控制；任何拿到链接的人都能读取订阅。

## GitHub Actions（现有方式）

仓库 **Settings → Secrets and variables → Actions** 中需要 `GIST_ID` 和可更新 Gist 的 `GIST_PAT`（建议只给 `gist` 权限）。旧配置 `PUSH_TOKEN` 仍兼容；Token 只放在 GitHub Actions Secrets，不得写进代码、文档、提交记录或公开日志。IPQuery 和 blocklist.de 不需要 API Key。

从 **Actions → Free Nodes → Run workflow → Run workflow** 可手动运行。工作流也会每六小时自动运行一次。成功时会一次性更新 `clash.yaml`、`v2ray.txt`、`singbox.json` 和 `report.json`；失败时保留上次 Gist 结果。

## 服务器自托管（Docker）

该模式把结果写进服务器本地目录，不需要 `GIST_ID` 或 GitHub Token。Compose 默认不开放任何网络端口；如果要让 Clash、Shadowrocket 等客户端从外部拉取订阅，还需要你在服务器上另行配置 HTTPS Web 服务器或反向代理，并自行决定访问控制。

要求：Linux x86-64 或 ARM64 服务器、Docker Engine 和 Docker Compose 插件。仓库根目录原有 `Dockerfile` 保持不变；自托管专用镜像是 `free-nodes/Dockerfile`。

```bash
# 在服务器上克隆仓库；/opt/aggregator 可换成自己的安装目录
git clone https://github.com/cesar699/aggregator.git /opt/aggregator
cd /opt/aggregator

# 确保容器运行用户能写入持久化数据目录
mkdir -p free-nodes/data
sudo chown -R "$(id -u):$(id -g)" free-nodes/data
export PUID="$(id -u)" PGID="$(id -g)"

# 构建镜像（包含 Mihomo；Sing-box 版本默认固定为 1.14.3）
docker compose -f free-nodes/compose.yaml build

# 手动跑一次完整流程
docker compose -f free-nodes/compose.yaml run --rm aggregate
```

首次成功后，四个文件位于 `free-nodes/data/published/`：`clash.yaml`、`v2ray.txt`、`singbox.json` 和 `report.json`。`published` 是指向版本化完整发布目录的符号链接；每次通过数量门槛后才原子切换，出错或新节点过少时，旧订阅保持不变。历史版本保存在旁边的 `published.releases/` 目录。`free-nodes/data/` 已加入 Git 和 Docker 忽略规则，避免误提交或把运行数据带入镜像构建上下文。

### 每六小时自动运行

在服务器当前用户的 crontab（`crontab -e`）中增加一行。把仓库路径、用户 UID/GID、`docker`/`flock` 路径和日志路径换成服务器上的实际值；常见 UID/GID 是 1000，但请以 `id -u`、`id -g` 为准：

```cron
17 */6 * * * cd /opt/aggregator && PUID=1000 PGID=1000 /usr/bin/flock -n /tmp/csmp-free-nodes.lock /usr/bin/docker compose -f free-nodes/compose.yaml run --rm aggregate >> /home/youruser/csmp-free-nodes.log 2>&1
```

用 `command -v docker` 和 `command -v flock` 查找可执行文件路径。此 cron 时间按服务器本地时区解释；`flock` 可避免上一次慢任务未结束时 cron 再启动一份。手动更新仍可重复执行上面的 `docker compose ... run --rm aggregate` 命令。升级代码后先 `git pull`，再运行 `docker compose -f free-nodes/compose.yaml build`。

Docker 容器以非 root UID/GID 运行、只读根文件系统、丢弃 Linux capabilities，并且不映射端口。数据只写入 `free-nodes/data` 挂载卷。首次构建需要联网下载固定版本的 Sing-box 发布包；需更新该版本时，在 `free-nodes/Dockerfile` 中改 `SINGBOX_VERSION`，并与 GitHub Actions 工作流中的版本保持一致。

> 自托管当前只负责运行任务和生成本地文件，不会自动创建公网订阅地址或 HTTPS。不要直接把无访问控制的目录暴露给公网；如需外部客户端订阅，请在自己的 HTTPS 反向代理上映射 `free-nodes/data/published/`，再把对应地址导入客户端。

## 节点源与检查规则

当前配置保留原有四个固定源，并新增两个通过实际 HTTP/YAML 与项目解析器检查的源：

1. [`v2raydog-node/free-nodes` V2Ray](https://raw.githubusercontent.com/v2raydog-node/free-nodes/main/v2ray.txt)
2. [`v2raydog-node/free-nodes` Clash](https://raw.githubusercontent.com/v2raydog-node/free-nodes/main/clash.yaml)
3. [`chenzhihan1751-cyber/node-sub-zixf`](https://raw.githubusercontent.com/chenzhihan1751-cyber/node-sub-zixf/main/sub/v2ray.txt)
4. [`735754647/Free-Nodes` Clash](https://735754647.github.io/Free-Nodes/clash.yaml)
5. [`0xRadikal/Free-v2ray-Configs` verified Clash](https://raw.githubusercontent.com/0xRadikal/Free-v2ray-Configs/main/verified/clash.yaml)
6. [`Au1rxx/free-vpn-subscriptions` Clash](https://raw.githubusercontent.com/Au1rxx/free-vpn-subscriptions/main/output/clash.yaml)

此外，每轮会用 GitHub REST API 搜索近期更新的公开仓库，最多检查 8 个仓库树，并从 `clash.yaml`、`v2ray.txt` 等高信号文件中最多补充 4 个候选源。搜索只读公开仓库；GitHub Actions 使用工作流自带令牌，不需要新增个人 Token。发现功能遇到限流或不可用时不重试、不影响六个固定源。每个发现源同样有独立失败记录；只有成功抓取并解析出的节点才会进入去重和测试。

单个源失败不会中止其他源；所有源都没有有效节点时整轮失败。报告会列出每个源是否读取成功、解析出多少节点及错误信息，并在 `source_discovery` 中记录搜索状态和候选源；这些数字是去重前解析数量，不代表实际可用节点数量。自动找到或格式解析成功不等于节点已实测可用；每个候选仍要经过下面的 Mihomo 和出口检查。

节点按协议、服务器、端口和身份去重；SSR、未知协议及配置不完整节点剔除。Mihomo 必须同时访问 Google `generate_204` 与 YouTube 静态图片，且两项延迟均不超过 5000ms。通过者才继续做出口公网 IP 检查；出口 IP 缺失、无效或非公网的节点会被剔除。报告记录国家、ASN、机房/移动/推测住宅类型、IPQuery 代理/VPN/Tor 风险标记与分数、Netflix/ChatGPT 解锁结果，以及黑名单结果。

黑名单来自 [blocklist.de 的 all.txt](https://lists.blocklist.de/lists/all.txt)，是对名单 IP 的精确匹配；它记录近期被报告的攻击 IP，不是覆盖所有威胁情报的“绝对干净”结论。若名单快照没有覆盖某个出口 IP 版本（例如只有 IPv4、节点出口是 IPv6），报告会写 `blacklist_status: ip_version_not_covered` 和 `blacklist_flag: null`，不会把未知误写成未命中。黑名单快照不可用或格式异常时，本轮不发布。

最终按双目标测试中较高的延迟排序，最多保留 200 个节点。发布前检查 Clash YAML、V2Ray Base64/每条分享链接、Sing-box JSON，并运行 Mihomo 配置检查和 `sing-box check`。少于 20 个节点，或低于上次保留数的一半（向上取整），都不发布；旧报告无法读取、输出验证失败或纯净度检查不可用时也保留旧结果。GitHub Actions 连续失败两次会在仓库创建提醒 Issue；服务器 cron 的失败详情写入你配置的日志文件。

## 验证边界

此前新增的两个固定订阅 URL 已读取并通过 YAML 与项目解析器兼容性检查，但这不代表节点已经可连通。自动发现功能目前通过模拟 GitHub API 的离线测试；本地匿名搜索请求遇到一次 403 限流，按设计没有重试，因此尚未验证实际 Actions 令牌下的搜索结果或发现源节点质量。本轮没有运行完整 Mihomo/出口检测、更新 Gist 或部署到服务器；只有完整生产流程成功结束后，才能确认实际保留的节点数。
