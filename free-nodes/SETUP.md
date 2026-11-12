# 部署步骤（首次手动设置，约 5 分钟）

> 以下步骤需要你本人在浏览器里完成，涉及 Token 创建，助手不代操作。**Token 只放仓库 Secrets，绝不写进代码、绝不公开。**

## 1. 创建一个 Secret Gist（放订阅文件）

1. 打开 https://gist.github.com/ ，登录 GitHub 账号 `cesar699`。
2. 新建 Gist，**选 Secret（不公开）**。
3. 先建 4 个占位文件，文件名必须 exactly 是：
   - `clash.yaml`（内容任意，如 `# placeholder`）
   - `v2ray.txt`
   - `singbox.json`（内容 `{}`）
   - `report.json`（内容 `{}`）
4. 点 **Create secret gist**，记下地址栏里的 Gist ID（一串十六进制字符）。

## 2. 创建一个只含 `gist` 权限的 Classic PAT

1. 打开 https://github.com/settings/tokens （Personal access tokens → Tokens (classic)）。
2. **Generate new token (classic)**，Note 填 `aggregator-gist`。
3. Expiration 选 **No expiration**（或 90 days，到期需重建）。
4. **只勾选 `gist`**（Create gists），不要勾其他权限。
5. 生成后**立即复制 Token，只显示一次**，不要发到聊天记录、不要写进代码。

## 3. 把两个值放进仓库 Secrets

1. 打开 https://github.com/cesar699/aggregator/settings/secrets/actions 。
2. **New repository secret**：
   - Name `GIST_ID`，Value = 第 1 步的 Gist ID。
   - Name `GIST_PAT`，Value = 第 2 步的 PAT。
3. （可选）如果你已有旧的 `PUSH_TOKEN`，也可以继续用——工作流同时读取 `GIST_PAT`，没有时才 fallback 到 `PUSH_TOKEN`。

## 4. 开启 Actions 并手动跑一次

1. 打开 https://github.com/cesar699/aggregator/actions ，如果 fork 默认禁用了 Actions，按提示启用。
2. 左侧选 **Free Nodes** → **Run workflow** → **Run workflow**。
3. 等待运行完成（约 5–20 分钟，取决于活节点数量和纯净度探测速度）。
4. 成功后打开 Gist，4 个文件应已更新为真实订阅内容；`report.json` 里有 `generated_at`、`counts` 和每节点的出口信息。

## 之后

- 每 6 小时自动运行一次，无需干预。
- 失败时 Gist 保留上一次成功的结果；连续失败 2 次会自动在仓库开 Issue 提醒。
- 轮换 Token 时只需更新 Secrets 里的 `GIST_PAT`，不用改代码。
- 订阅链接格式：`https://gist.githubusercontent.com/cesar699/<GIST_ID>/raw/<文件名>`。
