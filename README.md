# Outlook Manage

Outlook / Hotmail 本地账号管理 WebUI。以 **SQLite 为唯一权威数据源**，覆盖：

- 账号导入（文本 / 文件 / 注册产出 `oauth2.txt`）
- 协议测试（Graph / IMAP / POP / SMTP）
- Token 刷新与轮换落库
- 健康分类与微软错误码中文化（含 `service abuse mode` 等）
- 后台批量任务（并发可调、实时进度、原因聚合、**硬取消**）
- 按邮箱后缀路由，同步到远程 OutlookEmail 池
- 可选 ABUSE 恢复（临时邮箱 + 浏览器解封 + 重新授权）

上游注册仍用 [OutlookRegister](https://github.com/daimon3332/OutlookRegister) 产出：

```text
邮箱----密码----client_id----refresh_token
```

本项目负责注册之后的**导入 → 测试 → 刷新 → 同步 → 清理**全流程。

## 环境准备

```bash
pip install -r requirements.txt
```

可选（仅 ABUSE 恢复 / 浏览器解封需要）：

```bash
patchright install chromium
# 或 playwright install chromium
```

协议测试建议配置可用 HTTP 代理（IMAP/POP/SMTP 经代理更稳）。

## 快速开始

1. 复制配置并编辑密钥（**不要提交真实 `config.json`**）：

```bash
copy config.example.json config.json
# Linux / macOS:
# cp config.example.json config.json
```

2. 按需修改 `config.json`：代理、远程池地址/密码、临时邮箱、协议测试收件人等。

3. 启动：

```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 18080
```

4. 浏览器打开 <http://127.0.0.1:18080>

依赖：FastAPI · uvicorn · requests · PySocks · python-multipart；恢复流程另需 playwright / patchright。

## 目录结构

```text
OutlookManage/
  backend/
    main.py                 # FastAPI 入口与批量任务 API
    db.py                   # SQLite schema / 连接
    services/
      diagnostics.py        # AADSTS / 健康分类
      jobs.py               # 后台任务与硬取消
      protocols.py          # 协议测试调度（可杀子进程）
      remote_pool.py        # 远程池登录 / 导入 / token 同步
      abuse_recovery.py     # ABUSE 恢复
      oauth_reauth.py       # 重新授权
      temp_mail.py          # 临时邮箱客户端
      locks.py              # 账号级锁
  frontend/
    index.html
    app.js
    styles.css
    logo.svg
  tests/
    test_hardening.py
  data/                     # 运行时数据库（gitignore）
  logs/                     # 运行日志（gitignore）
  test_protocols.py         # 协议测试脚本（子进程 / 同进程）
  config.example.json       # 配置模板（可提交）
  config.json               # 本地真实配置（勿提交）
  requirements.txt
  README.md
  scope.md                  # Graph/IMAP/POP/SMTP scope 说明
```

## 完整使用流程

```text
① 注册（OutlookRegister）→ Results/oauth2.txt
② 导入本地库（预览 → 导入；可加载 oauth2.txt）
③ 批量协议测试 → 正常 / 其他错误 / 滥用封禁
④ 批量刷新 Token → 成功则按时间与远程双向同步
⑤ 同步未上传 / 校准远程（按需）
⑥ 封禁号：本地保留；可从远程移除；可选 ABUSE 恢复
```

**默认安全策略：**

- 批量刷新 / 测试 / 同步 **排除** `banned` 账号
- 测出或刷出封禁 → **自动从远程删除**，本地保留
- 列表接口默认不返回 `password` / `refresh_token`（详情抽屉才有）

## 配置说明（`config.json`）

路径：项目根目录。请从 `config.example.json` 复制后填写。

### 完整示例（占位符）

```json
{
  "proxy": { "url": "http://127.0.0.1:7890" },
  "database": { "path": "data/accounts.db" },
  "remote": {
    "base_url": "https://your-remote-outlook-pool.example",
    "password": "CHANGE_ME_REMOTE_PASSWORD",
    "group_map": { "outlook.com": 3, "hotmail.com": 8 },
    "skip_unmapped": true,
    "default_group_id": 9,
    "provider": "outlook",
    "account_format": "client_id_refresh_token"
  },
  "server": { "host": "127.0.0.1", "port": 18080 },
  "temp_mail": {
    "base_url": "https://your-tempmail.example",
    "domain": "your-tempmail.example",
    "admin_password": "CHANGE_ME_TEMPMAIL_ADMIN",
    "site_password": ""
  },
  "recovery": {
    "enabled": true,
    "headless": false,
    "wait_after_code_submit_sec": 8,
    "captcha_max_attempts": 4,
    "unrecoverable_max_attempts": 3,
    "mail_poll_timeout_sec": 180,
    "mail_poll_interval_sec": 5
  },
  "protocol_test": { "external_recipient": "you@example.com" },
  "ui": { "title": "Outlook Manage WebUI", "default_concurrency": 20 }
}
```

### 字段说明

| 字段 | 含义 |
|------|------|
| `proxy.url` | HTTP 代理，协议测试 / 部分网络请求使用 |
| `database.path` | SQLite 路径，默认 `data/accounts.db` |
| `remote.base_url` | 远程 OutlookEmail 池根地址 |
| `remote.password` | 远程池登录密码 |
| `remote.group_map` | 邮箱后缀 → 远程分组 ID |
| `remote.skip_unmapped` | 未映射后缀是否跳过同步 |
| `remote.default_group_id` | 未映射且未跳过时的默认分组 |
| `server.host` / `server.port` | 文档用本地服务说明（启动仍以 uvicorn 参数为准） |
| `temp_mail.*` | ABUSE 恢复用临时邮箱服务 |
| `recovery.*` | 解封浏览器是否无头、轮询验证码间隔等 |
| `protocol_test.external_recipient` | 可选外部收件人（发信探测） |
| `ui.default_concurrency` | 前端默认并发数 |

## 界面与操作要点

页面分区：**总览 → 推荐下一步 → 当前任务 → 导入 → 任务中心 → 账号池 → 配置 → 日志**。

### 导入

- 每行：`邮箱----密码----client_id----refresh_token`
- 支持粘贴 / 上传 txt / 加载默认 `oauth2.txt`（若配置了路径）
- 先 **预览** 再导入；同名覆盖会重置健康状态并标「待同步」

### 任务中心

- 并发数 1–100，批量任务共用
- **一键测试未测试** / **一键同步未上传** / **补测注册时间**
- **批量协议测试** / **批量刷新** / **批量恢复 ABUSE**
- **终止任务 = 硬取消**：立刻 `cancelled`、杀协议子进程、停线程池，未处理记跳过

### 账号池

- 筛选：正常 / 封禁 / 其他错误 / 未测试 / 未上传 / 域名等
- 勾选批量：刷新、测试、恢复、同步、远程移除、彻底删除
- 详情抽屉可改密钥与备注；列表默认不带密钥字段

### 远程同步

- 比较本地 `refresh_token_updated_at` 与远程刷新时间，**较新覆盖较旧**
- 新账号按 `group_map` 路由（默认 outlook→3、hotmail→8）
- **不挪动**个人/临时等手动分组（只纠正批量分组内放错）

## 账号健康状态

Health 主要看 **Graph + IMAP/POP**（SMTP 仅展示，不主导分类）。

| health_status | severity | 含义 |
|---|---|---|
| `all` | ok | Graph + IMAP/POP 可用 |
| `graph_only` | warn | 仅 Graph |
| `imap_pop` | warn | 仅 IMAP/POP |
| `token_invalid` | fail | refresh token 失效/过期 |
| `other_error` | fail | 脚本异常 / 疑似受限等 |
| `banned` | banned | 滥用封禁 / 锁定 / 禁用等账号级拒绝 |

说明：

- 微软常返回 `AADSTS70000` + `User account is found to be in service abuse mode`
- 官方错误码页对 `70000` 的通用解释是 InvalidGrant；**以 `error_description` 全文为准**
- 本项目对含 `service abuse` / `abuse mode` 的响应归为 **banned**，不是普通 token 失效

AADSTS 映射见 `backend/services/diagnostics.py`。

## 数据与隐私

| 位置 | 是否应提交 | 内容 |
|------|------------|------|
| `data/accounts.db` | **否** | 账号、密码、token、历史 |
| `config.json` | **否** | 远程密码、临时邮箱密钥等 |
| `logs/` | **否** | 运行日志（可能含邮箱） |
| `config.example.json` | 是 | 无真实密钥的模板 |
| 源码 / 前端 / 测试 | 是 | 业务逻辑 |

仓库已用 `.gitignore` 忽略：本地配置、数据库、日志、虚拟环境、缓存、浏览器 profile、密钥类文件名等。  
**推送前请确认 `git status` 无 `config.json` / `*.db` / `oauth2.txt` / 日志。**

## API 摘要

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/status` | 总览统计 |
| GET | `/api/accounts` | 账号列表（默认无密钥） |
| GET | `/api/accounts/{id}/detail` | 详情 + 历史 |
| POST | `/api/accounts/import-preview` | 导入预览 |
| POST | `/api/accounts/import-text` | 文本导入 |
| POST | `/api/accounts/batch/refresh` | 批量刷新 → `job_id` |
| POST | `/api/accounts/batch/protocol` | 批量协议测试 → `job_id` |
| POST | `/api/jobs/{id}/cancel` | **硬取消**任务 |
| GET / PUT | `/api/config` | 配置读写 |
| GET | `/api/logs` | 日志尾部 |

批量请求体常见字段：`{ "ids": [], "concurrency": 8 }`；`ids` 空表示按规则取全部（仍会排除封禁，视接口而定）。

## 开发与测试

```bash
python -m unittest tests.test_hardening -v
```

## 常见问题

**Q: 协议测试大量 ABUSE？**  
A: 多为微软账号处于 `service abuse mode`，不是本系统误判。可对少量号直接打 token 端点核对 `error_description`。

**Q: 取消任务后还在跑？**  
A: 请使用带硬取消的版本：取消会杀协议子进程并停池。需重启后端使新代码生效。

**Q: 远程同步不动手动分组？**  
A: 设计如此，避免覆盖个人/临时分组。

**Q: 如何只更新公开仓库？**  
A: 本目录即独立 git 仓库；只提交源码与 `config.example.json`，本地 `config.json` 与 `data/` 留在本机。

## License / 声明

仅供自有账号运维与技术研究。请遵守微软服务条款与当地法律；勿将真实账号库、密码、token、远程凭据推送到公开仓库。

---

## 友情链接

- [linux.do](https://linux.do)：**学AI，上L站！！！**
