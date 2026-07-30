# Outlook Graph Checker

用于批量判断 Outlook / Hotmail 账号是否能够通过 Microsoft Graph 获取邮件的最小 WebUI。

## 功能

- 导入 `client_id----refresh_token`
- 兼容原格式 `邮箱----密码----client_id----refresh_token`
- 使用 `/consumers/oauth2/v2.0/token` 刷新 Graph Token
- 调用 Graph `/me` 自动补全邮箱
- 调用 Graph `/me/messages?$top=1` 判断邮件读取是否正常
- 状态分类：正常、ABUSE、Token 无效、其他错误、未测试
- 一键测试未测试账号
- 代理、默认并发和管理密码设置

项目不再包含远程账号池同步、ABUSE 自动恢复、IMAP、POP、SMTP 或账号导出。

## 启动

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
cp config.example.json config.json
.venv/bin/python -m uvicorn backend.main:app --host 127.0.0.1 --port 31880 --proxy-headers
```

部署时建议只监听 `127.0.0.1`，由 Cloudflare Tunnel 回源到 `http://127.0.0.1:31880`。

## 状态含义

| 状态 | 含义 |
|---|---|
| `normal` | Token 刷新成功，Graph `/me` 与邮件读取成功 |
| `banned` | 微软返回 service abuse、abuse mode 或账号锁定 |
| `token_invalid` | Refresh Token 无效或过期 |
| `other_error` | 代理、网络或其他 Graph 请求错误 |
| 未测试 | 尚未执行 Graph 测活 |

SQLite 继续使用原 `data/accounts.db`，从旧版升级不需要迁移或清空账号。
