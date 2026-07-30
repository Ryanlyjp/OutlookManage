# 部署说明

优先让应用只监听回环地址，例如 `127.0.0.1:31880`，再通过 Tailscale Serve 向 tailnet 提供 HTTPS 访问，避免直接暴露管理 API。

```bash
python3 -m uvicorn backend.main:app --host 127.0.0.1 --port 31880
tailscale serve --bg http://127.0.0.1:31880
```

如需通过 Cloudflare Tunnel 发布，保持 Uvicorn 监听 `127.0.0.1:31880`，并将 Tunnel 的 origin service 指向 `http://127.0.0.1:31880`。不要将应用改为监听 `0.0.0.0` 或服务器公网地址。

管理密码使用 PBKDF2-SHA256 哈希保存在 `config.json` 的 `auth.password_hash`，明文密码不写入仓库。登录会话最长 12 小时；在设置页修改密码后，所有会话立即失效。

当前版本只执行 Graph 测活，不需要浏览器、Playwright、Patchright、IMAP/POP/SMTP 依赖或远程同步配置。
