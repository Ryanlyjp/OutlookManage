# Outlook Graph / IMAP / POP / SMTP Scope 说明

## 1. 当前账号格式属于什么类型
你现在本地保存的格式：

```text
邮箱----密码----client_id----refresh_token
```

这本质上是 **Microsoft identity platform OAuth2 委托授权账号**，核心凭据是：
- `client_id`
- `refresh_token`

它首先天然适用于 **Graph API**。如果同一个 client + user 已经拿到对应 delegated permission，那么也可能继续申请：
- IMAP OAuth token
- POP OAuth token
- SMTP OAuth token

所以它不是“只有 Graph 的死格式”，而是 **以 refresh token 为核心、可继续申请不同 resource / scope 的 OAuth2 账号格式**。

---

## 2. `.default` 和 `offline_access` 是什么

### `.default`
微软官方说明：
- `scope={resource}/.default` 表示向该 resource 请求“当前 client 针对该 resource 已被授予的 delegated permission 集合”
- 如果该用户以前已经同意过部分 delegated permission，那么返回的 access token 会带上这些已授予权限

对你这里来说：

```text
https://graph.microsoft.com/.default
```

表示：
- 向 Microsoft Graph 申请 access token
- 返回当前 `client_id + 当前用户` 已经具备的 Graph delegated permissions

官方文档：
- Microsoft Scopes and permissions: 2025-07-24  
  https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc

### `offline_access`
微软官方说明：
- `offline_access` 用来让应用获得长期访问能力
- 在 v2 endpoint 中，想拿到 refresh token，通常需要显式请求 `offline_access`

所以你的授权流里：

```text
scope=https://graph.microsoft.com/.default offline_access
```

含义就是：
- 申请 Graph 资源访问权限
- 同时请求 refresh token 能力

官方文档：
- Microsoft Scopes and permissions: 2025-07-24  
  https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc

---

## 3. 为什么 Graph token 里会看到 IMAP / POP / SMTP 权限名
本次实测中记录到的 Graph scope 字符串：

```text
https://graph.microsoft.com/.default
https://graph.microsoft.com/IMAP.AccessAsUser.All
https://graph.microsoft.com/Mail.ReadWrite
https://graph.microsoft.com/Mail.Send
https://graph.microsoft.com/POP.AccessAsUser.All
https://graph.microsoft.com/SMTP.Send
https://graph.microsoft.com/User.Read
```

这看起来会让人误以为：
- Graph = 也直接等于 IMAP / POP / SMTP 已全开

但更准确的理解是：

1. 你请求的是 `.default`
2. `.default` 会把当前 **client + user** 已授予的 delegated permissions 一起带回来
3. 所以 token 响应里的 `scope` 字符串可能包含：
   - `Mail.ReadWrite`
   - `Mail.Send`
   - `User.Read`
   - 以及 IMAP / POP / SMTP 相关 permission 名称

这说明：
- 该 client / user 关系上，确实存在这些 permission grant 的痕迹
- **但这不等于传统协议一定已经真正可用**

官方文档：
- Microsoft Scopes and permissions: 2025-07-24  
  https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc
- IMAP/POP/SMTP OAuth  
  https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth

---

## 4. 为什么“看见权限名”不等于协议已经可用
微软对 IMAP / POP / SMTP OAuth 的说明是两层：

1. **先有 OAuth permission / scope**
2. **邮箱侧 / 服务侧还要允许该协议本身**

也就是说，协议真正可用，至少要同时满足：
- OAuth token 可以成功申请
- 协议服务没有被 mailbox policy / 服务端开关禁用

所以会出现这种常见情况：
- Graph token 里能看到 `POP.AccessAsUser.All`
- 但 POP 协议实际仍返回 `This account has POP disabled`

或者：
- 能申请 `SMTP.Send` token
- 但 SMTP 服务仍返回 `SmtpClientAuthentication is disabled for the Mailbox`

这正是你这次账号的真实情况。

官方文档：
- IMAP/POP/SMTP OAuth 说明  
  https://learn.microsoft.com/en-us/exchange/client-developer/legacy-protocols/how-to-authenticate-an-imap-pop-smtp-application-by-using-oauth

---

## 5. 本次账号的实测结论
实测账号：`kwtyusjuyrku@outlook.com`  
代理：`http://127.0.0.1:7890`

### Graph
- `refresh_token -> Graph access token`：成功
- `GET /me`：成功
- `GET /me/messages`：成功
- `POST /me/sendMail`：成功，返回 `202`
- 发给自己后，Graph 轮询确认自发自收成功

结论：
- **Graph 可正常读取和发送邮件**
- 这说明账号本体、refresh token、Graph consent 基本正常

### IMAP
- IMAP OAuth token：申请成功
- 但协议层返回：

```text
User is authenticated but not connected.
```

结论：
- **不是 token 申请失败**
- 而是协议层实际不可用 / 未真正接通

### POP
- POP OAuth token：申请成功
- 协议层明确返回：

```text
This account has POP disabled. Go to the Outlook.com options page to enable POP.
```

结论：
- **POP 当前明确未开启**

### SMTP
- SMTP OAuth token：申请成功
- 协议层明确返回：

```text
535 5.7.139 Authentication unsuccessful, SmtpClientAuthentication is disabled for the Mailbox.
```

结论：
- **SMTP Client Authentication 当前被邮箱侧禁用**

---

## 6. 所以这个账号到底拥有哪些“真实可用能力”
按这次实测，不要只看 scope 名字，要看真正跑通的结果。

### 当前真实可用
- Graph profile
- Graph read mail
- Graph send mail
- Graph 自发自收验证

### 当前不可用 / 未开启
- IMAP：未真正接通
- POP：disabled
- SMTP：mailbox SMTP auth disabled

所以这个账号现在最准确的定位是：

> **Graph 邮箱账号可用，但传统协议能力并没有全开。**

---

## 7. 你的账号是不是“oauth2 / Graph 双令牌账号”
从实操角度看，商家所说的“oauth2 / Graph 双令牌”，往往不是严格的微软官方术语，而是市场表达。

更准确地说，你这类账号是：
- 有 Outlook / Microsoft OAuth2 refresh token
- 可用该 refresh token 继续申请 Graph access token
- 在某些场景下也可申请传统协议的 OAuth token

但是否真能用 IMAP / POP / SMTP，要看：
- consent
- mailbox setting
- protocol policy
- SMTP auth 开关

所以：
- **你的账号当然是 OAuth2 账号**
- **并且 Graph 已实测可用**
- 但不能因为返回了相关 scope，就直接视为 IMAP/POP/SMTP 都可用

---

## 8. Refresh Token 刷新后，远程项目会不会立刻失效
微软官方文档说明：
- refresh token 是围绕 `user + client` 绑定的长期凭据
- 使用 refresh token 获取新 access token 时，通常还会返回新的 refresh token
- 官方建议：拿到新的 refresh token 后应替换保存
- 旧 refresh token **不会因为你刚用了一次就立刻被系统自动撤销**

官方文档：
- Refresh tokens in the Microsoft identity platform（2025-11-05）  
  https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens

这意味着：
- **本地刷新一次 token，不等于远程项目立即彻底失效**
- 但如果本地已经拿到新 refresh token，而远程长期还保存旧 token，远程状态会越来越不稳定

所以你现在做“本地主控”是对的。

---

## 9. 为什么建议“本地为主控，远程为同步目标”
最佳实践是：

1. 本地保存主账号池
2. 本地执行 refresh
3. 本地立刻保存最新 refresh token
4. 标记该账号需要同步远程
5. 再选择：
   - 自动同步远程
   - 手动同步远程

这样可以避免：
- 远程还拿旧 token
- 本地和远程 refresh 时间不一致
- 你无法明确看到每个账号最新刷新时间

---

## 10. 对你当前系统设计的直接结论
如果你的目标是做稳定管理工具，那么当前最合理的判断是：

### 协议定位
- 主能力：**Graph**
- 传统协议：按账号实测单独判断，不预设可用

### 本地数据库建议至少记录
- `last_refresh_at`
- `last_refresh_status`
- `graph_status`
- `imap_status`
- `pop_status`
- `smtp_status`
- `remote_sync_status`

### 操作策略
- 任何 refresh 以本地为准
- 远程 OutlookEmail 作为同步目标 / 消费端
- Graph / IMAP / POP / SMTP 一律做“实测后归档”，而不是靠 scope 名字推断
