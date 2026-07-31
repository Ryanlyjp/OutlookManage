# OTP 接码与分享 API

## 邮件范围

邮件读取明确查询 Microsoft Graph 的 `inbox` 与 `junkemail` 两个目录，合并后按 `receivedDateTime` 倒序排列。读取邮件返回最新 5 封；提取 OTP 严格只检查全局最新一封，最新邮件没有验证码时返回 404，不向前搜索旧邮件。

接码页面可以输入账号池已有邮箱，或临时输入：

```text
邮箱----密码----Client ID----Refresh Token
```

临时凭据不保存到账号池，也不写入应用日志。

## 全局 API

在受管理密码保护的设置页可以查看、复制或修改全局 API Key。鉴权推荐使用：

```http
Authorization: Bearer <GLOBAL_API_KEY>
```

兼容查询参数 `?api_key=<GLOBAL_API_KEY>`，但查询参数可能进入代理访问日志。

按邮箱查找：

```http
GET /api/mailboxes/lookup?address=user@outlook.com
```

获取该邮箱最新邮件 OTP：

```http
GET /api/mailboxes/{account_id}/otp/latest
GET /api/mailboxes/{account_id}/otp/latest?format=text
```

## 分享页面和分享级 API

设置页从账号池选择邮箱创建分享。一个邮箱只能有一个分享；有效期单位为天，`0` 表示永久。分享支持停用、删除以及同时重新生成页面 Token 和分享 API Key。

分享 API Key 只允许读取绑定邮箱：

```http
GET /api/otp-share/latest
GET /api/otp-share/latest?format=text
GET /api/otp-share/emails
GET /api/otp-share/emails/{message_id}
GET /api/otp-share/emails/{message_id}/otp
GET /api/otp-share/emails/{message_id}/attachments/{attachment_id}
Authorization: Bearer <SHARE_API_KEY>
```

分享页面 URL 为：

```text
/otp-share/{page_token}
```

页面允许读取最新 5 封邮件、完整正文、提取 OTP 和下载真实文件附件。HTML 邮件在无脚本权限的 sandbox iframe 中显示。当前附件下载仅支持 Microsoft Graph `fileAttachment`；嵌入 Outlook 项目或云端引用附件会返回不支持提示。
