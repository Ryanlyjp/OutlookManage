# Graph 测活说明

测活只执行三步：

1. 使用 `client_id` 和 `refresh_token` 请求 Microsoft consumers Token 端点。
2. 请求 Graph `/me`，确认账号身份并补全邮箱地址。
3. 请求 Graph `/me/messages?$top=1`，确认具备邮件读取能力。

结果分为正常、ABUSE、Token 无效、其他错误和未测试。项目不再调用 IMAP、POP、SMTP、远程账号池或 ABUSE 自动恢复。

批量任务默认并发可在设置页修改，范围为 1–20；`lyjp` 当前建议使用 5，并通过 easyproxy `http://127.0.0.1:2323` 访问微软。
