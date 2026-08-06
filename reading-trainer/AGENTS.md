# Reading Trainer 项目硬性规则

本文件对本目录及全部子目录生效。任何 AI、开发者或自动化工具在修改项目之前，都必须先遵守以下约束。

## 数据架构（不可回退）

1. 腾讯服务器上的独立后端数据库 `reading_trainer.db` 是账号、邀请码、班级、设置、收藏、生词、错题、成绩和文章库的唯一主数据源。
2. 飞书多维表格只作为服务器数据的脱敏同步副本。同步必须使用稳定业务键进行幂等新增或更新；不得全表删除重建，不得删除飞书独有记录。
3. 浏览器只允许保存当前页面生命周期内的临时 UI 内存状态。严禁用 `localStorage`、`sessionStorage`、IndexedDB、Cache Storage、可由 JavaScript 写入的持久 Cookie 或前端文件替代服务器数据库。
4. 现有 `localStorage.getItem` / `removeItem` 仅用于一次性旧数据迁移：必须先确认服务器写入成功，再删除旧副本。不得新增浏览器持久化写入。
5. 会话必须由后端使用 `HttpOnly`、`Secure`、`SameSite` Cookie 管理；前端不得读取或保存会话令牌。
6. AI Key、飞书 Token、管理员凭据、密码、密码哈希和 Cookie 只能保存在服务器私有配置或数据库中，不得进入前端、Git、日志或飞书。
7. Reading Trainer 必须继续使用独立的 `reading_trainer.db`；绝对不得读取、覆盖、迁移或删除既有 `resumes.db`。

## 修改业务数据功能时

必须按以下顺序实现：

1. 先定义或修改后端 API 和数据库写入。
2. 再让前端通过 `/reading-trainer/api/v2` 调用后端。
3. 服务器保存成功后，再触发飞书脱敏同步。
4. 服务器失败时必须明确提示失败，不得静默降级成本地保存。
5. 新增数据实体时必须提供稳定业务键，并加入飞书幂等同步与敏感字段过滤测试。

## 禁止顺手修改

- 未经用户明确要求，不得修改登录页的布局、比例、素材、动画或视觉样式。
- 不得把飞书变成身份认证主库或网页直接访问的数据源。
- 不得把腾讯服务器主库降级为浏览器缓存或飞书副本。

## 每次交付前必须验证

```bash
python3 scripts/check_persistence_contract.py
python3 -m pytest -q server/tests
```

还必须在空浏览器环境验证：注册或登录后保存一条业务数据，刷新页面仍能从服务器读取，并确认 `localStorage`、`sessionStorage` 中没有业务数据。涉及生产部署时，先备份 `reading_trainer.db`，再发布；发布后验证飞书重复同步产生 `0 deletes`，且第二次同步不重复创建记录。

当前架构与验收记录以 `DATA-PERSISTENCE-REPORT.md` 为准；`WORKBUDDY_REPORT.md` 和 `REPORT.md` 中标注为历史的 localStorage 描述不得作为当前实现依据。
