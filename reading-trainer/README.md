# 新世纪 Reading Trainer

这是从 WorkBuddy 交接版整理出的可维护版本，已完成登录页优化和服务器化数据改造。

当前数据架构和验收结果以 [`DATA-PERSISTENCE-REPORT.md`](./DATA-PERSISTENCE-REPORT.md) 为准；历史设计过程可查看 [`REPORT.md`](./REPORT.md)。

## 打开

正式使用地址为 `https://kimdu.site/reading-trainer/`。直接双击 `ielts-toefl-reader.html` 只能查看前端页面，账号和业务功能仍依赖腾讯服务器 `/reading-trainer/api/v2`，不能把本地文件当成完整生产系统。

## 登录页设计来源

- 整体比例：`/Users/apple/Downloads/完整单画.png`
- 用户视角：`/Users/apple/Downloads/完整单画_副本.png`
- 卡片参考：`/Users/apple/Desktop/新世纪/网页-KIM/名师简介-06.png`
- Illustrator 源稿：`/Users/apple/Desktop/新世纪/网页-KIM/完整单画.ai`

## 数据保存规则（不可回退）

- 腾讯服务器独立数据库 `reading_trainer.db` 是唯一主库。
- 飞书多维表格是脱敏、幂等、非破坏性的同步副本，不是网页直连数据库。
- 浏览器不保存账号、会话或业务数据；`localStorage` 只允许读取并清理一次性旧数据。
- AI Key、飞书 Token 和管理员凭据只保存在服务器私有配置中。
- Reading Trainer 不得使用或改动原项目的 `resumes.db`。
- 未经用户明确要求，不修改已经验收的登录页视觉。

未来任何改动先阅读 [`AGENTS.md`](./AGENTS.md)，并运行：

```bash
python3 scripts/check_persistence_contract.py
python3 -m pytest -q server/tests
```

每次腾讯服务器上的宿主 `app.py` 更新或重启后，还必须运行：

```bash
python3 scripts/check_production_health.py
```

该检查会同时验证正式网页和 `/reading-trainer/api/v2/bootstrap`。如果接口返回
404，说明宿主程序遗漏了 `register_reading_trainer_v2(app)`，不能把这次部署视为成功。

`WORKBUDDY_REPORT.md` 和 `REPORT.md` 中关于 localStorage 的段落属于改造前历史记录，不能作为当前架构依据。

## 验证截图

`output/playwright/` 保存了桌面、竖屏和手机视口的登录与注册截图。
