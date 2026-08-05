# 新世纪 Reading Trainer

这是从 WorkBuddy 交接版整理出的可维护副本，已重新优化登录页的桌面、竖屏和手机布局。

完整的项目来源、实施过程、功能状态、测试结果和上线风险请查看 [`REPORT.md`](./REPORT.md)。

## 打开

双击 `ielts-toefl-reader.html` 即可使用。主文件仍会读取 `assets/` 中的登录边框和 Logo，移动或发布时请保留目录结构。

## 登录页设计来源

- 整体比例：`/Users/apple/Downloads/完整单画.png`
- 用户视角：`/Users/apple/Downloads/完整单画_副本.png`
- 卡片参考：`/Users/apple/Desktop/新世纪/网页-KIM/名师简介-06.png`
- Illustrator 源稿：`/Users/apple/Desktop/新世纪/网页-KIM/完整单画.ai`

## 注意事项

- 账号、成绩和设置主要保存在浏览器 `localStorage`。
- 管理员凭据仅用于管理员登录，不在其他页面展示；正式部署前请改为安全的后端配置。
- AI 出题和飞书同步涉及跨域网络请求，正式发布时建议改为后端代理。
- `WORKBUDDY_REPORT.md` 是原交接报告，部分文件名和测试账号已过期。

## 验证截图

`output/playwright/` 保存了桌面、竖屏和手机视口的登录与注册截图。
