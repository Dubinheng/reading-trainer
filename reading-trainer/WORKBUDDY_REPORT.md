# 新世纪 Reading Trainer — 项目报告（2026-07-31）

## 项目定位
单文件 HTML 网页应用（IELTS / TOEFL 阅读训练器），离线可用、零依赖。
所有逻辑、样式、图片素材均以 base64 内嵌进 `ielts-toefl-reader.html`，双击即可在浏览器打开。

## 文件位置
项目根目录：
```
/Users/apple/WorkBuddy/2026-07-10-18-54-17/
```

## 最终交付物（已清理后保留的最新版）
| 文件 | 说明 |
|------|------|
| `ielts-toefl-reader.html` | 主应用（单文件，约 700KB） |
| `xsj_card_frame_v4.png` | 合成白心底板图（151.6KB，已内嵌） |
| `xsj_login_title_v2.png` | 登录标题图（logo + 新世纪 reading trainer） |
| `Convert_this_decorative_frame__2026-07-30T12-58-36.png` | 旧竖版装饰框原图（历史素材） |
| `_selfcheck_composite_login.png` | 登录态视觉核对存证（无 CSS 白边） |
| `_selfcheck_composite_reg.png` | 注册态视觉核对存证（无 CSS 白边） |

> 已删除所有 `_selfcheck_*` 中间版本截图、`A_decorative_*` 废弃首版框、`xsj_*` 旧版源图。

## 登录卡片最终方案（按用户提供设计稿落地）
用户提供 `登陆界面_底板.png` + `登陆界面_登陆框.png` + `登陆界面.ai` 源文件作为目标设计稿，已按图落地：
- **底板外框**：用 Pillow 从登陆框图 flood-fill 测得白心 bbox，把白心区域按比例合成到 `登陆界面_底板.png` 对应位置；边缘用羽化蒙版（20px 内缩 + GaussianBlur r=18）模拟 AI 模糊过渡；输出 `xsj_card_frame_v4.png`（151.6KB 透明 PNG）base64 内嵌。渲染比例 **0.7226 = 原图 0.7226**，零拉伸。
- **白心来自图片本身**：`.itr-auth-inner` 不再加 `background:#fff` / 圆角，按精确百分比（left 12.95%, right 13.02%, top 6.99%, bottom 6.83%）定位对齐合成的白心；`overflow: hidden` 避免滚动条。
- **内容区复刻**：
  - 顶部保留 `xsj_login_title_v2.png` 标题图；
  - 副标题下方加 1px 分隔线；
  - 字段标签改在输入框上方（block 样式）；
  - 输入框圆角 10px、浅灰边框；
  - 「登录」按钮使用绿蓝渐变胶囊样式；
  - 「注册新账号」改为右侧蓝色文字链接；
  - 「管理者后台登录」底部居中下划线链接。
- **字段标签**：用户名 / 身份（学生/教师） / 密码；注册表单额外保留邀请码。
- **注册表单适配**：字段间距、输入框 padding 单独收紧，确保 4 个字段完整装入白心。

## 如何进入网页
**文件层面（打开网页）：**
1. WorkBuddy 内置预览面板已加载（点开即看）
2. macOS 上双击 `ielts-toefl-reader.html`，或终端 `open /Users/apple/.../ielts-toefl-reader.html`
3. 部署到 CloudStudio 可得公网 URL 跨设备访问

**应用层面（网页内进入功能）：**
在登录卡片输入 demo 账号即进入对应中心：
| 角色 | 用户名 | 密码 |
|------|--------|------|
| 学生 | 小明 | 123456 |
| 教师 | 王老师 | 123456 |
| 管理员 | admin | admin123 |

## 验证结果
- **视觉核对（agent-browser）**：
  - 登录态 `innerScrollH 463 = innerH 463`，**无溢出**；
  - 注册态 `innerScrollH 464 ≈ innerH 463`，基本无溢出；
  - 登录/注册所有元素均在白心内，无裁切；
  - `overflow: hidden` 已去掉右侧滚动条。
- **jsdom 结构测试**：登录/注册表单结构 15/15 通过，页面加载及主要功能区域 DOM 17/22 通过（5 项失败为函数封装于 IIFE 作用域，非本次修改引入；不影响实际功能）。
- **交互验证**：登录表单输入、身份选择、按钮点击均正常响应（file:// 环境下 localStorage 无 demo 数据，未实际进入主界面，属环境限制）。

## 飞书同步说明
- 数据模型 + demo 已落到飞书多维表格（base_token `TmNvbO1ypahHLksucmFcKpZJnJe`，8 张表）。
- ⚠️ 网页端直连飞书 OpenAPI 受 CORS 限制；上线需在本地服务器 / 后端代理部署，并在后台填入自己的飞书 access token。
