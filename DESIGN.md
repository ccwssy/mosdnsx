---
version: alpha
name: MosdnsX Panel
description: 单页内嵌 DNS 面板（Go embed + 原生 JS + 手写 CSS）的视觉与性能规范
colors:
  bg: "#f3f5f9"
  bg-card: "#ffffff"
  bg-alt: "#eef1f7"
  text-primary: "#0f172a"
  text-secondary: "#64748b"
  border: "#e2e8f0"
  accent: "#4f46e5"
  accent-hover: "#4338ca"
  accent-contrast: "#ffffff"
  danger: "#ef4444"
  success: "#22c55e"
  warning: "#f59e0b"
  dark-bg: "#0f121a"
  dark-bg-card: "#191e29"
  dark-bg-alt: "#222836"
  dark-text-primary: "#c9d1d9"
  dark-text-secondary: "#8b949e"
  dark-border: "#30363d"
  dark-accent: "#6d9dff"
typography:
  display:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: 2rem
    fontWeight: 700
    lineHeight: 1.2
    letterSpacing: -0.02em
  heading:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: 1.35rem
    fontWeight: 600
    lineHeight: 1.3
  subheading:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: 1.05rem
    fontWeight: 600
    lineHeight: 1.4
  body:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: 0.95rem
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "-apple-system, BlinkMacSystemFont, Segoe UI, Helvetica Neue, Arial, sans-serif"
    fontSize: 0.85rem
    fontWeight: 500
    lineHeight: 1.35
  mono:
    fontFamily: "SFMono-Regular, Consolas, Roboto Mono, monospace"
    fontSize: 0.9rem
    fontWeight: 400
    lineHeight: 1.6
rounded:
  sm: 8px
  md: 12px
  lg: 16px
  xl: 20px
  full: 999px
spacing:
  xs: 0.25rem
  sm: 0.5rem
  md: 0.75rem
  lg: 1rem
  xl: 1.5rem
  2xl: 2rem
  3xl: 2.5rem
gradients:
  start: "#4a90e2"
  mid: "#2e86de"
  end: "#4a90e2"
control:
  bg: "#f0f4f7"
  border: "#d5dce2"
  text: "#5e727e"
  hover-bg: "#e5edf3"
  active-bg: "#4a90e2"
  active-text: "#ffffff"
z-layers:
  base: 0
  content: 1
  sticky-header: 2
  nav-slider: 10
  toast: "1000"
  tooltip: "9999"
  initial-loader: "9999"
components:
  card:
    backgroundColor: "{colors.bg-card}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.lg}"
    padding: "{spacing.xl}"
  button:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-contrast}"
    rounded: "{rounded.sm}"
    padding: "{spacing.md}"
    typography: "{typography.body}"
  input:
    backgroundColor: "{colors.bg-alt}"
    textColor: "{colors.text-primary}"
    rounded: "{rounded.md}"
    height: 40px
  chip:
    backgroundColor: "{colors.bg-alt}"
    textColor: "{colors.text-secondary}"
    rounded: "{rounded.full}"
    typography: "{typography.label}"
  table-cell:
    padding: "{spacing.md}"
    typography: "{typography.body}"
---

## Overview

MosdnsX 面板是家庭 DNS 运维界面：看实时指标、翻查询日志、改规则与开关。使用场景一半是桌面浏览器扫一眼，一半是手机上临时查一条记录。因此规范目标只有两条：**数据先立得住**（数字对齐、层级可读、状态一眼可辨），**界面不掉帧**（低端手机、长时间常开标签页也不该卡）。

视觉上是克制的工具型界面：中性色打底、单一强调色承担全部交互语义、圆角与阴影分级克制。不做装饰性动效，不做全屏背景动画。

## Colors

单强调色 + 中性底。强调色只用于主操作、选中态、链接、关键数值，同一屏不引入第二种强调色。

- **bg / bg-card / bg-alt**：三级中性面。页面底 → 卡片面 → 内嵌区块（输入框、表格斑马纹）依次处理，避免靠边框区分所有层级。
- **text-primary / text-secondary**：正文与元信息两级，不引入第三级文字色。
- **accent**：唯一强调色。`accent-contrast` 只用于强调色底上的文字。
- **danger / success / warning**：仅状态语义（拦截、失败、告警），不做装饰。
- **dark-***：深色模式下同名角色，值不同。主题切换只换变量，不改结构。

## Themes

| 角色 | light | dark |
|---|---|---|
| bg | #f3f5f9 | #0f121a |
| bg-card | #ffffff | #191e29 |
| bg-alt | #eef1f7 | #222836 |
| text-primary | #0f172a | #c9d1d9 |
| text-secondary | #64748b | #8b949e |
| border | #e2e8f0 | #30363d |
| accent | #4f46e5 | #6d9dff |

主题（夜樱/常青/星光/黄昏/赤土）只允许覆盖上述变量值，**不得新增装饰层**：不引入全屏渐变动画、漂浮花瓣/星点伪元素、文字发光阴影。

## Typography

系统字体栈优先，零外部字体请求。

- **display**：页面唯一标题，`letter-spacing` 收紧到 -0.02em。
- **heading / subheading**：卡片标题两级，不出现第三级。
- **body**：正文与表格单元格默认 0.95rem；正文段落不长于一屏宽。
- **label**：元信息、表头、提示文案；表头可大写并加 1px 字距。
- **mono**：域名、规则原文、文件路径、版本号等逐字符对照的场景。

数据规范：**所有数值列、耗时、计数、比率必须 `font-variant-numeric: tabular-nums`**，否则刷新时数字左右跳动。

## Layout

- 页面容器最大宽 1300px（≥1600px 视口放宽到 1500px），左右内距 `2xl`；移动端降到 `lg`。
- 卡片网格用 `repeat(auto-fit, minmax(340px, 1fr))`，间距 `xl`；禁止在网格项内部再嵌自造列宽。
- 纵向节奏只用 `spacing` 刻度（0.25 / 0.5 / 0.75 / 1 / 1.5 / 2 / 2.5 rem），不写 0.85rem、1.15rem 这类非刻度值。
- 断点：768px（移动单列 + 表格转卡片）、992px（网格降列）、1440px（工具条折叠）、1600px（放宽容器）。

## Elevation & Depth

三级阴影，越靠前越接近用户：

- **sm**：卡片静置。
- **md**：悬停、下拉、浮层。
- **lg**：统计卡、弹窗。

阴影之外只用 1px 边框表达层级。**不用 `backdrop-filter` 表达层级**——模糊只允许出现在覆盖整屏的 dialog 遮罩上。

## Shapes

`sm` 8px（按钮、输入框、标签）、`md` 12px（内嵌区块、表头）、`lg` 16px（卡片）、`xl` 20px（统计卡）、`full` 胶囊（chip、开关）。不为单个组件发明新圆角值。

## Components

- **卡片**：`bg-card` + 1px `border` + `lg` 圆角，头部 1.25rem/1.5rem 内距 + 1px 分隔线。悬停只允许边框色与阴影变化。
- **统计卡**：纯色底（accent 或中性深色），不使用渐变、不使用背景图案 SVG，数值 `display` 字号 + `tabular-nums`。
- **按钮**：`primary` 用 accent 实底、`secondary` 用 bg-card + 边框、`danger` 用 danger 实底。高度 ≥40px，移动端可触摸区 ≥44px。
- **输入框 / 下拉**：`bg-alt` 底 + `md` 圆角 + 聚焦时 1px accent 边框 + 3px 半透明 accent 光环。
- **表格**：表头 sticky、大写字距、`bg-alt` 底；斑马纹第二行；数值列右对齐且 `tabular-nums`；移动端 `<768px` 转卡片式。
- **图标按钮**：必须带 `aria-label`；仅图标不带文字时提供 `title`。

## Do's and Don'ts

**Do**

- 交互反馈统一 150ms、`ease-out`，只动 `transform` 与 `opacity`。
- 大列表（>60 行）分批渲染，用 `requestAnimationFrame` 每帧 60 行，并带渲染代号防混写。
- 视口外的长表格容器加 `content-visibility: auto`。
- 全局 `@media (prefers-reduced-motion: reduce)` 停掉全部动画与过渡。
- 空状态给一个明确的下一步动作。

**Don't**

- 不用 `transform: translateY()/scale()` 做卡片或表格行的悬停位移（引发布局抖动、文字模糊、整表重排）。
- 不用全屏无限背景动画（`background-position` 动画、漂浮伪元素）；主题背景必须是静态的。
- 不在卡片、导航、列表上使用 `backdrop-filter`；模糊只留给整屏 dialog 遮罩。
- 不写 `transition: all`，只列具体属性。
- 不给静态元素常驻 `will-change`，仅在动画激活期间设置。
- 不跟随鼠标改 CSS 变量驱动卡片光斑（每次 `mousemove` 触发整卡重绘）。
- 不新增渐变强调色、渐变文字、发光作为主可操作提示。
- 不为同一语义引入第二个 token（如同时存在 `--color-border` 与 `--border-color`）。

## Z-Index 层级刻度

散落的 z-index（1000 / 9999 / 10001 混用）已收敛为固定刻度表。**新增层级必须先在这张表里占一行**，禁止再写 `9999` 这类魔法值；同一层内需要先后时使用 DOM 顺序，不靠调大数字。

| 层级 | 值 | 用途 | 出现位置 |
|---|---|---|---|
| base | 0 | 页面底色、伪元素光斑、装饰层 | `body::before`、`main::before/after`、`.card::before` |
| content | 1 | 正常内容、卡片、导航 | `.container`、`.main-nav a`、`.donut-chart-center-text` |
| sticky-header | 2 | 表格粘性表头 | `.scrollable-table-container thead th` |
| nav-slider | 10 | 顶部导航滑块、页面顶部渐变条 | `.main-nav-slider`、`body::after` |
| toast | 1000 | 轻提示（日志页） | `#toast` |
| tooltip | 9999 | 悬浮提示、初始加载遮罩（提示/遮罩层） | `#answers-tooltip`、`#initial-loader` |
| overlay | 1000 | 弹窗遮罩（首页） | `.modal-overlay` |
| top-tooltip | 10001 | 首页全局提示气泡（高于 toast，避免被遮） | `#global-tooltip` |
| glow-under | -1 | 弹窗呼吸描边，压在弹窗内容之下 | `dialog::after` |

## 动效令牌

交互反馈统一 ≤200ms、进场用 `ease-out`，只动 `transform` 与 `opacity`。

| 令牌 | 值 | 用途 |
|---|---|---|
| `--transition-fast` | 0.15s ease-out | 颜色、边框、阴影、小位移 |
| `--transition-med` | 0.18s ease-out | 导航滑块、状态指示灯 |
| `--transition-slow` | 0.2s ease-out | 主题底色切换 |

令牌只承载**时长与缓动**，属性一律在调用处显式写出；禁止 `transition: all`。

## 渐变与控件令牌

首页 `themeMap` 的语义翻译到日志页时，两侧共用同一组角色名：

| 令牌 | 对应首页变量 | 用途 |
|---|---|---|
| `--gradient-start` | `--gradient-start` | 顶部渐变条、统计卡渐变起点 |
| `--gradient-mid` | `--gradient-mid` | 统计卡渐变中点 |
| `--gradient-end` | `--gradient-end` | 顶部渐变条、统计卡渐变终点 |
| `--control-bg` | `--control-bg` | 输入框 / 下拉 / secondary 按钮底色 |
| `--control-border` | `--control-border` | 控件边框 |
| `--control-text` | `--control-text` | 控件文字 |
| `--control-hover-bg` | `--control-hover-bg` | 控件悬停底色 |
| `--control-active-bg` | `--control-active-bg` | 聚焦边框、主按钮实底 |
| `--control-active-text` | `--control-active-text` | 主按钮文字 |

**渐变只用于 3px 顶部条与统计卡底**，不得扩展到卡片标题、文字、按钮等主操作面（见 Do's and Don'ts）。

## 循环动画白名单

只允许下列循环动画存在，且**必须**同时满足：受 `prefers-reduced-motion: reduce` 关停、离屏时由 `.anim-paused` 暂停。

| 动画 | 位置 | 语义 |
|---|---|---|
| `pulse-small` | `.main-nav a .status-indicator.running` | 抓取运行中状态指示 |
| `spin` | `.refresh-btn[aria-busy="true"] svg`、`#loading-spinner` | 加载中反馈 |
| `skeleton-loading` | `.skeleton` | 骨架屏占位 |

装饰性循环动画（全屏背景位移、漂浮花瓣/星点、渐变扫描）**一律不允许**。
