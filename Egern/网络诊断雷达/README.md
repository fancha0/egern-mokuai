# 网络诊断雷达

Egern 超大号组件（systemExtraLarge）专用的全面网络诊断面板。

## 功能

- **本地网络**：网络名称、本地 IP、网关、直连延迟、IPv4/IPv6、DNS 提供商
- **当前代理**：出口国旗/城市、ISP、出口类型（住宅/机房/云厂商）、纯净度评分仪表盘
- **流媒体解锁**：Netflix / Disney+ / Spotify / TikTok / YouTube / Prime
- **AI 解锁检测**：ChatGPT / Claude / Gemini / Grok
- **底部信息栏**：ISP、属性类型、纯净评分、风险等级、更新时间

## 使用方法

在 Egern 中添加模块：

```
https://raw.githubusercontent.com/fancha0/egern-mokuai/main/Egern/网络诊断雷达/网络诊断雷达.yaml
```

然后在桌面添加**超大号** Egern 组件，选择「网络诊断雷达」脚本。

## AI 检测方式

| 服务 | 检测方式 |
|------|---------|
| ChatGPT | 网页端 + iOS APP 端双探测，识别地区限制与 CF 验证 |
| Gemini | batchexecute 接口获取出口地区（ISO3 映射） |
| Claude | /login 页检测 App unavailable 标记 |
| Grok | 主页 + 地区限制关键字识别 |

## 环境变量

| 变量 | 说明 |
|------|------|
| `POLICY` | 统一策略：指定后所有检测走该策略 |
| `LMT` | 流媒体检测策略组（POLICY 为空时生效） |
| `AI` | AI 检测策略组（POLICY 为空时生效） |
| `YS` | `1` = IP 隐私打码（123.123.*.*） |
| `XY` | 手动指定协议（VLESS / Trojan / HY2 / AnyTLS） |

## 来源

- 上游脚本：https://github.com/lylywayr/NetWork-Module
- AI 精确检测逻辑源自原 ai-connectivity 模块（已合并并移除独立模块）
