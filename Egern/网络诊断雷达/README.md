# 网络诊断雷达

Egern 超大号组件（systemExtraLarge）专用的全面网络诊断面板。

## 功能

- **本地网络**：网络名称、本地 IP、网关、直连延迟、IPv4/IPv6、DNS 提供商
- **当前代理**：出口国旗/城市、ISP、出口类型（住宅/机房/云厂商）、纯净度评分仪表盘
- **流媒体解锁**：Netflix / Disney+ / Spotify / TikTok / YouTube / Prime
- **AI 解锁检测**：ChatGPT / Claude / Gemini / DeepSeek / Grok / Perplexity
- **底部信息栏**：ISP、属性类型、纯净评分、风险等级、更新时间

## 使用方法

在 Egern 中添加模块：

```
https://raw.githubusercontent.com/fancha0/egern-mokuai/main/Egern/网络诊断雷达/网络诊断雷达.yaml
```

然后在桌面添加**超大号** Egern 组件，选择「网络诊断雷达」脚本。

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
- 本模块为托管备份，yaml 由 fancha0 编写
