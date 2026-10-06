# 网络信息（Egern 模块）

Egern 小组件：国内 / 落地双 IP 信息面板。灵感来自 Surge 模块「网络信息 𝕏」（[xream/scripts](https://github.com/xream/scripts)，GPL-3.0）。

## 功能

- **国内 IP**：bilibili / ipip / ip233 三源自动兜底（全部直连查询）
- **落地 IP**：ipwho.is / ip-api 双源自动兜底
- 每条含：位置、运营商，可选 ASN / ORG
- 国旗 emoji（可关）
- LAN IP、网关、网络接口、IPv6、DNS（来自 Egern 设备信息，不额外发请求）
- 大号组件额外展示：Wi-Fi 名称、蜂窝运营商/制式、查询来源与策略路径
- IP 隐私打码：`123.123.123.123` → `123.123.*.*`
- iOS 26 液态玻璃风格（与网络诊断雷达同款）

## 安装

Egern 模块链接：

```
https://raw.githubusercontent.com/fancha0/egern-mokuai/main/Egern/网络信息/网络信息.yaml
```

## 参数

| 变量 | 默认 | 说明 |
|------|------|------|
| DOMESTIC | bilibili | 国内 IP 首选来源（ipip / ip233 自动兜底） |
| LANDING | ipwhois | 落地 IP 首选来源（ipapi 自动兜底） |
| POLICY | 空 | 落地查询走的策略组，留空走默认规则 |
| DIRECT | DIRECT | 国内查询的直连策略名 |
| FLAG | 1 | 国旗显示 |
| ASN / ORG | 0 | 显示 ASN / ORG |
| YS | 0 | IP 打码 |
| LAN | 1 | 本机 IP、网关、网络接口 |
| IPv6 | 0 | IPv6 地址 |
| DNS | 1 | 大号显示 DNS 服务器 |
| SSID | 0 | 大号显示 Wi-Fi 名称（公开截图建议关闭） |

## 尺寸布局

- **systemMedium**：国内 / 落地双卡片 + 本机 IP
- **systemLarge**：国内 / 落地双卡片 + 本机网络详情 + 查询路径
- **systemExtraLarge**：完整信息布局
- 锁屏小组件也有对应的精简布局

## 文件

- `网络信息.js` — 组件脚本
- `网络信息.yaml` — 模块定义

## 备注

- 刷新间隔 30 分钟（脚本内 `refreshAfter`），模块更新检查 12 小时
- 上游如不可用会显示「查询失败」，不会阻塞另一条
