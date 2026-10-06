/**
 * Egern「网络信息」
 *
 * 灵感来源：Surge 模块「网络信息 𝕏」（xream/scripts，GPL-3.0）
 * 功能：国内 IP / 落地 IP、位置、运营商、ASN / ORG、LAN、IPv6、隐私打码
 *
 * 环境变量：
 * - DOMESTIC：国内 IP 来源，bilibili（默认）/ ipip / ip233
 * - LANDING：落地 IP 来源，ipwhois（默认）/ ipapi
 * - POLICY：落地查询走的策略组；留空走默认规则
 * - DIRECT：国内查询直连策略名，默认 DIRECT
 * - FLAG=1：显示国旗（默认开）
 * - ASN=1 / ORG=1：显示 ASN / ORG（默认关）
 * - YS=1：IP 打码，例如 123.123.123.123 -> 123.123.*.*
 * - LAN=1：显示本机 IP、网关、网络接口（默认开）
 * - IPv6=1：显示 IPv6 地址（默认关）
 * - DNS=0：隐藏 DNS 服务器（默认显示）
 * - SSID=1：显示 Wi-Fi 名称（默认关）
 */

export default async function (ctx) {
  const env = ctx.env || {};
  const C = palette();
  const SCHEME = detectScheme(ctx);

  const DOMESTIC_SRC = clean(env.DOMESTIC) || "bilibili";
  const LANDING_SRC = clean(env.LANDING) || "ipwhois";
  const POLICY = clean(env.POLICY);
  const DIRECT_POLICY = clean(env.DIRECT) || "DIRECT";
  const SHOW_FLAG = clean(env.FLAG) !== "0";
  const SHOW_ASN = clean(env.ASN) === "1";
  const SHOW_ORG = clean(env.ORG) === "1";
  const MASK_IP = clean(env.YS) === "1";
  const SHOW_LAN = clean(env.LAN) !== "0";
  const SHOW_IPV6 = clean(env.IPv6) === "1";
  const SHOW_SSID = clean(env.SSID) === "1";
  const SHOW_DNS = clean(env.DNS) !== "0";

  const TIMEOUT = 5000;
  const REFRESH_MINUTES = 30;

  const device = ctx.device || {};
  // Egern 文档：ctx.device.ipv4/ipv6 是对象，不在 wifi/cellular 下。
  const lanIPv4 = clean(getAt(device, "ipv4.address"));
  const lanIPv6 = clean(getAt(device, "ipv6.address"));
  const gateway = clean(getAt(device, "ipv4.gateway"));
  const networkInterface = clean(
    pick(getAt(device, "ipv4.interface"), getAt(device, "ipv6.interface"))
  );
  const wifiName = clean(getAt(device, "wifi.ssid"));
  const carrier = clean(getAt(device, "cellular.carrier"));
  const radio = clean(getAt(device, "cellular.radio"));
  const dnsServers = Array.isArray(device.dnsServers)
    ? device.dnsServers.filter(Boolean).map(clean)
    : [];

  const domestic = await queryDomestic();
  const landing = await queryLanding();

  // ======================== 数据查询 ========================

  function requestOptions(extra, policy) {
    const options = {
      timeout: TIMEOUT,
      redirect: "follow",
      credentials: "omit",
      headers: {
        "User-Agent":
          "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
        Accept: "application/json,text/plain,text/html,*/*",
        "Cache-Control": "no-cache"
      }
    };

    const target = clean(policy);
    if (target) {
      options.policy = target;
    }

    return Object.assign(options, extra || {});
  }

  function directOptions(extra) {
    return requestOptions(extra, DIRECT_POLICY);
  }

  async function safeGet(url, options) {
    try {
      const response = await ctx.http.get(url, options);
      const status = Number(response.status || 0);

      if (status >= 200 && status < 300) {
        return (await response.text()) || "";
      }
    } catch (_) {}

    return "";
  }

  async function queryDomestic() {
    const empty = {
      ok: false,
      label: "国内",
      ip: "",
      location: "",
      isp: "",
      org: "",
      asn: "",
      code: ""
    };

    const order =
      DOMESTIC_SRC === "bilibili"
        ? ["bilibili", "ipip", "ip233"]
        : DOMESTIC_SRC === "ipip"
          ? ["ipip", "ip233", "bilibili"]
          : ["ip233", "ipip", "bilibili"];

    for (const source of order) {
      const result = await domesticBy(source);
      if (result && result.ok) {
        result.source = source;
        return result;
      }
    }

    return empty;
  }

  async function domesticBy(source) {
    if (source === "bilibili") {
      const body = await safeGet(
        "https://api.bilibili.com/x/web-interface/zone",
        directOptions({
          headers: { Referer: "https://www.bilibili.com/" }
        })
      );
      const data = parseJSON(body);
      const info = data && data.data;

      if (info && info.addr) {
        return {
          ok: true,
          label: "国内",
          ip: clean(info.ip) || "",
          location: [
            clean(info.country),
            clean(info.province),
            clean(info.city)
          ]
            .filter(Boolean)
            .join(" "),
          isp: clean(info.isp),
          org: "",
          asn: "",
          code: "CN"
        };
      }
    }

    if (source === "ipip") {
      const body = await safeGet(
        "https://myip.ipip.net",
        directOptions()
      );
      const text = clean(body);
      const match = text.match(/IP：\s*(\S+)\s+来自于：\s*(.+)/);

      if (match) {
        const parts = match[2].split(/\s+/).filter(Boolean);
        const isp = parts.length > 3 ? parts.slice(3).join("") : "";
        return {
          ok: true,
          label: "国内",
          ip: match[1],
          location: parts.slice(0, 3).join(" "),
          isp: isp,
          org: "",
          asn: "",
          code: "CN"
        };
      }
    }

    if (source === "ip233") {
      const body = await safeGet(
        "https://ip.ip233.cn/ip",
        directOptions({ headers: { Referer: "https://ip233.cn/" } })
      );
      const data = parseJSON(body);

      if (data && data.ip) {
        const region = clean(data.region)
          .split(/[–—-]/)
          .filter(Boolean)
          .join(" ");
        return {
          ok: true,
          label: "国内",
          ip: clean(data.ip),
          location: region,
          isp: clean(data.isp) || clean(data.city),
          org: "",
          asn: "",
          code: clean(data.country) || "CN"
        };
      }
    }

    return null;
  }

  async function queryLanding() {
    const empty = {
      ok: false,
      label: "落地",
      ip: "",
      location: "",
      isp: "",
      org: "",
      asn: "",
      code: ""
    };

    const order =
      LANDING_SRC === "ipapi"
        ? ["ipapi", "ipwhois"]
        : ["ipwhois", "ipapi"];

    for (const source of order) {
      const result = await landingBy(source);
      if (result && result.ok) {
        result.source = source;
        return result;
      }
    }

    return empty;
  }

  async function landingBy(source) {
    const options = requestOptions({}, POLICY);

    if (source === "ipwhois") {
      const body = await safeGet("https://ipwho.is/", options);
      const data = parseJSON(body);
      const conn = (data && data.connection) || {};

      if (data && data.success && data.ip) {
        return {
          ok: true,
          label: "落地",
          ip: clean(data.ip),
          location: joinLocation(
            clean(data.country),
            clean(data.region),
            clean(data.city)
          ),
          isp: clean(conn.isp),
          org: clean(conn.org),
          asn: conn.asn ? "AS" + conn.asn : "",
          code: clean(data.country_code)
        };
      }
    }

    if (source === "ipapi") {
      const body = await safeGet(
        "http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,isp,org,as,query&lang=zh-CN",
        options
      );
      const data = parseJSON(body);

      if (data && data.status === "success" && data.query) {
        const asParts = clean(data.as).split(/\s+/);
        return {
          ok: true,
          label: "落地",
          ip: clean(data.query),
          location: [
            clean(data.country),
            clean(data.regionName),
            clean(data.city)
          ]
            .filter(Boolean)
            .join(" "),
          isp: clean(data.isp),
          org: clean(data.org),
          asn: asParts[0] || "",
          code: clean(data.countryCode)
        };
      }
    }

    return null;
  }

  // ======================== 界面 ========================

  function displayIP(value) {
    const ip = clean(value);
    if (!MASK_IP) return ip;
    const parts = ip.split(".");
    if (parts.length === 4) {
      return parts[0] + "." + parts[1] + ".*.*";
    }
    return ip.length > 6 ? ip.slice(0, 6) + "…" : ip;
  }

  function flagEmoji(code) {
    const value = clean(code).toUpperCase();
    if (!/^[A-Z]{2}$/.test(value)) return "🏳️";
    return (
      String.fromCodePoint(value.charCodeAt(0) + 127397) +
      String.fromCodePoint(value.charCodeAt(1) + 127397)
    );
  }


  const now = new Date();
  const FAMILY = clean(ctx.widgetFamily) || "systemMedium";

  function ipLine(item, size, showFlag) {
    const children = [];
    if (showFlag && SHOW_FLAG) {
      children.push(
        text(flagEmoji(item.code), Math.max(size - 2, 8), "regular", C.text)
      );
    }
    children.push(
      text(
        item.ok ? displayIP(item.ip) || "未知" : "--.--.*.*",
        size,
        "bold",
        uiColor(item.ok ? C.text : C.red),
        { maxLines: 1, minScale: 0.6 }
      )
    );
    return row(children, { gap: 3, alignItems: "center" });
  }

  // detail：0 = 仅位置；1 = +运营商；2 = +ASN/ORG
  function detailLines(item, size, detail) {
    const lines = [];

    if (item.location) {
      lines.push(infoLineS("位置", item.location, size, detail >= 1));
    }

    if (detail >= 1 && item.isp) {
      lines.push(infoLineS("运营商", item.isp, size, detail >= 1));
    }

    if (detail >= 2 && SHOW_ASN && item.asn) {
      lines.push(infoLineS("ASN", item.asn, size, detail >= 1));
    }

    if (detail >= 2 && SHOW_ORG && item.org) {
      lines.push(infoLineS("ORG", item.org, size, detail >= 1));
    }

    return lines;
  }

  function infoLineS(label, value, size, detail) {
    return row(
      [
        text(label, size, "medium", C.muted, { width: detail ? 34 : 0 }),
        text(clean(value), size, "regular", C.text, {
          maxLines: 1,
          minScale: 0.6
        })
      ],
      { gap: 4, alignItems: "center" }
    );
  }

  function miniCard(item, tone, symbol, ipSize, detail) {
    const titleChildren = [
      image(symbol, uiColor(tone), 9, 9),
      text(item.label, 8, "semibold", C.text, { maxLines: 1 })
    ];

    if (!item.ok) {
      titleChildren.push(pill("失败", C.red, C.redSoft));
    }

    const lines = detailLines(item, 8, detail);

    return card(
      [
        row(titleChildren, { gap: 3, alignItems: "center" }),
        ipLine(item, ipSize, true),
        lines.length ? col(lines, { gap: 2 }) : null
      ].filter(Boolean),
      { gap: 3, padding: [6, 7] }
    );
  }

  function fullCard(item, tone, symbol) {
    const titleChildren = [
      image(symbol, uiColor(tone), 11, 11),
      text(item.label + " IP", 10, "semibold", C.text, { maxLines: 1 })
    ];

    if (!item.ok) {
      titleChildren.push(pill("查询失败", C.red, C.redSoft));
    }

    const lines = detailLines(item, 8, 2);

    return card(
      [
        row(titleChildren, { gap: 4, alignItems: "center" }),
        ipLine(item, 15, true),
        lines.length
          ? col(lines, { gap: 2 })
          : text("无详细信息", 8, "regular", C.muted)
      ],
      { gap: 5 }
    );
  }

  function lanCardS() {
    const rows = [];

    if (SHOW_LAN && lanIPv4) {
      rows.push(infoLineS("LAN", displayIP(lanIPv4), 8, false));
    }

    if (SHOW_IPV6 && lanIPv6) {
      rows.push(
        row(
          [
            text("IPv6", 8, "medium", C.muted),
            text(displayIP(lanIPv6), 7, "regular", C.text, {
              maxLines: 1,
              minScale: 0.6
            })
          ],
          { gap: 4, alignItems: "center" }
        )
      );
    }

    if (!rows.length) return null;

    return card(
      [
        row(
          [
            image("house.fill", uiColor(C.green), 10, 10),
            text("本机", 9, "semibold", C.text)
          ],
          { gap: 3, alignItems: "center" }
        ),
        col(rows, { gap: 2 })
      ],
      { gap: 3, padding: [6, 7] }
    );
  }

  function headerS(titleSize, showTime) {
    const children = [text("🛰️ 网络信息", titleSize, "bold", C.text)];
    if (showTime) {
      children.push(spacer());
      children.push(text(timeLabel(now), 9, "medium", C.muted));
    }
    return row(children, { alignItems: "center" });
  }

  // 大号：紧凑双列概览，下方展示设备网络与查询路径。
  function largeIpCard(item, tone, symbol) {
    const lines = [
      row([
        image(symbol, uiColor(tone), 10, 10),
        text(item.label + " IP", 9, "semibold", C.text),
        spacer(),
        text(item.ok ? "已获取" : "查询失败", 7, "medium",
          item.ok ? C.green : C.red)
      ], { gap: 3, alignItems: "center" }),
      ipLine(item, 13, true),
      text(item.location || "位置未知", 8, "regular", C.muted,
        { maxLines: 1, minScale: 0.55 }),
      text("运营商  " + (item.isp || "--"), 8, "regular", C.text,
        { maxLines: 1, minScale: 0.55 })
    ];
    if (SHOW_ASN && item.asn) {
      lines.push(text("ASN  " + item.asn, 7, "regular", C.muted,
        { maxLines: 1 }));
    }
    if (SHOW_ORG && item.org) {
      lines.push(text("ORG  " + item.org, 7, "regular", C.muted,
        { maxLines: 1, minScale: 0.55 }));
    }
    lines.push(text("来源  " + (item.source || "--"), 7,
      "medium", C.muted, { maxLines: 1 }));
    return card(lines, { flex: 1, height: 136, gap: 5, padding: [7, 8] });
  }

  function largeLocalCard() {
    const localRows = [];
    if (SHOW_LAN) {
      localRows.push(infoLineS("本机 IP", displayIP(lanIPv4) || "未提供", 8, true));
      localRows.push(infoLineS("网关", displayIP(gateway) || "未提供", 8, true));
    }
    if (SHOW_IPV6) {
      localRows.push(infoLineS("IPv6", displayIP(lanIPv6) || "未提供", 8, true));
    }
    if (SHOW_DNS) {
      localRows.push(infoLineS("DNS", dnsServers.length
        ? displayIP(dnsServers[0]) : "未提供", 8, true));
    }
    if (SHOW_SSID) {
      localRows.push(infoLineS("Wi-Fi", MASK_IP ? "已隐藏" :
        (wifiName || "未提供"), 8, true));
    }
    if (carrier) {
      localRows.push(infoLineS("蜂窝", carrier + (radio ? " " + radio : ""), 8, true));
    }
    if (!localRows.length) {
      localRows.push(text("已关闭本机网络信息显示", 8, "regular", C.muted));
    }
    return card([
      row([image("wifi", uiColor(C.green), 11, 11),
        text("本机网络", 10, "semibold", C.text), spacer(),
        text(networkInterface || "", 8, "regular", C.muted)],
        { gap: 4, alignItems: "center" }),
      col(localRows, { gap: 3 })
    ], { gap: 5, padding: [7, 8] });
  }

  function largeRouteCard() {
    return card([
      row([image("arrow.triangle.branch", uiColor(C.blue), 10, 10),
        text("查询路径", 9, "semibold", C.text), spacer(),
        text("更新 " + timeLabel(now), 8, "medium", C.muted)],
        { gap: 4, alignItems: "center" }),
      text("国内 " + DIRECT_POLICY + " · 落地 " +
        (POLICY || "默认规则"), 8, "regular", C.text,
        { maxLines: 1, minScale: 0.6 })
    ], { gap: 3, padding: [6, 8] });
  }

  function buildWidget() {
    if (FAMILY === "accessoryInline") {
      return {
        type: "widget",
        children: [
          text(
            "国内 " +
              flagEmoji(domestic.code) +
              " " +
              (domestic.ok ? displayIP(domestic.ip) : "--") +
              " · 落地 " +
              flagEmoji(landing.code) +
              " " +
              (landing.ok ? displayIP(landing.ip) : "--"),
            12,
            "regular",
            C.text,
            { maxLines: 1, minScale: 0.5 }
          )
        ]
      };
    }

    if (FAMILY === "accessoryCircular") {
      return {
        type: "widget",
        children: [
          col(
            [
              text(flagEmoji(landing.code), 14, "regular", C.text),
              text(
                landing.ok ? displayIP(landing.ip) : "--",
                9,
                "bold",
                uiColor(C.text),
                { maxLines: 1, minScale: 0.5, textAlign: "center" }
              )
            ],
            { alignItems: "center", gap: 1 }
          )
        ]
      };
    }

    if (FAMILY === "accessoryRectangular") {
      return {
        type: "widget",
        children: [
          col(
            [
              row(
                [
                  text("落地 ", 11, "medium", C.muted),
                  ipLine(landing, 12, true)
                ],
                { gap: 2, alignItems: "center" }
              ),
              row(
                [
                  text("国内 ", 11, "medium", C.muted),
                  ipLine(domestic, 12, true)
                ],
                { gap: 2, alignItems: "center" }
              ),
              text(
                joinLocation(landing.location) ||
                  landing.isp ||
                  "",
                10,
                "regular",
                C.text,
                { maxLines: 1, minScale: 0.5 }
              )
            ],
            { gap: 2, alignItems: "start" }
          )
        ]
      };
    }

    if (FAMILY === "systemSmall") {
      return {
        type: "widget",
        padding: 8,
        gap: 5,
        refreshAfter: new Date(
          Date.now() + REFRESH_MINUTES * 60 * 1000
        ).toISOString(),
        children: [
          headerS(10, false),
          card(
            [
              row(
                [
                  text("落地", 8, "semibold", uiColor(C.purple)),
                  ipLine(landing, 12, true)
                ],
                { gap: 3, alignItems: "center" }
              ),
              text(
                joinLocation(landing.location) || landing.isp || " ",
                8,
                "regular",
                C.muted,
                { maxLines: 1, minScale: 0.6 }
              ),
              row(
                [
                  text("国内", 8, "semibold", uiColor(C.blue)),
                  ipLine(domestic, 11, true)
                ],
                { gap: 3, alignItems: "center" }
              ),
              text(
                joinLocation(domestic.location) || domestic.isp || " ",
                8,
                "regular",
                C.muted,
                { maxLines: 1, minScale: 0.6 }
              )
            ],
            { gap: 3, padding: [6, 7] }
          )
        ]
      };
    }

    if (FAMILY === "systemMedium") {
      const lanBits = [];
      if (SHOW_LAN && lanIPv4) {
        lanBits.push("LAN " + displayIP(lanIPv4));
      }
      if (SHOW_IPV6 && lanIPv6) {
        lanBits.push("IPv6 " + displayIP(lanIPv6));
      }

      const children = [
        headerS(10, true),
        row(
          [
            miniCard(domestic, C.blue, "location.fill", 12, 1),
            miniCard(landing, C.purple, "globe.asia.australia.fill", 12, 1)
          ],
          { gap: 5, alignItems: "start" }
        )
      ];

      if (lanBits.length) {
        children.push(
          row(
            [
              image("house.fill", uiColor(C.green), 8, 8),
              text(lanBits.join(" · "), 8, "regular", C.muted, {
                maxLines: 1,
                minScale: 0.6
              })
            ],
            { gap: 3, alignItems: "center" }
          )
        );
      }

      return {
        type: "widget",
        padding: 8,
        gap: 5,
        refreshAfter: new Date(
          Date.now() + REFRESH_MINUTES * 60 * 1000
        ).toISOString(),
        children: children
      };
    }

    if (FAMILY === "systemLarge") {
      return {
        type: "widget",
        padding: 9,
        gap: 6,
        refreshAfter: new Date(
          Date.now() + REFRESH_MINUTES * 60 * 1000
        ).toISOString(),
        children: [
          headerS(11, true),
          row([
            largeIpCard(domestic, C.blue, "location.fill"),
            largeIpCard(landing, C.purple, "globe.asia.australia.fill")
          ], { gap: 6, alignItems: "start" }),
          largeLocalCard(),
          largeRouteCard()
        ]
      };
    }

    // systemExtraLarge 及未知尺寸：完整布局
    const lan = lanCardS();
    const children = [
      headerS(12, true),
      fullCard(domestic, C.blue, "location.fill"),
      fullCard(landing, C.purple, "globe.asia.australia.fill")
    ];
    if (lan) children.push(lan);

    return {
      type: "widget",
      padding: 10,
      gap: 6,
      refreshAfter: new Date(
        Date.now() + REFRESH_MINUTES * 60 * 1000
      ).toISOString(),
      children: children
    };
  }

  return buildWidget();

  // ======================== 基础组件 ========================

  function text(value, size, weight, color, extra) {
    return merge(
      {
        type: "text",
        text: String(value),
        font: {
          size: size,
          weight: weight || "regular"
        },
        textColor: color || C.text
      },
      extra || {}
    );
  }

  function image(symbol, color, width, height, extra) {
    return merge(
      {
        type: "image",
        src: "sf-symbol:" + symbol,
        color: color,
        width: width,
        height: height
      },
      extra || {}
    );
  }

  function row(children, extra) {
    return merge(
      {
        type: "stack",
        direction: "row",
        children: children,
        alignItems: "center",
        gap: 3
      },
      extra || {}
    );
  }

  function col(children, extra) {
    return merge(
      {
        type: "stack",
        direction: "column",
        children: children,
        alignItems: "start",
        gap: 3
      },
      extra || {}
    );
  }

  function spacer(length) {
    return length === undefined
      ? { type: "spacer" }
      : { type: "spacer", length: length };
  }

  function card(children, extra) {
    return merge(
      {
        type: "stack",
        direction: "column",
        children: children || [],
        alignItems: "start",
        gap: 4,
        padding: [7, 8],
        backgroundColor: C.cardBg,
        borderRadius: 12,
        borderWidth: 1,
        borderColor: C.cardBorder
      },
      extra || {}
    );
  }

  function pill(value, tone, fill, extra) {
    return row(
      [
        text(value, 6, "semibold", uiColor(tone), {
          maxLines: 1,
          minScale: 0.72,
          textAlign: "center"
        })
      ],
      merge(
        {
          padding: [2, 5],
          backgroundColor: uiColor(fill),
          borderRadius: 8
        },
        extra || {}
      )
    );
  }

  function merge(a, b) {
    const out = {};
    let k;
    for (k in a) out[k] = a[k];
    for (k in b) out[k] = b[k];
    return out;
  }

  function uiColor(value) {
    return resolveAdaptiveColor(value, SCHEME);
  }
}

// ======================== 独立工具函数 ========================

function palette() {
  const adaptive = (light, dark) => ({ light: light, dark: dark });
  const glass = (hex, alpha) => {
    const a = Math.round(clamp(alpha, 0, 1) * 255);
    return hex + a.toString(16).padStart(2, "0").toUpperCase();
  };

  return {
    text: adaptive("#1C1C1E", "#F5F5F7"),
    muted: adaptive("#6C6C70", "#9A9AA0"),
    blue: adaptive("#0A84FF", "#409CFF"),
    blueSoft: adaptive(glass("#0A84FF", 0.16), glass("#409CFF", 0.22)),
    purple: adaptive("#5E5CE6", "#7D7AFF"),
    purpleSoft: adaptive(glass("#5E5CE6", 0.16), glass("#7D7AFF", 0.22)),
    green: adaptive("#34C759", "#30D158"),
    greenSoft: adaptive(glass("#34C759", 0.16), glass("#30D158", 0.22)),
    red: adaptive("#FF3B30", "#FF453A"),
    redSoft: adaptive(glass("#FF3B30", 0.14), glass("#FF453A", 0.2)),
    cardBg: adaptive(glass("#FFFFFF", 0.55), glass("#1C1C1E", 0.55)),
    cardBorder: adaptive(glass("#000000", 0.06), glass("#FFFFFF", 0.1))
  };
}

function detectScheme(ctx) {
  const raw = clean(
    pick(
      ctx.colorScheme,
      ctx.appearance,
      ctx.theme,
      ctx.widgetColorScheme
    )
  ).toLowerCase();

  if (raw.includes("dark") || raw.includes("深") || raw === "2") {
    return "dark";
  }

  return "light";
}

function resolveAdaptiveColor(value, scheme) {
  if (typeof value === "string") return value;

  if (value && typeof value === "object") {
    return scheme === "dark"
      ? clean(value.dark) || clean(value.light)
      : clean(value.light) || clean(value.dark);
  }

  return "";
}

function joinLocation() {
  const seen = {};
  const parts = [];

  for (let index = 0; index < arguments.length; index += 1) {
    const value = clean(arguments[index]);
    if (value && !seen[value]) {
      seen[value] = true;
      parts.push(value);
    }
  }

  return parts.join(" ");
}

function parseJSON(body) {
  if (!body) return null;
  if (typeof body === "object") return body;

  try {
    return JSON.parse(String(body));
  } catch (_) {}

  return null;
}

function timeLabel(date) {
  return (
    String(date.getHours()).padStart(2, "0") +
    ":" +
    String(date.getMinutes()).padStart(2, "0")
  );
}

function clean(value) {
  return String(value === undefined || value === null ? "" : value).trim();
}

function clamp(value, min, max) {
  const number = Number(value);
  if (!Number.isFinite(number)) return min;
  return Math.max(min, Math.min(max, number));
}

function pick() {
  for (let index = 0; index < arguments.length; index += 1) {
    const value = arguments[index];
    if (value !== undefined && value !== null && value !== "") {
      return value;
    }
  }
  return "";
}

function getAt(object, path) {
  if (!object || !path) return "";

  try {
    let current = object;
    const parts = String(path).split(".");

    for (let index = 0; index < parts.length; index += 1) {
      if (current === undefined || current === null) return "";
      current = current[parts[index]];
    }

    return current === undefined || current === null ? "" : current;
  } catch (_) {
    return "";
  }
}
