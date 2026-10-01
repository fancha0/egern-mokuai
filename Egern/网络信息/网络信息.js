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
 * - LAN=1：显示局域网 IP（默认开）
 * - IPv6=1：显示 IPv6 地址（默认关）
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

  const TIMEOUT = 5000;
  const REFRESH_MINUTES = 30;

  const device = ctx.device || {};
  const lanIPv4 = clean(
    pick(getAt(device, "wifi.ipv4"), getAt(device, "cellular.ipv4"))
  );
  const lanIPv6 = clean(
    pick(getAt(device, "wifi.ipv6"), getAt(device, "cellular.ipv6"))
  );

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
      const status = Number(response.status || response.statusCode || 0);

      if (status >= 200 && status < 300) {
        return response.body !== undefined
          ? response.body
          : response.data;
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
      const match = text.match(/IP[::]\s*(\S+)\s+来自于[::]\s*(.+)/);

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

  function infoCard(item, tone, symbol) {
    const titleLeft = [
      image(symbol, uiColor(tone), 11, 11),
      text(item.label + " IP", 10, "semibold", C.text)
    ];

    if (!item.ok) {
      titleLeft.push(pill("查询失败", C.red, C.redSoft));
    }

    const lines = [];

    if (item.location) {
      lines.push(infoLine("位置", item.location));
    }

    if (item.isp) {
      lines.push(infoLine("运营商", item.isp));
    }

    if (SHOW_ASN && item.asn) {
      lines.push(infoLine("ASN", item.asn));
    }

    if (SHOW_ORG && item.org) {
      lines.push(infoLine("ORG", item.org));
    }

    const ipRowChildren = [];

    if (SHOW_FLAG) {
      ipRowChildren.push(text(flagEmoji(item.code), 13, "regular", C.text));
    }

    ipRowChildren.push(
      text(
        item.ok ? displayIP(item.ip) || "未知" : "--.--.*.*",
        15,
        "bold",
        uiColor(item.ok ? tone : C.red)
      )
    );

    return card(
      [
        row(
          titleLeft.concat(item.ok ? [] : []),
          { gap: 4, alignItems: "center" }
        ),
        row(ipRowChildren, { gap: 5, alignItems: "center" }),
        lines.length
          ? col(lines, { gap: 2 })
          : text("无详细信息", 8, "regular", C.muted)
      ],
      { gap: 5 }
    );
  }

  function infoLine(label, value) {
    return row(
      [
        text(label, 8, "medium", C.muted, { width: 34 }),
        text(clean(value), 8, "regular", C.text, {
          maxLines: 1
        })
      ],
      { gap: 4, alignItems: "center" }
    );
  }

  function lanCard() {
    const rows = [];

    if (SHOW_LAN && lanIPv4) {
      rows.push(infoLine("LAN", displayIP(lanIPv4)));
    }

    if (SHOW_IPV6 && lanIPv6) {
      rows.push(
        row(
          [
            text("IPv6", 8, "medium", C.muted, { width: 34 }),
            text(displayIP(lanIPv6), 7, "regular", C.text, {
              maxLines: 1
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
            image("house.fill", uiColor(C.green), 11, 11),
            text("本机", 10, "semibold", C.text)
          ],
          { gap: 4, alignItems: "center" }
        ),
        col(rows, { gap: 2 })
      ],
      { gap: 4 }
    );
  }

  const now = new Date();

  const children = [
    row(
      [
        text("🛰️ 网络信息", 12, "bold", C.text),
        spacer(),
        text(timeLabel(now), 9, "medium", C.muted)
      ],
      { alignItems: "center" }
    ),
    infoCard(domestic, C.blue, "location.fill"),
    infoCard(landing, C.purple, "globe.asia.australia.fill")
  ];

  const lan = lanCard();
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

  // ======================== 基础组件 ========================

  function text(value, size, weight, color, extra) {
    return merge(
      {
        type: "text",
        text: String(value === undefined || value === null ? "" : value),
        fontSize: size,
        fontWeight: weight || "regular",
        color: color || C.text,
        maxLines: 0
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
    return {
      type: "spacer",
      length: typeof length === "number" ? length : 0
    };
  }

  function card(children, extra) {
    return merge(
      {
        type: "stack",
        direction: "column",
        children: children,
        alignItems: "start",
        gap: 4,
        width: null,
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
    return {
      type: "text",
      text: value,
      fontSize: 7,
      fontWeight: "semibold",
      color: uiColor(tone),
      maxLines: 1,
      padding: [2, 5],
      backgroundColor: uiColor(fill),
      borderRadius: 99
    };
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
