const COLORS = {
  success: "#34C759",
  warning: "#FF9500",
  failure: "#FF3B30",
  unknown: "#8E8E93",
  accent: "#0A84FF",
  teal: "#30B0C7",
  text: { light: "#1C1C1E", dark: "#FFFFFF" },
  secondary: { light: "#636366", dark: "#AEAEB2" },
  background: { light: "#F2F2F7", dark: "#1C1C1E" },
};

const PUBLIC_IP_URL = "https://api.ipify.org?format=json";
const PUBLIC_INFO_URL = "https://ipwho.is";

function parseChoice(value, allowed, fallback) {
  const parsed = Number.parseInt(value || "", 10);
  return allowed.includes(parsed) ? parsed : fallback;
}

function stringifyError(error) {
  return String(error && error.message ? error.message : error || "");
}

function makeRequestOptions(policy, timeout, extra = {}) {
  const options = {
    timeout,
    credentials: "omit",
    ...extra,
    headers: {
      Accept: "application/json,text/plain,*/*;q=0.8",
      "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
      "User-Agent":
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
      ...(extra.headers || {}),
    },
  };
  if (policy) options.policy = policy;
  return options;
}

async function getJSON(ctx, url, options) {
  const startedAt = Date.now();
  try {
    const response = await ctx.http.get(url, options);
    const textValue = await response.text();
    let data = null;
    try {
      data = textValue ? JSON.parse(textValue) : null;
    } catch {
      data = null;
    }
    return {
      ok: response.status >= 200 && response.status < 300 && data !== null,
      status: response.status,
      data,
      body: textValue,
      latency: Date.now() - startedAt,
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      data: null,
      body: "",
      latency: Date.now() - startedAt,
      error: stringifyError(error),
    };
  }
}

function firstString(...values) {
  for (const value of values) {
    if (value === undefined || value === null) continue;
    const normalized = String(value).trim();
    if (normalized) return normalized;
  }
  return "";
}

function firstNumber(...values) {
  for (const value of values) {
    if (value === undefined || value === null || value === "") continue;
    const parsed = Number.parseInt(String(value).replace(/^AS/i, ""), 10);
    if (Number.isFinite(parsed)) return parsed;
  }
  return null;
}

function normalizeRisk(value) {
  const textValue = firstString(value).toLowerCase();
  if (!textValue) return { label: "未知", level: "unknown", color: COLORS.unknown };
  if (/^(0|1|low|clean|safe|trust|pure|原生|纯净|低|极度纯净)$/.test(textValue)) {
    return { label: textValue === "1" ? "1 - 极度纯净" : "低风险", level: "success", color: COLORS.success };
  }
  if (/^(2|medium|moderate|中)$/.test(textValue)) {
    return { label: "中风险", level: "warning", color: COLORS.warning };
  }
  if (/^(3|4|5|high|risky|danger|高|欺诈|代理)$/.test(textValue)) {
    return { label: "高风险", level: "failure", color: COLORS.failure };
  }
  return { label: firstString(value), level: "unknown", color: COLORS.unknown };
}

function normalizeAttribute(value, fallback = "公开接口") {
  const textValue = firstString(value).toLowerCase();
  if (!textValue) return fallback;
  if (textValue.includes("residential") || textValue.includes("home") || textValue.includes("住宅")) return "住宅网络";
  if (textValue.includes("native") || textValue.includes("原生")) return "原生";
  if (textValue.includes("hosting") || textValue.includes("datacenter") || textValue.includes("机房")) return "机房/托管";
  if (textValue.includes("mobile") || textValue.includes("cellular") || textValue.includes("移动")) return "移动网络";
  if (textValue.includes("proxy") || textValue.includes("vpn")) return "代理/VPN";
  return firstString(value);
}

function buildAdvancedURL(endpoint, ip) {
  if (!endpoint) return "";
  if (endpoint.includes("{ip}")) return endpoint.replaceAll("{ip}", encodeURIComponent(ip));
  const separator = endpoint.includes("?") ? "&" : "?";
  return `${endpoint}${separator}ip=${encodeURIComponent(ip)}`;
}

function parsePublicInfo(ip, payload) {
  const connection = payload.connection || {};
  const asn = firstNumber(connection.asn, payload.asn, payload.as);
  const countryCode = firstString(payload.country_code, payload.countryCode, payload.country);
  const country = firstString(payload.country, payload.country_name);
  const region = firstString(payload.region, payload.regionName);
  const city = firstString(payload.city);
  const location = [city, region, country].filter(Boolean).join(", ") || countryCode || "未知";
  return {
    ip,
    source: "公开接口",
    statusText: "基础信息",
    isp: firstString(connection.isp, payload.isp, connection.org, payload.org, payload.organization, "未知"),
    organization: firstString(connection.org, payload.org, payload.organization, connection.isp, "未知"),
    asn,
    countryCode,
    location,
    attribute: "公开接口",
    risk: normalizeRisk("unknown"),
    detail: payload.success === false ? firstString(payload.message, "公开接口返回失败") : "公开接口查询成功",
  };
}

function parseAdvancedInfo(ip, payload, baseInfo) {
  const data = payload.data || payload.result || payload.ip || payload;
  const geo = data.geo || data.location || data.region || {};
  const network = data.network || data.connection || data.asn || {};
  const riskData = data.risk || data.security || data.score || {};
  const asn = firstNumber(data.asn, data.as, network.asn, network.number, baseInfo.asn);
  const countryCode = firstString(data.country_code, data.countryCode, geo.country_code, baseInfo.countryCode);
  const country = firstString(data.country, data.country_name, geo.country, baseInfo.country);
  const region = firstString(data.region, data.region_name, geo.region);
  const city = firstString(data.city, geo.city);
  const location = firstString(data.location_text, data.location, [city, region, country].filter(Boolean).join(", "), baseInfo.location);
  const attribute = normalizeAttribute(
    firstString(
      data.attribute,
      data.ip_type,
      data.type,
      data.usage_type,
      network.type,
      riskData.type,
      baseInfo.attribute,
    ),
    baseInfo.attribute,
  );
  const risk = normalizeRisk(
    firstString(data.risk_label, data.risk, data.risk_level, data.score, riskData.level, riskData.score, baseInfo.risk.label),
  );
  return {
    ip,
    source: "高级接口",
    statusText: risk.level === "unknown" ? "高级信息" : risk.label,
    isp: firstString(data.isp, network.isp, data.org, data.organization, baseInfo.isp, "未知"),
    organization: firstString(data.organization, data.org, network.org, network.organization, baseInfo.organization, "未知"),
    asn,
    countryCode,
    location,
    attribute,
    risk,
    detail: "高级接口查询成功",
  };
}

async function detectIP(ctx, policy, timeout) {
  const options = makeRequestOptions(policy, timeout);
  const response = await getJSON(ctx, PUBLIC_IP_URL, options);
  if (!response.ok || !response.data || !response.data.ip) {
    const error = response.error || `HTTP ${response.status}`;
    const statusText = /timed? ?out|timeout|超时/i.test(error) ? "检测超时" : "连接失败";
    return {
      ok: false,
      statusText,
      color: COLORS.failure,
      latency: response.latency,
      detail: `出口 IP 获取失败：${error}`,
    };
  }
  return {
    ok: true,
    ip: String(response.data.ip),
    latency: response.latency,
  };
}

async function queryPublicInfo(ctx, policy, timeout, ip) {
  const response = await getJSON(ctx, `${PUBLIC_INFO_URL}/${encodeURIComponent(ip)}?lang=zh-CN`, makeRequestOptions(policy, timeout));
  if (!response.ok || !response.data || response.data.success === false) {
    return {
      ok: false,
      info: parsePublicInfo(ip, {}),
      error: response.error || `HTTP ${response.status}`,
      latency: response.latency,
    };
  }
  return {
    ok: true,
    info: parsePublicInfo(ip, response.data),
    latency: response.latency,
  };
}

async function queryAdvancedInfo(ctx, policy, timeout, endpoint, token, ip, baseInfo) {
  const url = buildAdvancedURL(endpoint, ip);
  if (!url) return { ok: false, info: baseInfo, skipped: true };
  const headers = token ? { Authorization: `Bearer ${token}`, "X-API-Key": token } : {};
  const response = await getJSON(ctx, url, makeRequestOptions(policy, timeout, { headers }));
  if (!response.ok || !response.data) {
    return {
      ok: false,
      info: baseInfo,
      error: response.error || `HTTP ${response.status}`,
      latency: response.latency,
    };
  }
  return {
    ok: true,
    info: parseAdvancedInfo(ip, response.data, baseInfo),
    latency: response.latency,
  };
}

async function collectInfo(ctx, env) {
  const policy = firstString(env.POLICY);
  const timeout = parseChoice(env.REQUEST_TIMEOUT, [5000, 8000, 12000], 8000);
  const endpoint = firstString(env.IP_API_ENDPOINT);
  const token = firstString(env.IP_API_TOKEN);
  const ipProbe = await detectIP(ctx, policy, timeout);
  if (!ipProbe.ok) {
    return {
      ok: false,
      policy,
      ip: "--",
      statusText: ipProbe.statusText,
      color: ipProbe.color,
      latency: ipProbe.latency,
      isp: "未知",
      organization: "未知",
      asn: null,
      countryCode: "--",
      location: "未知",
      attribute: "未知",
      source: "无",
      risk: { label: "未知", level: "unknown", color: COLORS.unknown },
      detail: ipProbe.detail,
      checkedAt: new Date().toISOString(),
    };
  }

  const publicResult = await queryPublicInfo(ctx, policy, timeout, ipProbe.ip);
  let info = publicResult.info;
  let statusText = publicResult.ok ? info.statusText : "基础信息不完整";
  let detail = publicResult.ok ? info.detail : `公开接口失败：${publicResult.error}`;

  const advancedResult = await queryAdvancedInfo(ctx, policy, timeout, endpoint, token, ipProbe.ip, info);
  if (advancedResult.ok) {
    info = advancedResult.info;
    statusText = info.statusText;
    detail = info.detail;
  } else if (endpoint && !advancedResult.skipped) {
    detail = `${detail}；高级接口已降级：${advancedResult.error}`;
  }

  const available = publicResult.ok || Boolean(ipProbe.ip);
  const color = info.risk.level === "failure" ? COLORS.failure : info.risk.level === "warning" ? COLORS.warning : COLORS.success;
  return {
    ok: available,
    policy,
    ...info,
    statusText,
    color,
    latency: ipProbe.latency + (publicResult.latency || 0) + (advancedResult.latency || 0),
    detail,
    checkedAt: new Date().toISOString(),
  };
}

function text(textValue, options = {}) {
  return {
    type: "text",
    text: textValue,
    textColor: options.color || COLORS.text,
    font: options.font || { size: "body", weight: "regular" },
    textAlign: options.align || "left",
    maxLines: options.maxLines || 1,
    minScale: options.minScale || 0.65,
    ...(options.url ? { url: options.url } : {}),
  };
}

function image(symbol, color, size) {
  return {
    type: "image",
    src: `sf-symbol:${symbol}`,
    color,
    width: size,
    height: size,
  };
}

function stack(direction, children, options = {}) {
  return {
    type: "stack",
    direction,
    alignItems: options.alignItems || "center",
    gap: options.gap === undefined ? 6 : options.gap,
    ...(options.flex ? { flex: options.flex } : {}),
    ...(options.url ? { url: options.url } : {}),
    children,
  };
}

function widgetBase(refreshAfter, children, options = {}) {
  return {
    type: "widget",
    refreshAfter,
    backgroundColor: options.backgroundColor || COLORS.background,
    padding: options.padding === undefined ? 14 : options.padding,
    gap: options.gap === undefined ? 8 : options.gap,
    ...(options.url ? { url: options.url } : {}),
    children,
  };
}

function ipLookupURL(info) {
  return info.ip && info.ip !== "--" ? `https://ipinfo.io/${encodeURIComponent(info.ip)}` : "https://ipinfo.io/";
}

function asnText(asn) {
  return asn ? `AS${asn}` : "AS--";
}

function header(title = "IP 信息检测") {
  return stack("row", [
    image("location.magnifyingglass", COLORS.accent, 18),
    text(title, { font: { size: "headline", weight: "bold" } }),
  ]);
}

function infoRow(label, value, color = COLORS.secondary) {
  return stack(
    "row",
    [
      text(label, { color: COLORS.secondary, font: { size: "caption1", weight: "medium" } }),
      { type: "spacer" },
      text(value || "未知", {
        color,
        font: { size: "caption1", weight: "semibold" },
        align: "right",
        minScale: 0.55,
      }),
    ],
    { gap: 8 },
  );
}

function footer(info) {
  return stack("row", [
    text(`策略：${info.policy || "现有分流"}`, { color: COLORS.secondary, font: { size: "caption2" } }),
    { type: "spacer" },
    {
      type: "date",
      date: info.checkedAt,
      format: "relative",
      font: { size: "caption2" },
      textColor: COLORS.secondary,
      maxLines: 1,
      minScale: 0.65,
    },
  ]);
}

function notificationBody(info) {
  return [
    `节点：${info.policy || "现有分流"}`,
    `IP 地址：${info.ip}`,
    `ISP：${info.isp}`,
    `ASN：${asnText(info.asn)}`,
    `地理位置：${info.location}`,
    `属性来源：${info.attribute} · ${info.source}`,
    `风险系数：${info.risk.label}`,
  ].join("\n");
}

function maybeNotify(ctx, info, env) {
  if (String(env.NOTIFY_ON_REFRESH || "false").toLowerCase() !== "true") return;
  if (typeof ctx.notify !== "function") return;
  ctx.notify({
    title: "IP 信息概览",
    body: notificationBody(info),
    sound: false,
    duration: 5,
    action: {
      type: "openUrl",
      url: ipLookupURL(info),
    },
  });
}

function renderInline(info, refreshAfter) {
  const region = info.countryCode || "--";
  return widgetBase(
    refreshAfter,
    [
      text(`IP 信息：${region} · ${asnText(info.asn)} · ${info.risk.label}`, {
        color: info.color,
        font: { size: "caption1", weight: "semibold" },
      }),
    ],
    { padding: 0, gap: 0, url: ipLookupURL(info) },
  );
}

function renderCircular(info, refreshAfter) {
  return widgetBase(
    refreshAfter,
    [
      stack(
        "column",
        [
          image(info.ok ? "checkmark.shield" : "xmark.octagon", info.color, 16),
          text(info.countryCode || "--", {
            color: info.color,
            font: { size: "caption1", weight: "bold" },
            align: "center",
          }),
        ],
        { gap: 1 },
      ),
    ],
    { padding: 0, gap: 0, url: ipLookupURL(info) },
  );
}

function renderRectangular(info, refreshAfter) {
  return widgetBase(
    refreshAfter,
    [
      text(`${info.ip} · ${info.countryCode || "--"}`, {
        color: info.color,
        font: { size: "footnote", weight: "semibold" },
        minScale: 0.6,
      }),
      text(`${asnText(info.asn)} · ${info.isp}`, {
        color: COLORS.secondary,
        font: { size: "caption2", weight: "medium" },
        minScale: 0.55,
      }),
    ],
    { padding: 0, gap: 2, url: ipLookupURL(info) },
  );
}

function renderSmall(info, refreshAfter) {
  return widgetBase(
    refreshAfter,
    [
      header("IP 概览"),
      { type: "spacer" },
      text(info.ip, { color: info.color, font: { size: "headline", weight: "bold" }, minScale: 0.55 }),
      text(`${info.countryCode || "--"} · ${info.risk.label}`, {
        color: info.risk.color,
        font: { size: "footnote", weight: "semibold" },
        minScale: 0.6,
      }),
      text(info.isp, { color: COLORS.secondary, font: { size: "caption2" }, minScale: 0.55 }),
    ],
    { url: ipLookupURL(info) },
  );
}

function renderMedium(info, refreshAfter) {
  return widgetBase(
    refreshAfter,
    [
      header(),
      { type: "spacer", length: 2 },
      stack("row", [
        image(info.ok ? "network" : "exclamationmark.triangle", info.color, 18),
        text(info.ip, { color: info.color, font: { size: "headline", weight: "bold" }, minScale: 0.55 }),
        { type: "spacer" },
        text(info.countryCode || "--", { color: info.color, font: { size: "subheadline", weight: "bold" } }),
      ]),
      infoRow("ISP", info.isp),
      infoRow("ASN", asnText(info.asn), COLORS.teal),
      infoRow("位置", info.location),
    ],
    { url: ipLookupURL(info) },
  );
}

function detailBlock(info) {
  return stack(
    "column",
    [
      infoRow("节点", info.policy || "现有分流"),
      infoRow("IP 地址", info.ip, info.color),
      infoRow("ISP", info.isp),
      infoRow("ASN", asnText(info.asn), COLORS.teal),
      infoRow("地理位置", info.location),
      infoRow("属性来源", `${info.attribute} · ${info.source}`, COLORS.success),
      infoRow("风险系数", info.risk.label, info.risk.color),
    ],
    { alignItems: "stretch", gap: 7, url: ipLookupURL(info) },
  );
}

function renderLarge(info, refreshAfter, extraLarge = false) {
  const children = [
    header("IP 信息概览"),
    { type: "spacer", length: 2 },
    detailBlock(info),
    ...(extraLarge
      ? [
          { type: "spacer", length: 2 },
          text(info.detail, { color: COLORS.secondary, font: { size: "caption1" }, maxLines: 2 }),
        ]
      : []),
    { type: "spacer" },
    footer(info),
  ];
  return widgetBase(refreshAfter, children, { padding: 16, gap: 10, url: ipLookupURL(info) });
}

export default async function (ctx) {
  const env = ctx.env || {};
  const refreshInterval = parseChoice(env.REFRESH_INTERVAL, [300, 900, 1800, 3600], 900);
  const refreshAfter = new Date(Date.now() + refreshInterval * 1000).toISOString();
  const info = await collectInfo(ctx, env);
  maybeNotify(ctx, info, env);

  switch (ctx.widgetFamily) {
    case "accessoryInline":
      return renderInline(info, refreshAfter);
    case "accessoryCircular":
      return renderCircular(info, refreshAfter);
    case "accessoryRectangular":
      return renderRectangular(info, refreshAfter);
    case "systemSmall":
      return renderSmall(info, refreshAfter);
    case "systemLarge":
      return renderLarge(info, refreshAfter, false);
    case "systemExtraLarge":
      return renderLarge(info, refreshAfter, true);
    case "systemMedium":
    default:
      return renderMedium(info, refreshAfter);
  }
}
