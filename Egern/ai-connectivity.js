const COLORS = {
  success: "#34C759",
  warning: "#FF9500",
  restricted: "#FF3B30",
  failure: "#FF3B30",
  unknown: "#8E8E93",
  accent: "#0A84FF",
  text: { light: "#1C1C1E", dark: "#FFFFFF" },
  secondary: { light: "#636366", dark: "#AEAEB2" },
  background: { light: "#F2F2F7", dark: "#1C1C1E" },
};

const CHATGPT_URL = "https://chatgpt.com/";
const GEMINI_URL = "https://gemini.google.com/app";

function parseChoice(value, allowed, fallback) {
  const parsed = Number.parseInt(value || "", 10);
  return allowed.includes(parsed) ? parsed : fallback;
}

function getHeader(headers, name) {
  if (!headers) return "";
  if (typeof headers.get === "function") return headers.get(name) || "";
  return headers[name] || headers[name.toLowerCase()] || "";
}

function makeRequestOptions(policy, timeout, extra = {}) {
  const options = {
    timeout,
    credentials: "omit",
    ...extra,
    headers: {
      "User-Agent":
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1",
      Accept: "text/html,application/json;q=0.9,*/*;q=0.8",
      "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.6",
      ...(extra.headers || {}),
    },
  };
  if (policy) options.policy = policy;
  return options;
}

async function get(ctx, url, options, readBody = false) {
  const startedAt = Date.now();
  try {
    const response = await ctx.http.get(url, options);
    let body = "";
    if (readBody) {
      try {
        body = await response.text();
      } catch {
        body = "";
      }
    }
    return {
      ok: true,
      status: response.status,
      headers: response.headers,
      body,
      latency: Date.now() - startedAt,
    };
  } catch (error) {
    return {
      ok: false,
      status: 0,
      headers: null,
      body: "",
      latency: Date.now() - startedAt,
      error: String(error && error.message ? error.message : error),
    };
  }
}

function parseTraceRegion(trace) {
  if (!trace.ok || trace.status !== 200) return "--";
  const match = trace.body.match(/(?:^|\n)loc=([A-Z]{2})(?:\n|$)/i);
  return match ? match[1].toUpperCase() : "--";
}

function result(name, state, statusText, region, latency, detail, url) {
  return {
    name,
    state,
    statusText,
    region: region || "--",
    latency,
    detail,
    url,
    available: state === "success" || state === "warning",
    color: COLORS[state] || COLORS.unknown,
  };
}

function classifyChatGPT(session, region) {
  if (!session.ok) {
    return result(
      "ChatGPT",
      "failure",
      "连接失败",
      region,
      session.latency,
      "请求超时或网络不可达",
      CHATGPT_URL,
    );
  }

  const status = session.status;
  const location = getHeader(session.headers, "location").toLowerCase();
  if ((status >= 200 && status < 300) || status === 401) {
    return result("ChatGPT", "success", "已解锁", region, session.latency, `HTTP ${status}`, CHATGPT_URL);
  }
  if (status === 429) {
    return result(
      "ChatGPT",
      "warning",
      "可连接（限流）",
      region,
      session.latency,
      "HTTP 429",
      CHATGPT_URL,
    );
  }
  if (
    status >= 300 &&
    status < 400 &&
    (location.includes("auth") || location.includes("login") || location.includes("chatgpt.com"))
  ) {
    return result("ChatGPT", "success", "已解锁", region, session.latency, "需要登录", CHATGPT_URL);
  }
  if (status === 403) {
    return result("ChatGPT", "restricted", "访问受限", region, session.latency, "HTTP 403", CHATGPT_URL);
  }
  return result(
    "ChatGPT",
    "unknown",
    "检测异常",
    region,
    session.latency,
    `HTTP ${status}`,
    CHATGPT_URL,
  );
}

function geminiIsRegionRestricted(response) {
  const location = getHeader(response.headers, "location").toLowerCase();
  const body = (response.body || "").toLowerCase();
  const markers = [
    "support.google.com/gemini/answer/13575153",
    "isn't currently supported in your country",
    "is not currently supported in your country",
    "not available in your country",
    "country is not supported",
    "unsupported_country",
    "您所在的国家/地区目前无法使用",
    "您所在的国家/地区尚不支持",
    "目前无法在您所在的国家",
    "gemini 目前不支持",
  ];
  return markers.some((marker) => location.includes(marker) || body.includes(marker));
}

function classifyGemini(response, region) {
  if (!response.ok) {
    return result(
      "Gemini",
      "failure",
      "连接失败",
      region,
      response.latency,
      "请求超时或网络不可达",
      GEMINI_URL,
    );
  }

  const status = response.status;
  const location = getHeader(response.headers, "location").toLowerCase();
  if (geminiIsRegionRestricted(response)) {
    return result("Gemini", "restricted", "地区受限", region, response.latency, `HTTP ${status}`, GEMINI_URL);
  }
  if (status >= 200 && status < 300) {
    return result("Gemini", "success", "已解锁", region, response.latency, `HTTP ${status}`, GEMINI_URL);
  }
  if (
    status >= 300 &&
    status < 400 &&
    (location.includes("accounts.google.com") || location.includes("servicelogin"))
  ) {
    return result("Gemini", "success", "已解锁", region, response.latency, "需要登录", GEMINI_URL);
  }
  if (status === 401) {
    return result("Gemini", "success", "已解锁", region, response.latency, "需要登录", GEMINI_URL);
  }
  if (status === 429) {
    return result(
      "Gemini",
      "warning",
      "可连接（限流）",
      region,
      response.latency,
      "HTTP 429",
      GEMINI_URL,
    );
  }
  if (status === 403) {
    return result("Gemini", "restricted", "访问受限", region, response.latency, "HTTP 403", GEMINI_URL);
  }
  return result(
    "Gemini",
    "unknown",
    "检测异常",
    region,
    response.latency,
    `HTTP ${status}`,
    GEMINI_URL,
  );
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

function serviceLine(service, compact = false) {
  const detail = compact
    ? service.statusText
    : `${service.statusText} · 地区：${service.region} · ${service.latency} ms`;
  return {
    type: "stack",
    direction: "row",
    alignItems: "center",
    gap: 6,
    url: service.url,
    children: [
      image(service.name === "ChatGPT" ? "sparkles" : "stars", service.color, compact ? 13 : 16),
      text(service.name, {
        font: { size: compact ? "footnote" : "subheadline", weight: "semibold" },
      }),
      { type: "spacer" },
      text(detail, {
        color: service.color,
        font: { size: compact ? "caption2" : "footnote", weight: "semibold" },
        align: "right",
        minScale: 0.55,
      }),
    ],
  };
}

function header(title = "AI 服务检测") {
  return {
    type: "stack",
    direction: "row",
    alignItems: "center",
    gap: 7,
    children: [
      image("network", COLORS.accent, 18),
      text(title, { font: { size: "headline", weight: "bold" } }),
    ],
  };
}

function widgetBase(refreshAfter, children, options = {}) {
  return {
    type: "widget",
    refreshAfter,
    backgroundColor: options.backgroundColor || COLORS.background,
    padding: options.padding === undefined ? 14 : options.padding,
    gap: options.gap === undefined ? 8 : options.gap,
    children,
  };
}

function renderInline(services, refreshAfter) {
  const count = services.filter((service) => service.available).length;
  return widgetBase(
    refreshAfter,
    [text(`AI：${count}/2 可用`, { font: { size: "caption1", weight: "semibold" } })],
    { padding: 0, gap: 0 },
  );
}

function renderCircular(services, refreshAfter) {
  const count = services.filter((service) => service.available).length;
  const color = count === 2 ? COLORS.success : count === 1 ? COLORS.warning : COLORS.failure;
  return widgetBase(
    refreshAfter,
    [
      {
        type: "stack",
        direction: "column",
        alignItems: "center",
        gap: 1,
        children: [
          image("network", color, 16),
          text(`${count}/2`, {
            color,
            font: { size: "caption1", weight: "bold" },
            align: "center",
          }),
        ],
      },
    ],
    { padding: 0, gap: 0 },
  );
}

function renderRectangular(services, refreshAfter) {
  return widgetBase(
    refreshAfter,
    services.map((service) =>
      text(`${service.name}：${service.statusText}，地区：${service.region}`, {
        color: service.color,
        font: { size: "footnote", weight: "medium" },
        url: service.url,
        minScale: 0.55,
      }),
    ),
    { padding: 0, gap: 2 },
  );
}

function renderSmall(services, refreshAfter) {
  return widgetBase(refreshAfter, [
    header("AI 连通性"),
    { type: "spacer" },
    ...services.map((service) => serviceLine(service, true)),
  ]);
}

function renderMedium(services, refreshAfter) {
  return widgetBase(refreshAfter, [header(), { type: "spacer" }, ...services.map((service) => serviceLine(service))]);
}

function serviceDetail(service) {
  return {
    type: "stack",
    direction: "column",
    alignItems: "start",
    gap: 5,
    flex: 1,
    url: service.url,
    children: [
      {
        type: "stack",
        direction: "row",
        alignItems: "center",
        gap: 7,
        children: [
          image(service.name === "ChatGPT" ? "sparkles" : "stars", service.color, 18),
          text(service.name, { font: { size: "headline", weight: "bold" } }),
        ],
      },
      text(service.statusText, {
        color: service.color,
        font: { size: "subheadline", weight: "semibold" },
      }),
      text(`地区：${service.region}`, { color: COLORS.secondary, font: { size: "footnote" } }),
      text(`延迟：${service.latency} ms`, { color: COLORS.secondary, font: { size: "footnote" } }),
      text(service.detail, { color: COLORS.secondary, font: { size: "caption2" } }),
    ],
  };
}

function footer(policy, checkedAt) {
  return {
    type: "stack",
    direction: "row",
    alignItems: "center",
    gap: 5,
    children: [
      text(`策略：${policy || "现有分流"}`, {
        color: COLORS.secondary,
        font: { size: "caption2" },
      }),
      { type: "spacer" },
      {
        type: "date",
        date: checkedAt,
        format: "relative",
        font: { size: "caption2" },
        textColor: COLORS.secondary,
        maxLines: 1,
        minScale: 0.65,
      },
    ],
  };
}

function renderLarge(services, refreshAfter, policy, checkedAt, extraLarge = false) {
  const details = extraLarge
    ? [
        {
          type: "stack",
          direction: "row",
          alignItems: "start",
          gap: 18,
          flex: 1,
          children: services.map(serviceDetail),
        },
      ]
    : services.map(serviceDetail);
  return widgetBase(refreshAfter, [header(), { type: "spacer", length: 4 }, ...details, { type: "spacer" }, footer(policy, checkedAt)], {
    padding: 16,
    gap: 12,
  });
}

export default async function (ctx) {
  const env = ctx.env || {};
  const policy = (env.POLICY || "").trim();
  const refreshInterval = parseChoice(env.REFRESH_INTERVAL, [300, 900, 1800, 3600], 900);
  const requestTimeout = parseChoice(env.REQUEST_TIMEOUT, [5000, 8000, 12000], 8000);
  const checkedAt = new Date().toISOString();
  const refreshAfter = new Date(Date.now() + refreshInterval * 1000).toISOString();

  const traceOptions = makeRequestOptions(policy, requestTimeout, {
    redirect: "manual",
    headers: { Accept: "text/plain,*/*;q=0.8" },
  });
  const serviceOptions = makeRequestOptions(policy, requestTimeout, { redirect: "manual" });

  const [trace, chatgptSession, geminiResponse] = await Promise.all([
    get(ctx, "https://chatgpt.com/cdn-cgi/trace", traceOptions, true),
    get(ctx, "https://chatgpt.com/api/auth/session", serviceOptions, false),
    get(ctx, GEMINI_URL, serviceOptions, true),
  ]);

  const exitRegion = parseTraceRegion(trace);
  const chatgpt = classifyChatGPT(chatgptSession, exitRegion);
  const gemini = classifyGemini(geminiResponse, policy ? exitRegion : "--");
  const services = [chatgpt, gemini];

  switch (ctx.widgetFamily) {
    case "accessoryInline":
      return renderInline(services, refreshAfter);
    case "accessoryCircular":
      return renderCircular(services, refreshAfter);
    case "accessoryRectangular":
      return renderRectangular(services, refreshAfter);
    case "systemSmall":
      return renderSmall(services, refreshAfter);
    case "systemLarge":
      return renderLarge(services, refreshAfter, policy, checkedAt, false);
    case "systemExtraLarge":
      return renderLarge(services, refreshAfter, policy, checkedAt, true);
    case "systemMedium":
    default:
      return renderMedium(services, refreshAfter);
  }
}
