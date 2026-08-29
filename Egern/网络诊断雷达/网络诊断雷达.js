/**
 * Egern「网络诊断雷达」
 *
 * 环境变量：
 * - POLICY：最高优先级。指定后，出口、延迟、UDP/QUIC、流媒体、AI 全部统一走 POLICY
 * - LMT：流媒体检测策略组。POLICY 为空时生效
 * - AI：AI 检测策略组。POLICY 为空时生效
 * - YS=1：显示 IP 的地方启用隐私打码，例如 123.123.123.123 -> 123.123.*.*
 * - YS=0 或不设置：不打码
 * - XY：手动指定协议，例如 VLESS / Trojan / HY2 / AnyTLS
 * - XY 未设置：继续按原逻辑从 Egern 上下文 / 节点元数据 / 节点名尝试识别
 *
 * 策略优先级：
 * POLICY ＞ LMT / AI ＞ 单服务内置候选策略名匹配 ＞ 不指定 policy
 *
 * 单服务匹配逻辑：
 * - POLICY 为空，LMT/AI 也为空时，每个服务单独使用自己的候选策略名表
 * - 每个服务在本轮刷新中只匹配一次
 * - 匹配成功后缓存本轮结果
 * - 匹配不到时该服务不传 policy，走 Widget 默认请求方式
 * - 服务小国旗来自该服务实际使用策略的出口地区，不再复用顶部当前代理出口
 */

export default async function (ctx) {
  const env = ctx.env || {};
  const C = palette();
  const SCHEME = detectScheme(ctx);

  const POLICY = clean(env.POLICY);
  const POLICY_LABEL = POLICY || "默认规则";
  const LMT_POLICY = clean(env.LMT);
  const AI_POLICY = clean(env.AI);
  const MASK_IP = clean(env.YS) === "1";
  const FORCE_PROTOCOL = clean(env.XY);

  const TIMEOUT = 4500;
  const POLICY_PROBE_TIMEOUT = 1800;
  const POLICY_PROBE_BATCH_SIZE = 6;
  const REFRESH_MINUTES = 15;
  const FORCE_LOCAL_MAINLAND = true;

  const servicePolicyCache = {};
  const policyProbeCache = {};
  const policyExitCache = {};

  const SCREEN_W = numberInRange(
    pick(getScreenMetric(ctx, "width"), 440),
    320,
    900,
    440
  );

  const SCREEN_H = numberInRange(
    pick(getScreenMetric(ctx, "height"), 956),
    568,
    1400,
    956
  );

  const WIDTH_SCALE = SCREEN_W / 440;
  const HEIGHT_SCALE = SCREEN_H / 956;
  const UI_SCALE = clamp(WIDTH_SCALE * 0.88 + HEIGHT_SCALE * 0.12, 0.9, 1.06);
  const FONT_SCALE = clamp(UI_SCALE, 0.9, 1.045);

  const CURRENT_PROXY = getCurrentProxyInfo(ctx);
  const NODE_PROTOCOL =
    protocolFromXY(FORCE_PROTOCOL) ||
    CURRENT_PROXY.protocol ||
    "未暴露";

  const MAINLAND_LATENCY_URLS = [
    "http://connect.rom.miui.com/generate_204",
    "http://wifi.vivo.com.cn/generate_204",
    "https://www.baidu.com/favicon.ico",
    "https://www.qq.com/favicon.ico",
    "https://www.aliyun.com/favicon.ico"
  ];

  const GLOBAL_PROXY_LATENCY_URLS = [
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://www.google.com/generate_204",
    "https://www.cloudflare.com/favicon.ico"
  ];

  const POLICY_PROBE_URLS = [
    "https://cp.cloudflare.com/generate_204",
    "https://www.gstatic.com/generate_204",
    "https://www.cloudflare.com/favicon.ico"
  ];

  const QUIC_TRACE_URLS = [
    "https://cloudflare-quic.com/cdn-cgi/trace",
    "https://cloudflare.com/cdn-cgi/trace",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://one.one.one.one/cdn-cgi/trace",
    "https://1.1.1.1/cdn-cgi/trace"
  ];

  const MEDIA_SERVICE_IDS = [
    "netflix",
    "disney",
    "spotify",
    "tiktok",
    "youtube",
    "prime"
  ];

  const AI_SERVICE_IDS = [
    "chatgpt",
    "claude",
    "gemini",
    "grok"
  ];

  const device = ctx.device || {};
  const wifi = device.wifi || {};
  const ipv4 = device.ipv4 || {};
  const ipv6 = device.ipv6 || {};

  const dnsServers = Array.isArray(device.dnsServers)
    ? device.dnsServers.filter(Boolean)
    : [];

  let networkName = getLocalNetworkName(device);

  const localIP =
    clean(
      pick(
        ipv4.address,
        wifi.ip,
        wifi.ipAddress,
        device.ipAddress,
        device.ip
      )
    ) || "未获取";

  const gateway =
    clean(
      pick(
        ipv4.gateway,
        wifi.gateway,
        device.gateway
      )
    ) || "未获取";

  const hasIPv4 = Boolean(clean(localIP)) && localIP !== "未获取";
  const hasIPv6 = Boolean(clean(pick(ipv6.address, device.ipv6Address)));
  const baseDNS = detectDNSProvider(dnsServers);
  const now = new Date();

  function S(value) {
    if (typeof value !== "number") return value;
    return Math.round(value * UI_SCALE * 100) / 100;
  }

  function FS(value) {
    if (typeof value !== "number") return value;
    return Math.round(value * FONT_SCALE * 100) / 100;
  }

  function displayIP(value) {
    return MASK_IP ? maskIP(value) : value;
  }

  function scaleStyle(object) {
    if (!object || typeof object !== "object" || Array.isArray(object)) {
      return object;
    }

    const scaled = {};
    const scaleKeys = {
      width: true,
      height: true,
      gap: true,
      borderRadius: true,
      borderWidth: true,
      length: true
    };

    Object.keys(object).forEach(function (key) {
      const value = object[key];

      if (key === "padding" && Array.isArray(value)) {
        scaled[key] = value.map(function (item) {
          return S(item);
        });
      } else if (scaleKeys[key] && typeof value === "number") {
        scaled[key] = S(value);
      } else {
        scaled[key] = value;
      }
    });

    return scaled;
  }

  function uiColor(value) {
    return resolveAdaptiveColor(value, SCHEME);
  }

  function requestOptions(extra) {
    const options = {
      timeout: TIMEOUT,
      redirect: "follow",
      credentials: "omit",
      headers: {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
        Accept: "application/json,text/plain,text/html,*/*",
        "Cache-Control": "no-cache"
      }
    };

    if (POLICY) {
      options.policy = POLICY;
    }

    return Object.assign(options, extra || {});
  }

  function directRequestOptions(extra) {
    return Object.assign(
      {
        timeout: TIMEOUT,
        redirect: "follow",
        credentials: "omit",
        policy: "DIRECT",
        headers: {
          "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
          Accept: "application/json,text/plain,text/html,*/*",
          "Cache-Control": "no-cache"
        }
      },
      extra || {}
    );
  }

  function serviceRequestOptions(policy, extra) {
    const options = {
      timeout: TIMEOUT,
      redirect: "follow",
      credentials: "omit",
      headers: {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,text/plain,*/*;q=0.8",
        "Cache-Control": "no-cache"
      }
    };

    const targetPolicy = clean(policy);

    if (targetPolicy) {
      options.policy = targetPolicy;
    }

    return Object.assign(options, extra || {});
  }

  function policyProbeRequestOptions(policy, extra) {
    const options = {
      timeout: POLICY_PROBE_TIMEOUT,
      redirect: "follow",
      credentials: "omit",
      headers: {
        "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,application/json,text/plain,*/*;q=0.8",
        "Cache-Control": "no-cache"
      }
    };

    const targetPolicy = clean(policy);

    if (targetPolicy) {
      options.policy = targetPolicy;
    }

    return Object.assign(options, extra || {});
  }

  async function getJSON(url) {
    try {
      const response = await ctx.http.get(url, requestOptions());
      return {
        ok: response.status >= 200 && response.status < 400,
        status: response.status,
        data: await response.json()
      };
    } catch (_) {
      return {
        ok: false,
        status: 0,
        data: null
      };
    }
  }

  async function getJSONDirect(url) {
    try {
      const response = await ctx.http.get(url, directRequestOptions());
      return {
        ok: response.status >= 200 && response.status < 400,
        status: response.status,
        data: await response.json()
      };
    } catch (_) {
      return {
        ok: false,
        status: 0,
        data: null
      };
    }
  }

  async function getText(url) {
    const startedAt = Date.now();

    try {
      const response = await ctx.http.get(url, requestOptions());
      return {
        ok: response.status >= 200 && response.status < 400,
        status: response.status,
        text: (await response.text()) || "",
        ms: Math.max(1, Date.now() - startedAt)
      };
    } catch (_) {
      return {
        ok: false,
        status: 0,
        text: "",
        ms: Math.max(1, Date.now() - startedAt)
      };
    }
  }

  async function getServiceStatus(url, servicePolicy) {
    const startedAt = Date.now();

    try {
      const response = await ctx.http.get(
        url,
        serviceRequestOptions(servicePolicy)
      );

      return {
        ok: response.status >= 200 && response.status < 500,
        status: response.status,
        ms: Math.max(1, Date.now() - startedAt)
      };
    } catch (_) {
      return {
        ok: false,
        status: 0,
        ms: Math.max(1, Date.now() - startedAt)
      };
    }
  }

  // ---------- 精确 AI 检测（源自 fancha0/egern-mokuai ai-connectivity）----------

  function probeHeader(headers, name) {
    if (!headers) return "";
    if (typeof headers.get === "function") return headers.get(name) || "";
    return headers[name] || headers[name.toLowerCase()] || "";
  }

  async function probeGet(url, policy, extra) {
    const startedAt = Date.now();
    try {
      const response = await ctx.http.get(
        url,
        serviceRequestOptions(policy, extra || {})
      );
      let body = "";
      try {
        body = (await response.text()).slice(0, 200000);
      } catch (_) {}
      return {
        ok: true,
        status: response.status,
        headers: response.headers,
        body: body,
        latency: Date.now() - startedAt
      };
    } catch (_) {
      return {
        ok: false,
        status: 0,
        headers: null,
        body: "",
        latency: Date.now() - startedAt
      };
    }
  }

  async function probePost(url, body, policy, extra) {
    const startedAt = Date.now();
    try {
      const response = await ctx.http.post(
        url,
        serviceRequestOptions(policy, {
          body: body,
          ...(extra || {})
        })
      );
      let text = "";
      try {
        text = (await response.text()).slice(0, 200000);
      } catch (_) {}
      return {
        ok: true,
        status: response.status,
        headers: response.headers,
        body: text,
        latency: Date.now() - startedAt
      };
    } catch (_) {
      return {
        ok: false,
        status: 0,
        headers: null,
        body: "",
        latency: Date.now() - startedAt
      };
    }
  }

  // ChatGPT：双端探测（网页 + iOS APP 端）
  async function probeChatGPT(policy) {
    const [web, ios] = await Promise.all([
      probeGet("https://chatgpt.com/", policy, { redirect: "manual" }),
      probeGet("https://ios.chat.openai.com/", policy)
    ]);

    const webText = (web.body || "").toLowerCase();
    const webOk = web.ok && web.status >= 200 && web.status < 400;
    const webBlocked =
      webText.includes("unsupported_country_region_territory") ||
      webText.includes("unsupported country");
    const webCf =
      webText.includes("cf-mitigated") ||
      webText.includes("challenge-platform") ||
      webText.includes("enable javascript and cookies");

    const iosText = (ios.body || "").toLowerCase();
    const iosBlocked =
      iosText.includes("blocked_why_headline") ||
      iosText.includes("unsupported_country_region_territory") ||
      iosText.includes("unsupported_country");
    const iosOk = ios.ok && !iosBlocked && ios.status >= 200 && ios.status < 500;

    if (webOk && iosOk) return { ok: true, note: "" };
    if (iosOk && !webOk) return { ok: true, note: "APP" };
    if (webBlocked || iosBlocked) return { ok: false, note: "受限" };
    if (webCf) return { ok: false, note: "验证" };
    if (webOk || iosOk) return { ok: true, note: "" };
    return { ok: false, note: "" };
  }

  // Gemini：batchexecute 接口取 countryCode
  const GEMINI_ISO3_TO_ISO2 = {
    USA: "US", SGP: "SG", JPN: "JP", HKG: "HK", TWN: "TW", GBR: "GB",
    CAN: "CA", AUS: "AU", DEU: "DE", FRA: "FR", KOR: "KR", NLD: "NL",
    ITA: "IT", ESP: "ES", MYS: "MY", THA: "TH", IDN: "ID", PHL: "PH",
    VNM: "VN", IND: "IN", BRA: "BR", MEX: "MX", CHE: "CH", AUT: "AT",
    BEL: "BE", SWE: "SE", NOR: "NO", DNK: "DK", FIN: "FI", POL: "PL",
    CZE: "CZ", PRT: "PT", GRC: "GR", IRL: "IE", ISL: "IS", NZL: "NZ",
    ZAF: "ZA", ARE: "AE", SAU: "SA", TUR: "TR", RUS: "RU", UKR: "UA"
  };

  async function probeGemini(policy) {
    const body =
      'f.req=[["K4WWud","[[0],[\\"en-US\\"]]",null,"generic"]]';
    const response = await probePost(
      "https://gemini.google.com/_/BardChatUi/data/batchexecute",
      body,
      policy,
      {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Accept-Language": "en-US"
        }
      }
    );

    if (!response.ok || !response.body) return { ok: false, note: "", region: "" };

    const matched =
      response.body.match(
        /(?:\\"|"|\\\\x22)countryCode(?:\\"|"|\\\\x22)\s*[:\\,]\s*(?:\\"|"|\\\\x22)?([A-Z]{2})(?:\\"|"|\\\\x22)?/i
      ) ||
      response.body.match(/,2,1,200,(?:\\"|")([A-Z]{3})(?:\\"|")/);

    if (matched && matched[1]) {
      const code = matched[1].toUpperCase();
      const region = GEMINI_ISO3_TO_ISO2[code] || code;
      return { ok: true, note: "", region: region };
    }

    const text = response.body.toLowerCase();
    if (
      text.includes("not available in your country") ||
      text.includes("unsupported_country") ||
      text.includes("not supported in your country")
    ) {
      return { ok: false, note: "受限", region: "" };
    }
    if (response.status >= 200 && response.status < 400) {
      return { ok: true, note: "", region: "" };
    }
    return { ok: false, note: "", region: "" };
  }

  // Claude：/login 页检测
  async function probeClaude(policy) {
    const response = await probeGet("https://claude.ai/login", policy);
    if (!response.ok) return { ok: false, note: "" };
    if (response.status === 403) return { ok: false, note: "受限" };
    const body = (response.body || "").toLowerCase();
    if (
      body.includes("app unavailable") ||
      body.includes("unsupported_country") ||
      body.includes("not available in your country")
    ) {
      return { ok: false, note: "受限" };
    }
    if (response.status >= 200 && response.status < 400) {
      return { ok: true, note: "" };
    }
    return { ok: false, note: "" };
  }

  // 通用：主页 + 地区限制识别（Grok）
  async function probeGenericAI(url, policy) {
    const response = await probeGet(url, policy);
    if (!response.ok) return { ok: false, note: "" };
    const body = (response.body || "").toLowerCase();
    if (
      body.includes("not available in your country") ||
      body.includes("not available in your region") ||
      body.includes("unsupported country")
    ) {
      return { ok: false, note: "受限" };
    }
    if (response.status >= 200 && response.status < 400) {
      return { ok: true, note: "" };
    }
    return { ok: false, note: "" };
  }

  // AI 精确检测统一入口：返回 ok / note（受限|验证|限流）/ region
  async function probeAIService(id, policy) {
    if (id === "chatgpt") return probeChatGPT(policy);
    if (id === "gemini") return probeGemini(policy);
    if (id === "claude") return probeClaude(policy);
    if (id === "grok") return probeGenericAI("https://grok.com/", policy);
    return { ok: false, note: "", region: "" };
  }

  async function getPolicyExit(policy) {
    const targetPolicy = clean(policy);
    const key = targetPolicy || "__DEFAULT__";

    if (!policyExitCache[key]) {
      policyExitCache[key] = (async function () {
        const urls = [
          "http://ip-api.com/json/?lang=zh-CN&fields=status,message,query,country,countryCode,regionName,city,isp,org,as,asname&_=" + Date.now(),
          "https://ipwho.is/?lang=zh-CN&_=" + Date.now(),
          "https://api.ipapi.is/?_=" + Date.now()
        ];

        for (let index = 0; index < urls.length; index += 1) {
          try {
            const response = await ctx.http.get(
              urls[index],
              serviceRequestOptions(targetPolicy, {
                headers: {
                  "User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)",
                  Accept: "application/json,text/plain,*/*",
                  "Cache-Control": "no-cache"
                }
              })
            );

            if (response.status < 200 || response.status >= 400) {
              continue;
            }

            const parsed = parsePolicyExit(await response.json());

            if (parsed && parsed.countryCode) {
              return parsed;
            }
          } catch (_) {}
        }

        return {
          ip: "",
          country: "",
          countryCode: "",
          city: "",
          region: "",
          label: "NET"
        };
      })();
    }

    return await policyExitCache[key];
  }

  function parsePolicyExit(data) {
    if (!data || typeof data !== "object") {
      return {
        ip: "",
        country: "",
        countryCode: "",
        city: "",
        region: "",
        label: "NET"
      };
    }

    const ip = clean(
      pick(
        data.query,
        data.ip,
        data.ip_address,
        getAt(data, "location.ip")
      )
    );

    const rawCountry = clean(
      pick(
        data.country,
        data.country_name,
        getAt(data, "location.country")
      )
    );

    const code = countryCode(
      pick(
        data.countryCode,
        data.country_code,
        getAt(data, "location.country_code"),
        rawCountry.length === 2 ? rawCountry : ""
      )
    );

    const region = clean(
      pick(
        data.regionName,
        data.region,
        getAt(data, "location.region")
      )
    );

    const city = clean(
      pick(
        data.city,
        getAt(data, "location.city")
      )
    );

    return {
      ip: ip,
      country: rawCountry,
      countryCode: code,
      city: city,
      region: region,
      label: code ? flag(code) + " " + code : "NET"
    };
  }

  async function probePolicy(policy) {
    const name = clean(policy);

    if (!name) {
      return false;
    }

    const key = name.toLowerCase();

    if (!policyProbeCache[key]) {
      policyProbeCache[key] = (async function () {
        const urls = POLICY_PROBE_URLS.map(function (url) {
          return url + "?_=" + Date.now() + randomAlphaNum(5);
        });

        for (let index = 0; index < urls.length; index += 1) {
          try {
            const response = await ctx.http.get(
              urls[index],
              policyProbeRequestOptions(name)
            );

            if (response.status >= 200 && response.status < 500) {
              return true;
            }
          } catch (_) {}
        }

        return false;
      })();
    }

    return await policyProbeCache[key];
  }

  async function firstWorkingPolicy(candidates) {
    const list = dedupeCandidates(candidates);

    for (let start = 0; start < list.length; start += POLICY_PROBE_BATCH_SIZE) {
      const batch = list.slice(start, start + POLICY_PROBE_BATCH_SIZE);
      const results = await Promise.all(
        batch.map(function (policy) {
          return probePolicy(policy);
        })
      );

      for (let index = 0; index < results.length; index += 1) {
        if (results[index]) {
          return batch[index];
        }
      }
    }

    return "";
  }

  async function resolveServicePolicy(serviceId, category) {
    const id = clean(serviceId).toLowerCase();
    const type = clean(category).toLowerCase();
    const cacheKey = type + ":" + id;

    if (Object.prototype.hasOwnProperty.call(servicePolicyCache, cacheKey)) {
      return servicePolicyCache[cacheKey];
    }

    let result = "";

    if (POLICY) {
      result = POLICY;
    } else if (type === "lmt" && LMT_POLICY) {
      result = LMT_POLICY;
    } else if (type === "ai" && AI_POLICY) {
      result = AI_POLICY;
    } else {
      result = await firstWorkingPolicy(
        servicePolicyCandidates(id, type)
      );
    }

    servicePolicyCache[cacheKey] = result;
    return result;
  }

  async function resolveServicePolicyMap(ids, category) {
    const entries = await Promise.all(
      ids.map(async function (id) {
        return [
          id,
          await resolveServicePolicy(id, category)
        ];
      })
    );

    const map = {};

    entries.forEach(function (entry) {
      map[entry[0]] = entry[1];
    });

    return map;
  }

  async function getExit() {
    const baseResults = await Promise.all([
      getJSON("https://api.ipapi.is/?_=" + Date.now()),
      getJSON(
        "http://ip-api.com/json/?lang=zh-CN&fields=status,message,query,country,countryCode,regionName,city,isp,org,as,asname,proxy,hosting,mobile&_=" +
          Date.now()
      ),
      getJSON("https://ipwho.is/?lang=zh-CN&_=" + Date.now()),
      getJSON("https://ipinfo.io/json?_=" + Date.now())
    ]);

    const sourceNames = [
      "ipapi.is",
      "ip-api",
      "ipwho.is",
      "ipinfo"
    ];

    const candidates = [];

    for (let index = 0; index < baseResults.length; index += 1) {
      if (!baseResults[index].ok || !baseResults[index].data) {
        continue;
      }

      const parsed = parseExitSource(
        baseResults[index].data,
        sourceNames[index]
      );

      if (parsed.ip) {
        candidates.push(parsed);
      }
    }

    let merged = mergeExitSources(candidates);

    if (!merged.ip || merged.ip === "未识别") {
      return {
        ip: "未识别",
        city: "出口检测失败",
        region: "",
        country: "",
        countryCode: "",
        isp: "未知组织",
        kind: "未知网络",
        flags: {}
      };
    }

    const proxyCheck = await getProxyCheck(merged.ip);

    if (proxyCheck && proxyCheck.ip) {
      merged = mergeExitSources([merged, proxyCheck]);
    }

    return merged;
  }

  async function getLocalExit() {
    const results = await Promise.all([
      getJSONDirect(
        "http://ip-api.com/json/?lang=zh-CN&fields=status,message,query,country,countryCode,regionName,city,isp,org,as,asname&_=" +
          Date.now()
      ),
      getJSONDirect("https://ipwho.is/?lang=zh-CN&_=" + Date.now()),
      getJSONDirect("https://api.ipapi.is/?_=" + Date.now())
    ]);

    for (let index = 0; index < results.length; index += 1) {
      const parsed = parseLocalExit(
        results[index].data,
        FORCE_LOCAL_MAINLAND
      );

      if (results[index].ok && parsed.ip) {
        if (FORCE_LOCAL_MAINLAND && parsed.countryCode !== "CN") {
          return {
            ip: parsed.ip,
            city: "",
            region: "",
            country: "中国",
            countryCode: "CN",
            isp: parsed.isp || "",
            org: parsed.org || "",
            asname: parsed.asname || "",
            as: parsed.as || "",
            label: "中国大陆"
          };
        }

        return parsed;
      }
    }

    return {
      ip: "",
      city: "",
      region: "",
      country: "中国",
      countryCode: "CN",
      isp: "",
      org: "",
      asname: "",
      as: "",
      label: "中国大陆"
    };
  }

  async function getDNSVerified() {
    const results = await Promise.all([
      probeEDNSResolver(),
      probeEDNSResolver()
    ]);

    const valid = results.filter(function (item) {
      return item && item.ok && item.ip;
    });

    if (valid.length === 0) {
      return {
        ok: false,
        full: "",
        short: "",
        ip: "",
        geo: "",
        isp: "",
        org: "",
        asname: "",
        as: ""
      };
    }

    const primary = valid[0];

    const providerByText = providerFromText(
      [
        primary.geo,
        primary.ip,
        primary.isp,
        primary.org,
        primary.asname,
        primary.as
      ].join(" ")
    );

    if (providerByText.short) {
      return {
        ok: true,
        full: providerByText.full,
        short: providerByText.short,
        ip: primary.ip,
        geo: primary.geo,
        isp: primary.isp,
        org: primary.org,
        asname: primary.asname,
        as: primary.as
      };
    }

    const providerByIP = detectDNSProvider([primary.ip]);

    if (providerByIP.short && !isWeakDNSLabel(providerByIP.short)) {
      return {
        ok: true,
        full: providerByIP.full,
        short: providerByIP.short,
        ip: primary.ip,
        geo: primary.geo,
        isp: primary.isp,
        org: primary.org,
        asname: primary.asname,
        as: primary.as
      };
    }

    const ispLabel = compactDNSProviderName(
      primary.isp ||
      primary.org ||
      primary.asname ||
      primary.as ||
      primary.geo
    );

    return {
      ok: true,
      full: primary.isp || primary.org || primary.asname || primary.geo || "未知 DNS",
      short: ispLabel,
      ip: primary.ip,
      geo: primary.geo,
      isp: primary.isp,
      org: primary.org,
      asname: primary.asname,
      as: primary.as
    };
  }

  async function probeEDNSResolver() {
    const host = randomAlphaNum(32) + ".edns.ip-api.com";

    const result = await getJSONDirect(
      "http://" + host + "/json?_=" + Date.now()
    );

    if (!result.ok || !result.data) {
      return {
        ok: false,
        ip: "",
        geo: "",
        isp: "",
        org: "",
        asname: "",
        as: ""
      };
    }

    const dns = result.data.dns || {};
    const ip = clean(dns.ip);
    const geo = clean(dns.geo);

    if (!ip) {
      return {
        ok: false,
        ip: "",
        geo: geo,
        isp: "",
        org: "",
        asname: "",
        as: ""
      };
    }

    const info = await getDNSResolverInfo(ip);

    return {
      ok: true,
      ip: ip,
      geo: geo,
      isp: info.isp,
      org: info.org,
      asname: info.asname,
      as: info.as
    };
  }

  async function getDNSResolverInfo(ip) {
    const target = clean(ip);

    if (!target) {
      return {
        isp: "",
        org: "",
        asname: "",
        as: ""
      };
    }

    const result = await getJSONDirect(
      "http://ip-api.com/json/" +
        encodeURIComponent(target) +
        "?lang=zh-CN&fields=status,message,query,country,countryCode,regionName,city,isp,org,as,asname&_=" +
        Date.now()
    );

    if (!result.ok || !result.data || result.data.status === "fail") {
      return {
        isp: "",
        org: "",
        asname: "",
        as: ""
      };
    }

    return {
      isp: clean(result.data.isp),
      org: clean(result.data.org),
      asname: clean(result.data.asname),
      as: clean(result.data.as)
    };
  }

  async function getProxyLatency() {
    const measured = await measureLatencySet(
      GLOBAL_PROXY_LATENCY_URLS,
      false
    );

    return {
      ok: measured.ok,
      ms: measured.ms,
      target: measured.target
    };
  }

  async function getLocalLatency() {
    const measured = await measureLatencySet(
      MAINLAND_LATENCY_URLS,
      true
    );

    return {
      ok: measured.ok,
      ms: measured.ms,
      target: measured.target
    };
  }

  async function measureLatencySet(urls, direct) {
    const results = await Promise.all(
      urls.map(function (url) {
        return latencyProbe(url, direct);
      })
    );

    const passed = results
      .filter(function (item) {
        return item.ok && item.ms > 0;
      })
      .sort(function (a, b) {
        return a.ms - b.ms;
      });

    if (passed.length === 0) {
      return {
        ok: false,
        ms: 0,
        target: ""
      };
    }

    const best = passed[0];

    return {
      ok: true,
      ms: best.ms,
      target: best.url
    };
  }

  async function latencyProbe(url, direct) {
    const startedAt = Date.now();

    try {
      const response = direct
        ? await ctx.http.get(url, directRequestOptions())
        : await ctx.http.get(url, requestOptions());

      return {
        ok: response.status >= 200 && response.status < 400,
        status: response.status,
        ms: Math.max(1, Date.now() - startedAt),
        url: url
      };
    } catch (_) {
      return {
        ok: false,
        status: 0,
        ms: Math.max(1, Date.now() - startedAt),
        url: url
      };
    }
  }

  async function getProxyCheck(ip) {
    const target = clean(ip);

    if (!target || target === "未识别") {
      return null;
    }

    const result = await getJSON(
      "https://proxycheck.io/v2/" +
        encodeURIComponent(target) +
        "?vpn=1&asn=1&risk=1&time=1&_=" +
        Date.now()
    );

    if (!result.ok || !result.data) {
      return null;
    }

    return parseProxyCheck(result.data, target);
  }

  async function getQuic() {
    const urls = QUIC_TRACE_URLS.map(function (url) {
      return url + "?_=" + Date.now() + randomAlphaNum(5);
    });

    const results = await Promise.all(
      urls.map(function (url) {
        return getText(url);
      })
    );

    let hasH3 = false;
    let hasReachable = false;

    for (let index = 0; index < results.length; index += 1) {
      const item = results[index];

      if (!item || !item.ok) {
        continue;
      }

      hasReachable = true;

      const trace = parseTrace(item.text);
      const protocol = clean(trace.http).toLowerCase();

      if (
        protocol === "h3" ||
        protocol === "http3" ||
        protocol === "http/3" ||
        protocol.includes("h3") ||
        protocol.includes("http/3")
      ) {
        hasH3 = true;
        break;
      }
    }

    if (hasH3) {
      return {
        value: "✓/✓",
        tone: "green"
      };
    }

    return {
      value: "×/×",
      tone: hasReachable ? "amber" : "red"
    };
  }

  async function testService(id, name, kind, color, url, servicePolicy) {
    const serviceExitPromise = getPolicyExit(servicePolicy);

    if (!url) {
      const emptyExit = await serviceExitPromise;

      return {
        id: id,
        name: name,
        kind: kind,
        color: color,
        ok: false,
        policy: servicePolicy || "",
        countryCode: emptyExit.countryCode || "",
        country: emptyExit.country || "",
        exit: emptyExit
      };
    }

    const separator = url.includes("?") ? "&" : "?";

    // AI 服务使用精确检测（来自 fancha0/egern-mokuai ai-connectivity 模块）
    const isAI = AI_SERVICE_IDS.indexOf(id) !== -1;

    const [result, serviceExit] = await Promise.all([
      isAI
        ? probeAIService(id, servicePolicy)
        : getServiceStatus(
            url + separator + "_=" + Date.now(),
            servicePolicy
          ).then(function (status) {
            return { ok: status.ok, note: "", region: "" };
          }),
      serviceExitPromise
    ]);

    return {
      id: id,
      name: name,
      kind: kind,
      color: color,
      ok: result.ok,
      note: result.note || "",
      region: result.region || "",
      policy: servicePolicy || "",
      countryCode: result.region || serviceExit.countryCode || "",
      country: serviceExit.country || "",
      exit: serviceExit
    };
  }

  const [
    mediaPolicyMap,
    aiPolicyMap
  ] = await Promise.all([
    resolveServicePolicyMap(MEDIA_SERVICE_IDS, "lmt"),
    resolveServicePolicyMap(AI_SERVICE_IDS, "ai")
  ]);

  const [
    exit,
    localExit,
    verifiedDNS,
    proxyLatency,
    localLatency,
    quic,
    media,
    ai
  ] = await Promise.all([
    getExit(),
    getLocalExit(),
    getDNSVerified(),
    getProxyLatency(),
    getLocalLatency(),
    getQuic(),

    Promise.all([
      testService("netflix", "Netflix", "netflix", C.netflix, "https://www.netflix.com/title/81215567", mediaPolicyMap.netflix),
      testService("disney", "Disney+", "disney", C.disney, "https://www.disneyplus.com/", mediaPolicyMap.disney),
      testService("spotify", "Spotify", "spotify", C.spotify, "https://open.spotify.com/", mediaPolicyMap.spotify),
      testService("tiktok", "TikTok", "tiktok", C.tiktok, "https://www.tiktok.com/", mediaPolicyMap.tiktok),
      testService("youtube", "YouTube", "youtube", C.youtube, "https://www.youtube.com/", mediaPolicyMap.youtube),
      testService("prime", "Prime", "prime", C.prime, "https://www.primevideo.com/", mediaPolicyMap.prime)
    ]),

    Promise.all([
      testService("chatgpt", "ChatGPT", "chatgpt", C.chatgpt, "https://chatgpt.com/", aiPolicyMap.chatgpt),
      testService("claude", "Claude", "claude", C.claude, "https://claude.ai/", aiPolicyMap.claude),
      testService("gemini", "Gemini", "gemini", C.gemini, "https://gemini.google.com/", aiPolicyMap.gemini),
      testService("grok", "Grok", "grok", C.grok, "https://grok.com/", aiPolicyMap.grok)
    ])
  ]);

  const carrierByDirectISP = carrierFromISP(
    [
      localExit.isp,
      localExit.org,
      localExit.asname,
      localExit.as
    ].join(" ")
  );

  if (!networkName && carrierByDirectISP) {
    networkName = carrierByDirectISP;
  }

  if (!networkName) {
    networkName = "移动数据";
  }

  const dns = chooseDNSProvider(baseDNS, verifiedDNS);
  const dnsLabel = dnsTinyLabel(dns.short || dns.full);
  const localArea = localExit.label || "中国大陆";
  const nat = detectNAT(localIP, exit.ip);
  const purity = purityScore(exit);
  const risk = riskLevel(exit, purity);

  const proxyLatencyColor = proxyLatency.ok
    ? proxyLatency.ms <= 220 ? C.green : C.amber
    : C.red;

  const localLatencyColor = localLatency.ok
    ? localLatency.ms <= 220 ? C.green : C.amber
    : C.red;

  const natColor = toneColor(nat.tone, C);
  const quicColor = toneColor(quic.tone, C);

  const purityColor =
    purity.score >= 75 ? C.green :
    purity.score >= 45 ? C.amber :
    C.red;

  const riskColor =
    risk === "低风险" ? C.green :
    risk === "中风险" ? C.amber :
    C.red;

  function merge(base, extra) {
    return scaleStyle(Object.assign({}, base || {}, extra || {}));
  }

  function text(value, size, weight, color, extra) {
    return merge(
      {
        type: "text",
        text: String(value),
        font: {
          size: FS(size),
          weight: weight || "regular"
        },
        textColor: color || C.text
      },
      extra
    );
  }

  function image(symbol, color, width, height, extra) {
    return merge(
      {
        type: "image",
        src: "sf-symbol:" + symbol,
        color: color || C.text,
        width: width || 10,
        height: height || 10
      },
      extra
    );
  }

  function rawImage(src, width, height, extra) {
    return merge(
      {
        type: "image",
        src: src,
        width: width,
        height: height,
        resizable: true
      },
      extra || {}
    );
  }

  function svgImage(svg, width, height, extra) {
    return rawImage(svgDataURI(svg), width, height, extra);
  }

  function row(children, extra) {
    return merge(
      {
        type: "stack",
        direction: "row",
        alignItems: "center",
        children: children || []
      },
      extra
    );
  }

  function col(children, extra) {
    return merge(
      {
        type: "stack",
        direction: "column",
        alignItems: "start",
        children: children || []
      },
      extra
    );
  }

  function spacer(length) {
    return length === undefined
      ? { type: "spacer" }
      : { type: "spacer", length: S(length) };
  }

  function card(children, extra) {
    return merge(
      {
        type: "stack",
        direction: "column",
        alignItems: "start",
        padding: [6, 7],
        gap: 4,
        backgroundColor: C.card,
        backgroundGradient: {
          type: "linear",
          colors: [C.cardTop, C.cardBottom],
          startPoint: { x: 0, y: 0 },
          endPoint: { x: 1, y: 1 }
        },
        borderRadius: 14,
        borderWidth: 1,
        borderColor: C.cardBorder,
        children: children || []
      },
      extra
    );
  }

  function pill(value, tone, fill, extra) {
    return row(
      [
        text(value, 6, "semibold", tone, {
          maxLines: 1,
          minScale: 0.72,
          textAlign: "center"
        })
      ],
      merge(
        {
          padding: [2, 5],
          backgroundColor: fill,
          borderRadius: 8
        },
        extra
      )
    );
  }

  function proxyTagLine(value, tone, fill) {
    return row(
      [
        text(value, 4.7, "semibold", tone, {
          maxLines: 1,
          minScale: 0.42,
          textAlign: "center"
        })
      ],
      {
        width: 37,
        height: 7.2,
        padding: [0.7, 2.5],
        backgroundColor: fill,
        borderRadius: 4.8,
        alignItems: "center"
      }
    );
  }

  function proxyTagRows(tagOne, tagTwo, toneOne, fillOne, toneTwo, fillTwo) {
    return col(
      [
        proxyTagLine(tagOne, toneOne, fillOne),
        proxyTagLine(tagTwo, toneTwo, fillTwo)
      ],
      {
        width: 39,
        gap: 1,
        alignItems: "start"
      }
    );
  }

  function iconBox(symbol, tone, fill, side) {
    return row(
      [
        image(
          symbol,
          tone,
          Math.round(side * 0.52),
          Math.round(side * 0.52)
        )
      ],
      {
        width: side,
        height: side,
        padding: 3,
        backgroundColor: fill,
        borderRadius: 12
      }
    );
  }

  function sectionTitle(symbol, title, right, tone) {
    const children = [
      image(symbol, tone, 11, 11),
      text(title, 10, "semibold", C.text, {
        maxLines: 1
      })
    ];

    if (right) {
      children.push(spacer());
      children.push(right);
    }

    return row(children, { gap: 3 });
  }

  function metricBox(symbol, label, value, tone, extra) {
    const options = extra || {};
    const valueSize = options.valueSize || 6.1;
    const valueMinScale = options.valueMinScale || 0.35;
    const labelSize = options.labelSize || 5;
    const labelMinScale = options.labelMinScale || 0.72;

    return col(
      [
        row(
          [
            image(symbol, tone, 7, 7),
            text(label, labelSize, "medium", C.muted, {
              maxLines: 1,
              minScale: labelMinScale,
              textAlign: "center"
            })
          ],
          {
            gap: 1,
            alignItems: "center"
          }
        ),

        text(value, valueSize, "semibold", tone, {
          maxLines: 1,
          minScale: valueMinScale,
          textAlign: "center"
        })
      ],
      {
        flex: 1,
        height: 24,
        padding: [0, 0],
        gap: 0,
        alignItems: "center"
      }
    );
  }

  function header() {
    return row(
      [
        row(
          [
            iconBox("waveform.path.ecg", C.blue, C.blueSoft, 28),

            col(
              [
                row(
                  [
                    text("网络诊断雷达", 11, "bold", C.text, {
                      maxLines: 1,
                      minScale: 0.72
                    }),

                    pill("Pro", C.purple, C.purpleSoft, {
                      padding: [1, 4]
                    })
                  ],
                  {
                    gap: 3,
                    alignItems: "center"
                  }
                ),

                text("Egern · 全面网络状态检测", 6, "medium", C.muted, {
                  maxLines: 1,
                  minScale: 0.78
                })
              ],
              {
                flex: 1,
                gap: 0
              }
            )
          ],
          {
            width: 171,
            height: 34,
            gap: 6
          }
        ),

        row(
          [
            spacer(),

            image("scope", C.purple, 11, 11),

            col(
              [
                text("当前策略", 5, "medium", C.muted, {
                  maxLines: 1,
                  textAlign: "center"
                }),

                row(
                  [
                    text(
                      POLICY ? "●" : "○",
                      7,
                      "bold",
                      POLICY ? C.green : C.purple
                    ),

                    text(POLICY_LABEL, 7, "semibold", C.text, {
                      maxLines: 1,
                      minScale: 0.72
                    })
                  ],
                  {
                    gap: 2,
                    alignItems: "center"
                  }
                )
              ],
              {
                width: 52,
                gap: 0,
                alignItems: "start"
              }
            ),

            spacer()
          ],
          {
            flex: 1,
            height: 34,
            padding: [3, 0],
            gap: 3
          }
        ),

        col(
          [
            text(timeLabel(now), 11, "bold", C.text, {
              maxLines: 1,
              minScale: 0.82,
              textAlign: "right"
            }),

            text(dateLabel(now), 5, "medium", C.muted, {
              maxLines: 1,
              minScale: 0.82,
              textAlign: "right"
            })
          ],
          {
            width: 43,
            height: 34,
            alignItems: "end",
            gap: 0
          }
        )
      ],
      {
        height: 34,
        gap: 4
      }
    );
  }

  function localCard() {
    return card(
      [
        sectionTitle(
          "wifi",
          "本地网络",
          image("globe.asia.australia.fill", C.blue, 12, 12),
          C.blue
        ),

        row(
          [
            iconBox("wifi", C.blue, C.blueSoft, 42),

            col(
              [
                row(
                  [
                    text(networkName, 11, "semibold", C.text, {
                      flex: 1,
                      maxLines: 1,
                      minScale: 0.68
                    }),

                    pill("已连接", C.green, C.greenSoft, {
                      padding: [1, 4]
                    })
                  ],
                  { gap: 3 }
                ),

                text(displayIP(localIP), 8, "medium", C.subtext, {
                  maxLines: 1,
                  minScale: 0.72
                }),

                row(
                  [
                    text(flag(localExit.countryCode) || "🇨🇳", 8, "regular", C.text),

                    text(localArea, 7, "medium", C.muted, {
                      maxLines: 1,
                      minScale: 0.72
                    })
                  ],
                  { gap: 2 }
                )
              ],
              {
                flex: 1,
                gap: 1
              }
            )
          ],
          { gap: 6 }
        ),

        row(
          [
            metricBox(
              "router.fill",
              "网关",
              gatewayLabel(displayIP(gateway)),
              C.blue,
              {
                valueSize: 5.4,
                valueMinScale: 0.28
              }
            ),

            metricBox(
              "clock",
              "直连延迟",
              localLatency.ok ? localLatency.ms + "ms" : "失败",
              localLatencyColor
            ),

            metricBox(
              "network",
              "IPV4/IPV6",
              (hasIPv4 ? "✓" : "×") + "/" + (hasIPv6 ? "✓" : "×"),
              hasIPv4 && hasIPv6
                ? C.green
                : hasIPv4
                  ? C.amber
                  : C.red
            ),

            metricBox(
              "cloud.fill",
              "DNS",
              dnsLabel,
              C.purple,
              {
                valueSize: 5.4,
                valueMinScale: 0.28
              }
            )
          ],
          { gap: 2 }
        )
      ],
      {
        flex: 1,
        height: 100
      }
    );
  }

  function flagBox() {
    return row(
      [
        text(flag(exit.countryCode) || "🌐", 22, "regular", C.text, {
          maxLines: 1,
          textAlign: "center"
        })
      ],
      {
        width: 36,
        height: 36,
        padding: 2,
        backgroundColor: C.purpleSoft,
        borderRadius: 11
      }
    );
  }

  function scoreGauge() {
    return svgImage(
      purityGaugeSVG(
        purity.score,
        {
          track: uiColor(C.scoreTrack),
          left: uiColor(C.scoreLeft),
          right: uiColor(C.scoreRight),
          glow: uiColor(C.scoreGlow),
          text: uiColor(C.scoreLeft),
          muted: uiColor(C.muted)
        }
      ),
      68,
      52,
      {
        borderRadius: 16
      }
    );
  }

  function proxyCard() {
    const city =
      clean(exit.city) ||
      clean(exit.country) ||
      "未知地区";

    const tagOne = exit.kind || "未知网络";

    const tagTwo =
      clean(exit.cloudProvider) ||
      (
        exit.kind === "住宅 IP"
          ? "原生住宅"
          : exit.kind === "移动网络"
            ? "移动出口"
            : exit.kind === "商业机房"
              ? "商业机房"
              : "出口网络"
      );

    const tagOneTone =
      exit.kind === "商业机房"
        ? C.amber
        : C.green;

    const tagOneFill =
      exit.kind === "商业机房"
        ? C.amberSoft
        : C.greenSoft;

    const tagTwoTone = C.green;
    const tagTwoFill = C.greenSoft;

    return card(
      [
        sectionTitle(
          "point.3.connected.trianglepath.dotted",
          "当前代理",
          pill(
            proxyLatency.ok ? "连接正常" : "检测失败",
            proxyLatency.ok ? C.green : C.red,
            proxyLatency.ok ? C.greenSoft : C.redSoft
          ),
          C.purple
        ),

        row(
          [
            flagBox(),

            col(
              [
                row(
                  [
                    text(flag(exit.countryCode) || "🌐", 7, "regular", C.text),

                    text(city, 9.2, "semibold", C.text, {
                      flex: 1,
                      maxLines: 1,
                      minScale: 0.55
                    })
                  ],
                  { gap: 2 }
                ),

                text(shortISP(exit.isp), 7.2, "medium", C.subtext, {
                  maxLines: 1,
                  minScale: 0.62
                }),

                proxyTagRows(
                  tagOne,
                  tagTwo,
                  tagOneTone,
                  tagOneFill,
                  tagTwoTone,
                  tagTwoFill
                )
              ],
              {
                flex: 1,
                gap: 1
              }
            ),

            row(
              [
                scoreGauge()
              ],
              {
                width: 68,
                height: 52,
                alignItems: "center",
                justifyContent: "center"
              }
            )
          ],
          {
            gap: 4,
            alignItems: "center"
          }
        ),

        row(
          [
            metricBox(
              "clock",
              "延迟",
              proxyLatency.ok ? proxyLatency.ms + "ms" : "失败",
              proxyLatencyColor
            ),

            metricBox(
              "circle.hexagongrid.fill",
              "NAT",
              nat.label,
              natColor
            ),

            metricBox(
              "paperplane.fill",
              "UDP/QUIC",
              quic.value,
              quicColor,
              {
                labelSize: 4.25,
                labelMinScale: 0.38
              }
            ),

            metricBox(
              "slider.horizontal.3",
              "协议",
              NODE_PROTOCOL,
              C.purple,
              {
                valueSize: 5.4,
                valueMinScale: 0.34
              }
            )
          ],
          { gap: 2 }
        )
      ],
      {
        flex: 1,
        height: 100,
        padding: [5, 6],
        gap: 3
      }
    );
  }

  function serviceLogoLarge(item) {
    const base = {
      width: 23,
      height: 23,
      padding: 2,
      backgroundColor: C.tileIconBg,
      borderRadius: 7
    };

    if (item.kind === "spotify") {
      return row(
        [
          image("dot.radiowaves.left.and.right", item.color, 15, 15)
        ],
        base
      );
    }

    if (item.kind === "tiktok") {
      return row(
        [
          image("music.note", item.color, 15, 15)
        ],
        base
      );
    }

    if (item.kind === "youtube") {
      return row(
        [
          image("play.rectangle.fill", item.color, 15, 15)
        ],
        base
      );
    }

    if (item.kind === "prime") {
      return row(
        [
          image("play.tv.fill", item.color, 15, 15)
        ],
        base
      );
    }

    if (item.kind === "chatgpt") {
      return row(
        [
          rawImage(
            "data:image/png;base64,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",
            15,
            15,
            { cornerRadius: 4 }
          )
        ],
        base
      );
    }

    if (item.kind === "claude") {
      return row(
        [
          rawImage(
            "data:image/png;base64,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",
            15,
            15,
            { cornerRadius: 4 }
          )
        ],
        base
      );
    }

    if (item.kind === "gemini") {
      return row(
        [
          rawImage(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAJAAAACQCAYAAADnRuK4AAAEDmlDQ1BrQ0dDb2xvclNwYWNlR2VuZXJpY1JHQgAAOI2NVV1oHFUUPpu5syskzoPUpqaSDv41lLRsUtGE2uj+ZbNt3CyTbLRBkMns3Z1pJjPj/KRpKT4UQRDBqOCT4P9bwSchaqvtiy2itFCiBIMo+ND6R6HSFwnruTOzu5O4a73L3PnmnO9+595z7t4LkLgsW5beJQIsGq4t5dPis8fmxMQ6dMF90A190C0rjpUqlSYBG+PCv9rt7yDG3tf2t/f/Z+uuUEcBiN2F2Kw4yiLiZQD+FcWyXYAEQfvICddi+AnEO2ycIOISw7UAVxieD/Cyz5mRMohfRSwoqoz+xNuIB+cj9loEB3Pw2448NaitKSLLRck2q5pOI9O9g/t/tkXda8Tbg0+PszB9FN8DuPaXKnKW4YcQn1Xk3HSIry5ps8UQ/2W5aQnxIwBdu7yFcgrxPsRjVXu8HOh0qao30cArp9SZZxDfg3h1wTzKxu5E/LUxX5wKdX5SnAzmDx4A4OIqLbB69yMesE1pKojLjVdoNsfyiPi45hZmAn3uLWdpOtfQOaVmikEs7ovj8hFWpz7EV6mel0L9Xy23FMYlPYZenAx0yDB1/PX6dledmQjikjkXCxqMJS9WtfFCyH9XtSekEF+2dH+P4tzITduTygGfv58a5VCTH5PtXD7EFZiNyUDBhHnsFTBgE0SQIA9pfFtgo6cKGuhooeilaKH41eDs38Ip+f4At1Rq/sjr6NEwQqb/I/DQqsLvaFUjvAx+eWirddAJZnAj1DFJL0mSg/gcIpPkMBkhoyCSJ8lTZIxk0TpKDjXHliJzZPO50dR5ASNSnzeLvIvod0HG/mdkmOC0z8VKnzcQ2M/Yz2vKldduXjp9bleLu0ZWn7vWc+l0JGcaai10yNrUnXLP/8Jf59ewX+c3Wgz+B34Df+vbVrc16zTMVgp9um9bxEfzPU5kPqUtVWxhs6OiWTVW+gIfywB9uXi7CGcGW/zk98k/kmvJ95IfJn/j3uQ+4c5zn3Kfcd+AyF3gLnJfcl9xH3OfR2rUee80a+6vo7EK5mmXUdyfQlrYLTwoZIU9wsPCZEtP6BWGhAlhL3p2N6sTjRdduwbHsG9kq32sgBepc+xurLPW4T9URpYGJ3ym4+8zA05u44QjST8ZIoVtu3qE7fWmdn5LPdqvgcZz8Ww8BWJ8X3w0PhQ/wnCDGd+LvlHs8dRy6bLLDuKMaZ20tZrqisPJ5ONiCq8yKhYM5cCgKOu66Lsc0aYOtZdo5QCwezI4wm9J/v0X23mlZXOfBjj8Jzv3WrY5D+CsA9D7aMs2gGfjve8ArD6mePZSeCfEYt8CONWDw8FXTxrPqx/r9Vt4biXeANh8vV7/+/16ffMD1N8AuKD/A/8leAvFY9bLAAAAOGVYSWZNTQAqAAAACAABh2kABAAAAAEAAAAaAAAAAAACoAIABAAAAAEAAACQoAMABAAAAAEAAACQAAAAABz3KLIAACdXSURBVHgB7Z0JlB1Vmcfr1ls7HYgxMRHEQRgRZER2go4MARHEDUIIW+AI45zMDGdQBxE1OmN7dBRBcUwARYdBBwhLA664ELZBWQbRE8FgFiEoCWGLIp1e3lJV8/9/371V9V53RzrpdPq9epVU37Xqvbr39/7fd2/dV8/zOlunBTot0GmBTgt0WqDTAp0W6LRApwU6LdBpgU4LTFwLmIl7qdZ6pXUHHXP49HBwvhdF5gVTvvX1K+66v7WuYGLebQegEdp5/YFzT54RDF1T9sIyi4c8v7LJL52124r/7R2heqaz/Exf/QgX/6Pjzyt1B5WeQhSU+8PQ4454qSuofIZlIxyS6awOQE3dv8+za/fOR8HelSiKSxgveeFe+zyzZp84sxORFugA1ARCKeg/stt4+QQfz2N8CvLKKGuqnvlkB6AmBMpe/biU+MSlzCuZ8Ng4oxORFugAlALh0Tnvm50Pw8OrUZjK1SjzcmHwFtYZVpjhjA5Aqc6fPvTikVNMNCNI5bko87pN9MrpQ30dM+YaBWEHoFRjdEX1eblUujnKsq6oMq85P8vpDkC293/91nmzcmH9mAqG7aNtLDNecMx9qDtanazldwCyPT5jcNM7p/pm5kjmi1U4EquanFfy8zN3qW4+zh6W+aADkCAQma6gdoYZwXlmcWh8r+7nBaAaIPLCcCGQ6szio206AKER1hz0nn2KYXhkevKQ4EQwWHUAQ2ioPjU/520GTMY3f/fwW07em3WyvnUAAgE7hy+eOdWPymnvh6pDYAhPDerj9orJe3m/0JWLqmdmHR5ef+YBenDOwp1LYbCwap1npzqiOIClloPpIkg0YQQJQA1AmXCTfiHuje2cdYgyD9BulQ0n7eSFu9dAQmBVR0AR1YHpEhVK/B+CNAiICvnC67r7Np3YASjDLXDlwYsKuMt+LkdeYqoARpWqI4pDeKg4qjriCwlUqkRVwAZv+tyeuT35DDdhtk3YMd7aY0vGO7TfS5moJnMlAAGcql+wfhDrwoxFvuf7+cMOija8owNQBlugp6fHn1Kvn+8BBvVxUs6yqA6VSPfYpNGhRlndFESdQr9gjInOj+AQZbAJ5ZIze+FrDj3umBm1gZ9WjfHrRofrAQAJIMp1mCeJ+4wjT9LMww61CgBdHfVClIW5QvhSvusdZ9z+n3dlEaJMOtFUn2JQWxz5OZ+jLfF7rK+j/g+UB6MvUSCUq3+ENJRHRmOsK2Ytj+nEgm/q4WKeswNQRlrg1Nsefjd8n7l9UBSFhHCoeYp9HQErZdacOXPmjTAhziG9yeWP3u2BweMz0nwNl5m5Tw3XNcMl/nTdzxkCoDPMVlFEdQiNqk4d5dzFkXYhQOJtDRwfq1Hg5w3mjz593vFLMrdmOnMA7brpybPLxj+4Hz6MDtkVnsRcWWDsqEuH8qo26kAnQAlcgGkAPrSfKx76evPiWQ0fzwwkMuVE3zHn9NmvCf/8cM5Eu+GrOrGjTOdYnGWXR2cZJix2phFXR5ohdqlnj7dlnl/k13+eGuyedvDi3g8+nwF25BIzpUCvNP2fKuZyu3EmWRRHTFWiKJqXKBKH66I69H+cCWMoaXWo9ZgC4fFy+a7XmsGhT2YFHl5nZhTo529b8LZX1Cp3BsYrchZ5uKJAcTBsl2G6VSBRm1iNrApxGN9QblUJeRzWR36xMuDnj/rsd/7lgSyAlAkFuukt/9pVCmpf8XK5YqVZTayiJLctrNo01Yudac4BwT/i7lQp7WwHfrGEecWv9Jx9tXyrtd0hygRArzEbLizn8odshplJRl0pEwSIEkBooiwchMjFoS4KSgocAUlNmgJV8Abx/R9TmDKn76XggnaHh9fX9ibs7r89+/CpXv9duGHaVbPOr84up02Rc4jVhCWzz4l5UnOGdMqE0WTF+SmzhlsczB+oebmjlvYufKidQWprgLheZ+e+5+4tGrP/IBY1O58mBkiASoOUxN0ITCABNGmohoFjb28oXLi9AbC8XNmrRtGvhobKc//7+yf0tStEbb0Uobx500VYBL//5jBqcHwdHA4ocYpFWRQgwjIyJFap4rqNCqTH5HWYjwWxfqH7oMivfR7wnNeuALWtAv3kyLPO2ikKv12BS5JWD6pEAlDKdMXmyOUBjhgUzXNQufO5tKsXp+25QvhWGJVFNRMtvPba469vR4jaEqDb3nH2ATvVq3cFYW56Bet2hvspmicgNUGS1E3MmYCxhXppcJK6blhf4utvqoX+Ub3XHflou0HUdgD94L2LZk4d2nxXLszttzlIq4gFQkBwULmQZbrXbTkX1bu8kUJ8U96Wa71miJJy+kNTvHoUrsDyobf3XvXWP7YTRG01jL9y0aJCqdZ3VSEHeOAg69A8GXbLvE3D/I4rc6HeJOXNUhm+yxCeZa4c8z9uyI86elPVzgnZupy9lhlsDvFtvILvm4X5qQcMBqVvzJ17d1v5nW0F0O4b+i7uyuXe14fv5/Buue46T+Mm/WKIBBIHCsL4tkXS8QJLAyiEJinXY5J0gHNwd+Cw3MUrYd0LC93z83vOolPdNlvbmLCfnHj6R7oi70uDddznCgBEVPRqIZQjKmBEBTWiyeGtCjfCQnqYM5x2pKU+jrGmKjFRPEdezimmzdO4lnMEpqaNr0kn2pk/lotTjeF9Lah/+N6r3vDVdqCoLQD68fzT31+OoqtqWGtaCfCpBzS1oIh5GMQBEYfpOjTXzmen0oFugMJ2vOtwhlqeHBNy3gjKlkBi66SOFVDiNOFy59GQk4yhX6oFYXD2A9947bJWh6jlAfrhyaeehOf2XFcPc+UKlSek8rgQcUAU3/yMO5YqQTCSzk0AUwVxkKTrOLjoIDv4XMj6cdyeV9KiUCiz4DEvxNIPLIUdqIXhab+68lU/aGWIWhqgH5522ru7veCGIPSnDgEeqk0VpouhgsQ0AEInaucrNA1QCFRJfgwJOtrFpb6tp2YJ6hWfU+s1Q+VgcmZMwOE5CRr2CKYMeS9Vg/opK78+7aetClHLAnTbwpPfg4dhXgd4dqbfUxflUZ/HgaQQASjpfKcQDhZC5eIJBA4aHcYn4AkQ7PwUWApR4uvEkFBl+JpQHdZxxzjICJXUFYjMi/V6dPrqKwo/aUWIWhKg294/f/5UL/oWlWewTuVRp1nBod8D/0dUqCSKpAqksLDjHFDDYUn7RY1QCQQNICYwCQxWkaQeAbK7qpcFxgKYVqUI67CxvQTSzly11LScOWs5gG7/+/diTbP5GqApD8XKoz6POM8OHpiyalgSU5aYMB15DZskbFIW6XQAoJ1vQ5tO+zoNkEh5yml2sKTAcvVFgVAeQQG52WAA00WLVi8110lmi/xpKYCWL3rXRwHPFzBMx2hLfR7n66jfo74P/SAO4x1AdS/lSI8AQqJEhMUqlQBgzRziOnTXcmeCEsBS4OD8Aoocw3hafVw9gtPU9MhCTh3LiS5YvcS0zBC/6SomJ/Y9CxYUj5j90sWA50OVKr4IKKMsmCoM1euEhf4Phu8KjYY1qE9V/CKokAA0XEkIixsdpSEiAA2jsBgGZ7YUBAHIAuPmhsQvEvicGXPQII18pzojtjR6g2oUBd4lu8zwFt/TY+oj1ptEmZMeoFv/6dhZM8vBN0q+f0J/BV8EhG9Tt8N1dZwVIPV7qDwYedF0UYEC+kAKkPgddv2PAOKUyIZp1UiUxQHTHAIKC0kaIjcyk3MRLOtAa3oE1RkFBEx+e2Hg9ZrA++dVl5tNo1SbFNmTGqCffuSog6f64dUFz99vcxWTgeIY6+RgnYpDUESFnNooTA4gllcIEGByHc3Q7TJSogrJjDFC669IXac6qfkbdw6tr1DF4AlQidpQkSJChJ0PrRrrhvlGKtGvsA7unNVfNY+M9fiJqj/2K5ugd3b3x484u8sEl5ooN30AZkvhcX6PjrQID81XPcLtATFjFiRAQz+oil9rcjCxQx0AsZ9DmFJKko6nIXHHEQaFS89FQNwxrB/DBOgiUR+qztZvOD2ehOa9ACX60KrLzKSctZ50AH2nZ+4rZtcHLyoY7x/rge+ps4xRVuw0WwVy/o1ABJWhGqWAIThVgKUAyZocVZ4UMAJEKu1AcaEqVFpVLEDoWTFPPJZzPQJSUo9gbY3qjISa+ER83mfoLfX6vU+t/m8zqZbHTiqA7vm3w47oLgZLSsYcsHmI/o5THnScNV9yg5R+kAPIKo8C1BVDRN9HIAJUNfxYU936I6ogCQhMJyqi+TFALLPK4o5TlVFY0vWcAmEh60gcbHMeTRpu6P8iNN55a79q/m+bTzhOJ5gUAP3PBcd27/OKZy8smvBCY/LlfvF3CA9MFpUn4jyPKo8DSEwXVUZA4h1uKpACRCWqUI0EIpQh5FC+4Q451CMNAONpSBw4oi4oU3CoPKgHLzdOSxnTL99J3tq+w0tRi/rxJj4/1Odd+uS3zNDWnmu8jtvhAD3whQPmdudrFxd9c+hABU+DF1MFeCIFiDdG1WGm/8NRlk4ais9jAaoTlhRAVQGpSyGiAgGgoHkob32UtG+UhiWGyyqXmjMLkvN3LFjbS3VG7GT0GEHCpON9eCTIhauWmPtHrDdBmTsMoNu/eOCury4OLsZYZREe3V0YiFUH63nEdBEY3fXuOkdddoeDrMN2qA59IOvr1IMu9XuCKaJGBEl2lKsCQT1GUB6nJk51YnjQU5zFlnILy9YOzce7Py1EQ+jAK2pV74uPf908N96v8XLON+EAXd0zt3zojKf/vmSCjxdy5rX9aIIq1y6HGKZDdRQeXRRG0yX3uQQcKA/AkcVidJgZZwhV4mjL+UBVQFSLAA4gqoYECSFHaajfoDB0gAmIAyM1SovVRuo0AWTVZ7yc5JfTSaPWQe/JnFHdWwfT9rn8M961K3tNddT626FgAgHq8R/72rITSqa2uJSLDqnUjTdU49wObh2I4jin2ZkuwkRzBYgwOahxqg3jhMYBpM4y/R71gazqEB5CFEwFQISKAKWH8urPyEw0IbKwpP0gVR4FSB1tzu1sHyd5W/pW3hLeFuaN7se80X+sWWJ+tC3nG8uxEwBQZFZ+4/XvnJqvXVAw4dERvmYzUMFDLQUcBQiLwSQt6iMqROXhLQs6zgQJ0Ag4asJkdtkC5Ibp1YAAcdjuzJcqEAGqhd04XtbfAJQmiNIqRHNlTVyUgo0gjefQfCwdNJa6eJt0svn/R/jzJdxTu3ssx29N3e0GUE/P3PzC1/3+XVNz1Q/6Ufj2HD4m/XCSxVTRXKV3QKWgOBNGc+XAYWhNl5gtPJYOTrFzoitizpimI00fiCMxqlC3NWMACBDVAZb6OFZRHDjWlKXBUuWhiVOgJqPqbKmz8bapRhEePvsjfCKWrJrh3eH1mPRPgWzp8DGVjTtAP7tiv+l7Tt80Dz9QuwgD5zl4ii4UB0+Cx6RggEkMVR4N1d8BPAAo9n1SCqSqAyWy4Kjpohqp+dLZZguPqI+aLweQ+D8hTJhVoRDgufma2PchQFSdHTQ0H1NvjbEyQcIogLf578XfK3M17/srrzCbx3iaLVYfN4DWLvurv5leqC0s+sFp5Xy4RwAfh+Co4uB3/iw8qjwAyKkOwIrj1onWobpTIPpBXJrKEL5P7ANxpjlxoGXoztGYqJB1nkWFoEThTji2Gz/zRTMGX8iNrKy5Svs6Ekd+q6nOlnpZTBsqYOi/Gqbt2nzeu2HlV8zvtnTMyy3bJoAe/eYes2dNqx5bztdOL/jh3K5S1IUhpTeEPRQTNRJAqj6qOtZ0OZjo71gFqiKk86xLN2i2rPNsQ466KhYgNWlUn8QHqtDv4QgMCkQTxjCAeYs8LGjHcW7IHsNDJUJLc2/Xjc42Lw8z2n0wb8vhK92Q9707AdNWf1t2zAA9ds3uu0wv1o/oKtRPLPjB0V3FaDZ+/Mir4udu8BAMUE5ACI6qTkCFYR6eZBqrD+CqCTQMqTRUIYZuJzCEib4Q4taJZsjRl5g0mKOKONKABnGd8+FwndBYH4gKRJAEIPwmDwASM4ZbG4TIwUNz1gpO8riBjV6Xz4n0l7ce570dZu57aOr713zZvDCW1/mLAHHe5qi/Xrfv1K7a2wqmdmzOj+YAmpn4jp5Xq+GxKU2uWTNAAo8ARJAICkACVAqNgiTgAChRGwGHIBEcCxBVh2rEnQAJRIkJ05FYokDqSHfjRixHX3SmacKoQFMSgGjOoEaEqJ3M1Vg6n3VFlTgFoDBtRNZ9gGK5H3j3zXqVt/ovLWrbIkBPX7fLwmlTa58wUbRPV4mOQeTVsEauGZr0m44BEsVxvo+qT82qUKw+VoligBw8ojr0eahE3N3wnRCpAumNUsapOqpAFfpAYrY470NwVIHUBwJAUKMI6iMqhLoejotwWZ1NWwBmDQ+CoM8NaxJ4FaR/g/Bzay4z3x2tjcDeyNtTy3Y78pU7Vb/dlQ//xseinCE8aIe+zZbgkTPh1eWNMIE4mLF7hM5iHCH2kCHJR3noM23jTLu8HPJRh+WB7Hh9F0cZJrCRxkJihHWmEQ9sfh31mC91pNzVY57Bj6Tw3ByiNEko33dGN1EhCAR8JG4lLCw4GAp1/Rs+FB06WpOgyUfeyhhRlaA6Ffg2PPHL30aobOFoBIqgsBMVJAHFwhMIYOhopGNwBAYLCUERWAgDQGE9C0sd+c3gaBlUEODwuNAPAS5aya8DYkI0wnt++RfcnjXRJBGbqOCVMYO0YLSL5EzBuG7oS90YYb8gdN0jasRsvjmbz8+/7ABJgEKCznggO4BBGOKAQHbkA66Aj6yzeQIP8vh1hjrLcF6qpMuX+lQtnAgPWfEMZti8sKaL1yF1+MEv1WyYSo0g6GyNLbCFG3/4PI68bR4qLKtWvKCEhUyxSRq56vBc9IlsFhLGE1OWxBOzRbOGfuVOkOJd06oaFp5YeZBmnHA4UyVlTOseKxHqeFQaKo4oD6dpnQLVoEKIY91oZ0u1APqCE5EwZxW4pjelShqiowK0x1nr73lusHg2vvn5WBiZoIzfRyoX4WONeoQ9L19Youg0blAFwsHQxSN0qPOFNLTwoI5AhPo0aYTDhRInKATG7uL3EBaXZ8ERgCxMNFdqqmCLfe6ESEM8PRHvSaHCwzAlLu85q3/Yd4CGd/ixVWE6fgUzdvqar5pfjNYk6JLRt6/cvPmRmYe9+epdi0Pfw7zOY7WAE+PmleWCN6WARcu0TTQ3zRt/AZLZAE/NE5Di5ztIhfyVwAC7/lqgCzHMd3nw4PirgHwMC/eahJhcxPwBnr+MPO4YqdlQ47gJizw+1EkmCvHR4W0K3sCNYKIipPH+7dtlSBPGpM1Dgv/QhMzMxMbrJzQSRt6z6LjlmLFeis/yp7qHvIt+83WzcksNYVtuS1Uayx6+5o27vLrrpSOm+PUTcdvi6ClNE4msTXBq+OBzuK4h0siromOqLGOcZdgZUiMJBR+IqcN2xjl8x30wrCRkvOLmgTCMr2D+hsN5fmVHJhE5fJedk4hYPIaJRK5S5AKzOpZ0BAwxvA8RjzCHZDAhiWfOQRBtyDReQ/MLCPkR3OJnq7FRWi1FaHh5+JQDlqcRuxPAfLdW8n7++JfGtjBtzACl2+rBZXvM3q1QPQ5LNU7Deua5XeWoK8DkItf6pMFRYAiOAlTFp5zgxLuAxZumAAcdJyEBwj0rAiUACUjJPBBvYwhAGG3qty84H8Q78Vj/jKUdhCgARAGgSUCaAnBghwGMwXkbQkIDoGK4CFWbKRFE3N3K6MfF3QXVuQF3DZb/bqnZ6p+n2iaAEpiw5mfZ7vu+qlw7o5yrn96dj/aoYtTTXyUouqcVSPIEIsICkNBRVCFRIweQgwehUyBVHkAEBZL7YFAgVSECA3Bk13VBhCigEkF9RIGoREhHWDsdK49TIBeKMqXgEiVqfXMmasPOCr21+LssDL0bMDm4Kum/rY+NE0DJG/ghlnMcOGvTvKIJFuVy4Ry6FH0pkJwZq6RUqEKABBzCRGBowqhGqkIOIDVnasIEIKiPWxeUBohxLukInBIJRKpEEcoalIdKhG+5iiKlFUigoiLRnI17MyUNth1j9G3ofMJS/Qx/rvS6vO+vvnh8v1e23VpmLhaUfe2NTxzflat/yJjg7fwUECTxc9AhAhBDKo8FiGWxCQNQBEeASvlBVCFVH94fo+pwbRAX2QMapqEwNF3qA1lTJr4QgYIfhDI1X+rzOFOW+ESNCiQmjZC1EEQEhwvK8KZ/jEnAJatmesu9nhZZUDb8AxWZh27a47gppvZRKNLRHHn1YcSs0ChQVKCqAKMAESKnQFQhcaAZCkh0oPXemIADX0jBcaGasgQi+kKJKQsRF1igLI2mzDnWaH36SDRnAIehxtMjuOFXORlyYscY4ACfSyZiSSs/Wtt5M9Fhp3h4fFvP7ffcdM0JXX5tcbEUHhJQWjENAxdJPiq4uaAz0ZhR1jhNto1jqMAPFGef8RfvN4eZZIactsbO2WVMBMosM/NlPSfzdLJQXqghjio+Xpgz0Qh5A5ghN7yU5kFx+JmVejZOoCbjRucYn0Fe9oQvqp/Aseo90bd6/7Rqt+MPvGa6N7DR5MI3F0pmWgWdB0HC/A7mgtAKOg/kQs4PIc4nZEC55DG76Ex+kY9TBfzxW+bJjnoMpQx14vkfwBbCNGoac0Koo+YIwCgzejuDkDBNollDihlnvs2TAyaRU423JU/xiLwn0Hgfxdd6zl919fg4x9IIL+OPtszLqDjeVa66/sBdpxf6Fvt+sAjWpNBXo19EE+bjB2xprhin+dI1QbKwDGn55ipNmNudD2T9IXWg4RPRgcbcEB1pMWd0pK1jbTiUp5qkzRidZZorcZ5T5k1MGc2YLWcIKHf0RnMFtRwC75cHFe/izHyxsLnhv3n9m+ZOKVe+6BfDw+gbDUIthtC54kyjo7hiUdZDI8+tDZIvGzo/iD4QOrmeAoiONZ1ozgk5gBI/iOuAOJmoAOncD+I4XwyJwEWYUtBIufWTCJUoWfPVTEAaH3mBJ/B+Dqt9IR5AtUN/3HeHf5R+cMtzT+757kOu78oN4OGp0RyvYPKcM1IPB9/kgNkQUwUzwriaLBvCbPFGsTw0QcyUmjHWVzMHk8U6gFDMG0Lmy81ldgT+yebiLkRmbLYazJc1czwSr8czTORGcPCKm3ExPZWXvHN/903z5ES+/kivNbEtMNI7SOV9vvfNR5TLtSWmEB3ArzzLED+lQKJGMGMNXzSEMsjDp6AqOqTnMF6H9To3pEN6VSKasTKcTU4mUnU4ylKVScclj4ozTIGsIqFMR2pITwRE6CX7FeaHMI44b81SM2l+h3WHK1CKH+/O3mf/8MZT3nRjPqhM9/PRIXInHmqEVTyJElkFCURxtIwKlDjPiNOhZrkLrSJRidSJVkeYCwQIQPpTFCuPzdXSpI6Wp3O3rxLhEujQR/B3lkB7zllzpVmXbrMdHU+33Y5+Lw2v/4lbDzqnUKh9GRDJI+7ctzToB/GhCzoXRDWC2kiem1BkmnEqkZ0TkhlppjmZCAVCfuxEi+NMZcEuykIH2ioN8tSptr6Py3f1eCz9IeZvh00mBEPvBcxUfHDtUnP9dniJbT7lpFKg9NX8/MaNK/aft8cdfj54S65oZtex1DCgGuHjqMtE6O/YNBQm8Y/UD2IZF8xrqIrEtPhAUCf55Fj/hq+rUfd5sgqjlWJ/SNTK5cUHOXVSVUtfw7bEOTzHRf0Scxzz11xu7tyWc23PYyctQLzo/+vdsHG/Bfvf4oWDe+fL3t5Yj6QQERzZHSwOJgVF532cWdMwdqStOWs2XQkcfGVQ4kCREEkSBoC1FNC4cskgRMwYH4jE38FjfvM579TfLt3xjrJc9Ch/JjVAfM8P3/h4/1+d9LZbC+HmabliNEcnEO2ITPwcC5Pziej3iNJQnQiUUyIHEkNctrIQg+Dax+kJ0y4+LLTKJfk4j4b4i/cQn9idcCwhz4W3Bn/n4tUbvXOfv8oMjOXwHVHXNuOOeOmxv+Y5txx+Ya4QfAHfI/P1553cJCPngfT+mIb0dzg6gw8EfyjAqIvzQvSJOAoL4Qepv8PesvM/8GPi0VfzyMzVif2lkUZo1k+iT7QVSkRnGVsN8FyA38tYIqkW+DPpFSjdhituWn/fvgv2fMrPRe/Ehz3Pr0+rj+NMGkIZtVFlmEc1UuXRED4QDnRzQcmIi6/Cj7/VGhe6bCljDf28xcellYilUkwlYkTr8hR/abPwDMDn+cDqy8x//aX6k6m8pQBiwz1y4x9WvGHe61f5hfDdYKHIr/AIKEiIyXLAoDcbAdJ7aApPYmpiGFIdLqCg/xMEYnQSSPhmAIrUEeC0tp6PECWvwaqjbRYe/tzTGXiY+C2j1Zus+S0HEBvysd4nH9v7xL0ehQa9B3fLS/y+feJUO3BcmKiRwpOeC0p3ugVGiQAA2mUOJqbSsDm1kXzBCDXdsQhVhbYMEeHBy7yIWxKnAp4JeyydXtn4/G1JgHjpv7153Zq/nr/XoyYfngCIoEQpiKg+VCSaMPSSmC2E6lBrvuCi/OBs7Hwk0JsNwEi+bWilQ1CxpMRA6fGsx6PdSV2cEA3fnPJYeH46vEZr5LQsQGzeNb2AaN4+q00hOAH85GNAqEgEpsEHYsc6eOgL2Q62YAg8I0DC19FsCwYSjLk8FzqIYoCkYBSIwBTOMWDNVksqD9uFW0sDxAtYe/Pjv33dSXut9wvRezFN5Mtko4CSKBJNF2FyznPiB0lH6p9YfQQP1RFGxZQBBMZlQ8TGHSwauszGXNbVHKtETHMJFBzmVvR5XCu4sOUB4oU80fvEit3n7zXgF6Nj1al28Kjj7Pwjjsz07rzC5KhIAyAYOBaEFJvA6zg0+JoSJwxSh1BovTjNfOTFuVA8KqCd5zm/1UZbvOaRtrYAiBe2rvfx+187f6/pftk7PMBtj9j/QRcmcadEAElGSTjQdbz2tLSRg0PwiPMR0f9SJ4YjDYnUxdEuZE0pZ4bBHXWYznp4yeql/uf0JK3/d2QPr0Wvq3/T7h+tV/zv58q0RzBoqd3Y78Dr9+Fp7Pi9eFcneegCH8IgD16QMuRjrajUlfpIM+S6a56vIc+dIxW6ctQ1JTybMazevMsMf3GLNu+Ib7ttFIhXt/GHvwxnnXjoHcYbfJdXNLNk4b71h5zfo74QTZmqgrSKjcvQndni94ARlRI7JJeaapJEVZhGZf0vcR7KDD3MhjBdPm7kRcHQCsyNL/jFRWV+K7RttrYCiL2y8ZbfDOxy8n4PGL9+KpaCdHF4T1gcQOm49L50JSmw3U94JG7TLp/1JAtgOMA0QwpsNeJjc1GZQpjjco9gUxjVTlh96czf8zTttLUdQOycp3tXPTPrpDc9bfLBPD49RG93uFEYQwKlYLnulk614FhO4n4eyxxRrFo8F6YS8PtnYRTW/uHxS15zV3zCNoq0JUDsn2d6Vz0y6+S9X23K5pAAbosqjwPHjsKoFejoBCJNi3LYMpEdKomVGIVL/goGLt8mUgFMVwHfxa8NXfb4RXteIgVt+KetnOjm/ukfmvaxoBL92i+RAOcwI8QkTJxGPO0Y65cRnSNtHWh+KZG7ONjqQOtDq2w9cay1Dh1w7qaAEV+975f54LlPNr+vdkq3rQKxk/5466OVV5904IooV1uIe64FefAVzIo+AItqYz8/MkfjdMiqEBUIm+am4hqNS6WS1NPaIlzyq81evwmjBb/7wpx1rk47hm0NEDvs2ZtXrp8xf9+86fLm8vG16v80mjBIhvatmDNEIVhKiAVHAhsXQlgHaNnD5GB3LMpNAWuug9pn1n3m0BulrI3/tLUJc/22Odrj4nAwfNg4U2bnZ2IzJmk1a/LYX6ZjM+fmdVCeniNCHZkjsqbNzQuZIuCs9z8YhUOXutdv57DtFYid91Lvg/WZ8w94LMrXzoQpyyWLyjBKovrECmNVJi0tEoeqOFViiM05z2riXJ58HvFs2+j0J//97U9qbnv/zQRA7MJNN698avrJb5wNU3ZYVOdTPnQYz7J4BWEKJEVJSkkLIxYixm3a5UshTRcmDGu1y36/+F1XMSsLWyZMWNyR/k6fjSrheq+AmSGYIzz4Ss2SvTURmzTkqymjWdPRlZgvV8+aQHfLA09B9rw8pCno/0M1HPp8/HoZiGRGgdiXf7rxkf7pp7yp3ytG7+UjhahCTk0Yijly5ktMm80TEFCXZeAkqcc8+S8zzuDo/A0fO/U+qZ6RP9lSIHRqbsOu346Gol+aEryhWFFUiVSBoDjM544bqaIyrp51mFV5WI/ONnY8MzuqDz40tc9cmxFu4svMlALxqv/444eCafP33+gVgtMinRhCrlUXiSHuZIWh3RlL6rkUQqqS4aPy84se/8TC1VItQ38yp0Ds2z/8dt/boqq5Gz+falUIauPURdSGaatCDFEmPhHrUHFcXYSmCIMWVO5Y/+d1LbuumW2ytVvmFEga6p57op0WHLABZupMPplRGw+BTChqUvycWIFYAznOP3L56hPxx4QW9V348XV6nmz9zaQCsYs3rNzn7qjq3817VvhKauL3xOoC5eFkIv0cq0qxP2RHYVQfOD93bDj3g/fwnFncMguQ19ODX5UqfxlrPTCu4tBKTZWGCo7cZBWILEioI0N2a94iTCiZKLwU0oQTZHPLLkDo7/Uz91oOX+gXokKEiEoTj7g0rr9oSL8HaQuZgFVE/aDy4FPPDt2ZTXT0qjMNkHdUTz0Ky5fHd+UFosRkxcA4eBocbExG5vwroGQ4ILtbtgFCv1crM74bVaInPfyeqm5NSmRVSU2XhYuzztXaE0NR1/eyi45eeeYB+uOZS/Fgg8J1ppAekMKppjOdVh5xnNWMGZgv/LvmhQ98rK8DUNZbgNdfL16H2elBGZ279nAjM0LEuR8okbs/FlWrA7iPf52rmuUw8wrEzt942v+swnTQvepMp3AgPG4Y79YHcfIxCu9af84la1M1MxvtACRdj2F4UICiOD8oxYNAZEGKzZrXUR/bRB2AbENE3qt+ElW85z37qz0phGJfCN/Q8WC+njX13PKG8gwnOgDZzn/mlKXPY6XincPMmJTbkRnnfoy3fMP7L9+UYWYaLr0DULo56oXvYGZ6lA3w0A+KzHdGqZDJ7A5AqW4Pg+7/jarRphHNGFoqqobPR37+Z6lDMh/tAJRC4Lkz/utZ4+UeMPnhzrTJcwG+/8Azp1y91T+RnXqptol2AGruyiB3e3JrI1XILyEGHec51SIS7QDU1CJ46CvMGL6CmBYhxJmHH1bpmK/m9mpKZz5Zfnraai/019BkuU3ioVnbtfP0VS6vE2oLpG8AddoELcA10zvP338Tvn74PlPycxaemqmVP/z7E6/6daeRGlsgLdSNJRlP7XL9mUeYcu0UPODMi4ZyvRtPXXZvxpukc/mdFui0QKcFOi3QaYFOC3RaoNMCnRbotECnBTotsMNb4P8BmP5vzw6Vz38AAAAASUVORK5CYII=",
            15,
            15,
            { cornerRadius: 4 }
          )
        ],
        base
      );
    }

    if (item.kind === "grok") {
      return row(
        [
          rawImage(
            "data:image/png;base64,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c8AIASaQEXycmAnEHDBCgAlkBB8nZgKVEg6cd56dprRTailpNFeqUaNGDVG7dm0r6jCBrMAeX6EXXXSR6NChgzh69Gh8mYbIiQkUAizXbr3wwgvFo48+Knbs2CH++ecfK+oxgazAbl5otWrVxOzZs8WWLVvE7t27zTOMmAMTKCJwNpNVqVJFLFy4UPz8889i9erVNlURZah0jpFotQnCFX7++eeLV199VVxyySXilltusfbqytYaBOJ/RYAB9TzyzTfflEeOHJHXXnutK23G5CmGB4h6HrlgwQIJGTZsmCvkgR5MINcxQM9DYx6PPKtWrZIVKlRgArncaGXLlvUaCQ2FzzZ1Rc+zZMkSjzyOvbo8XMoROP+XUqZMGdGgQQNx1VVXiUaNGnn/GjZsKC677DKBgWpma+DMmTPi77//Fr/++qv48ccfxffffy9++OEH8e2334o9e/Ykil3lypXFyy+/LPr16+eVM2PGDPH5558nWmaUzK0+YaRwauXjVdCxY0c5efJkuXnzZrlv3z7vyY7yH02h5bp16+S4ceNku3btZMWKFWOtB/JbtGjROdU+++wzecEFF8RaRkzYp9eAMSkcGkTqZbyG/vTTT881SJwfTp06JWlBTw4fPlxSrxZav3xcqOfJIc/Zs2fl3XffbZxvfjkxfS+9BLruuuskvQLk4cOH4+RLYF4HDhzwyrz++usjNTjGPLTOk1PGu+++K8uVKxcpv5hIElR26SNQ/fr15dy5cyVtMOY0RJpf/vjjD/n888/LunXrBoGfcw09z2uvvZaj5unTp+Wtt96ac18KpAhTXukhEA2M5QMPPCBpbyinEWx+oYG3fPjhhyXIEdTwuJ7f80Dv9evXy/LlywemDco3hWulg0CXX355wQawSZ5M2V988YVs2bKlLwkwYMartpDcf//9vulSIIdO2cVPoLZt20qa3hbC3+pvGzZskP379w+cPVWqVEm++OKLBfXcv3+/rFOnjk4j2rynuAnUp08feejQoYINYOPHkydPSqwW9+jRQzm1R88zf/58XzWx7+VIL+OrR1EvJN57772CBsuCnmLCOZrAEOu7777zFglprUXs2rVL0KxNnDhxQlDLChp/CBhu1atXT9AGpmjatKm36FizZs2cAo8dOyZWrlwpXnrpJUHjFkFT75zr+V9olVvQIFugDn7y/vvv+11y6ndf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",
            15,
            15,
            { cornerRadius: 4 }
          )
        ],
        base
      );
    }

    const mark =
      item.kind === "netflix"
        ? "N"
        : item.kind === "disney"
          ? "D+"
          : "AI";

    const fontSize = item.kind === "disney" ? 10 : 13;

    return row(
      [
        text(mark, fontSize, "bold", item.color, {
          maxLines: 1,
          textAlign: "center"
        })
      ],
      base
    );
  }

  function compactServiceTile(item) {
    const statusColor = item.ok ? C.green : C.red;
    const serviceCountryCode =
      countryCode(item.countryCode) ||
      countryCode(exit.countryCode);

    const serviceRegionLabel = serviceCountryCode
      ? flag(serviceCountryCode) + " " + serviceCountryCode
      : "NET";

    const statusLabel = item.ok
      ? (item.note ? item.note : "OK")
      : (item.note ? item.note : "失败");

    return row(
      [
        serviceLogoLarge(item),

        col(
          [
            text(item.name, 7, "semibold", C.text, {
              maxLines: 1,
              minScale: 0.66
            }),

            row(
              [
                text(
                  serviceRegionLabel,
                  5,
                  "medium",
                  C.subtext,
                  {
                    maxLines: 1
                  }
                ),

                text(
                  statusLabel,
                  5.6,
                  "semibold",
                  item.ok ? statusColor : C.red,
                  {
                    maxLines: 1
                  }
                )
              ],
              { gap: 2 }
            )
          ],
          {
            flex: 1,
            gap: 1
          }
        )
      ],
      {
        flex: 1,
        height: 31,
        padding: [4, 4],
        gap: 4,
        backgroundColor: C.tileBg,
        borderRadius: 9,
        borderWidth: 1,
        borderColor: C.tileBorder
      }
    );
  }

  function serviceGrid(items) {
    const rows = [];
    for (let i = 0; i < items.length; i += 2) {
      const tiles = [compactServiceTile(items[i])];
      if (i + 1 < items.length) {
        tiles.push(compactServiceTile(items[i + 1]));
      }
      rows.push(
        row(tiles, {
          height: 31,
          gap: 5
        })
      );
    }

    return col(rows, {
      flex: 1,
      height: 101 + (items.length > 6 ? 0 : 0),
      gap: 4
    });
  }

  function serviceCard(title, symbol, items, tone) {
    const passed = items.filter(item => item.ok).length;

    return card(
      [
        sectionTitle(
          symbol,
          title,
          pill(
            passed + "/" + items.length,
            passed === items.length ? C.green : C.amber,
            passed === items.length ? C.greenSoft : C.amberSoft
          ),
          tone
        ),

        serviceGrid(items)
      ],
      {
        flex: 1,
        height: 133,
        padding: [5, 6],
        gap: 5
      }
    );
  }

  function footerCell(symbol, label, value, tone) {
    return col(
      [
        row(
          [
            image(symbol, tone, 13, 13),

            col(
              [
                text(label, 6, "medium", C.muted, {
                  maxLines: 1
                }),

                text(value, 7, "semibold", tone, {
                  maxLines: 1,
                  minScale: 0.64
                })
              ],
              {
                flex: 1,
                gap: 0
              }
            )
          ],
          {
            gap: 4
          }
        )
      ],
      {
        flex: 1,
        padding: [1, 3]
      }
    );
  }

  function footer() {
    return card(
      [
        row(
          [
            footerCell(
              "server.rack",
              "ISP / 厂商",
              shortISP(exit.isp),
              C.blue
            ),

            footerCell(
              "house.fill",
              "属性类型",
              exit.kind,
              exit.kind === "商业机房"
                ? C.amber
                : C.green
            ),

            footerCell(
              "checkmark.shield.fill",
              "纯净评分",
              purity.score + "分",
              purityColor
            ),

            footerCell(
              "shield.lefthalf.filled",
              "风险等级",
              risk,
              riskColor
            ),

            footerCell(
              "arrow.clockwise",
              "更新时间",
              timeLabel(now),
              C.purple
            )
          ],
          {
            height: 30,
            padding: [0, 0],
            gap: 0,
            alignItems: "center"
          }
        )
      ],
      {
        height: 40,
        padding: [4, 5],
        gap: 0
      }
    );
  }

  const dashboard = col(
    [
      header(),

      row(
        [
          localCard(),
          proxyCard()
        ],
        {
          height: 100,
          gap: 6,
          alignItems: "start"
        }
      ),

      row(
        [
          serviceCard("流媒体解锁", "play.rectangle.fill", media, C.blue),
          serviceCard("AI 解锁检测", "sparkles", ai, C.purple)
        ],
        {
          height: 133,
          gap: 6,
          alignItems: "start"
        }
      ),

      footer()
    ],
    {
      height: 342,
      padding: [8, 8],
      gap: 6
    }
  );

  return {
    type: "widget",
    padding: S(8),
    gap: 0,
    refreshAfter: new Date(
      Date.now() + REFRESH_MINUTES * 60 * 1000
    ).toISOString(),
    children: [
      dashboard,
      spacer()
    ]
  };
}

function palette() {
  const adaptive = (light, dark) => ({
    light: light,
    dark: dark
  });

  // 液态玻璃（iOS 26 风格）：8 位 HEX 带透明度（#RRGGBBAA）
  // 组件背景透明 → 系统磨砂玻璃透过；卡片半透明 + 细描边
  const glass = (hex, alpha) => {
    const a = Math.round(clamp(alpha, 0, 1) * 255);
    return hex + a.toString(16).padStart(2, "0").toUpperCase();
  };
  const glassAdaptive = (hexL, aL, hexD, aD) => ({
    light: glass(hexL, aL),
    dark: glass(hexD, aD)
  });

  return {
    // 根背景：全透明，壁纸与系统磨砂直接透出
    root: adaptive("#E3EAF500", "#07101F00"),

    dashboard: adaptive("#E3EAF500", "#07101F00"),
    dashboardBorder: adaptive("#E3EAF500", "#07101F00"),

    // 卡片：半透明玻璃质感
    card: glassAdaptive("#FFFFFF", 0.08, "#101A2D", 0.18),
    cardTop: glassAdaptive("#FFFFFF", 0.12, "#142039", 0.22),
    cardBottom: glassAdaptive("#F0F5FF", 0.04, "#0D1728", 0.1),

    proxyTop: glassAdaptive("#FFFFFF", 0.12, "#142039", 0.22),
    proxyBottom: glassAdaptive("#F0F5FF", 0.04, "#0D1728", 0.1),

    // 描边：浅色用白色描边（玻璃高光），深色用低透明蓝
    cardBorder: glassAdaptive("#FFFFFF", 0.12, "#FFFFFF", 0.12),

    // 服务瓦片：比卡片更透一层
    tileBg: glassAdaptive("#FFFFFF", 0.08, "#162238", 0.16),
    tileIconBg: glassAdaptive("#FFFFFF", 0.12, "#1D3154", 0.22),
    tileBorder: glassAdaptive("#FFFFFF", 0.1, "#FFFFFF", 0.1),

    scoreTrack: glassAdaptive("#D8E1EA", 0.2, "#273045", 0.3),
    scoreGlow: adaptive("#1AE27F", "#1AE27F"),
    scoreLeft: adaptive("#22C96D", "#3BE28A"),
    scoreRight: adaptive("#E25769", "#FF627A"),

    footerDivider: glassAdaptive("#C7D2E6", 0.15, "#32486D", 0.2),

    text: adaptive("#18253F", "#F1F5FF"),
    subtext: adaptive("#4E617F", "#BBC8E0"),
    muted: adaptive("#74839A", "#8694AE"),

    blue: adaptive("#2E74D2", "#70AEFF"),
    blueSoft: glassAdaptive("#DDEAFF", 0.22, "#183B71", 0.3),

    purple: adaptive("#7C63D8", "#B09AFF"),
    purpleSoft: glassAdaptive("#EAE3FF", 0.22, "#31275A", 0.3),

    green: adaptive("#229B62", "#58D79D"),
    greenSoft: glassAdaptive("#DDF7E8", 0.22, "#163F34", 0.3),

    amber: adaptive("#B9821D", "#FFC866"),
    amberSoft: glassAdaptive("#FFF0D0", 0.22, "#503918", 0.3),

    red: adaptive("#D64A59", "#FF7D88"),
    redSoft: glassAdaptive("#FFE2E6", 0.22, "#4A232C", 0.3),

    netflix: adaptive("#E50914", "#FF505B"),
    disney: adaptive("#2B76D8", "#7DB7FF"),
    spotify: adaptive("#1DB954", "#1ED760"),
    tiktok: adaptive("#111827", "#FFFFFF"),
    youtube: adaptive("#FF0033", "#FF4B4B"),
    prime: adaptive("#1978CC", "#7CB8FF"),

    chatgpt: adaptive("#1F2937", "#EAF0FF"),
    claude: adaptive("#C86B35", "#FFA26E"),
    gemini: adaptive("#6D6FE8", "#9EA9FF"),
    grok: adaptive("#111827", "#F1F5FF")
  };
}

function servicePolicyCandidates(serviceId, category) {
  const id = clean(serviceId).toLowerCase();
  const type = clean(category).toLowerCase();

  const commonLMT = [
    "LMT",
    "流媒体",
    "流媒体解锁",
    "流媒体服务",
    "流媒体策略",
    "流媒体节点",
    "全球流媒体",
    "国际流媒体",
    "国外流媒体",
    "海外流媒体",
    "全球媒体",
    "国际媒体",
    "国外媒体",
    "海外媒体",
    "媒体",
    "媒体服务",
    "媒体解锁",
    "影音",
    "影音娱乐",
    "影音解锁",
    "视频",
    "视频服务",
    "视频解锁",
    "串流",
    "串流媒体",
    "串流媒體",
    "流媒體",
    "解锁",
    "解鎖",
    "国际解锁",
    "海外解锁",
    "Global Media",
    "International Media",
    "Overseas Media",
    "Media",
    "Media Unlock",
    "Unlock Media",
    "Streaming",
    "Streaming Media",
    "Streaming Unlock",
    "Global Streaming",
    "International Streaming",
    "Overseas Streaming",
    "Proxy Media",
    "Stream",
    "Video",
    "Video Streaming",
    "TV",
    "Movie",
    "Movies",
    "Entertainment",
    "NETFLIX",
    "Netflix",
    "Disney",
    "Disney+",
    "YouTube",
    "Spotify",
    "Prime",
    "Prime Video",
    "TikTok",
    "HBO",
    "Max",
    "Hulu",
    "Apple TV",
    "Apple TV+",
    "Emby",
    "Plex",
    "動畫瘋",
    "动画疯",
    "Bahamut",
    "Bilibili 港澳台",
    "哔哩哔哩港澳台",
    "港台番剧",
    "港台",
    "🎬 流媒体",
    "📺 流媒体",
    "🎥 流媒体",
    "🎞 流媒体",
    "🍿 流媒体",
    "🎬 Streaming",
    "📺 Streaming",
    "🎥 Streaming",
    "🎬 Media",
    "📺 Media",
    "🍿 Media"
  ];

  const commonAI = [
    "AI",
    "Ai",
    "ai",
    "人工智能",
    "人工智能服务",
    "AI服务",
    "AI 服务",
    "AI解锁",
    "AI 解锁",
    "AI平台",
    "AI 平台",
    "AI工具",
    "AI 工具",
    "AI策略",
    "AI 策略",
    "AI节点",
    "AI 节点",
    "AI專用",
    "AI专用",
    "AI国外",
    "AI海外",
    "全球AI",
    "国际AI",
    "国外AI",
    "海外AI",
    "AIGC",
    "AGI",
    "LLM",
    "OpenAI",
    "Open AI",
    "ChatGPT",
    "Chat GPT",
    "GPT",
    "GPT4",
    "GPT-4",
    "GPT-5",
    "Claude",
    "Anthropic",
    "Gemini",
    "Google AI",
    "Bard",
    "DeepSeek",
    "Grok",
    "xAI",
    "XAI",
    "Perplexity",
    "Copilot",
    "Microsoft Copilot",
    "Poe",
    "Notion AI",
    "Midjourney",
    "Sora",
    "Cursor",
    "AI Proxy",
    "AI Services",
    "AI Unlock",
    "AI Global",
    "Global AI",
    "International AI",
    "Overseas AI",
    "Proxy AI",
    "🤖 AI",
    "✨ AI",
    "🧠 AI",
    "🤖 人工智能",
    "✨ 人工智能",
    "🧠 人工智能"
  ];

  const serviceMap = {
    netflix: [
      "Netflix",
      "NETFLIX",
      "NetFlix",
      "NF",
      "奈飞",
      "奈飛",
      "网飞",
      "網飛",
      "Netflix 解锁",
      "Netflix 解鎖",
      "Netflix Unlock",
      "Netflix 专用",
      "Netflix 專用",
      "Netflix节点",
      "Netflix 節点",
      "NF解锁",
      "NF 解锁",
      "NF Unlock",
      "Netflix/Disney",
      "Netflix & Disney",
      "Netflix Disney",
      "奈飞节点",
      "奈飞解锁",
      "🎬 Netflix",
      "🎥 Netflix",
      "🍿 Netflix"
    ],

    disney: [
      "Disney+",
      "Disney",
      "Disney Plus",
      "DisneyPlus",
      "D+",
      "DPlus",
      "迪士尼",
      "迪士尼+",
      "Disney 解锁",
      "Disney+ 解锁",
      "Disney Unlock",
      "DisneyPlus 解锁",
      "Disney 专用",
      "Disney 專用",
      "Disney 节点",
      "Disney 節点",
      "Disney+ 节点",
      "Disney+ 節点",
      "🎬 Disney+",
      "🏰 Disney+",
      "🎥 Disney"
    ],

    spotify: [
      "Spotify",
      "SPOTIFY",
      "声破天",
      "聲破天",
      "Spotify 解锁",
      "Spotify Unlock",
      "Spotify Premium",
      "Spotify 专用",
      "Spotify 專用",
      "Spotify 节点",
      "Spotify 節点",
      "音乐",
      "音樂",
      "Music",
      "🎵 Spotify",
      "🎧 Spotify"
    ],

    tiktok: [
      "TikTok",
      "Tik Tok",
      "TIKTOK",
      "TK",
      "抖音国际版",
      "抖音國際版",
      "国际抖音",
      "國際抖音",
      "TikTok 解锁",
      "TikTok Unlock",
      "TikTok 专用",
      "TikTok 專用",
      "TikTok 节点",
      "TikTok 節点",
      "🎵 TikTok",
      "🎬 TikTok"
    ],

    youtube: [
      "YouTube",
      "Youtube",
      "YOUTUBE",
      "YT",
      "油管",
      "YouTube 解锁",
      "YouTube Unlock",
      "YouTube Premium",
      "YouTube Music",
      "YT Premium",
      "YT 解锁",
      "YT Unlock",
      "Google",
      "Google YouTube",
      "谷歌",
      "谷歌服务",
      "谷歌服務",
      "Google Services",
      "Google Service",
      "🎬 YouTube",
      "📺 YouTube",
      "▶️ YouTube"
    ],

    prime: [
      "Prime",
      "Prime Video",
      "PrimeVideo",
      "Amazon Prime",
      "Amazon Video",
      "Amazon",
      "亚马逊视频",
      "亞馬遜視頻",
      "亚马逊",
      "亞馬遜",
      "Prime 解锁",
      "Prime Unlock",
      "Prime Video 解锁",
      "Prime Video Unlock",
      "Prime 专用",
      "Prime 專用",
      "Prime 节点",
      "Prime 節点",
      "🎬 Prime",
      "📺 Prime"
    ],

    chatgpt: [
      "ChatGPT",
      "Chat GPT",
      "OpenAI",
      "Open AI",
      "GPT",
      "GPT4",
      "GPT-4",
      "GPT5",
      "GPT-5",
      "OpenAI 解锁",
      "ChatGPT 解锁",
      "OpenAI Unlock",
      "ChatGPT Unlock",
      "OpenAI 专用",
      "OpenAI 專用",
      "ChatGPT 专用",
      "ChatGPT 專用",
      "OpenAI 节点",
      "ChatGPT 节点",
      "🤖 ChatGPT",
      "🤖 OpenAI",
      "✨ ChatGPT"
    ],

    claude: [
      "Claude",
      "Anthropic",
      "Claude AI",
      "Claude 解锁",
      "Claude Unlock",
      "Anthropic 解锁",
      "Anthropic Unlock",
      "Claude 专用",
      "Claude 專用",
      "Claude 节点",
      "Claude 節点",
      "🤖 Claude",
      "🧠 Claude"
    ],

    gemini: [
      "Gemini",
      "Google AI",
      "Bard",
      "Google Bard",
      "Gemini 解锁",
      "Gemini Unlock",
      "Google AI 解锁",
      "Google AI Unlock",
      "Gemini 专用",
      "Gemini 專用",
      "Gemini 节点",
      "Gemini 節点",
      "Google",
      "谷歌",
      "谷歌 AI",
      "🤖 Gemini",
      "✨ Gemini"
    ],

    deepseek: [
      "DeepSeek",
      "Deepseek",
      "DEEPSEEK",
      "深度求索",
      "DeepSeek 解锁",
      "DeepSeek Unlock",
      "DeepSeek 专用",
      "DeepSeek 專用",
      "DeepSeek 节点",
      "DeepSeek 節点",
      "🤖 DeepSeek",
      "🧠 DeepSeek"
    ],

    grok: [
      "Grok",
      "grok",
      "GROK",
      "xAI",
      "XAI",
      "X AI",
      "Grok 解锁",
      "Grok Unlock",
      "xAI 解锁",
      "xAI Unlock",
      "Grok 专用",
      "Grok 專用",
      "Grok 节点",
      "Grok 節点",
      "X",
      "Twitter AI",
      "🤖 Grok",
      "✨ Grok"
    ],

    perplexity: [
      "Perplexity",
      "PERPLEXITY",
      "Perplexity AI",
      "Perplexity 解锁",
      "Perplexity Unlock",
      "Perplexity 专用",
      "Perplexity 專用",
      "Perplexity 节点",
      "Perplexity 節点",
      "PPLX",
      "PPLX AI",
      "🤖 Perplexity",
      "🔎 Perplexity"
    ]
  };

  const serviceCandidates = serviceMap[id] || [];

  if (type === "ai") {
    return serviceCandidates.concat(commonAI);
  }

  return serviceCandidates.concat(commonLMT);
}

function dedupeCandidates(values) {
  const seen = {};
  const output = [];

  (values || []).forEach(function (value) {
    const raw = clean(value);
    const key = raw.toLowerCase();

    if (!raw || seen[key]) {
      return;
    }

    seen[key] = true;
    output.push(raw);
  });

  return output;
}

function getLocalNetworkName(device) {
  const wifi = (device && device.wifi) || {};
  const cellular = (device && device.cellular) || {};

  const wifiName = firstMeaningful(
    wifi.ssid,
    wifi.name,
    wifi.networkName,
    getAt(device, "network.ssid"),
    getAt(device, "wifiSSID")
  );

  if (wifiName) {
    return wifiName;
  }

  const carrierName = firstMeaningful(
    cellular.carrier,
    cellular.carrierName,
    cellular.operator,
    cellular.operatorName,
    cellular.network,
    cellular.networkName,
    cellular.provider,
    cellular.serviceProvider,

    getAt(device, "carrier"),
    getAt(device, "carrierName"),
    getAt(device, "operator"),
    getAt(device, "operatorName"),
    getAt(device, "network.carrier"),
    getAt(device, "network.carrierName"),
    getAt(device, "network.operator"),
    getAt(device, "telephony.carrier"),
    getAt(device, "telephony.carrierName"),
    getAt(device, "cellularProvider")
  );

  if (carrierName) {
    return normalizeCarrierName(carrierName);
  }

  const code = firstMeaningful(
    cellular.mccmnc,
    cellular.mccMnc,
    cellular.plmn,
    cellular.operatorCode,
    getAt(device, "network.mccmnc"),
    getAt(device, "network.plmn"),
    getAt(device, "telephony.mccmnc")
  );

  const byCode = carrierByMCCMNC(code);

  if (byCode) {
    return byCode;
  }

  const mcc = firstMeaningful(
    cellular.mcc,
    cellular.mobileCountryCode,
    getAt(device, "network.mcc"),
    getAt(device, "telephony.mobileCountryCode")
  );

  const mnc = firstMeaningful(
    cellular.mnc,
    cellular.mobileNetworkCode,
    getAt(device, "network.mnc"),
    getAt(device, "telephony.mobileNetworkCode")
  );

  const byMccMnc = carrierByMCCMNC(clean(mcc) + clean(mnc));

  if (byMccMnc) {
    return byMccMnc;
  }

  return "";
}

function firstMeaningful() {
  for (let index = 0; index < arguments.length; index += 1) {
    const value = clean(arguments[index]);

    if (isMeaningful(value)) {
      return value;
    }
  }

  return "";
}

function isMeaningful(value) {
  const v = clean(value);
  const lower = v.toLowerCase();

  if (!v) return false;
  if (v === "--") return false;
  if (v === "-") return false;
  if (v === "—") return false;
  if (lower === "null") return false;
  if (lower === "undefined") return false;
  if (lower === "unknown") return false;
  if (lower === "unknow") return false;
  if (lower === "none") return false;
  if (lower === "n/a") return false;
  if (lower === "wifi") return false;
  if (lower === "wlan") return false;
  if (lower === "5g") return false;
  if (lower === "4g") return false;
  if (lower === "lte") return false;
  if (lower === "nr") return false;

  return true;
}

function normalizeCarrierName(value) {
  const raw = clean(value);
  const lower = raw.toLowerCase();

  if (!raw) return "";

  if (
    raw.includes("中国移动") ||
    lower.includes("china mobile") ||
    lower.includes("cmcc") ||
    lower.includes("cmnet") ||
    lower.includes("cmi")
  ) {
    return "中国移动";
  }

  if (
    raw.includes("中国联通") ||
    lower.includes("china unicom") ||
    lower.includes("unicom") ||
    lower.includes("cucc")
  ) {
    return "中国联通";
  }

  if (
    raw.includes("中国电信") ||
    lower.includes("china telecom") ||
    lower.includes("chinanet") ||
    lower.includes("telecom") ||
    lower.includes("ctc")
  ) {
    return "中国电信";
  }

  if (
    raw.includes("中国广电") ||
    lower.includes("china broadnet") ||
    lower.includes("cbn") ||
    lower.includes("broadnet") ||
    lower.includes("broadcasting network")
  ) {
    return "中国广电";
  }

  return raw;
}

function carrierFromISP(value) {
  return normalizeCarrierName(value);
}

function carrierByMCCMNC(value) {
  const code = clean(value).replace(/\D/g, "");

  const mobile = [
    "46000",
    "46002",
    "46004",
    "46007",
    "46008"
  ];

  const unicom = [
    "46001",
    "46006",
    "46009"
  ];

  const telecom = [
    "46003",
    "46005",
    "46011",
    "46012"
  ];

  const broadnet = [
    "46015"
  ];

  if (mobile.includes(code)) return "中国移动";
  if (unicom.includes(code)) return "中国联通";
  if (telecom.includes(code)) return "中国电信";
  if (broadnet.includes(code)) return "中国广电";

  return "";
}

function maskIP(value) {
  const raw = clean(value);

  if (!raw || raw === "未获取" || raw === "—" || raw === "-") {
    return raw;
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(raw)) {
    const parts = raw.split(".");
    return parts[0] + "." + parts[1] + ".*.*";
  }

  if (raw.includes(".")) {
    return raw.replace(
      /(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}/g,
      "$1.$2.*.*"
    );
  }

  if (raw.includes(":")) {
    const parts = raw.split(":").filter(Boolean);
    if (parts.length >= 2) {
      return parts[0] + ":" + parts[1] + ":****:****";
    }
  }

  return raw;
}

function purityGaugeSVG(score, colors) {
  const value = Math.max(0, Math.min(100, Number(score) || 0));

  const cx = 75;
  const cy = 85;
  const rx = 55;
  const ry = 55;

  const theta = Math.PI - Math.PI * value / 100;
  const px = cx + rx * Math.cos(theta);
  const py = cy - ry * Math.sin(theta);

  const safeTrack = svgColor(colors.track, "#D8E1EA");
  const safeLeft = svgColor(colors.left, "#22C96D");
  const safeRight = svgColor(colors.right, "#E25769");
  const safeGlow = svgColor(colors.glow, "#1AE27F");
  const safeText = svgColor(colors.text, "#22C96D");
  const safeMuted = svgColor(colors.muted, "#74839A");

  const leftDash =
    value >= 99.9
      ? "100 0"
      : Math.max(0.1, value).toFixed(1) + " 100";

  return [
    '<svg xmlns="http://www.w3.org/2000/svg" width="150" height="112" viewBox="0 0 150 112">',
    "<defs>",
    '<filter id="softGlow" x="-50%" y="-50%" width="200%" height="200%">',
    '<feGaussianBlur stdDeviation="2.1" result="blur"/>',
    "<feMerge>",
    '<feMergeNode in="blur"/>',
    '<feMergeNode in="SourceGraphic"/>',
    "</feMerge>",
    "</filter>",
    "</defs>",
    '<path d="M20 85 A55 55 0 0 1 130 85" fill="none" stroke="' + safeTrack + '" stroke-width="9" stroke-linecap="round" opacity="0.75"/>',
    '<path d="M20 85 A55 55 0 0 1 130 85" fill="none" stroke="' + safeRight + '" stroke-width="8.2" stroke-linecap="round" opacity="0.95"/>',
    '<path d="M20 85 A55 55 0 0 1 130 85" fill="none" stroke="' + safeGlow + '" stroke-width="13" stroke-linecap="round" pathLength="100" stroke-dasharray="' + leftDash + '" opacity="0.16"/>',
    '<path d="M20 85 A55 55 0 0 1 130 85" fill="none" stroke="' + safeLeft + '" stroke-width="8.4" stroke-linecap="round" pathLength="100" stroke-dasharray="' + leftDash + '" opacity="1"/>',
    '<circle cx="' + px.toFixed(2) + '" cy="' + py.toFixed(2) + '" r="6.5" fill="' + safeGlow + '" opacity="0.20"/>',
    '<circle cx="' + px.toFixed(2) + '" cy="' + py.toFixed(2) + '" r="4.2" fill="' + safeLeft + '" filter="url(#softGlow)" opacity="1"/>',
    '<text x="75" y="61" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif" font-size="30" font-weight="850" fill="' + safeText + '">' + Math.round(value) + "</text>",
    '<text x="75" y="75" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif" font-size="10" font-weight="760" fill="' + safeMuted + '">/100</text>',
    '<text x="75" y="90" text-anchor="middle" font-family="-apple-system,BlinkMacSystemFont,Helvetica,Arial,sans-serif" font-size="10" font-weight="760" fill="' + safeMuted + '">纯净评分</text>',
    "</svg>"
  ].join("");
}

function svgDataURI(svg) {
  return "data:image/svg+xml;charset=utf-8," +
    encodeURIComponent(svg)
      .replace(/'/g, "%27")
      .replace(/"/g, "%22");
}

function svgColor(value, fallback) {
  const color = clean(value);
  if (/^#[0-9a-fA-F]{6}$/.test(color)) return color;
  if (/^#[0-9a-fA-F]{3}$/.test(color)) return color;
  return fallback;
}

function getCurrentProxyInfo(ctx) {
  const proxyName = clean(
    pick(
      getAt(ctx, "node.name"),
      getAt(ctx, "proxy.name"),
      getAt(ctx, "currentProxy.name"),
      getAt(ctx, "selectedProxy.name"),
      getAt(ctx, "selectedNode.name"),
      getAt(ctx, "policy.node.name"),
      getAt(ctx, "policy.selected.name"),
      getAt(ctx, "policy.current.name"),
      getAt(ctx, "outbound.name"),
      getAt(ctx, "profile.currentNode.name"),
      getAt(ctx, "profile.selectedNode.name"),
      findProxyNameInObject(ctx)
    )
  );

  const rawProtocol = clean(
    pick(
      getAt(ctx, "node.protocol"),
      getAt(ctx, "node.type"),
      getAt(ctx, "node.scheme"),
      getAt(ctx, "proxy.protocol"),
      getAt(ctx, "proxy.type"),
      getAt(ctx, "proxy.scheme"),
      getAt(ctx, "currentProxy.protocol"),
      getAt(ctx, "currentProxy.type"),
      getAt(ctx, "currentProxy.scheme"),
      getAt(ctx, "selectedProxy.protocol"),
      getAt(ctx, "selectedProxy.type"),
      getAt(ctx, "selectedProxy.scheme"),
      getAt(ctx, "selectedNode.protocol"),
      getAt(ctx, "selectedNode.type"),
      getAt(ctx, "selectedNode.scheme"),
      getAt(ctx, "policy.node.protocol"),
      getAt(ctx, "policy.node.type"),
      getAt(ctx, "policy.selected.protocol"),
      getAt(ctx, "policy.selected.type"),
      getAt(ctx, "policy.current.protocol"),
      getAt(ctx, "policy.current.type"),
      getAt(ctx, "outbound.protocol"),
      getAt(ctx, "outbound.type"),
      getAt(ctx, "outbound.scheme"),
      getAt(ctx, "profile.currentNode.protocol"),
      getAt(ctx, "profile.currentNode.type"),
      getAt(ctx, "profile.selectedNode.protocol"),
      getAt(ctx, "profile.selectedNode.type"),
      findProtocolInObject(ctx)
    )
  );

  const protocol =
    normalizeProxyProtocol(rawProtocol) ||
    normalizeProxyProtocol(proxyName);

  return {
    name: proxyName,
    protocol: protocol
  };
}

function findProtocolInObject(object) {
  const found = [];
  const seen = [];

  function walk(value, path, depth) {
    if (depth > 5) return;
    if (!value || typeof value !== "object") return;
    if (seen.indexOf(value) >= 0) return;

    seen.push(value);

    Object.keys(value).forEach(function (key) {
      const next = value[key];
      const nextPath = path ? path + "." + key : key;
      const lowerPath = nextPath.toLowerCase();

      if (typeof next === "string") {
        const protocol = normalizeProxyProtocol(next);

        if (
          protocol &&
          (
            lowerPath.includes("proxy") ||
            lowerPath.includes("node") ||
            lowerPath.includes("outbound") ||
            lowerPath.includes("policy") ||
            lowerPath.includes("protocol") ||
            lowerPath.includes("scheme")
          )
        ) {
          found.push(protocol);
        }
      } else if (next && typeof next === "object") {
        walk(next, nextPath, depth + 1);
      }
    });
  }

  walk(object, "", 0);

  return found[0] || "";
}

function findProxyNameInObject(object) {
  const found = [];
  const seen = [];

  function walk(value, path, depth) {
    if (depth > 5) return;
    if (!value || typeof value !== "object") return;
    if (seen.indexOf(value) >= 0) return;

    seen.push(value);

    Object.keys(value).forEach(function (key) {
      const next = value[key];
      const nextPath = path ? path + "." + key : key;
      const lowerPath = nextPath.toLowerCase();

      if (typeof next === "string") {
        if (
          isMeaningful(next) &&
          (
            lowerPath.includes("proxy") ||
            lowerPath.includes("node") ||
            lowerPath.includes("outbound") ||
            lowerPath.includes("policy")
          ) &&
          (
            lowerPath.includes("name") ||
            lowerPath.includes("title")
          )
        ) {
          found.push(next);
        }
      } else if (next && typeof next === "object") {
        walk(next, nextPath, depth + 1);
      }
    });
  }

  walk(object, "", 0);

  return found[0] || "";
}

function protocolFromXY(value) {
  const raw = clean(value);

  if (!raw) {
    return "";
  }

  return normalizeProxyProtocol(raw) || raw;
}

function normalizeProxyProtocol(value) {
  const raw = clean(value);
  const text = raw.toLowerCase();

  if (!text) {
    return "";
  }

  const normalized = text
    .replace(/[_\-]+/g, " ")
    .replace(/[()[\]{}|,;]+/g, " ");

  const checks = [
    [/vless/, "VLESS"],
    [/vmess/, "VMESS"],
    [/trojan/, "Trojan"],
    [/shadowsocks\s*r|ssr/, "SSR"],
    [/shadowsocks|(^|\s)ss($|\s)/, "SS"],
    [/hysteria\s*2|hy2/, "HY2"],
    [/hysteria/, "Hysteria"],
    [/tuic/, "TUIC"],
    [/snell/, "Snell"],
    [/any\s*tls|anytls/, "AnyTLS"],
    [/wireguard|(^|\s)wg($|\s)/, "WireGuard"],
    [/socks\s*5|socks5/, "SOCKS5"],
    [/socks/, "SOCKS"],
    [/http\s*2|h2/, "HTTP/2"],
    [/https/, "HTTPS"],
    [/http/, "HTTP"],
    [/ssh/, "SSH"],
    [/mieru/, "Mieru"],
    [/juicity/, "Juicity"],
    [/shadow\s*tls|shadowtls/, "ShadowTLS"],
    [/naive/, "Naive"],
    [/brook/, "Brook"]
  ];

  for (let index = 0; index < checks.length; index += 1) {
    if (checks[index][0].test(normalized)) {
      return checks[index][1];
    }
  }

  return "";
}

function parseExitSource(data, sourceName) {
  if (!data || typeof data !== "object") {
    return {};
  }

  const ip = clean(
    pick(
      data.ip,
      data.query,
      data.ip_address,
      getAt(data, "location.ip")
    )
  );

  if (!ip) {
    return {};
  }

  const isp = clean(
    pick(
      getAt(data, "company.name"),
      getAt(data, "connection.isp"),
      getAt(data, "connection.org"),
      getAt(data, "asn.name"),
      data.isp,
      data.org,
      data.organization,
      data.asname,
      data.as,
      "未知组织"
    )
  );

  const orgText = [
    isp,
    data.org,
    data.organization,
    data.as,
    data.asname,
    getAt(data, "company.name"),
    getAt(data, "asn.name"),
    getAt(data, "connection.org"),
    getAt(data, "connection.isp")
  ].join(" ");

  const cloud = cloudProviderFromText(orgText);

  const flags = {
    datacenter:
      truthy(
        pick(
          data.is_datacenter,
          data.hosting,
          getAt(data, "security.is_datacenter"),
          getAt(data, "company.is_datacenter")
        )
      ) || cloud.hit,

    hosting:
      truthy(
        pick(
          data.hosting,
          data.is_hosting,
          getAt(data, "security.is_hosting")
        )
      ) || cloud.hit,

    cloud: cloud.hit,

    proxy: truthy(
      pick(
        data.proxy,
        data.is_proxy,
        getAt(data, "security.is_proxy"),
        getAt(data, "security.proxy")
      )
    ),

    vpn: truthy(
      pick(
        data.is_vpn,
        getAt(data, "security.is_vpn"),
        getAt(data, "security.vpn")
      )
    ),

    tor: truthy(
      pick(
        data.is_tor,
        getAt(data, "security.is_tor"),
        getAt(data, "security.tor")
      )
    ),

    abuser: truthy(
      pick(
        data.is_abuser,
        getAt(data, "security.is_abuser")
      )
    ),

    mobile: truthy(
      pick(
        data.mobile,
        data.is_mobile,
        getAt(data, "connection.mobile")
      )
    ),

    residential: false,

    risk: numberOrNull(
      pick(
        data.risk,
        getAt(data, "security.risk"),
        getAt(data, "risk.score")
      )
    )
  };

  const rawType = clean(
    pick(
      getAt(data, "company.type"),
      getAt(data, "connection.type"),
      getAt(data, "asn.type")
    )
  ).toLowerCase();

  if (
    rawType.includes("isp") ||
    rawType.includes("residential") ||
    rawType.includes("broadband")
  ) {
    flags.residential = true;
  }

  if (
    rawType.includes("hosting") ||
    rawType.includes("datacenter") ||
    rawType.includes("cloud")
  ) {
    flags.datacenter = true;
    flags.hosting = true;
  }

  const rawCountry = clean(
    pick(
      getAt(data, "location.country"),
      data.country_name,
      data.country
    )
  );

  return {
    source: sourceName || "",
    ip: ip,
    city: clean(
      pick(
        getAt(data, "location.city"),
        data.city,
        getAt(data, "location.region"),
        data.regionName,
        data.region,
        "未知城市"
      )
    ),
    region: clean(
      pick(
        getAt(data, "location.region"),
        data.regionName,
        data.region
      )
    ),
    country:
      rawCountry.length === 2
        ? ""
        : rawCountry,
    countryCode: countryCode(
      pick(
        getAt(data, "location.country_code"),
        data.country_code,
        data.countryCode,
        rawCountry.length === 2 ? rawCountry : ""
      )
    ),
    isp: cloud.name || isp,
    cloudProvider: cloud.name,
    kind: classifyExitKind(flags),
    flags: flags
  };
}

function parseProxyCheck(data, ip) {
  if (!data || typeof data !== "object") {
    return null;
  }

  const target = clean(ip);
  const keys = Object.keys(data);
  const fallbackKey = keys.find(function (key) {
    return key !== "status" && key !== "message";
  });

  const item = data[target] || data[fallbackKey];

  if (!item || typeof item !== "object") {
    return null;
  }

  const typeText = clean(
    pick(
      item.type,
      item.proxy,
      item.provider,
      item.organisation,
      item.asn,
      item.operator
    )
  );

  const orgText = [
    item.provider,
    item.organisation,
    item.operator,
    item.asn,
    item.type
  ].join(" ");

  const cloud = cloudProviderFromText(orgText);

  const proxyValue = clean(item.proxy).toLowerCase();
  const typeLower = typeText.toLowerCase();

  const flags = {
    datacenter:
      cloud.hit ||
      typeLower.includes("hosting") ||
      typeLower.includes("server") ||
      typeLower.includes("business"),

    hosting:
      cloud.hit ||
      typeLower.includes("hosting") ||
      typeLower.includes("server"),

    cloud: cloud.hit,

    proxy:
      proxyValue === "yes" ||
      typeLower.includes("proxy"),

    vpn:
      typeLower.includes("vpn"),

    tor:
      typeLower.includes("tor"),

    abuser:
      typeLower.includes("abuse") ||
      typeLower.includes("blacklist") ||
      typeLower.includes("spam"),

    mobile:
      typeLower.includes("mobile"),

    residential:
      typeLower.includes("residential"),

    risk:
      numberOrNull(item.risk)
  };

  return {
    source: "proxycheck.io",
    ip: target,
    city: clean(item.city),
    region: clean(item.region),
    country: clean(item.country),
    countryCode: countryCode(item.isocode),
    isp: clean(
      pick(
        cloud.name,
        item.provider,
        item.organisation,
        item.operator,
        "未知组织"
      )
    ),
    cloudProvider: cloud.name,
    kind: classifyExitKind(flags),
    flags: flags
  };
}

function mergeExitSources(sources) {
  const valid = (sources || []).filter(function (item) {
    return item && item.ip;
  });

  if (valid.length === 0) {
    return {
      ip: "未识别",
      city: "出口检测失败",
      region: "",
      country: "",
      countryCode: "",
      isp: "未知组织",
      kind: "未知网络",
      flags: {}
    };
  }

  const primaryIP =
    mostCommon(
      valid.map(function (item) {
        return item.ip;
      })
    ) || valid[0].ip;

  const sameIP = valid.filter(function (item) {
    return item.ip === primaryIP;
  });

  const allText = sameIP
    .map(function (item) {
      return [
        item.isp,
        item.cloudProvider,
        item.country,
        item.city,
        item.region
      ].join(" ");
    })
    .join(" ");

  const cloud = cloudProviderFromText(allText);

  const evidence = {
    sourceCount: sameIP.length,
    datacenterCount: 0,
    hostingCount: 0,
    cloudCount: cloud.hit ? 1 : 0,
    proxyCount: 0,
    vpnCount: 0,
    torCount: 0,
    abuserCount: 0,
    mobileCount: 0,
    residentialCount: 0,
    riskMax: null,
    riskCount: 0
  };

  sameIP.forEach(function (item) {
    const flags = item.flags || {};

    if (flags.datacenter) evidence.datacenterCount += 1;
    if (flags.hosting) evidence.hostingCount += 1;
    if (flags.cloud) evidence.cloudCount += 1;
    if (flags.proxy) evidence.proxyCount += 1;
    if (flags.vpn) evidence.vpnCount += 1;
    if (flags.tor) evidence.torCount += 1;
    if (flags.abuser) evidence.abuserCount += 1;
    if (flags.mobile) evidence.mobileCount += 1;
    if (flags.residential) evidence.residentialCount += 1;

    if (Number.isFinite(Number(flags.risk))) {
      evidence.riskCount += 1;
      evidence.riskMax = Math.max(
        Number(evidence.riskMax || 0),
        Number(flags.risk)
      );
    }
  });

  const mergedFlags = {
    datacenter: evidence.datacenterCount > 0,
    hosting: evidence.hostingCount > 0,
    cloud: evidence.cloudCount > 0,
    proxy: evidence.proxyCount > 0,
    vpn: evidence.vpnCount > 0,
    tor: evidence.torCount > 0,
    abuser: evidence.abuserCount > 0,
    mobile: evidence.mobileCount > 0,
    residential: evidence.residentialCount > 0,
    risk: evidence.riskMax,
    evidence: evidence
  };

  if (cloud.hit) {
    mergedFlags.datacenter = true;
    mergedFlags.hosting = true;
    mergedFlags.cloud = true;
    mergedFlags.residential = false;
  }

  const kind = classifyExitKind(mergedFlags);

  return {
    ip: primaryIP,
    city: bestField(sameIP, "city") || "未知城市",
    region: bestField(sameIP, "region"),
    country: bestField(sameIP, "country"),
    countryCode: countryCode(bestField(sameIP, "countryCode")),
    isp: cloud.name || bestField(sameIP, "isp") || "未知组织",
    cloudProvider: cloud.name,
    kind: kind,
    flags: mergedFlags,
    sources: sameIP
      .map(function (item) {
        return item.source;
      })
      .filter(Boolean)
  };
}

function classifyExitKind(flags) {
  const f = flags || {};

  if (f.mobile) {
    return "移动网络";
  }

  if (f.residential) {
    return "住宅 IP";
  }

  if (f.datacenter || f.hosting || f.cloud) {
    return "商业机房";
  }

  if (f.proxy || f.vpn) {
    return "住宅 IP";
  }

  return "未知网络";
}

function cloudProviderFromText(value) {
  const text = clean(value).toLowerCase();

  if (!text) {
    return {
      hit: false,
      name: ""
    };
  }

  const providers = [
    ["oracle", "Oracle"],
    ["oci", "Oracle"],
    ["amazon", "AWS"],
    ["aws", "AWS"],
    ["google cloud", "Google Cloud"],
    ["google llc", "Google"],
    ["microsoft", "Microsoft Azure"],
    ["azure", "Microsoft Azure"],
    ["digitalocean", "DigitalOcean"],
    ["vultr", "Vultr"],
    ["linode", "Akamai Linode"],
    ["akamai", "Akamai"],
    ["ovh", "OVH"],
    ["hetzner", "Hetzner"],
    ["leaseweb", "Leaseweb"],
    ["m247", "M247"],
    ["choopa", "Vultr"],
    ["contabo", "Contabo"],
    ["scaleway", "Scaleway"],
    ["hivelocity", "Hivelocity"],
    ["cloudflare", "Cloudflare"],
    ["tencent cloud", "Tencent Cloud"],
    ["alibaba cloud", "Alibaba Cloud"],
    ["aliyun", "Alibaba Cloud"],
    ["alicloud", "Alibaba Cloud"],
    ["huawei cloud", "Huawei Cloud"],
    ["volcengine", "Volcengine"],
    ["ucloud", "UCLOUD"],
    ["uccloud", "UCLOUD"]
  ];

  for (let index = 0; index < providers.length; index += 1) {
    if (text.includes(providers[index][0])) {
      return {
        hit: true,
        name: providers[index][1]
      };
    }
  }

  return {
    hit: false,
    name: ""
  };
}

function mostCommon(values) {
  const count = {};
  let best = "";
  let bestCount = 0;

  values
    .map(clean)
    .filter(Boolean)
    .forEach(function (value) {
      count[value] = (count[value] || 0) + 1;

      if (count[value] > bestCount) {
        best = value;
        bestCount = count[value];
      }
    });

  return best;
}

function bestField(items, field) {
  const values = (items || [])
    .map(function (item) {
      return clean(item[field]);
    })
    .filter(Boolean);

  return mostCommon(values) || values[0] || "";
}

function numberOrNull(value) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return null;
  }

  return parsed;
}

function parseLocalExit(data, forceLocalMainland) {
  if (!data || typeof data !== "object") {
    return {};
  }

  const ip = clean(
    pick(
      data.query,
      data.ip,
      data.ip_address,
      getAt(data, "location.ip")
    )
  );

  if (!ip) {
    return {};
  }

  const countryCodeValue = countryCode(
    pick(
      data.countryCode,
      data.country_code,
      getAt(data, "location.country_code")
    )
  );

  const country = clean(
    pick(
      data.country,
      data.country_name,
      getAt(data, "location.country")
    )
  );

  const region = clean(
    pick(
      data.regionName,
      data.region,
      getAt(data, "location.region")
    )
  );

  const city = clean(
    pick(
      data.city,
      getAt(data, "location.city")
    )
  );

  const isChina =
    countryCodeValue === "CN" ||
    country.includes("中国") ||
    forceLocalMainland;

  const label = isChina
    ? mainlandAreaLabel(region, city)
    : formatLocalArea(countryCodeValue, country, region, city);

  return {
    ip: ip,
    country: isChina ? "中国" : country,
    countryCode: isChina ? "CN" : countryCodeValue,
    region: region,
    city: city,
    isp: clean(pick(data.isp, data.org, data.organization)),
    org: clean(data.org),
    asname: clean(data.asname),
    as: clean(data.as),
    label: label
  };
}

function mainlandAreaLabel(region, city) {
  const label = formatLocalArea("CN", "中国", region, city);

  if (!label || label === "中国") {
    return "中国大陆";
  }

  return label;
}

function formatLocalArea(countryCodeValue, country, region, city) {
  const cc = countryCode(countryCodeValue);
  let r = clean(region);
  let c = clean(city);

  r = r
    .replace(/省$/g, "")
    .replace(/市$/g, "")
    .replace(/壮族自治区$/g, "")
    .replace(/回族自治区$/g, "")
    .replace(/维吾尔自治区$/g, "")
    .replace(/自治区$/g, "");

  c = c.replace(/市$/g, "");

  if (cc === "CN" || country.includes("中国")) {
    if (["北京", "上海", "天津", "重庆"].includes(r)) {
      return r;
    }

    if (r && c && r !== c) {
      return r + c;
    }

    return c || r || "中国";
  }

  if (c && r && c !== r) {
    return r + " " + c;
  }

  return c || r || country || "直连地区未知";
}

function providerFromText(value) {
  const text = clean(value).toLowerCase();

  if (!text) {
    return { full: "", short: "" };
  }

  if (text.includes("cloudflare")) return { full: "Cloudflare DNS", short: "CF" };
  if (text.includes("google")) return { full: "Google DNS", short: "谷歌" };
  if (text.includes("quad9")) return { full: "Quad9 DNS", short: "Q9" };
  if (text.includes("opendns") || text.includes("cisco")) return { full: "OpenDNS", short: "Open" };
  if (text.includes("adguard")) return { full: "AdGuard DNS", short: "AdG" };
  if (text.includes("nextdns")) return { full: "NextDNS", short: "Next" };
  if (text.includes("cleanbrowsing")) return { full: "CleanBrowsing DNS", short: "Clean" };
  if (text.includes("dns.sb")) return { full: "DNS.SB", short: "DNS.SB" };
  if (text.includes("mullvad")) return { full: "Mullvad DNS", short: "Mull" };
  if (text.includes("control d") || text.includes("controld")) return { full: "Control D DNS", short: "CtrlD" };

  if (
    text.includes("alidns") ||
    text.includes("alibaba") ||
    text.includes("aliyun") ||
    text.includes("alicloud") ||
    text.includes("alibaba cloud")
  ) {
    return { full: "AliDNS", short: "阿里" };
  }

  if (
    text.includes("dnspod") ||
    text.includes("tencent") ||
    text.includes("tencent cloud")
  ) {
    return { full: "DNSPod", short: "腾讯" };
  }

  if (
    text.includes("baidu") ||
    text.includes("baidudns")
  ) {
    return { full: "Baidu DNS", short: "百度" };
  }

  if (
    text.includes("360") ||
    text.includes("qihoo")
  ) {
    return { full: "360 DNS", short: "360" };
  }

  if (
    text.includes("114dns") ||
    text.includes("114 dns") ||
    text.includes("114.114")
  ) {
    return { full: "114DNS", short: "114" };
  }

  if (
    text.includes("chinanet") ||
    text.includes("china telecom") ||
    text.includes("telecom") ||
    text.includes("ctc") ||
    text.includes("中国电信") ||
    text.includes("电信")
  ) {
    return { full: "中国电信 DNS", short: "电信" };
  }

  if (
    text.includes("china mobile") ||
    text.includes("cmcc") ||
    text.includes("cmnet") ||
    text.includes("cmi") ||
    text.includes("中国移动") ||
    text.includes("移动")
  ) {
    return { full: "中国移动 DNS", short: "移动" };
  }

  if (
    text.includes("china unicom") ||
    text.includes("unicom") ||
    text.includes("cucc") ||
    text.includes("中国联通") ||
    text.includes("联通")
  ) {
    return { full: "中国联通 DNS", short: "联通" };
  }

  if (
    text.includes("cernet") ||
    text.includes("china education") ||
    text.includes("education network") ||
    text.includes("中国教育") ||
    text.includes("教育网")
  ) {
    return { full: "中国教育网 DNS", short: "教育" };
  }

  if (
    text.includes("great wall broadband") ||
    text.includes("gwbn") ||
    text.includes("长城宽带")
  ) {
    return { full: "长城宽带 DNS", short: "长宽" };
  }

  if (
    text.includes("drpeng") ||
    text.includes("鹏博士")
  ) {
    return { full: "鹏博士 DNS", short: "鹏博" };
  }

  return { full: "", short: "" };
}

function compactDNSProviderName(value) {
  const text = clean(value);

  if (!text) {
    return "未知";
  }

  const provider = providerFromText(text);

  if (provider.short) {
    return provider.short;
  }

  const lower = text.toLowerCase();

  if (lower.includes("telecom")) return "电信";
  if (lower.includes("mobile")) return "移动";
  if (lower.includes("unicom")) return "联通";
  if (lower.includes("education")) return "教育";
  if (lower.includes("cloudflare")) return "CF";
  if (lower.includes("google")) return "谷歌";
  if (lower.includes("oracle")) return "Oracle";
  if (lower.includes("amazon") || lower.includes("aws")) return "AWS";
  if (lower.includes("microsoft") || lower.includes("azure")) return "Azure";

  const cleaned = text
    .replace(/^as\d+\s*/i, "")
    .replace(/co\.,?\s*ltd\.?/ig, "")
    .replace(/company/ig, "")
    .replace(/limited/ig, "")
    .replace(/inc\.?/ig, "")
    .replace(/llc/ig, "")
    .replace(/corporation/ig, "")
    .replace(/network/ig, "")
    .replace(/communications?/ig, "")
    .replace(/internet/ig, "")
    .replace(/technology/ig, "")
    .replace(/\s+/g, " ")
    .trim();

  if (!cleaned) {
    return "未知";
  }

  if (/[\u4e00-\u9fa5]/.test(cleaned)) {
    return cleaned.slice(0, 4);
  }

  const first = cleaned.split(/[ ,，/|()]+/).filter(Boolean)[0];

  if (!first) {
    return "未知";
  }

  return first.length > 6
    ? first.slice(0, 6)
    : first;
}

function chooseDNSProvider(baseDNS, verifiedDNS) {
  const base = baseDNS || {
    full: "",
    short: ""
  };

  const verified = verifiedDNS || {
    ok: false,
    full: "",
    short: "",
    ip: "",
    geo: "",
    isp: "",
    org: "",
    asname: "",
    as: ""
  };

  const verifiedProvider = providerFromText(
    [
      verified.full,
      verified.short,
      verified.geo,
      verified.ip,
      verified.isp,
      verified.org,
      verified.asname,
      verified.as
    ].join(" ")
  );

  if (verifiedProvider.short) {
    return verifiedProvider;
  }

  if (verified.ok && verified.short && !isWeakDNSLabel(verified.short)) {
    return {
      full: verified.full || verified.short,
      short: dnsTinyLabel(verified.short)
    };
  }

  const baseProvider = providerFromText(
    [
      base.full,
      base.short
    ].join(" ")
  );

  if (baseProvider.short) {
    return baseProvider;
  }

  if (base.short && !isWeakDNSLabel(base.short)) {
    return {
      full: base.full,
      short: dnsTinyLabel(base.short)
    };
  }

  if (verified.ok && verified.ip) {
    return {
      full: verified.ip,
      short: compactDNSProviderName(
        verified.isp ||
        verified.org ||
        verified.asname ||
        verified.as ||
        verified.geo ||
        verified.ip
      )
    };
  }

  return {
    full: "未知 DNS",
    short: "未知"
  };
}

function isWeakDNSLabel(value) {
  return [
    "",
    "系统",
    "网关",
    "自定义",
    "自定",
    "未知",
    "IPv6"
  ].includes(clean(value));
}

function dnsTinyLabel(value) {
  const name = clean(value);
  const provider = providerFromText(name);

  if (provider.short) {
    return provider.short;
  }

  const map = {
    "Cloudflare": "CF",
    "Cloudflare DNS": "CF",
    "CF": "CF",
    "Google": "谷歌",
    "Google DNS": "谷歌",
    "谷歌": "谷歌",
    "AliDNS": "阿里",
    "Ali": "阿里",
    "阿里": "阿里",
    "DNSPod": "腾讯",
    "Pod": "腾讯",
    "腾讯": "腾讯",
    "OpenDNS": "Open",
    "Open": "Open",
    "AdGuard": "AdG",
    "AdG": "AdG",
    "Quad9": "Q9",
    "Q9": "Q9",
    "114DNS": "114",
    "114": "114",
    "NextDNS": "Next",
    "Next": "Next",
    "中国电信 DNS": "电信",
    "电信": "电信",
    "中国移动 DNS": "移动",
    "移动": "移动",
    "中国联通 DNS": "联通",
    "联通": "联通",
    "中国教育网 DNS": "教育",
    "教育": "教育",
    "网关 DNS": "网关",
    "网关": "网关",
    "系统": "系统",
    "自定义": "自定",
    "自定": "自定",
    "未知": "未知",
    "IPv6": "IPv6"
  };

  if (map[name]) {
    return map[name];
  }

  if (name.length <= 4) {
    return name;
  }

  return "未知";
}

function purityScore(exit) {
  const flags = (exit && exit.flags) || {};
  const evidence = flags.evidence || {};
  const kind = clean(exit && exit.kind);

  let score;

  if (kind === "住宅 IP") {
    score = 92;
  } else if (kind === "移动网络") {
    score = 92;
  } else if (kind === "教育网络" || kind === "企业网络") {
    score = 88;
  } else if (kind === "商业机房") {
    score = 78;
  } else {
    score = 72;
  }

  const proxyCount = Number(evidence.proxyCount || 0);
  const vpnCount = Number(evidence.vpnCount || 0);
  const torCount = Number(evidence.torCount || 0);
  const abuserCount = Number(evidence.abuserCount || 0);
  const riskValue = Number(flags.risk);

  const proxyVpnEvidenceCount = proxyCount + vpnCount;

  if (torCount > 0 || flags.tor) {
    score -= 55;
  }

  if (abuserCount > 0 || flags.abuser) {
    score -= 35;
  }

  if (proxyVpnEvidenceCount >= 2) {
    score -= 30;
  } else if (proxyVpnEvidenceCount === 1) {
    score -= 16;
  }

  if (Number.isFinite(riskValue)) {
    if (riskValue >= 80) {
      score -= 25;
    } else if (riskValue >= 70) {
      score -= 20;
    } else if (riskValue >= 40) {
      score -= 10;
    } else if (riskValue >= 20) {
      score -= 4;
    }
  }

  if (kind === "商业机房" || flags.datacenter || flags.hosting || flags.cloud) {
    score -= 8;
  }

  if (
    kind === "住宅 IP" &&
    !flags.proxy &&
    !flags.vpn &&
    !flags.tor &&
    !flags.abuser
  ) {
    score += 3;
  }

  if (
    kind === "移动网络" &&
    !flags.proxy &&
    !flags.vpn &&
    !flags.tor &&
    !flags.abuser
  ) {
    score += 3;
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    score: score,
    risk: 100 - score,
    evidence: evidence
  };
}

function riskLevel(exit, purity) {
  const flags = (exit && exit.flags) || {};
  const evidence = flags.evidence || {};
  const score = Number(purity && purity.score);
  const riskValue = Number(flags.risk);

  const proxyVpnEvidenceCount =
    Number(evidence.proxyCount || 0) +
    Number(evidence.vpnCount || 0);

  if (
    flags.tor ||
    Number(evidence.torCount || 0) > 0 ||
    flags.abuser ||
    Number(evidence.abuserCount || 0) > 0 ||
    riskValue >= 85 ||
    score < 45 ||
    (
      proxyVpnEvidenceCount >= 2 &&
      (
        score < 60 ||
        riskValue >= 70
      )
    )
  ) {
    return "高风险";
  }

  if (
    score < 75 ||
    flags.datacenter ||
    flags.hosting ||
    flags.cloud ||
    proxyVpnEvidenceCount > 0 ||
    riskValue >= 40
  ) {
    return "中风险";
  }

  return "低风险";
}

function toneColor(tone, colors) {
  if (tone === "green") return colors.green;
  if (tone === "red") return colors.red;
  return colors.amber;
}

function parseIPv4(ip) {
  const parts = clean(ip).split(".");
  if (parts.length !== 4) return null;

  const values = parts.map(Number);

  if (
    values.some(function (value) {
      return !Number.isInteger(value) || value < 0 || value > 255;
    })
  ) {
    return null;
  }

  return values;
}

function isPrivateIPv4(ip) {
  const parts = parseIPv4(ip);
  if (!parts) return false;

  return (
    parts[0] === 10 ||
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    (parts[0] === 192 && parts[1] === 168)
  );
}

function isCGNATIPv4(ip) {
  const parts = parseIPv4(ip);
  return Boolean(
    parts &&
    parts[0] === 100 &&
    parts[1] >= 64 &&
    parts[1] <= 127
  );
}

function isPublicIPv4(ip) {
  const parts = parseIPv4(ip);

  return Boolean(
    parts &&
    !isPrivateIPv4(ip) &&
    !isCGNATIPv4(ip) &&
    parts[0] !== 0 &&
    parts[0] !== 127 &&
    parts[0] < 224 &&
    !(parts[0] === 169 && parts[1] === 254)
  );
}

function detectNAT(localIP, exitIP) {
  if (isCGNATIPv4(localIP)) {
    return {
      label: "CGNAT",
      tone: "amber"
    };
  }

  if (
    isPrivateIPv4(localIP) &&
    isPublicIPv4(exitIP)
  ) {
    return {
      label: "Open",
      tone: "green"
    };
  }

  if (isPublicIPv4(localIP)) {
    return {
      label: "Open",
      tone: "green"
    };
  }

  if (isPrivateIPv4(localIP)) {
    return {
      label: "NAT",
      tone: "amber"
    };
  }

  return {
    label: "未知",
    tone: "red"
  };
}

function detectDNSProvider(addresses) {
  const list = Array.isArray(addresses)
    ? addresses.map(clean).filter(Boolean)
    : [clean(addresses)].filter(Boolean);

  if (list.length === 0) {
    return {
      full: "系统 DNS",
      short: "系统"
    };
  }

  const providers = [
    {
      full: "Cloudflare DNS",
      short: "CF",
      values: [
        "1.1.1.1",
        "1.0.0.1",
        "2606:4700:4700::1111",
        "2606:4700:4700::1001",
        "2606:4700:4700::64",
        "2606:4700:4700::6400"
      ]
    },
    {
      full: "Google DNS",
      short: "谷歌",
      values: [
        "8.8.8.8",
        "8.8.4.4",
        "2001:4860:4860::8888",
        "2001:4860:4860::8844"
      ]
    },
    {
      full: "Quad9 DNS",
      short: "Q9",
      values: [
        "9.9.9.9",
        "149.112.112.112",
        "2620:fe::fe",
        "2620:fe::9"
      ]
    },
    {
      full: "OpenDNS",
      short: "Open",
      values: [
        "208.67.222.222",
        "208.67.220.220",
        "2620:119:35::35",
        "2620:119:53::53"
      ]
    },
    {
      full: "AdGuard DNS",
      short: "AdG",
      values: [
        "94.140.14.14",
        "94.140.15.15",
        "94.140.14.15",
        "94.140.15.16",
        "2a10:50c0::ad1:ff",
        "2a10:50c0::ad2:ff"
      ]
    },
    {
      full: "AliDNS",
      short: "阿里",
      values: [
        "223.5.5.5",
        "223.6.6.6",
        "2400:3200::1",
        "2400:3200:baba::1"
      ]
    },
    {
      full: "DNSPod",
      short: "腾讯",
      values: [
        "119.29.29.29",
        "119.28.28.28",
        "2402:4e00::"
      ]
    },
    {
      full: "114DNS",
      short: "114",
      values: [
        "114.114.114.114",
        "114.114.115.115",
        "240c::6666",
        "240c::6644"
      ]
    },
    {
      full: "NextDNS",
      short: "Next",
      values: [
        "45.90.28.",
        "45.90.30.",
        "2a07:a8c0:"
      ]
    }
  ];

  for (let i = 0; i < list.length; i += 1) {
    const raw = normalizeDNS(list[i]);

    for (let p = 0; p < providers.length; p += 1) {
      const provider = providers[p];

      for (let v = 0; v < provider.values.length; v += 1) {
        const value = provider.values[v].toLowerCase();

        if (raw === value || raw.startsWith(value)) {
          return provider;
        }
      }
    }
  }

  for (let i = 0; i < list.length; i += 1) {
    const raw = normalizeDNS(list[i]);

    if (
      raw.startsWith("fe80:") ||
      isPrivateIPv4(raw)
    ) {
      return {
        full: "本地网关 DNS",
        short: "网关"
      };
    }
  }

  return {
    full: "自定义 DNS",
    short: "自定义"
  };
}

function normalizeDNS(value) {
  return clean(value)
    .toLowerCase()
    .replace(/^\[/, "")
    .replace(/\]$/, "")
    .replace(/%.*$/, "");
}

function gatewayLabel(value) {
  const gateway = clean(value);
  if (!gateway || gateway === "未获取") return "—";
  return gateway;
}

function shortISP(value) {
  const isp = clean(value);

  if (!isp || isp === "未知组织") {
    return "未知";
  }

  if (isp.length <= 12) {
    return isp;
  }

  const words = isp.split(/\s+/);

  if (words.length > 1) {
    return words[0];
  }

  return isp.slice(0, 11) + "…";
}

function randomAlphaNum(length) {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789";
  let out = "";

  for (let index = 0; index < length; index += 1) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }

  return out;
}

function timeLabel(date) {
  return (
    String(date.getHours()).padStart(2, "0") +
    ":" +
    String(date.getMinutes()).padStart(2, "0")
  );
}

function dateLabel(date) {
  const weekday = ["日", "一", "二", "三", "四", "五", "六"][date.getDay()];

  return (
    String(date.getMonth() + 1).padStart(2, "0") +
    "/" +
    String(date.getDate()).padStart(2, "0") +
    " 周" +
    weekday
  );
}

function getScreenMetric(ctx, key) {
  const candidates = [
    getAt(ctx, "screen." + key),
    getAt(ctx, "device.screen." + key),
    getAt(ctx, "device.screenSize." + key)
  ];

  try {
    if (typeof screen !== "undefined" && screen && Number(screen[key]) > 0) {
      candidates.push(screen[key]);
    }
  } catch (_) {}

  for (let index = 0; index < candidates.length; index += 1) {
    const value = Number(candidates[index]);

    if (Number.isFinite(value) && value > 0) {
      return value;
    }
  }

  return "";
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

  if (
    raw.includes("dark") ||
    raw.includes("深") ||
    raw === "2"
  ) {
    return "dark";
  }

  return "light";
}

function resolveAdaptiveColor(value, scheme) {
  if (typeof value === "string") {
    return value;
  }

  if (value && typeof value === "object") {
    return scheme === "dark"
      ? clean(value.dark) || clean(value.light)
      : clean(value.light) || clean(value.dark);
  }

  return "";
}

function clean(value) {
  return String(
    value === undefined || value === null ? "" : value
  ).trim();
}

function clamp(value, min, max) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return min;
  }

  return Math.max(min, Math.min(max, number));
}

function numberInRange(value, min, max, fallback) {
  const parsed = Number(value);

  if (!Number.isFinite(parsed)) {
    return fallback;
  }

  return Math.max(min, Math.min(max, Math.round(parsed)));
}

function pick() {
  for (let index = 0; index < arguments.length; index += 1) {
    const value = arguments[index];

    if (
      value !== undefined &&
      value !== null &&
      clean(value) !== ""
    ) {
      return value;
    }
  }

  return "";
}

function getAt(object, path) {
  const keys = String(path).split(".");
  let current = object;

  for (let index = 0; index < keys.length; index += 1) {
    if (
      !current ||
      typeof current !== "object" ||
      !(keys[index] in current)
    ) {
      return "";
    }

    current = current[keys[index]];
  }

  return current === undefined || current === null
    ? ""
    : current;
}

function truthy(value) {
  return value === true ||
    value === 1 ||
    ["true", "1", "yes", "y"].includes(
      clean(value).toLowerCase()
    );
}

function parseTrace(value) {
  const output = {};

  String(value || "")
    .split(/\r?\n/)
    .forEach(function (line) {
      const position = line.indexOf("=");

      if (position > 0) {
        output[line.slice(0, position).trim()] =
          line.slice(position + 1).trim();
      }
    });

  return output;
}

function countryCode(value) {
  const code = clean(value).toUpperCase();
  return /^[A-Z]{2}$/.test(code) ? code : "";
}

function flag(value) {
  const code = countryCode(value);
  if (!code) return "";
  return (
    String.fromCodePoint(code.charCodeAt(0) + 127397) +
    String.fromCodePoint(code.charCodeAt(1) + 127397)
  );
}