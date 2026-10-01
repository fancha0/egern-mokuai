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
      typeof symbol === "string" ? image(symbol, tone, 11, 11) : symbol,
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

            rawImage(
            "data:image/png;base64,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",
            11,
            11,
            { cornerRadius: 2 }
          ),

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
          rawImage(
            "data:image/png;base64,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",
            12,
            12,
            { cornerRadius: 2 }
          ),
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

    if (item.kind === "tiktok") {
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

    if (item.kind === "youtube") {
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

    if (item.kind === "prime") {
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

    if (item.kind === "netflix") {
      return row(
        [
          rawImage(
            "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAGAAAABgCAYAAADimHc4AAAHjElEQVR42u2d3W8cVxmHn/fM7Ic/kjTeOCEiaYiaKAoSAkE/EAWpFapU0TaoFKlSK/4B7rklhUsuuOaqV0gVFUKIqlCuClWhVKhwQUqE4hKSJk2Ik4Y43ux6d875cTGzdklS4hh77LOcV1p5bEuz55xn3s85846xjiJoGAzPTe76bia+F5b/jK3lfDkwDPbSvqX55wTOIKxyHGagc+3OdzKzH6gaxNqmhDnAG8f33bj8/dEc12vNHFtUBDIA05NnW7OHDKQ1gtzKsmUBGJgHzJhwZscA/QayBKBG8aAWlpuFJ09D+xEI46YFWxpAZXYAfda1Z++vfIBLAGoc3wDRwHY4hccjGfNYAQDwTSxzZl9dmN67Cyg0RhC2/EQEro/AOLrg/ZesDA0TgJqjoWI7tsMUHj9ejnnNuUUCsDYtsGEZFT387db2gwZ+XMxQLJNwPRQmjSOFNR5aUY4EoDYzBBTT5lrBeOw0tEuFiB9CNGosyLoKCDvSaO+cNdDxBKDesfbBbxOfKYr8XoBHxsAPRDOBygz5CWfTea5HKwA+9tJEVFeQIF+Q5NDT703t3mNrrjInAGvVAjeAYsZln297HR6HaCg6G2pgfQkRnrmbmzQJwDpGQzeQGmbPfDC9dyZ2LYhSAwJoAttvYfhg5YSVANTMoYfkFb4VuyOOEkClBWa4Jy6ye08CsDm+gBy2DVrhiep3SwBqBmCgzPF8zI44ZgAyMIn7TzdnjhLptpVoARhYAWTGVNPxdOWMswSgRgmgNpaBO3b6wIF2MkGbIEVpjg43/9l9wMob9lkCUKMZGqDQduwQ+kaMc4peAwRqyDKHfWVuas/uSilcAlDjHHqIAIemQvGQgd6NyAxFD6DatjLc6dwO4b4OMB9RhXQstnYI3JJEUHjgTGv2vkdLM5QA1DmPqkR9NDc9mJzwJpghoNhmriELX1O5bYUQQWY8TjuNswUFAvblC82ZgxUYlwDUpwWugGK72adk7uFKA5IJqt8jmzCeOsu+iTxY3xKAes1QF8mMxyYnbnRkWkoaUL8zDtNmE33pWWdM+gSg/pygL8nIvilxD+Um3gSgTmc8AFrGF3HWSgA2SQoQUoctnguMJQCrkjDBMZUdDxKAuhkIyM12WXWcAGyWGUpR0KaHpQlAkgQgAfgfEislAJso2Rg2aYoJgDzqJgCblEwBwYm/2bI1SgDqtv9grusYX0ew1U2QBeS9WHBlRqsEoMar34GTwoIIr7dKo5QA1D04yV0z515tlY4gJAA1Dy4zut7b612FJcCNmxmKIBFTtn92/vwQ+/1E2RHXJwC1+gGX2Tl6eP2yZRb1M8GRhqGl2Q9Bb1wPmrfyBktIAGqSMDI5xeRcgd6eLrXAJwA1SSYrAO7l3IeZ8WohoTFyxjFowIq5MftjD51pYRkJQG1+IFQ/benG1LuS/ak9RjlBBOVoFQCnONQ8yJm+HK8tSoVBptQxa+OlsHKRDzPnAbIifzOgMxOYjYMWRHBL0kaLHARu7+DiyQDvVANPbSs3fPkJxUfSgsxAFvTrLqGXpbaVG5+IqXyTybJFEpgtDX6hYJda2LKTTgA2TvyKNpRa8EkWL5vjtwWK4jGkKAGMjHtmdvMjp0FgAXtliAaxv9Ungjwg+JvAhBfA9vfmfyrsQlaaodS0bwN14Za6zwujwYtXfGmGUtvKDdOAcNvCW1kotfDjYvTCtwRggwDYrRowalW5t/fh2yZOugRg48JQd5MPuOn/To6X8ojD0QieJDf/MYtvBkEZPxmiQKTbVmKohvqPCVMFsO/61PsevdUkztuVUfqA/5QzSwS9OFmGQj4BWHcJ4b/5AAPRdG/+S6EvyGMzQzG8yK24g5+m1dQF4X4+XaYDPgFYR/Er5ejb+gFBNnvlyvUcfta0+FrZx5CIrS68dO7kfAjnM2go9Yxbvzyggd2p/1t4GbLr3W2nmriXZ8zJoWEsAPKtPkBvFu7gI1Q647ml83Te6WLmsYYRR4Eoml0Rd3QVQKbsrcWgP09jLhZnvOUBrMIEYRBO8OnmJ5Yu/d3B76bMoskJtv6uCPyqHGqfvwogM71xSb7roKnUqmBdMuFVAfgCFMfB5T17DdmJaeLQghiKcavqgmug5znUmOXKdbC/BIvjrdtbvxSxSg0AOMxcFX4WL15TuNwsm3iHBOD20Y2qTxh9KN+O6qsKaCEohoVf9QJaeZ5sX//qH3JxPi9L2aNzjr5HGu14+T/IA0Q54VG8PlooHDhX/rQyZi/rCKPP6NIdGHebVJmA82a/yuBz01jmq3MFhJaPbw1xqzqG3ZRjsJGmbMMA2Mri2sqx4YCBhEeXvNlFD4uCrqSuGYumsOjMLXqx6NDi8O4bXnkDvdf2P7rayy43jN1BYaeZ7QTrBDFjphlEp2VuavQQuJavGH3kuPxyi00DTHJedk2EOWfZqRD0D5zeB52jcGe7eZifytv9pbxXDK66cA95GNIIPdqh2oQbRm9JPQHN0dW4WmcMcN/Vq2eBHx4H9xRkHQ5kbfpZn0He2O6zPExmIfjMnN95o3CzmYUOpl1FsF3OXMeJDtAR2g12xNCGmOt/AxsrEZX0puY4AAAAAElFTkSuQmCC",
            15,
            15,
            { cornerRadius: 4 }
          )
        ],
        base
      );
    }

    if (item.kind === "disney") {
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
          serviceCard("流媒体解锁", rawImage(
            "data:image/png;base64,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",
            11,
            11,
            { cornerRadius: 2 }
          ), media, C.blue),
          serviceCard("AI 解锁检测", rawImage(
            "data:image/png;base64,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",
            11,
            11,
            { cornerRadius: 2 }
          ), ai, C.purple)
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