export default async function (ctx) {
  const results = {
    chatgpt: { name: "ChatGPT", status: "checking", color: "#8E8E93" },
    gemini: { name: "Gemini", status: "checking", color: "#8E8E93" },
  };

  // 测试 ChatGPT 连通性
  try {
    const chatgptResp = await ctx.http.get("https://api.openai.com/v1/models", {
      headers: {
        Authorization: `Bearer ${ctx.env.OPENAI_API_KEY || "test"}`,
      },
      timeout: 10000,
      redirect: "manual",
    });
    if (chatgptResp.status === 200 || chatgptResp.status === 401) {
      results.chatgpt.status = "Available";
      results.chatgpt.color = "#34C759";
    } else {
      results.chatgpt.status = `Error ${chatgptResp.status}`;
      results.chatgpt.color = "#FF3B30";
    }
  } catch (e) {
    results.chatgpt.status = "Failed";
    results.chatgpt.color = "#FF3B30";
  }

  // 测试 Gemini 连通性
  try {
    const geminiResp = await ctx.http.get(
      "https://generativelanguage.googleapis.com/v1/models",
      {
        timeout: 10000,
        redirect: "manual",
      }
    );
    if (geminiResp.status === 200 || geminiResp.status === 401 || geminiResp.status === 403) {
      results.gemini.status = "Available";
      results.gemini.color = "#34C759";
    } else {
      results.gemini.status = `Error ${geminiResp.status}`;
      results.gemini.color = "#FF3B30";
    }
  } catch (e) {
    results.gemini.status = "Failed";
    results.gemini.color = "#FF3B30";
  }

  // 根据小组件尺寸返回不同布局
  if (ctx.widgetFamily === "accessoryCircular") {
    return {
      type: "widget",
      children: [
        {
          type: "text",
          text: "AI",
          font: { size: "headline", weight: "bold" },
          textColor: "#FFFFFF",
        },
        {
          type: "text",
          text: results.chatgpt.status === "Available" && results.gemini.status === "Available" ? "OK" : "FAIL",
          font: { size: "caption2" },
          textColor: results.chatgpt.status === "Available" && results.gemini.status === "Available" ? "#34C759" : "#FF3B30",
        },
      ],
    };
  }

  if (ctx.widgetFamily === "accessoryRectangular") {
    return {
      type: "widget",
      children: [
        {
          type: "stack",
          direction: "row",
          alignItems: "center",
          gap: 6,
          children: [
            { type: "text", text: "ChatGPT", font: { size: "footnote", weight: "medium" } },
            { type: "spacer" },
            { type: "text", text: results.chatgpt.status, font: { size: "caption2" }, textColor: results.chatgpt.color },
          ],
        },
        {
          type: "stack",
          direction: "row",
          alignItems: "center",
          gap: 6,
          children: [
            { type: "text", text: "Gemini", font: { size: "footnote", weight: "medium" } },
            { type: "spacer" },
            { type: "text", text: results.gemini.status, font: { size: "caption2" }, textColor: results.gemini.color },
          ],
        },
      ],
    };
  }

  // 默认主屏幕小组件布局
  return {
    type: "widget",
    backgroundGradient: {
      type: "linear",
      colors: ["#1a1a2e", "#16213e"],
      startPoint: { x: 0, y: 0 },
      endPoint: { x: 1, y: 1 },
    },
    padding: 16,
    gap: 12,
    children: [
      {
        type: "stack",
        direction: "row",
        alignItems: "center",
        gap: 8,
        children: [
          {
            type: "image",
            src: "sf-symbol:brain.head.profile",
            color: "#007AFF",
            width: 20,
            height: 20,
          },
          {
            type: "text",
            text: "AI 连通性检测",
            font: { size: "headline", weight: "bold" },
            textColor: "#FFFFFF",
          },
        ],
      },
      {
        type: "stack",
        direction: "column",
        gap: 8,
        children: [
          {
            type: "stack",
            direction: "row",
            alignItems: "center",
            gap: 8,
            children: [
              {
                type: "image",
                src: "sf-symbol:sparkles",
                color: "#000000",
                width: 16,
                height: 16,
              },
              {
                type: "text",
                text: "ChatGPT",
                font: { size: "subheadline", weight: "medium" },
                textColor: "#FFFFFF",
                flex: 1,
              },
              {
                type: "text",
                text: results.chatgpt.status,
                font: { size: "subheadline", weight: "semibold" },
                textColor: results.chatgpt.color,
              },
            ],
          },
          {
            type: "stack",
            direction: "row",
            alignItems: "center",
            gap: 8,
            children: [
              {
                type: "image",
                src: "sf-symbol:stars",
                color: "#4285F4",
                width: 16,
                height: 16,
              },
              {
                type: "text",
                text: "Gemini",
                font: { size: "subheadline", weight: "medium" },
                textColor: "#FFFFFF",
                flex: 1,
              },
              {
                type: "text",
                text: results.gemini.status,
                font: { size: "subheadline", weight: "semibold" },
                textColor: results.gemini.color,
              },
            ],
          },
        ],
      },
      {
        type: "date",
        format: "relative",
        font: { size: "caption2" },
        textColor: "#888888",
      },
    ],
  };
}
