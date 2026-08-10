// =========================
// 流量统计 - 响应拦截脚本
// 脚本类型: http_response
// match: "^https?://.*"
// =========================
// 拦截所有 HTTP/HTTPS 响应，读取 Content-Length 累计流量
// 通过 ctx.storage 持久化存储，按天/周/月分别统计

export default async function(ctx) {
  try {
    // 读取响应头 Content-Length
    const headers = ctx.response?.headers;
    let contentLength = 0;
    if (headers) {
      const raw = typeof headers.get === 'function'
        ? headers.get('content-length')
        : (headers['content-length'] || headers['Content-Length'] || headers['Content-Length'.toLowerCase()] || '');
      const n = parseInt(String(raw || ''), 10);
      if (Number.isFinite(n) && n > 0) contentLength = n;
    }

    // 如果拿不到 Content-Length，尝试读取 body 大小
    if (contentLength === 0 && ctx.response?.body) {
      try {
        const text = await ctx.response.text();
        if (text) contentLength = new Blob([text]).size || text.length;
      } catch {}
    }

    if (contentLength <= 0) return;

    // 计算当前日期 key
    const now = new Date();
    const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
    const dayKey = `traffic_day_${today}`;

    // 本周 key（周一为起始）
    const dayIdx = (now.getDay() + 6) % 7; // 0=周一
    const weekStart = new Date(now);
    weekStart.setDate(now.getDate() - dayIdx);
    weekStart.setHours(0, 0, 0, 0);
    const weekKey = `traffic_week_${weekStart.getFullYear()}-${String(weekStart.getMonth() + 1).padStart(2, '0')}-${String(weekStart.getDate()).padStart(2, '0')}`;

    // 本月 key
    const monthKey = `traffic_month_${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

    // 总计 key
    const totalKey = 'traffic_total';

    // 读取并累加（ctx.storage 同步操作）
    const dayBytes = parseInt(ctx.storage.get(dayKey) || '0', 10) + contentLength;
    ctx.storage.set(dayKey, String(dayBytes));

    const weekBytes = parseInt(ctx.storage.get(weekKey) || '0', 10) + contentLength;
    ctx.storage.set(weekKey, String(weekBytes));

    const monthBytes = parseInt(ctx.storage.get(monthKey) || '0', 10) + contentLength;
    ctx.storage.set(monthKey, String(monthBytes));

    const totalBytes = parseInt(ctx.storage.get(totalKey) || '0', 10) + contentLength;
    ctx.storage.set(totalKey, String(totalBytes));

    // 记录今日请求次数
    const countKey = `traffic_count_${today}`;
    const count = parseInt(ctx.storage.get(countKey) || '0', 10) + 1;
    ctx.storage.set(countKey, String(count));

    // 记录最后更新时间
    ctx.storage.set('traffic_last_update', now.toISOString());

    // 记录今日起始时间（用于 widget 显示"今日已运行时长"）
    const startKey = `traffic_start_${today}`;
    if (!ctx.storage.get(startKey)) {
      ctx.storage.set(startKey, now.toISOString());
    }
  } catch (e) {
    // 静默失败，不影响正常流量
  }
}
