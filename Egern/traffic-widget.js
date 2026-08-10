// =========================
// 流量统计 - 小组件展示脚本
// 脚本类型: generic
// =========================

const C = {
  success: '#34C759', warning: '#FF9500', restricted: '#FF3B30', failure: '#FF3B30',
  unknown: '#8E8E93', accent: '#0A84FF',
  text: { light: '#1C1C1E', dark: '#FFFFFF' },
  secondary: { light: '#666666', dark: '#B0B0B0' },
  bg: { light: '#FFFFFF', dark: '#1C1C1E' },
};

function fmtBytes(bytes) {
  if (!bytes || bytes <= 0) return '0 B';
  const KB = 1024, MB = KB * 1024, GB = MB * 1024, TB = GB * 1024;
  if (bytes >= TB) return (bytes / TB).toFixed(2) + ' TB';
  if (bytes >= GB) return (bytes / GB).toFixed(2) + ' GB';
  if (bytes >= MB) return (bytes / MB).toFixed(1) + ' MB';
  if (bytes >= KB) return (bytes / KB).toFixed(1) + ' KB';
  return bytes + ' B';
}

function tx(t, o = {}) {
  return { type: 'text', text: t, font: o.font || { size: 10 }, textColor: o.color || C.text, textAlign: o.align || 'left', maxLines: o.maxLines || 1, minScale: o.minScale || 0.6 };
}
function icon(n, c, s = 11) {
  return { type: 'image', src: `sf-symbol:${n}`, color: c, width: s, height: s };
}
function line() {
  return { type: 'stack', height: 0.5, backgroundColor: { light: 'rgba(0,0,0,0.08)', dark: 'rgba(255,255,255,0.12)' } };
}

function getInfo(ctx, key) {
  const v = ctx.storage.get(key);
  if (!v) return { bytes: 0, display: '0 B', color: C.secondary };
  const n = parseInt(v, 10) || 0;
  return { bytes: n, display: fmtBytes(n), color: n > 1024 * 1024 * 1024 ? C.warning : n > 0 ? C.success : C.secondary };
}

function row(label, info, iconName) {
  return {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 5, children: [
      icon(iconName, C.accent, 11),
      tx(label, { color: C.secondary, font: { size: 10 } }),
      { type: 'spacer' },
      tx(info.display, { color: info.color, font: { size: 10, weight: 'bold' } }),
    ]
  };
}

function compact(ss, refresh) {
  const total = ss.total;
  return { type: 'widget', refreshAfter: refresh, padding: 0, children: [tx(`● 代理流量 ${total.display}`, { color: total.color, font: { size: 'caption1', weight: 'semibold' } })] };
}

function notice(refresh, msg) {
  return { type: 'widget', refreshAfter: refresh, padding: 16, children: [tx(msg, { font: { size: 'callout' }, align: 'center' })] };
}

function dashboard(ctx, refresh) {
  const now = new Date();

  // 日期 key
  const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}-${String(now.getDate()).padStart(2, '0')}`;
  const dayIdx = (now.getDay() + 6) % 7;
  const weekStart = new Date(now);
  weekStart.setDate(now.getDate() - dayIdx);
  weekStart.setHours(0, 0, 0, 0);
  const weekKey = `traffic_week_${weekStart.getFullYear()}-${String(weekStart.getMonth() + 1).padStart(2, '0')}-${String(weekStart.getDate()).padStart(2, '0')}`;
  const monthKey = `traffic_month_${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

  // 读取数据
  const day = getInfo(ctx, `traffic_day_${today}`);
  const week = getInfo(ctx, weekKey);
  const month = getInfo(ctx, monthKey);
  const total = getInfo(ctx, 'traffic_total');
  const count = ctx.storage.get(`traffic_count_${today}`) || '0';
  const lastUpdate = ctx.storage.get('traffic_last_update');

  // 计算日均
  const dayBytes = day.bytes || 0;
  const avgPerReq = parseInt(count, 10) > 0 ? dayBytes / parseInt(count, 10) : 0;

  // 标题栏
  const titleRow = {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 5, children: [
      tx('流量统计', { color: { light: '#1A1A1A', dark: '#FFD700' }, font: { size: 13, weight: 'heavy' } }),
      icon('chart.bar.fill', C.accent, 13),
      { type: 'spacer' },
      icon('arrow.clockwise', { light: '#666', dark: '#B0B0B0' }, 10),
      { type: 'date', date: lastUpdate || now.toISOString(), format: 'relative', font: { size: 'caption2' }, textColor: { light: '#666', dark: '#B0B0B0' } },
    ]
  };

  // 今日详情行
  const detailRow = {
    type: 'stack', direction: 'row', gap: 12, children: [
      {
        type: 'stack', direction: 'column', gap: 3, flex: 1, children: [
          row('今日下载', day, 'arrow.down.circle.fill'),
          row('本周累计', week, 'calendar'),
        ]
      },
      {
        type: 'stack', direction: 'column', gap: 3, flex: 1, children: [
          row('本月累计', month, 'calendar.badge.clock'),
          row('总计', total, 'internaldn'),
        ]
      },
    ]
  };

  // 请求数和平均
  const statRow = {
    type: 'stack', direction: 'row', alignItems: 'center', gap: 5, children: [
      icon('number.circle', C.secondary, 10),
      tx(`今日 ${count} 次请求`, { color: C.secondary, font: { size: 9 } }),
      { type: 'spacer' },
      icon('gauge', C.secondary, 10),
      tx(`均值 ${fmtBytes(avgPerReq)}/次`, { color: C.secondary, font: { size: 9 } }),
    ]
  };

  return {
    type: 'widget', refreshAfter: refresh, padding: [8, 10], gap: 5, children: [
      titleRow,
      detailRow,
      line(),
      statRow,
      tx('仅统计 MITM 解密流量', { color: { light: '#999', dark: '#666' }, font: { size: 8 }, maxLines: 1 }),
    ]
  };
}

export default async function(ctx) {
  const e = ctx.env || {};
  const ri = parseInt(e.REFRESH_INTERVAL || '900', 10);
  const refresh = new Date(Date.now() + ri * 1000).toISOString();

  // 检查是否有数据
  const total = ctx.storage.get('traffic_total');
  if (!total) {
    return notice(refresh, '暂无流量数据\n请确保已开启 MITM 并安装拦截脚本');
  }

  const data = {
    day: getInfo(ctx, `traffic_day_${new Date().toISOString().slice(0, 10)}`),
    total: getInfo(ctx, 'traffic_total'),
  };

  if (ctx.widgetFamily === 'accessoryInline' || ctx.widgetFamily === 'accessoryCircular') {
    return compact(data, refresh);
  }
  if (ctx.widgetFamily === 'systemSmall' || ctx.widgetFamily === 'accessoryRectangular') {
    return notice(refresh, `代理流量总计\n${data.total.display}`);
  }
  return dashboard(ctx, refresh);
}
