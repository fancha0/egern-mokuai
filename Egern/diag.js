// =========================
// Egern ctx 对象诊断脚本
// 脚本类型: generic (widget)
// 用途：探测 ctx 对象上所有可用的属性和方法
//       特别是是否有流量相关的隐藏 API
// =========================

export default async function(ctx) {
  const results = [];

  // 1. 枚举 ctx 顶层属性
  results.push('=== ctx 顶层属性 ===');
  for (const key of Object.keys(ctx)) {
    const val = ctx[key];
    const type = typeof val;
    if (type === 'object' && val !== null) {
      const subKeys = Object.keys(val).join(', ');
      results.push(`ctx.${key} = [object] { ${subKeys} }`);
    } else if (type === 'function') {
      results.push(`ctx.${key} = [function]`);
    } else {
      results.push(`ctx.${key} = ${String(val).substring(0, 80)}`);
    }
  }

  // 2. 深入探测 ctx.device
  results.push('');
  results.push('=== ctx.device 详情 ===');
  if (ctx.device) {
    for (const key of Object.keys(ctx.device)) {
      const val = ctx.device[key];
      if (typeof val === 'object' && val !== null) {
        const sub = {};
        for (const k of Object.keys(val)) {
          sub[k] = String(val[k]).substring(0, 60);
        }
        results.push(`device.${key} = ${JSON.stringify(sub)}`);
      } else {
        results.push(`device.${key} = ${String(val).substring(0, 80)}`);
      }
    }
  }

  // 3. 探测 ctx.app
  results.push('');
  results.push('=== ctx.app 详情 ===');
  if (ctx.app) {
    for (const key of Object.keys(ctx.app)) {
      results.push(`app.${key} = ${String(ctx.app[key]).substring(0, 80)}`);
    }
  }

  // 4. 探测 ctx.storage 可用方法
  results.push('');
  results.push('=== ctx.storage 方法 ===');
  if (ctx.storage) {
    results.push(`storage keys: ${Object.keys(ctx.storage).join(', ')}`);
  }

  // 5. 尝试访问可能的流量 API
  results.push('');
  results.push('=== 流量 API 探测 ===');
  const trafficKeys = ['traffic', 'stats', 'connections', 'bytes', 'dataUsage', 'networkStats', 'ifconfig', 'interface'];
  for (const key of trafficKeys) {
    results.push(`ctx.${key}: ${ctx[key] !== undefined ? JSON.stringify(ctx[key]).substring(0, 100) : 'undefined'}`);
  }

  // 6. 尝试访问本地 API 端口
  results.push('');
  results.push('=== 本地 API 端口探测 ===');
  const ports = [3080, 3090, 6171, 9090, 9999, 8080, 8443];
  for (const port of ports) {
    try {
      const resp = await ctx.http.get(`http://127.0.0.1:${port}/`, { timeout: 2000 });
      const body = await resp.text();
      results.push(`127.0.0.1:${port} → HTTP ${resp.status}, body: ${body.substring(0, 100)}`);
    } catch(e) {
      results.push(`127.0.0.1:${port} → ${String(e).substring(0, 60)}`);
    }
  }

  // 7. 尝试常见的 API 路径
  results.push('');
  results.push('=== API 路径探测 (port 3080) ===');
  const paths = ['/traffic', '/connections', '/stats', '/api/traffic', '/api/stats', '/v1/traffic', '/api/v1/traffic', '/query'];
  for (const path of paths) {
    try {
      const resp = await ctx.http.get(`http://127.0.0.1:3080${path}`, { timeout: 2000 });
      const body = await resp.text();
      results.push(`3080${path} → HTTP ${resp.status}, body: ${body.substring(0, 100)}`);
    } catch(e) {
      results.push(`3080${path} → ${String(e).substring(0, 50)}`);
    }
  }

  // 8. 检查 ctx 上所有以 get 开头的函数
  results.push('');
  results.push('=== ctx 上的函数 ===');
  for (const key of Object.keys(ctx)) {
    if (typeof ctx[key] === 'function') {
      results.push(`ctx.${key}()`);
    }
    if (typeof ctx[key] === 'object' && ctx[key] !== null) {
      for (const subKey of Object.keys(ctx[key])) {
        if (typeof ctx[key][subKey] === 'function') {
          results.push(`ctx.${key}.${subKey}()`);
        }
      }
    }
  }

  // 保存结果到 storage 以便查看
  ctx.storage.set('diag_results', results.join('\n'));

  // 返回 widget 展示
  const lines = results.slice(0, 40); // 最多显示 40 行
  return {
    type: 'widget',
    padding: 8,
    gap: 2,
    children: lines.map(line => ({
      type: 'text',
      text: line,
      font: { size: 7 },
      textColor: { light: '#1C1C1E', dark: '#FFFFFF' },
      maxLines: 1,
      minScale: 0.5,
    })),
  };
}
