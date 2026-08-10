const C={success:'#34C759',warning:'#FF9500',restricted:'#FF3B30',failure:'#FF3B30',unknown:'#8E8E93',accent:'#0A84FF',chatgpt:'#10A37F',gemini:'#4B8BF5',claude:'#D97757',copilot:'#7B61FF',perplexity:'#20808D',text:{light:'#1C1C1E',dark:'#FFF'},secondary:{light:'#636366',dark:'#AEAEB2'},background:{light:'#F2F2F7',dark:'#1C1C1E'},card:{light:'#FFF',dark:'#2C2C2E'}};
const SERVICES={
 chatgpt:{name:'ChatGPT',url:'https://chatgpt.com/',icon:'bubble.left.and.bubble.right.fill',color:C.chatgpt,probe:'https://chatgpt.com/',restricted:['unsupported_country_region_territory','unsupported country','country or region is not supported'],challenge:['cf-mitigated','challenge-platform','enable javascript and cookies']},
 gemini:{name:'Gemini',url:'https://gemini.google.com/',icon:'sparkle',color:C.gemini,probe:'https://gemini.google.com/',restricted:['support.google.com/gemini/answer/13575153','isn\'t currently supported in your country','not available in your country','您所在的国家/地区目前无法使用']},
 claude:{name:'Claude',url:'https://claude.ai/',icon:'text.bubble.fill',color:C.claude,probe:'https://claude.ai/',restricted:['unsupported country','not available in your country','not available in your region','您所在的地区']},
 copilot:{name:'Copilot',url:'https://copilot.microsoft.com/',icon:'person.crop.circle.badge.checkmark',color:C.copilot,probe:'https://copilot.microsoft.com/',restricted:['not available in your country','not available in your region','unsupported country']},
 perplexity:{name:'Perplexity',url:'https://www.perplexity.ai/',icon:'magnifyingglass',color:C.perplexity,probe:'https://www.perplexity.ai/',restricted:['not available in your country','not available in your region','unsupported country']}
};
function int(v,a,d){v=parseInt(v||'',10);return a.includes(v)?v:d} function header(h,n){if(!h)return'';return typeof h.get==='function'?(h.get(n)||''):(h[n]||h[n.toLowerCase()]||'')}
function opts(policy,timeout,redirect='manual'){const o={timeout,redirect,credentials:'omit',headers:{'User-Agent':'Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1','Accept':'text/html,application/json;q=0.9,*/*;q=0.8','Accept-Language':'zh-CN,zh;q=0.9,en;q=0.6'}};if(policy)o.policy=policy;return o}
async function get(ctx,url,o,body=true){const t=Date.now();try{const r=await ctx.http.get(url,o);let b='';if(body)try{b=(await r.text()).slice(0,180000)}catch{}return{ok:true,status:r.status,headers:r.headers,body:b,latency:Date.now()-t}}catch(e){return{ok:false,status:0,headers:null,body:'',latency:Date.now()-t,error:String(e?.message||e)}}}
function traceRegion(r){const m=r.ok&&r.status===200&&r.body.match(/(?:^|\n)loc=([A-Z]{2})(?:\n|$)/i);return m?m[1].toUpperCase():'--'}
function failureDetail(r){const e=(r.error||'').toLowerCase();if(e.includes('timeout'))return '请求超时';if(e.includes('dns')||e.includes('resolve'))return 'DNS 解析失败';if(e.includes('ssl')||e.includes('tls')||e.includes('certificate'))return 'TLS 连接失败';return '网络不可达'}
function make(id,state,status,region,latency,detail){const s=SERVICES[id];return{id,...s,state,status,region:region||'--',latency,detail,available:['success','warning'].includes(state),color:C[state]||C.unknown}}
function classify(id,r,region){const s=SERVICES[id];if(!r.ok)return make(id,'failure','连接失败',region,r.latency,failureDetail(r));const loc=header(r.headers,'location').toLowerCase(),all=(loc+'\n'+r.body).toLowerCase();if(s.restricted.some(x=>all.includes(x.toLowerCase())))return make(id,'restricted','地区受限',region,r.latency,`HTTP ${r.status}`);if((s.challenge||[]).some(x=>all.includes(x)))return make(id,'warning','需要验证',region,r.latency,'Cloudflare / 浏览器验证');if(r.status>=200&&r.status<300){if(id==='gemini'&&!/45631641,null,true|gemini|accounts\.google\.com/i.test(r.body))return make(id,'warning','可连接',region,r.latency,'页面特征不足，建议登录确认');return make(id,'success','已解锁',region,r.latency,`HTTP ${r.status}`)}if(r.status>=300&&r.status<400&&/accounts\.google\.com|login|signin|auth/i.test(loc))return make(id,'success','已解锁',region,r.latency,'需要登录');if(r.status===401)return make(id,'success','已解锁',region,r.latency,'需要登录 / 认证');if(r.status===429)return make(id,'warning','可连接（限流）',region,r.latency,'HTTP 429');if(r.status===403)return make(id,'restricted','访问受限',region,r.latency,'HTTP 403');return make(id,'unknown','检测异常',region,r.latency,`HTTP ${r.status}`)}
function tx(text, o={}) { return {type:'text',text,font:o.font||{size:10},textColor:o.color||C.text,textAlign:o.align||'left',maxLines:o.maxLines||1,minScale:o.minScale||.6}; }
function icon(name,color,size=11){return {type:'image',src:`sf-symbol:${name}`,color,width:size,height:size};}
function line(){return {type:'stack',height:.5,backgroundColor:{light:'rgba(0,0,0,0.08)',dark:'rgba(255,255,255,0.12)'}};}
function stateView(s){
 const bad=s.state==='failure'||s.state==='restricted';
 const warn=s.state==='warning'||s.state==='unknown';
 return {label:bad?'不可用':warn?(s.status==='需要验证'?'待验证':'受限/异常'):(s.region==='--'?'可用':s.region), color:bad?C.failure:warn?C.warning:C.success, icon:bad?'xmark.circle.fill':warn?'exclamationmark.circle.fill':'checkmark.circle.fill'};
}
function serviceRow(s){const v=stateView(s);return {type:'stack',direction:'row',alignItems:'center',gap:5,children:[icon(v.icon,v.color),tx(s.name,{font:{size:10,weight:'medium'}}),{type:'spacer'},tx(v.label,{color:v.color,font:{size:10,weight:'bold'}})]};}
function latencyRow(s){const v=stateView(s), d=s.latency>0?`${s.latency} ms`:'--';return {type:'stack',direction:'row',alignItems:'center',gap:5,children:[icon('bolt.horizontal',v.color),tx(s.name,{color:C.secondary,font:{size:10}}),{type:'spacer'},tx(d,{color:s.latency<400?C.success:s.latency<900?C.warning:C.failure,font:{size:10,weight:'bold'}})]};}
function compact(ss,refresh){const n=ss.filter(x=>x.available).length,col=n===ss.length?C.success:n?C.warning:C.failure;return {type:'widget',refreshAfter:refresh,padding:0,backgroundColor:C.background,children:[tx(`● AI 服务 ${n}/${ss.length} 可用`,{color:col,font:{size:'caption1',weight:'semibold'}})]};}
function notice(refresh,msg){return {type:'widget',refreshAfter:refresh,padding:16,backgroundColor:{light:'#FFFFFF',dark:'#1C1C1E'},children:[tx(msg,{font:{size:'callout'},align:'center'})]};}
function dashboard(ss,refresh,policy,at){
 const left=ss.slice(0,Math.ceil(ss.length/2)), right=ss.slice(Math.ceil(ss.length/2));
 const count=ss.filter(x=>x.available).length, overall=count===ss.length?C.success:count?C.warning:C.failure;
 const title=count===ss.length?'全部可用':`${count}/${ss.length} 可用`;
 return {type:'widget',refreshAfter:refresh,padding:[8,10],gap:5,backgroundColor:{light:'#FFFFFF',dark:'#1C1C1E'},children:[
  {type:'stack',direction:'row',alignItems:'center',gap:5,children:[
   tx('AI 服务连通性',{color:{light:'#1A1A1A',dark:'#FFD700'},font:{size:13,weight:'heavy'}}),
   icon(count===ss.length?'checkmark.shield.fill':'exclamationmark.shield.fill',overall,12),tx(title,{color:overall,font:{size:11,weight:'bold'}}),
   {type:'spacer'},icon('arrow.triangle.branch',{light:'#FF9500',dark:'#FF9500'},11),tx(policy||'默认分流',{color:{light:'#FF9500',dark:'#FF9500'},font:{size:10,weight:'bold'}}),{type:'spacer'},icon('arrow.clockwise',{light:'#666',dark:'#B0B0B0'},10),{type:'date',date:at,format:'relative',font:{size:'caption2'},textColor:{light:'#666',dark:'#B0B0B0'}}]},
  {type:'stack',direction:'row',gap:12,children:[
   {type:'stack',direction:'column',gap:3,flex:1,children:left.map(serviceRow)},
   {type:'stack',direction:'column',gap:3,flex:1,children:right.map(serviceRow)}]},line(),
  {type:'stack',direction:'row',gap:12,children:[
   {type:'stack',direction:'column',gap:3,flex:1,children:left.map(latencyRow)},
   {type:'stack',direction:'column',gap:3,flex:1,children:right.map(latencyRow)}]},
  tx('状态：绿色可用 · 黄色需验证/异常 · 红色不可用',{color:{light:'#666',dark:'#B0B0B0'},font:{size:9},maxLines:1})
 ]};
}
export default async function(ctx){
 const e=ctx.env||{},policy=(e.POLICY||'').trim(),mode=['fast','standard','strict'].includes(e.DETECTION_MODE)?e.DETECTION_MODE:'standard',timeout=int(e.REQUEST_TIMEOUT,[5000,8000,12000],8000),ri=int(e.REFRESH_INTERVAL,[300,900,1800,3600],900),raw=(e.SERVICES||'all').toLowerCase().split(',').map(x=>x.trim()),ids=raw.includes('all')?Object.keys(SERVICES):Object.keys(SERVICES).filter(x=>raw.includes(x)),selected=ids.length?ids:['chatgpt','gemini'];
 const at=new Date().toISOString(),refresh=new Date(Date.now()+ri*1000).toISOString(),trace=await get(ctx,'https://chatgpt.com/cdn-cgi/trace',opts(policy,timeout),true),region=traceRegion(trace);
 const probes=await Promise.all(selected.map(id=>get(ctx,SERVICES[id].probe,opts(policy,timeout),mode!=='fast'))),ss=probes.map((p,i)=>classify(selected[i],p,region));
 if(ctx.widgetFamily==='accessoryInline'||ctx.widgetFamily==='accessoryCircular')return compact(ss,refresh);
 if(ctx.widgetFamily==='systemSmall'||ctx.widgetFamily==='accessoryRectangular')return notice(refresh,'请使用中号或大号组件');
 return dashboard(ss,refresh,policy,at);
}
