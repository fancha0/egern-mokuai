const C={success:'#34C759',warning:'#FF9500',restricted:'#FF3B30',failure:'#FF3B30',unknown:'#8E8E93',accent:'#0A84FF',chatgpt:'#10A37F',gemini:'#4B8BF5',claude:'#D97757',copilot:'#7B61FF',perplexity:'#20808D',text:{light:'#1C1C1E',dark:'#FFF'},secondary:{light:'#636366',dark:'#AEAEB2'},background:{light:'#F2F2F7',dark:'#1C1C1E'}};
const SERVICES={
 chatgpt:{name:'ChatGPT',url:'https://chatgpt.com/'},
 gemini:{name:'Gemini',url:'https://gemini.google.com/'},
 claude:{name:'Claude',url:'https://claude.ai/'},
 copilot:{name:'Copilot',url:'https://copilot.microsoft.com/'},
 perplexity:{name:'Perplexity',url:'https://www.perplexity.ai/'}
};
const UA='Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1';

function int(v,a,d){v=parseInt(v||'',10);return a.includes(v)?v:d}
function opts(policy,timeout,extra={}){const {redirect='manual',...headers}=extra;const o={timeout,credentials:'omit',redirect,headers:{'User-Agent':UA,'Accept':'text/html,application/json;q=0.9,*/*;q=0.8','Accept-Language':'zh-CN,zh;q=0.9,en;q=0.6',...headers}};if(policy)o.policy=policy;return o}
async function get(ctx,url,o,readBody=true){const t=Date.now();try{const r=await ctx.http.get(url,o);let b='';if(readBody)try{b=(await r.text()).slice(0,200000)}catch{}return{ok:true,status:r.status,headers:r.headers,body:b,latency:Date.now()-t}}catch(e){return{ok:false,status:0,headers:null,body:'',latency:Date.now()-t,error:String(e?.message||e)}}}
async function post(ctx,url,body,o){const t=Date.now();try{const opt={...o,body};const r=await ctx.http.post(url,opt);let b='';try{b=(await r.text()).slice(0,200000)}catch{}return{ok:true,status:r.status,headers:r.headers,body:b,latency:Date.now()-t}}catch(e){return{ok:false,status:0,headers:null,body:'',latency:Date.now()-t,error:String(e?.message||e)}}}
function traceRegion(r){if(!r.ok||r.status!==200)return'--';const m=r.body.match(/(?:^|\n)loc=([A-Z]{2})(?:\n|$)/i);return m?m[1].toUpperCase():'--'}
function failDetail(r){const e=(r.error||'').toLowerCase();if(e.includes('timeout'))return'超时';if(e.includes('dns')||e.includes('resolve'))return'DNS 失败';if(e.includes('ssl')||e.includes('tls'))return'TLS 失败';return'网络不可达'}
function make(id,state,status,region,latency,detail){return{id,...SERVICES[id],state,status,region:region||'--',latency,detail,available:['success','warning'].includes(state),color:C[state]||C.unknown}}

// ChatGPT：同时探测网页端和 APP 端
async function checkChatGPT(ctx,policy,timeout,region){
 const o=opts(policy,timeout),oIos=opts(policy,timeout,{redirect:'follow'});
 const [web,ios]=await Promise.all([
  get(ctx,'https://chatgpt.com/',o,true),
  get(ctx,'https://ios.chat.openai.com/',oIos,true)
 ]);
 const wt=(web.body||'').toLowerCase();
 const webOk=web.ok&&web.status>=200&&web.status<400;
 const webBlock=wt.includes('unsupported_country_region_territory')||wt.includes('unsupported country');
 const webCf=wt.includes('cf-mitigated')||wt.includes('challenge-platform')||wt.includes('enable javascript and cookies');
 const it=(ios.body||'').toLowerCase();
 const iosBlocked=it.includes('blocked_why_headline')||it.includes('unsupported_country_region_territory')||it.includes('unsupported_country');
 const iosOk=ios.ok&&!iosBlocked;
 const lat=Math.max(web.latency,ios.latency);
 if(webOk&&iosOk)return make('chatgpt','success','已解锁',region,lat,'网页+APP 可达');
 if(iosOk&&!webOk)return make('chatgpt','success','APP 可用',region,ios.latency,'仅 APP 端可达');
 if(webOk&&webBlock)return make('chatgpt','restricted','地区受限',region,lat,'unsupported_country');
 if(webCf&&!webBlock)return make('chatgpt','warning','需要验证',region,lat,'Cloudflare 验证');
 if(webOk||iosOk)return make('chatgpt','warning','部分可用',region,lat,'仅部分端可达');
 return make('chatgpt','failure','不可用',region,lat,failDetail(web));
}

// Gemini：POST batchexecute 接口取 countryCode
async function checkGemini(ctx,policy,timeout,region){
 const body='f.req=%5B%5B%22K4WWud%22%2C%22%5B%5B0%5D%2C%5B%5C%22en-US%5C%22%5D%5D%22%2Cnull%2C%22generic%22%5D%5D';
 const o=opts(policy,timeout,{redirect:'follow','Content-Type':'application/x-www-form-urlencoded','Accept-Language':'en-US'});
 const r=await post(ctx,'https://gemini.google.com/_/BardChatUi/data/batchexecute',body,o);
 if(!r.ok||!r.body)return make('gemini','failure','不可用',region,r.latency,failDetail(r));
 const m=r.body.match(/"countryCode"\s*:\s*"?([A-Z]{2})"?/i);
 if(m&&m[1])return make('gemini','success','已解锁',m[1].toUpperCase(),r.latency,`地区 ${m[1].toUpperCase()}`);
 const lt=r.body.toLowerCase();
 if(lt.includes('not available in your country')||lt.includes('unsupported'))return make('gemini','restricted','地区受限',region,r.latency,'地区不支持');
 if(r.status>=200&&r.status<300)return make('gemini','success','已解锁',region,r.latency,`HTTP ${r.status}`);
 return make('gemini','warning','可连接',region,r.latency,`HTTP ${r.status}`);
}

// Claude：访问 /login 页面
async function checkClaude(ctx,policy,timeout,region){
 const o=opts(policy,timeout,{redirect:'follow'});
 const r=await get(ctx,'https://claude.ai/login',o,true);
 if(!r.ok)return make('claude','failure','不可用',region,r.latency,failDetail(r));
 if(r.status===403)return make('claude','restricted','访问受限',region,r.latency,'HTTP 403');
 const b=(r.body||'').toLowerCase();
 if(b.includes('app unavailable')||b.includes('unsupported_country')||b.includes('not available in your country'))return make('claude','restricted','地区受限',region,r.latency,'地区不支持');
 if(r.status>=200&&r.status<400)return make('claude','success','已解锁',region,r.latency,`HTTP ${r.status}`);
 return make('claude','unknown','检测异常',region,r.latency,`HTTP ${r.status}`);
}

// Copilot：访问主页
async function checkCopilot(ctx,policy,timeout,region){
 const o=opts(policy,timeout,{redirect:'follow'});
 const r=await get(ctx,'https://copilot.microsoft.com/',o,true);
 if(!r.ok)return make('copilot','failure','不可用',region,r.latency,failDetail(r));
 const b=(r.body||'').toLowerCase();
 if(b.includes('not available in your country')||b.includes('not available in your region')||b.includes('unsupported country'))return make('copilot','restricted','地区受限',region,r.latency,'地区不支持');
 if(r.status>=200&&r.status<400)return make('copilot','success','已解锁',region,r.latency,`HTTP ${r.status}`);
 if(r.status===429)return make('copilot','warning','限流',region,r.latency,'HTTP 429');
 return make('copilot','unknown','检测异常',region,r.latency,`HTTP ${r.status}`);
}

// Perplexity：访问主页
async function checkPerplexity(ctx,policy,timeout,region){
 const o=opts(policy,timeout,{redirect:'follow'});
 const r=await get(ctx,'https://www.perplexity.ai/',o,true);
 if(!r.ok)return make('perplexity','failure','不可用',region,r.latency,failDetail(r));
 const b=(r.body||'').toLowerCase();
 if(b.includes('not available in your country')||b.includes('not available in your region')||b.includes('unsupported country'))return make('perplexity','restricted','地区受限',region,r.latency,'地区不支持');
 if(r.status>=200&&r.status<400)return make('perplexity','success','已解锁',region,r.latency,`HTTP ${r.status}`);
 return make('perplexity','unknown','检测异常',region,r.latency,`HTTP ${r.status}`);
}

const CHECKS={chatgpt:checkChatGPT,gemini:checkGemini,claude:checkClaude,copilot:checkCopilot,perplexity:checkPerplexity};

// ---------- UI ----------
function tx(t,o={}){return{type:'text',text:t,font:o.font||{size:10},textColor:o.color||C.text,textAlign:o.align||'left',maxLines:o.maxLines||1,minScale:o.minScale||.6}}
function icon(n,c,s=11){return{type:'image',src:`sf-symbol:${n}`,color:c,width:s,height:s}}
function line(){return{type:'stack',height:.5,backgroundColor:{light:'rgba(0,0,0,0.08)',dark:'rgba(255,255,255,0.12)'}}}
function stateView(s){const bad=s.state==='failure'||s.state==='restricted';const warn=s.state==='warning'||s.state==='unknown';return{label:bad?'不可用':warn?(s.status==='需要验证'?'待验证':'异常'):(s.region==='--'?'可用':s.region),color:bad?C.failure:warn?C.warning:C.success,icon:bad?'xmark.circle.fill':warn?'exclamationmark.circle.fill':'checkmark.circle.fill'}}
function serviceRow(s){const v=stateView(s);return{type:'stack',direction:'row',alignItems:'center',gap:5,children:[icon(v.icon,v.color),tx(s.name,{font:{size:10,weight:'medium'}}),{type:'spacer'},tx(v.label,{color:v.color,font:{size:10,weight:'bold'}})]}}
function latencyRow(s){const v=stateView(s),d=s.latency>0?`${s.latency} ms`:'--';return{type:'stack',direction:'row',alignItems:'center',gap:5,children:[icon('bolt.horizontal',v.color),tx(s.name,{color:C.secondary,font:{size:10}}),{type:'spacer'},tx(d,{color:s.latency<400?C.success:s.latency<900?C.warning:C.failure,font:{size:10,weight:'bold'}})]}}
function compact(ss,refresh){const n=ss.filter(x=>x.available).length,col=n===ss.length?C.success:n?C.warning:C.failure;return{type:'widget',refreshAfter:refresh,padding:0,children:[tx(`● AI 服务 ${n}/${ss.length} 可用`,{color:col,font:{size:'caption1',weight:'semibold'}})]}}
function notice(refresh,msg){return{type:'widget',refreshAfter:refresh,padding:16,children:[tx(msg,{font:{size:'callout'},align:'center'})]}}
function dashboard(ss,refresh,policy,at){
 const left=ss.slice(0,Math.ceil(ss.length/2)),right=ss.slice(Math.ceil(ss.length/2));
 const count=ss.filter(x=>x.available).length,overall=count===ss.length?C.success:count?C.warning:C.failure;
 const title=count===ss.length?'全部可用':`${count}/${ss.length} 可用`;
 return{type:'widget',refreshAfter:refresh,padding:[8,10],gap:5,children:[
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
  tx('绿色可用 · 黄色异常/待验证 · 红色不可用',{color:{light:'#666',dark:'#B0B0B0'},font:{size:9},maxLines:1})
 ]};
}
export default async function(ctx){
 const e=ctx.env||{},policy=(e.POLICY||'').trim(),timeout=int(e.REQUEST_TIMEOUT,[5000,8000,12000],8000),ri=int(e.REFRESH_INTERVAL,[300,900,1800,3600],900);
 const raw=(e.SERVICES||'all').toLowerCase().split(',').map(x=>x.trim()),ids=raw.includes('all')?Object.keys(SERVICES):Object.keys(SERVICES).filter(x=>raw.includes(x));
 const selected=ids.length?ids:['chatgpt','gemini'];
 const at=new Date().toISOString(),refresh=new Date(Date.now()+ri*1000).toISOString();
 const trace=await get(ctx,'https://chatgpt.com/cdn-cgi/trace',opts(policy,timeout,{redirect:'follow',Accept:'text/plain,*/*;q=0.8'}),true);
 const region=traceRegion(trace);
 const ss=await Promise.all(selected.map(id=>CHECKS[id](ctx,policy,timeout,region)));
 if(ctx.widgetFamily==='accessoryInline'||ctx.widgetFamily==='accessoryCircular')return compact(ss,refresh);
 if(ctx.widgetFamily==='systemSmall'||ctx.widgetFamily==='accessoryRectangular')return notice(refresh,'请使用中号或大号组件');
 return dashboard(ss,refresh,policy,at);
}
