/* XDR Dashboard — Core: shared utils, SSE, events, stats, status, tabs, download */
const B='';
let ef=0, allE=[];
const EN={1:'EXEC',2:'FILE_OPEN',3:'NET_CONN',4:'MOD_LOAD',5:'PRIV_ESC'};
const NN={1:'BLOCK_IP',2:'ARP_SPOOF',3:'DNS_TUNNEL',4:'NEW_MAC'};
const AC={1:'info',2:'warning',3:'critical'}, AL={1:'INFO',2:'WARN',3:'CRITICAL'};

/* ── Shared utilities ── */
function $(id){return document.getElementById(id)}
function esc(t){const d=document.createElement('div');d.textContent=t;return d.innerHTML}
function api(u,m,d){return fetch(`${B}${u}`,{method:m||'POST',headers:{'Content-Type':'application/json'},body:d?JSON.stringify(d):undefined}).then(()=>fetchBlocklists())}

/* ── Download CSV ── */
function downloadCSV(filename, headers, rows){
    const bom='\uFEFF';
    let csv=bom+headers.join(',')+'\n';
    rows.forEach(r=>{csv+=r.map(c=>'"'+(String(c).replace(/"/g,'""'))+'"').join(',')+'\n'});
    const blob=new Blob([csv],{type:'text/csv;charset=utf-8'});
    const a=document.createElement('a');a.href=URL.createObjectURL(blob);
    a.download=filename;a.click();URL.revokeObjectURL(a.href);
}

/* ── SSE ── */
function connectSSE(){
    const s=new EventSource(`${B}/api/stream`);
    s.onopen=()=>{$('sse-dot').style.background='var(--success)';$('sse-label').textContent='실시간 연결됨'};
    s.onmessage=e=>{try{const v=JSON.parse(e.data);allE.push(v);if(allE.length>500)allE=allE.slice(-500);renderEvent(v);updateStat(v)}catch{}};
    s.onerror=()=>{$('sse-dot').style.background='var(--critical)';$('sse-label').textContent='연결 끊김';setTimeout(connectSSE,3000)};
}

/* ── Render event ── */
function renderEvent(v){
    const lv=v.alert_level||1;if(ef>0&&lv<ef)return;
    const fd=$('event-feed');if(!fd)return;
    if(fd.querySelector('div[style]')&&!fd.querySelector('.event-item'))fd.innerHTML='';
    const c=AC[lv]||'info',l=AL[lv]||'INFO',t=v._time?v._time.split('T')[1]?.substring(0,8)||'':'';
    let d='';
    if(v.source==='EDR'){const n=EN[v.event_type]||v.event_type;d=`${n} pid=${v.pid||'-'} ${v.comm||''}`;if(v.filename)d+=` [${v.filename}]`;if(v.dst_ip&&v.dst_ip!=='0.0.0.0')d+=` → ${v.dst_ip}:${v.dst_port||0}`}
    else if(v.source==='NDR'){const n=NN[v.event_type]||v.event_type;d=`${n} ${v.src_ip||'?'}:${v.src_port||0} → ${v.dst_ip||'?'}:${v.dst_port||0}`;if(v.action===1)d+=' [DROP]'}
    else if(v.source==='ADMIN')d=`${v.action} ${v.target||''}`;
    else if(v.source==='CORRELATION')d=v.message||JSON.stringify(v);
    else if(v.source==='DETECTOR')d=`${v.reason}: ${v.detail||''}`;
    else if(v.source==='SYSTEM')d=v.message||`${v.action} ${v.target||''}`;
    else if(v.source==='YARA')d=v.detail||'YARA match';
    else d=JSON.stringify(v);
    const el=document.createElement('div');el.className=`event-item ${c}`;
    el.innerHTML=`<span class="event-time">${t}</span><span class="event-badge ${c}">${v.source||'SYS'} ${l}</span><span class="event-detail">${esc(d)}</span>`;
    fd.insertBefore(el,fd.firstChild);while(fd.children.length>200)fd.removeChild(fd.lastChild);
}

function updateStat(v){
    const l=v.alert_level||0;
    if(l>=3){const e=$('stat-critical');if(e)e.textContent=+e.textContent+1}
    else if(l===2){const e=$('stat-warning');if(e)e.textContent=+e.textContent+1}
    const e=$('stat-events');if(e)e.textContent=+e.textContent+1;
}

/* ── Filter tabs ── */
function initFilterTabs(){
    document.querySelectorAll('.filter-tab').forEach(t=>{
        t.addEventListener('click',()=>{
            document.querySelectorAll('.filter-tab').forEach(x=>x.classList.remove('active'));
            t.classList.add('active');ef=+t.dataset.level;refilter()});
    });
}
function refilter(){const fd=$('event-feed');if(!fd)return;fd.innerHTML='';(ef===0?allE:allE.filter(e=>(e.alert_level||0)>=ef)).slice(-200).forEach(renderEvent)}

/* ── Fetch helpers ── */
function fetchStats(){fetch(`${B}/api/stats`).then(r=>r.json()).then(d=>{if($('stat-total'))$('stat-total').textContent=fmt(d.total||0);if($('stat-pass'))$('stat-pass').textContent=fmt(d.passed||0);if($('stat-drop'))$('stat-drop').textContent=fmt(d.dropped||0);if(d.critical_count!==undefined&&$('stat-critical'))$('stat-critical').textContent=d.critical_count;if(d.warning_count!==undefined&&$('stat-warning'))$('stat-warning').textContent=d.warning_count;if(d.event_count!==undefined&&$('stat-events'))$('stat-events').textContent=d.event_count}).catch(()=>{})}
function fmt(n){if(n>=1e9)return(n/1e9).toFixed(1)+'B';if(n>=1e6)return(n/1e6).toFixed(1)+'M';if(n>=1e3)return(n/1e3).toFixed(1)+'K';return ''+n}
function fetchStatus(){fetch(`${B}/api/status`).then(r=>r.json()).then(d=>{const e=$('badge-edr'),n=$('badge-ndr');if(e)e.className=`badge ${d.edr_loaded?'ok':'err'}`;if(n)n.className=`badge ${d.ndr_attached?'ok':'err'}`;if($('sys-kernel')&&d.kernel)$('sys-kernel').textContent=d.kernel;if($('sys-uptime')&&d.uptime)$('sys-uptime').textContent=d.uptime}).catch(()=>{})}
function fetchKernelUpdate(){fetch(`${B}/api/kernel-update`).then(r=>r.json()).then(d=>{const el=$('kernel-alert');if(el)el.style.display=d.has_update?'flex':'none';if($('kern-current'))$('kern-current').textContent=d.current||'-';if($('kern-latest'))$('kern-latest').textContent=d.latest||'-';if($('kern-checked'))$('kern-checked').textContent=d.last_check?d.last_check.split('T')[1]?.substring(0,8)||'-':'-'}).catch(()=>{})}
function loadExistingEvents(){fetch(`${B}/api/events?limit=100`).then(r=>r.json()).then(ev=>{allE=ev;const fd=$('event-feed');if(fd)fd.innerHTML='';ev.forEach(renderEvent)}).catch(()=>{})}
function downloadEvents(){const h=['시간','소스','레벨','상세'];const r=allE.map(e=>[e._time||'',e.source||'',e.alert_level||0,JSON.stringify(e)]);downloadCSV('xdr_events.csv',h,r)}

/* ── Tab navigation ── */
function initTabs(){
    document.querySelectorAll('.nav-tab').forEach(tab=>{
        tab.addEventListener('click',()=>{
            document.querySelectorAll('.nav-tab').forEach(t=>t.classList.remove('active'));
            tab.classList.add('active');
            document.querySelectorAll('.tab-content').forEach(p=>p.style.display='none');
            const target=$(tab.dataset.tab);if(target)target.style.display='block';
            if(tab.dataset.tab==='tab-processes')loadProcesses();
            if(tab.dataset.tab==='tab-network')loadConnections();
            if(tab.dataset.tab==='tab-blocked')loadBlockedView();
        });
    });
}

/* ── Master init (runs after ALL JS files loaded) ── */
function masterInit(){
    initTabs();
    initFilterTabs();
    connectSSE();
    fetchStats();
    fetchStatus();
    fetchKernelUpdate();
    loadExistingEvents();
    fetchBlocklists();
    initBlocklistKeys();
    initProcSearch();
    initConnSearch();
    setInterval(fetchStats,5000);
    setInterval(fetchStatus,10000);
    setInterval(fetchKernelUpdate,60000);
    setInterval(fetchBlocklists,15000);
}
document.addEventListener('DOMContentLoaded', masterInit);
