/* XDR Dashboard — Blocklist management + Blocked view */
/* Depends on: dashboard.js ($, esc, B, api, downloadCSV) */
var blData={};

function fetchBlocklists(){
    fetch(B+'/api/blocklists').then(r=>r.json()).then(d=>{
        blData=d;
        renderTags('list-ips',d.blocked_ips||[],function(v){rmItem('ip',v)});
        renderTags('list-ports',(d.blocked_ports||[]).map(String),function(v){rmItem('port',v)});
        renderTags('list-pids',(d.blocked_pids||[]).map(String),function(v){rmItem('pid',v)});
        renderTags('list-paths',d.blocked_paths||[],function(v){rmPath(v)});
        var hashes=d.blocked_hashes||[];
        renderTags('list-hashes',hashes.map(function(h){return (h.name||'?')+' '+h.hash.substring(0,12)+'...'}),function(v,i){if(hashes[i])rmHash(hashes[i].hash)});
        var macs=Object.entries(d.known_macs||{}).map(function(e){return e[0]+' → '+e[1]});
        renderTags('list-macs',macs,function(v){rmItem('mac',v.split(' → ')[0])});
        if($('tab-blocked')&&$('tab-blocked').style.display!=='none')renderBlockedView(d);
        // Update blocked count badge
        var cnt=$('blocked-count');
        if(cnt){var total=(d.blocked_ips||[]).length+(d.blocked_ports||[]).length+(d.blocked_pids||[]).length+(d.blocked_paths||[]).length+(d.blocked_hashes||[]).length+Object.keys(d.known_macs||{}).length;cnt.textContent=total}
    }).catch(function(){});
}

function renderTags(id,items,onRm){
    var c=$(id);if(!c)return;
    if(!items.length){c.innerHTML='<span class="empty-msg">없음</span>';return}
    c.innerHTML=items.map(function(it,i){return '<span class="tag">'+esc(it)+'<span class="remove" data-i="'+i+'" data-item="'+esc(it)+'">×</span></span>'}).join('');
    c.querySelectorAll('.remove').forEach(function(b){b.addEventListener('click',function(){onRm(b.dataset.item,+b.dataset.i)})});
}

function addBlockedIP(){var v=$('input-ip');if(!v||!v.value.trim())return;api('/api/blocklists/ip','POST',{ip:v.value.trim()});v.value=''}
function addBlockedPort(){var v=$('input-port');var p=+v.value;if(!p)return;api('/api/blocklists/port','POST',{port:p});v.value=''}
function addBlockedPID(){var v=$('input-pid');var p=+v.value;if(!p)return;api('/api/blocklists/pid','POST',{pid:p});v.value=''}
function addKnownMAC(){var i=$('input-mac-ip'),m=$('input-mac');if(!i||!m||!i.value||!m.value)return;api('/api/blocklists/mac','POST',{ip:i.value.trim(),mac:m.value.trim()});i.value='';m.value=''}
function addBlockedPath(){var v=$('input-path');if(!v||!v.value.trim())return;api('/api/blocklists/path','POST',{path:v.value.trim()});v.value=''}
function addBlockedHash(){var v=$('input-hash');if(!v||!v.value.trim()||v.value.trim().length!==64){alert('SHA256 64자 필요');return}api('/api/blocklists/hash','POST',{hash:v.value.trim()});v.value=''}

function rmItem(t,k){fetch(B+'/api/blocklists/'+t+'/'+k,{method:'DELETE'}).then(function(){fetchBlocklists()})}
function rmPath(p){fetch(B+'/api/blocklists/path',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({path:p})}).then(function(){fetchBlocklists()})}
function rmHash(h){fetch(B+'/api/blocklists/hash/'+h,{method:'DELETE'}).then(function(){fetchBlocklists()})}

function killAndBlock(){
    var v=$('input-killblock');var pid=+v.value;if(!pid)return;
    if(!confirm('PID '+pid+' Kill + 영구차단?'))return;
    fetch(B+'/api/kill-and-block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:pid})}).then(function(r){return r.json()}).then(function(d){
        alert('Kill: '+(d.killed?'성공':'실패')+'\n경로: '+(d.path||'-')+'\n해시: '+(d.sha256?d.sha256.substring(0,16)+'...':'-'));v.value='';fetchBlocklists()}).catch(function(e){alert('오류:'+e)});
}

/* ── Blocked items view ── */
function loadBlockedView(){fetchBlocklists()}

function renderBlockedView(d){
    var el=$('blocked-table-body');if(!el)return;
    var rows=[];
    (d.blocked_ips||[]).forEach(function(ip){rows.push({type:'IP',target:ip,mode:'패킷 DROP',action:function(){rmItem('ip',ip)}})});
    (d.blocked_ports||[]).forEach(function(p){rows.push({type:'포트',target:String(p),mode:'패킷 DROP',action:function(){rmItem('port',p)}})});
    (d.blocked_pids||[]).forEach(function(p){rows.push({type:'PID',target:String(p),mode:'SIGKILL (반영구)',action:function(){rmItem('pid',p)}})});
    (d.blocked_paths||[]).forEach(function(p){rows.push({type:'경로',target:p,mode:'SIGKILL (영구)',action:function(){rmPath(p)}})});
    (d.blocked_hashes||[]).forEach(function(h){rows.push({type:'해시',target:(h.name||'?')+' '+h.hash.substring(0,20)+'...',mode:(h.reason||'수동')+' (영구)',action:function(){rmHash(h.hash)}})});
    Object.entries(d.known_macs||{}).forEach(function(e){rows.push({type:'MAC',target:e[0]+' → '+e[1],mode:'ARP 보호',action:function(){rmItem('mac',e[0])}})});

    if(!rows.length){el.innerHTML='<tr><td colspan="4" style="text-align:center;color:var(--text-muted);padding:20px">차단된 항목 없음</td></tr>';return}

    el.innerHTML=rows.map(function(r,i){
        var cls=r.type==='PID'||r.type==='경로'||r.type==='해시'?'critical':'warning';
        return '<tr><td><span class="event-badge '+cls+'">'+r.type+'</span></td><td class="mono" style="font-size:11px;word-break:break-all">'+esc(r.target)+'</td><td style="font-size:11px;color:var(--text-muted)">'+r.mode+'</td><td><button class="btn btn-sm btn-danger unblock-btn" data-idx="'+i+'">해제</button></td></tr>'
    }).join('');

    el.querySelectorAll('.unblock-btn').forEach(function(btn){
        btn.addEventListener('click',function(){
            var idx=+btn.dataset.idx;
            if(rows[idx])rows[idx].action();
        });
    });
}

function downloadBlocked(){
    var h=['유형','대상','모드'];var r=[];var d=blData;
    (d.blocked_ips||[]).forEach(function(v){r.push(['IP',v,'패킷 DROP'])});
    (d.blocked_ports||[]).forEach(function(v){r.push(['포트',v,'패킷 DROP'])});
    (d.blocked_pids||[]).forEach(function(v){r.push(['PID',v,'SIGKILL'])});
    (d.blocked_paths||[]).forEach(function(v){r.push(['경로',v,'SIGKILL'])});
    (d.blocked_hashes||[]).forEach(function(v){r.push(['해시',v.hash,v.reason||''])});
    Object.entries(d.known_macs||{}).forEach(function(e){r.push(['MAC',e[0]+'→'+e[1],'ARP'])});
    downloadCSV('xdr_blocked.csv',h,r);
}

function initBlocklistKeys(){
    var bind=function(id,fn){var el=$(id);if(el)el.addEventListener('keydown',function(e){if(e.key==='Enter')fn()})};
    bind('input-ip',addBlockedIP);bind('input-port',addBlockedPort);bind('input-pid',addBlockedPID);
    bind('input-path',addBlockedPath);bind('input-hash',addBlockedHash);bind('input-killblock',killAndBlock);
}
