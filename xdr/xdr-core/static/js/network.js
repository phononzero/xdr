/* XDR Dashboard — Network Connections */
/* Depends on: dashboard.js ($, esc, B, api, downloadCSV) */
var connAutoRefresh=null, connData=[];

function loadConnections(){
    var el=$('conn-table-body');if(!el)return;
    el.innerHTML='<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--text-muted)">로딩 중...</td></tr>';
    fetch(B+'/api/connections').then(function(r){return r.json()}).then(function(data){connData=data;renderConnTable(data)}).catch(function(e){el.innerHTML='<tr><td colspan="8" style="color:var(--critical)">오류: '+e+'</td></tr>'});
}

function renderConnTable(data){
    var el=$('conn-table-body');if(!el)return;
    var filter=($('conn-search')?$('conn-search').value:'').toLowerCase();
    var filtered=filter?data.filter(function(c){return c.comm.toLowerCase().indexOf(filter)>=0||c.local_addr.indexOf(filter)>=0||c.peer_addr.indexOf(filter)>=0||String(c.local_port).indexOf(filter)>=0||String(c.peer_port).indexOf(filter)>=0||String(c.pid).indexOf(filter)>=0}):data;
    if(!filtered.length){el.innerHTML='<tr><td colspan="8" style="text-align:center;color:var(--text-muted)">연결 없음</td></tr>';return}
    el.innerHTML=filtered.map(function(c){
        var sc=c.state==='ESTAB'?'var(--success)':c.state==='LISTEN'?'var(--accent)':c.state==='TIME-WAIT'?'var(--text-muted)':'var(--text-secondary)';
        var isLocal=!c.peer_addr||c.peer_addr==='*'||c.peer_addr==='0.0.0.0'||c.peer_addr==='::';
        return '<tr><td style="color:var(--accent)">'+c.proto+'</td><td style="color:'+sc+'">'+
        (c.state||'-')+'</td><td class="mono" style="font-size:11px">'+esc(c.local_addr)+':'+c.local_port+
        '</td><td class="mono" style="font-size:11px">'+esc(c.peer_addr)+':'+c.peer_port+
        '</td><td class="mono">'+(c.pid||'-')+'</td><td>'+esc(c.comm||'-')+
        '</td><td>'+(!isLocal&&c.peer_addr?'<button class="btn btn-sm btn-primary" onclick="blockConnIP(\''+esc(c.peer_addr)+'\')">IP차단</button>':'-')+
        '</td><td>'+(c.peer_port>0?'<button class="btn btn-sm btn-primary" onclick="blockConnPort('+c.peer_port+')">포트</button> ':'')+
        (c.pid>0?'<button class="btn btn-sm btn-danger" onclick="killBlockProc('+c.pid+')">Kill</button>':'')+'</td></tr>';
    }).join('');
}

function blockConnIP(ip){if(!confirm('IP '+ip+' 차단?'))return;api('/api/blocklists/ip','POST',{ip:ip}).then(function(){loadConnections();fetchBlocklists()})}
function blockConnPort(port){if(!confirm('포트 '+port+' 차단?'))return;api('/api/blocklists/port','POST',{port:port}).then(function(){loadConnections();fetchBlocklists()})}

function setConnAutoRefresh(){
    var input=$('conn-interval');if(!input)return;
    var s=parseInt(input.value)||0;
    if(connAutoRefresh){clearInterval(connAutoRefresh);connAutoRefresh=null}
    if(s>0){connAutoRefresh=setInterval(loadConnections,s*1000);$('conn-auto-label').textContent='자동 '+s+'s'}
    else{$('conn-auto-label').textContent='수동'}
}

function downloadConnections(){
    var h=['Proto','상태','로컬주소','로컬포트','원격주소','원격포트','PID','프로세스'];
    var r=connData.map(function(c){return [c.proto,c.state,c.local_addr,c.local_port,c.peer_addr,c.peer_port,c.pid,c.comm]});
    downloadCSV('xdr_connections.csv',h,r);
}

function initConnSearch(){var el=$('conn-search');if(el)el.addEventListener('input',function(){renderConnTable(connData)})}
