/* XDR Dashboard — Process List */
/* Depends on: dashboard.js ($, esc, B, api, downloadCSV) */
var procAutoRefresh=null, procData=[];

function loadProcesses(){
    var el=$('proc-table-body');if(!el)return;
    el.innerHTML='<tr><td colspan="7" style="text-align:center;padding:20px;color:var(--text-muted)">로딩 중...</td></tr>';
    fetch(B+'/api/processes').then(function(r){return r.json()}).then(function(data){
        procData=data;renderProcessTable(data);
    }).catch(function(e){el.innerHTML='<tr><td colspan="7" style="color:var(--critical)">오류: '+e+'</td></tr>'});
}

function renderProcessTable(data){
    var el=$('proc-table-body');if(!el)return;
    var filter=($('proc-search')?$('proc-search').value:'').toLowerCase();
    var filtered=filter?data.filter(function(p){
        return p.comm.toLowerCase().indexOf(filter)>=0||
        (p.exe||'').toLowerCase().indexOf(filter)>=0||
        String(p.pid).indexOf(filter)>=0||
        (p.cmdline||'').toLowerCase().indexOf(filter)>=0
    }):data;
    if(!filtered.length){el.innerHTML='<tr><td colspan="7" style="text-align:center;color:var(--text-muted)">프로세스 없음</td></tr>';return}
    el.innerHTML=filtered.map(function(p){
        var rss=p.rss_kb>1024?(p.rss_kb/1024).toFixed(1)+'M':p.rss_kb+'K';
        var s0=p.state?p.state[0]:'';
        var sc=s0==='R'?'var(--success)':s0==='S'?'var(--text-muted)':s0==='Z'?'var(--critical)':'var(--text-secondary)';
        return '<tr><td class="mono">'+p.pid+'</td><td>'+p.ppid+'</td><td style="color:var(--accent)">'+esc(p.comm)+'</td><td title="'+esc(p.exe||'')+'" style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px">'+esc(p.exe||'-')+'</td><td style="color:'+sc+'">'+p.state+'</td><td style="text-align:right">'+rss+'</td><td><button class="btn btn-sm btn-primary" onclick="blockProcPID('+p.pid+')">차단</button> <button class="btn btn-sm btn-danger" onclick="killBlockProc('+p.pid+')">Kill</button></td></tr>';
    }).join('');
}

function blockProcPID(pid){if(!confirm('PID '+pid+' 차단?'))return;api('/api/blocklists/pid','POST',{pid:pid}).then(function(){loadProcesses()})}
function killBlockProc(pid){
    if(!confirm('PID '+pid+' Kill + 영구차단?'))return;
    fetch(B+'/api/kill-and-block',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({pid:pid})}).then(function(r){return r.json()}).then(function(d){
        alert('Kill: '+(d.killed?'성공':'실패')+'\n경로: '+(d.path||'-')+'\n해시: '+(d.sha256?d.sha256.substring(0,16)+'...':'-'));loadProcesses();fetchBlocklists()}).catch(function(e){alert('오류:'+e)});
}

function setAutoRefresh(){
    var input=$('proc-interval');if(!input)return;
    var s=parseInt(input.value)||0;
    if(procAutoRefresh){clearInterval(procAutoRefresh);procAutoRefresh=null}
    if(s>0){procAutoRefresh=setInterval(loadProcesses,s*1000);$('proc-auto-label').textContent='자동 '+s+'s'}
    else{$('proc-auto-label').textContent='수동'}
}

function downloadProcesses(){
    var h=['PID','PPID','이름','경로','상태','메모리(KB)','명령줄'];
    var r=procData.map(function(p){return [p.pid,p.ppid,p.comm,p.exe||'',p.state,p.rss_kb,p.cmdline||'']});
    downloadCSV('xdr_processes.csv',h,r);
}

function initProcSearch(){var el=$('proc-search');if(el)el.addEventListener('input',function(){renderProcessTable(procData)})}
