import { useState, useMemo } from 'react'
import { Download, Filter } from 'lucide-react'
import { apiGet, downloadCSV, type XDREvent, type XDRStats } from '../api/client'
import { useEffect } from 'react'

const EN: Record<number, string> = {1:'EXEC',2:'FILE_OPEN',3:'NET_CONN',4:'MOD_LOAD',5:'PRIV_ESC',6:'PROC_EXIT',7:'MEMFD_CREATE',8:'PTRACE'};
const NN: Record<number, string> = {1:'BLOCK_IP',2:'ARP_SPOOF',3:'DNS_TUNNEL',4:'NEW_MAC'};
const AC: Record<number, string> = {1:'info',2:'warning',3:'critical'};
const AL: Record<number, string> = {1:'INFO',2:'WARN',3:'CRITICAL'};

function fmtNum(n: number) {
  if (n >= 1e9) return (n/1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n/1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n/1e3).toFixed(1) + 'K';
  return String(n);
}

function procTag(v: XDREvent): string {
  const parts: string[] = [];
  if (v.comm) parts.push(`프로세스: ${v.comm}`);
  if (v.pid) parts.push(`pid=${v.pid}`);
  if (v.ppid) {
    const parentName = v.ppid_comm || '';
    parts.push(parentName ? `ppid=${v.ppid}(${parentName})` : `ppid=${v.ppid}`);
  }
  if (v.cmdline && v.cmdline !== v.filename) parts.push(`명령: ${v.cmdline}`);
  else if (v.filename) parts.push(`경로=${v.filename}`);
  return parts.length ? `[${parts.join(' ')}]` : '';
}

function parentChainStr(v: XDREvent): string {
  if (!v.parent_chain || !v.parent_chain.length) return '';
  return ' 부모체인: ' + v.parent_chain.map(
    (p: {comm: string, pid: number}) => `${p.comm}(${p.pid})`
  ).join(' → ');
}

function eventDetail(v: XDREvent): string {
  const tag = procTag(v);

  if (v.source === 'EDR') {
    const n = EN[v.event_type || 0] || String(v.event_type);
    let d = `${n} ${tag}`;
    if (v.dst_ip && v.dst_ip !== '0.0.0.0') d += ` → ${v.dst_ip}:${v.dst_port || 0}`;
    return d;
  }
  if (v.source === 'NDR') {
    const n = NN[v.event_type || 0] || String(v.event_type);
    return `${n} ${v.src_ip}:${v.src_port} → ${v.dst_ip}:${v.dst_port}${v.action === 1 ? ' [DROP]' : ''}`;
  }
  if (v.source === 'ADMIN') return `${v.action} ${v.target || ''}`;
  if (v.source === 'CORRELATION') return v.message || JSON.stringify(v);
  if (v.source === 'DETECTOR') {
    const chain = parentChainStr(v);
    const mitre = v.mitre_id ? `[${v.mitre_id}] ` : '';
    return `${mitre}${v.reason}: ${tag} ${v.detail || ''}${chain}`;
  }
  if (v.source === 'SYSTEM') return v.message || `${v.action} ${v.target || ''}`;
  if (v.source === 'YARA') {
    const chain = parentChainStr(v);
    return `YARA 매치: ${tag} ${v.detail || ''}${chain}`;
  }
  if (v.detail) return `${tag} ${v.detail}`;
  return JSON.stringify(v);
}

interface Props { events: XDREvent[] }

export default function Dashboard({ events }: Props) {
  const [filter, setFilter] = useState(0);
  const [stats, setStats] = useState<XDRStats | null>(null);

  useEffect(() => {
    apiGet<XDRStats>('/stats').then(setStats).catch(() => {});
    const t = setInterval(() => apiGet<XDRStats>('/stats').then(setStats).catch(() => {}), 5000);
    return () => clearInterval(t);
  }, []);

  const filtered = useMemo(() => {
    if (filter === 0) return events;
    return events.filter(e => (e.alert_level || 0) >= filter);
  }, [events, filter]);

  const critCount = events.filter(e => (e.alert_level || 0) >= 3).length;
  const warnCount = events.filter(e => (e.alert_level || 0) === 2).length;

  return (
    <>
      <div className="page-header">
        <h2 className="page-title">📊 대시보드</h2>
        <button className="btn btn-sm" onClick={() => {
          downloadCSV('xdr_events.csv', ['시간','소스','레벨','상세'],
            events.map(e => [e._time || '', e.source || '', e.alert_level || 0, eventDetail(e)]));
        }}>
          <Download size={14} /> 다운로드
        </button>
      </div>

      <div className="stats-grid">
        <div className="stat-card accent">
          <div className="stat-label">총 패킷</div>
          <div className="stat-value">{fmtNum(stats?.total || 0)}</div>
        </div>
        <div className="stat-card success">
          <div className="stat-label">통과</div>
          <div className="stat-value">{fmtNum(stats?.passed || 0)}</div>
        </div>
        <div className="stat-card warning">
          <div className="stat-label">차단</div>
          <div className="stat-value">{fmtNum(stats?.dropped || 0)}</div>
        </div>
        <div className="stat-card critical">
          <div className="stat-label">CRITICAL</div>
          <div className="stat-value">{stats?.critical_count ?? critCount}</div>
        </div>
        <div className="stat-card warning">
          <div className="stat-label">WARNING</div>
          <div className="stat-value">{stats?.warning_count ?? warnCount}</div>
        </div>
        <div className="stat-card accent">
          <div className="stat-label">이벤트</div>
          <div className="stat-value">{stats?.event_count ?? events.length}</div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <span className="card-title">📡 실시간 이벤트</span>
          <div className="toolbar">
            <div className="filter-pills">
              {[{l: 0, t: '전체'}, {l: 3, t: 'CRITICAL'}, {l: 2, t: 'WARNING'}, {l: 1, t: 'INFO'}].map(f => (
                <button key={f.l} className={`filter-pill ${filter === f.l ? 'active' : ''}`} onClick={() => setFilter(f.l)}>{f.t}</button>
              ))}
            </div>
            <Filter size={14} style={{color: 'var(--text-dim)'}} />
          </div>
        </div>
        <div className="card-body" style={{maxHeight: 700, overflow: 'auto'}}>
          {filtered.length === 0 ? (
            <div className="empty">이벤트 대기 중...</div>
          ) : filtered.map((ev, i) => {
            const lv = ev.alert_level || 1;
            const cls = AC[lv] || 'info';
            const label = AL[lv] || 'INFO';
            const time = ev._time?.split('T')[1]?.substring(0, 8) || '';
            return (
              <div key={i} className={`event-item ${cls}`}>
                <span className="event-time">{time}</span>
                <span className={`event-badge ${cls}`}>{ev.source || 'SYS'} {label}</span>
                <span className="event-detail">{eventDetail(ev)}</span>
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}
