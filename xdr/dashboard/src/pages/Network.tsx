import { useState, useEffect, useRef, useCallback } from 'react'
import { RefreshCw, Download, Search, Globe, Plug, Skull } from 'lucide-react'
import { apiGet, apiPost, downloadCSV, type ConnectionInfo } from '../api/client'

interface Props { onRefreshBlocklist: () => void }

export default function NetworkPage({ onRefreshBlocklist }: Props) {
  const [conns, setConns] = useState<ConnectionInfo[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [autoSec, setAutoSec] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    apiGet<ConnectionInfo[]>('/connections').then(d => { setConns(d); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (autoSec > 0) timerRef.current = setInterval(load, autoSec * 1000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [autoSec, load]);

  const filtered = search
    ? conns.filter(c => c.comm.toLowerCase().includes(search.toLowerCase()) ||
        c.local_addr.includes(search) || c.peer_addr.includes(search) ||
        String(c.local_port).includes(search) || String(c.peer_port).includes(search) ||
        String(c.pid).includes(search))
    : conns;

  const blockIP = (ip: string) => {
    if (!confirm(`IP ${ip} 차단?`)) return;
    apiPost('/blocklists/ip', { ip }).then(() => { load(); onRefreshBlocklist(); });
  };

  const blockPort = (port: number) => {
    if (!confirm(`포트 ${port} 차단?`)) return;
    apiPost('/blocklists/port', { port }).then(() => { load(); onRefreshBlocklist(); });
  };

  const killBlock = (pid: number) => {
    if (!confirm(`PID ${pid} Kill + 영구차단?`)) return;
    apiPost<any>('/kill-and-block', { pid }).then(d => {
      alert(`Kill: ${d.killed ? '성공' : '실패'}`);
      load(); onRefreshBlocklist();
    });
  };

  const stateColor = (s: string) => {
    if (s === 'ESTAB') return 'var(--success)';
    if (s === 'LISTEN') return 'var(--accent)';
    if (s === 'TIME-WAIT') return 'var(--text-dim)';
    return 'var(--text-secondary)';
  };

  return (
    <>
      <div className="page-header">
        <h2 className="page-title">🌐 네트워크 ({filtered.length})</h2>
        <div className="toolbar">
          <div style={{position: 'relative'}}>
            <Search size={14} style={{position: 'absolute', left: 8, top: 9, color: 'var(--text-dim)'}} />
            <input className="input" placeholder="검색..." value={search} onChange={e => setSearch(e.target.value)}
              style={{paddingLeft: 28, width: 180}} />
          </div>
          <button className="btn btn-sm" onClick={load} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'pulse' : ''} /> 새로고침
          </button>
          <input className="input" type="number" placeholder="초" min={1} max={300}
            style={{width: 55}} onChange={e => setAutoSec(parseInt(e.target.value) || 0)} />
          <span style={{fontSize: 10, color: 'var(--text-dim)'}}>{autoSec > 0 ? `자동 ${autoSec}s` : '수동'}</span>
          <button className="btn btn-sm" onClick={() => {
            downloadCSV('xdr_connections.csv', ['Proto','상태','로컬주소','로컬포트','원격주소','원격포트','PID','프로세스'],
              conns.map(c => [c.proto, c.state, c.local_addr, c.local_port, c.peer_addr, c.peer_port, c.pid, c.comm]));
          }}><Download size={14} /></button>
        </div>
      </div>

      <div className="card">
        <div className="card-body" style={{maxHeight: 600}}>
          {filtered.length === 0 ? (
            <div className="empty">{loading ? '로딩 중...' : '연결 없음'}</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr><th>Proto</th><th>상태</th><th>로컬</th><th>원격</th><th>PID</th><th>프로세스</th><th>IP차단</th><th>액션</th></tr>
              </thead>
              <tbody>
                {filtered.map((c, i) => {
                  const isLocal = !c.peer_addr || c.peer_addr === '*' || c.peer_addr === '0.0.0.0' || c.peer_addr === '::';
                  return (
                    <tr key={i}>
                      <td style={{color: 'var(--accent)'}}>{c.proto}</td>
                      <td style={{color: stateColor(c.state)}}>{c.state || '-'}</td>
                      <td className="mono" style={{fontSize: 11}}>{c.local_addr}:{c.local_port}</td>
                      <td className="mono" style={{fontSize: 11}}>{c.peer_addr}:{c.peer_port}</td>
                      <td className="mono">{c.pid || '-'}{(c as any).enriched && ' ⚡'}</td>
                      <td>{c.comm || '-'}{(c as any).enriched && <span title="eBPF 캐시에서 복원" style={{color: 'var(--warning)', marginLeft: 4}}>⚡</span>}</td>
                      <td>
                        {!isLocal && c.peer_addr ? (
                          <button className="btn btn-sm" onClick={() => blockIP(c.peer_addr)}>
                            <Globe size={12} /> IP
                          </button>
                        ) : '-'}
                      </td>
                      <td>
                        <div className="toolbar">
                          {c.peer_port > 0 && (
                            <button className="btn btn-sm" onClick={() => blockPort(c.peer_port)}>
                              <Plug size={12} /> 포트
                            </button>
                          )}
                          {c.pid > 0 && (
                            <button className="btn btn-sm btn-danger" onClick={() => killBlock(c.pid)}>
                              <Skull size={12} /> Kill
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
