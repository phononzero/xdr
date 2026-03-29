import { useState, useEffect, useRef, useCallback } from 'react'
import { RefreshCw, Download, Search, ShieldBan, Skull } from 'lucide-react'
import { apiGet, apiPost, downloadCSV, type ProcessInfo } from '../api/client'

interface Props { onRefreshBlocklist: () => void }

export default function Processes({ onRefreshBlocklist }: Props) {
  const [procs, setProcs] = useState<ProcessInfo[]>([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(false);
  const [autoSec, setAutoSec] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    apiGet<ProcessInfo[]>('/processes').then(d => { setProcs(d); setLoading(false); }).catch(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (timerRef.current) clearInterval(timerRef.current);
    if (autoSec > 0) timerRef.current = setInterval(load, autoSec * 1000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [autoSec, load]);

  const filtered = search
    ? procs.filter(p => p.comm.toLowerCase().includes(search.toLowerCase()) ||
        (p.exe || '').toLowerCase().includes(search.toLowerCase()) ||
        String(p.pid).includes(search) ||
        (p.cmdline || '').toLowerCase().includes(search.toLowerCase()))
    : procs;

  const blockPid = (pid: number) => {
    if (!confirm(`PID ${pid} 차단?`)) return;
    apiPost('/blocklists/pid', { pid }).then(() => { load(); onRefreshBlocklist(); });
  };

  const killBlock = (pid: number) => {
    if (!confirm(`PID ${pid} Kill + 영구차단?`)) return;
    apiPost<any>('/kill-and-block', { pid }).then(d => {
      alert(`Kill: ${d.killed ? '성공' : '실패'}\n경로: ${d.path || '-'}\n해시: ${d.sha256?.substring(0, 16) || '-'}...`);
      load(); onRefreshBlocklist();
    });
  };

  const stateColor = (s: string) => {
    const c = s?.[0];
    if (c === 'R') return 'var(--success)';
    if (c === 'S') return 'var(--text-dim)';
    if (c === 'Z') return 'var(--critical)';
    return 'var(--text-secondary)';
  };

  return (
    <>
      <div className="page-header">
        <h2 className="page-title">⚙️ 프로세스 ({filtered.length})</h2>
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
            downloadCSV('xdr_processes.csv', ['PID','PPID','이름','경로','상태','메모리(KB)','명령줄'],
              procs.map(p => [p.pid, p.ppid, p.comm, p.exe || '', p.state, p.rss_kb, p.cmdline || '']));
          }}><Download size={14} /></button>
        </div>
      </div>

      <div className="card">
        <div className="card-body" style={{maxHeight: 600}}>
          {filtered.length === 0 ? (
            <div className="empty">{loading ? '로딩 중...' : '프로세스 없음'}</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr><th>PID</th><th>PPID</th><th>이름</th><th>경로</th><th>상태</th><th>메모리</th><th>액션</th></tr>
              </thead>
              <tbody>
                {filtered.map(p => (
                  <tr key={p.pid}>
                    <td className="mono">{p.pid}</td>
                    <td>{p.ppid}</td>
                    <td style={{color: 'var(--accent)'}}>{p.comm}{(p as any).enriched && <span title="eBPF 캐시에서 복원" style={{color: 'var(--warning)', marginLeft: 4}}>⚡</span>}</td>
                    <td className="mono" title={p.exe || ''} style={{maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 11}}>{p.exe || '-'}{(p as any).enriched && p.exe && <span style={{color: 'var(--warning)'}}> ⚡</span>}</td>
                    <td style={{color: stateColor(p.state)}}>{p.state}</td>
                    <td style={{textAlign: 'right'}}>{p.rss_kb > 1024 ? (p.rss_kb / 1024).toFixed(1) + 'M' : p.rss_kb + 'K'}</td>
                    <td>
                      <div className="toolbar">
                        <button className="btn btn-sm" onClick={() => blockPid(p.pid)}><ShieldBan size={12} /> 차단</button>
                        <button className="btn btn-sm btn-danger" onClick={() => killBlock(p.pid)}><Skull size={12} /> Kill</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </>
  );
}
