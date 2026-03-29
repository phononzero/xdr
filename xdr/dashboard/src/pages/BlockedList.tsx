import { Download, RefreshCw, Unlock } from 'lucide-react'
import { apiDelete, downloadCSV, type BlocklistData } from '../api/client'

interface Props {
  blocklist: BlocklistData | null;
  onRefresh: () => void;
}

interface BlockedItem {
  type: string;
  target: string;
  mode: string;
  unblock: () => void;
}

export default function BlockedList({ blocklist, onRefresh }: Props) {
  if (!blocklist) return <div className="empty">로딩 중...</div>;

  const items: BlockedItem[] = [];
  blocklist.blocked_ips?.forEach(ip => items.push({ type: 'IP', target: ip, mode: '패킷 DROP', unblock: () => apiDelete(`/blocklists/ip/${ip}`).then(onRefresh) }));
  blocklist.blocked_ports?.forEach(p => items.push({ type: '포트', target: String(p), mode: '패킷 DROP', unblock: () => apiDelete(`/blocklists/port/${p}`).then(onRefresh) }));
  blocklist.blocked_pids?.forEach(p => items.push({ type: 'PID', target: String(p), mode: 'SIGKILL (반영구)', unblock: () => apiDelete(`/blocklists/pid/${p}`).then(onRefresh) }));
  blocklist.blocked_paths?.forEach(p => items.push({ type: '경로', target: p, mode: 'SIGKILL (영구)', unblock: () => apiDelete('/blocklists/path', { path: p }).then(onRefresh) }));
  blocklist.blocked_hashes?.forEach(h => items.push({ type: '해시', target: `${h.name || '?'} ${h.hash.substring(0, 20)}...`, mode: `${h.reason || '수동'} (영구)`, unblock: () => apiDelete(`/blocklists/hash/${h.hash}`).then(onRefresh) }));
  Object.entries(blocklist.known_macs || {}).forEach(([ip, mac]) => items.push({ type: 'MAC', target: `${ip} → ${mac}`, mode: 'ARP 보호', unblock: () => apiDelete(`/blocklists/mac/${ip}`).then(onRefresh) }));

  const badgeClass = (type: string) =>
    type === 'PID' || type === '경로' || type === '해시' ? 'critical' : 'warning';

  return (
    <>
      <div className="page-header">
        <h2 className="page-title">🔒 차단 목록 ({items.length})</h2>
        <div className="toolbar">
          <button className="btn btn-sm" onClick={onRefresh}><RefreshCw size={14} /> 새로고침</button>
          <button className="btn btn-sm" onClick={() => {
            downloadCSV('xdr_blocked.csv', ['유형', '대상', '모드'],
              items.map(i => [i.type, i.target, i.mode]));
          }}><Download size={14} /> 다운로드</button>
        </div>
      </div>

      <div className="card">
        <div className="card-body" style={{maxHeight: 600}}>
          {items.length === 0 ? (
            <div className="empty">차단된 항목 없음</div>
          ) : (
            <table className="data-table">
              <thead>
                <tr><th>유형</th><th>대상</th><th>모드</th><th>액션</th></tr>
              </thead>
              <tbody>
                {items.map((item, i) => (
                  <tr key={i}>
                    <td><span className={`event-badge ${badgeClass(item.type)}`}>{item.type}</span></td>
                    <td className="mono" style={{fontSize: 11, wordBreak: 'break-all'}}>{item.target}</td>
                    <td style={{fontSize: 11, color: 'var(--text-dim)'}}>{item.mode}</td>
                    <td>
                      <button className="btn btn-sm btn-danger" onClick={() => {
                        if (confirm(`"${item.target}" 차단 해제?`)) item.unblock();
                      }}><Unlock size={12} /> 해제</button>
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
