import { useState } from 'react'
import { Zap, FolderLock, Hash, Globe, Plug, ShieldAlert, Shield } from 'lucide-react'
import { apiPost, type BlocklistData } from '../api/client'

interface Props {
  blocklist: BlocklistData | null;
  onRefresh: () => void;
}

function AddForm({ placeholder, icon, buttonText, onAdd, type, danger }: {
  placeholder: string; icon: React.ReactNode; buttonText: string;
  onAdd: (v: string) => void; type?: string; danger?: boolean;
}) {
  const [val, setVal] = useState('');
  const submit = () => { if (val.trim()) { onAdd(val.trim()); setVal(''); } };
  return (
    <div className="add-form">
      {icon}
      <input className="input" type={type || 'text'} placeholder={placeholder} value={val}
        onChange={e => setVal(e.target.value)} onKeyDown={e => e.key === 'Enter' && submit()} />
      <button className={`btn ${danger ? 'btn-danger' : 'btn-primary'}`} onClick={submit}>{buttonText}</button>
    </div>
  );
}

export default function BlockRules({ blocklist, onRefresh }: Props) {
  const block = async (path: string, data: Record<string, unknown>) => {
    try { await apiPost(path, data); onRefresh(); } catch (e) { alert('오류: ' + e); }
  };

  return (
    <>
      <div className="page-header">
        <h2 className="page-title">🚫 차단 등록</h2>
      </div>

      <div className="grid-2">
        {/* Kill & Block */}
        <div className="card">
          <div className="card-header"><span className="card-title">⚡ Kill & 영구차단</span></div>
          <div className="card-body" style={{padding: 16, background: 'var(--critical-bg)', borderLeft: '3px solid var(--critical)'}}>
            <div style={{fontSize: 11, color: 'var(--text-dim)', marginBottom: 10}}>PID 즉시 Kill + 경로/해시 자동 영구 등록</div>
            <AddForm placeholder="PID" type="number" icon={<Zap size={16} style={{color: 'var(--critical)'}} />}
              buttonText="Kill & Block" danger
              onAdd={v => {
                const pid = parseInt(v);
                if (!pid || !confirm(`PID ${pid} Kill + 영구차단?`)) return;
                apiPost('/kill-and-block', { pid }).then((d: any) => {
                  alert(`Kill: ${d.killed ? '성공' : '실패'}\n경로: ${d.path || '-'}\n해시: ${d.sha256?.substring(0, 16) || '-'}...`);
                  onRefresh();
                }).catch(e => alert('오류: ' + e));
              }} />
          </div>
        </div>

        {/* Path block */}
        <div className="card">
          <div className="card-header"><span className="card-title">📁 경로 차단 (영구)</span></div>
          <div className="card-body" style={{padding: 16}}>
            <AddForm placeholder="/tmp/malware 또는 /dev/shm/*" icon={<FolderLock size={16} />}
              buttonText="차단" onAdd={v => block('/blocklists/path', { path: v })} />
            <div className="tag-list" style={{marginTop: 10}}>
              {(blocklist?.blocked_paths || []).map(p => (
                <span key={p} className="tag">{p}</span>
              ))}
            </div>
          </div>
        </div>

        {/* Hash block */}
        <div className="card">
          <div className="card-header"><span className="card-title">🔑 해시 차단 (SHA256)</span></div>
          <div className="card-body" style={{padding: 16}}>
            <AddForm placeholder="SHA256 64자" icon={<Hash size={16} />}
              buttonText="차단" onAdd={v => {
                if (v.length !== 64) return alert('SHA256 해시는 64자여야 합니다');
                block('/blocklists/hash', { hash: v });
              }} />
          </div>
        </div>

        {/* IP block */}
        <div className="card">
          <div className="card-header"><span className="card-title">🌐 차단 IP (패킷 DROP)</span></div>
          <div className="card-body" style={{padding: 16}}>
            <AddForm placeholder="192.168.1.100" icon={<Globe size={16} />}
              buttonText="차단" onAdd={v => block('/blocklists/ip', { ip: v })} />
            <div className="tag-list" style={{marginTop: 10}}>
              {(blocklist?.blocked_ips || []).map(ip => (
                <span key={ip} className="tag">{ip}</span>
              ))}
            </div>
          </div>
        </div>

        {/* Port block */}
        <div className="card">
          <div className="card-header"><span className="card-title">🔌 차단 포트</span></div>
          <div className="card-body" style={{padding: 16}}>
            <AddForm placeholder="4444" type="number" icon={<Plug size={16} />}
              buttonText="차단" onAdd={v => block('/blocklists/port', { port: parseInt(v) })} />
            <div className="tag-list" style={{marginTop: 10}}>
              {(blocklist?.blocked_ports || []).map(p => (
                <span key={p} className="tag">{p}</span>
              ))}
            </div>
          </div>
        </div>

        {/* PID block */}
        <div className="card">
          <div className="card-header"><span className="card-title">🔒 차단 PID (반영구)</span></div>
          <div className="card-body" style={{padding: 16}}>
            <AddForm placeholder="PID" type="number" icon={<ShieldAlert size={16} />}
              buttonText="차단" onAdd={v => block('/blocklists/pid', { pid: parseInt(v) })} />
          </div>
        </div>

        {/* ARP MAC */}
        <div className="card grid-full">
          <div className="card-header"><span className="card-title">🛡️ ARP 보호 (IP-MAC)</span></div>
          <div className="card-body" style={{padding: 16}}>
            <div className="add-form">
              <Shield size={16} />
              <input className="input" placeholder="IP" id="mac-ip" style={{width: 140}} />
              <input className="input" placeholder="aa:bb:cc:dd:ee:ff" id="mac-addr" />
              <button className="btn btn-primary" onClick={() => {
                const ip = (document.getElementById('mac-ip') as HTMLInputElement).value.trim();
                const mac = (document.getElementById('mac-addr') as HTMLInputElement).value.trim();
                if (ip && mac) block('/blocklists/mac', { ip, mac });
              }}>등록</button>
            </div>
          </div>
        </div>
      </div>
    </>
  );
}
