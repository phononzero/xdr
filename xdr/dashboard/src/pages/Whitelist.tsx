import { useState, useEffect } from 'react';
import { ShieldCheck, ShieldBan, Plus, Trash2, RefreshCw, Search, UserCheck } from 'lucide-react';
import { apiGet, apiPost, apiDelete } from '../api/client';

interface WLRule {
  comm: string;
  path: string;
  scope: string;
  reason: string;
}

interface ProcessInfo {
  pid: number;
  name?: string;
  comm?: string;
  exe: string;
  ppid: number;
}

const SCOPE_OPTIONS = [
  { value: 'all', label: '전체 검사' },
  { value: 'fileless', label: '파일리스 탐지' },
  { value: 'lolbins', label: 'LOLBins 탐지' },
  { value: 'ptrace', label: 'Ptrace 감시' },
  { value: 'sequence', label: '시퀀스 탐지' },
  { value: 'container', label: '컨테이너 탈출' },
  { value: 'rootkit', label: '루트킷 탐지' },
  { value: 'lateral', label: '횡이동 탐지' },
];

export default function Whitelist() {
  const [tab, setTab] = useState<'white' | 'black'>('white');
  const [whiteRules, setWhiteRules] = useState<WLRule[]>([]);
  const [blackRules, setBlackRules] = useState<WLRule[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [form, setForm] = useState({ comm: '', path: '', scope: 'all', reason: '' });

  // Process picker state
  const [showPicker, setShowPicker] = useState(false);
  const [processes, setProcesses] = useState<ProcessInfo[]>([]);
  const [procSearch, setProcSearch] = useState('');
  const [loadingProcs, setLoadingProcs] = useState(false);
  const [selectedProc, setSelectedProc] = useState<ProcessInfo | null>(null);

  useEffect(() => { reload(); }, []);

  async function reload() {
    try {
      const [w, b] = await Promise.all([
        apiGet<WLRule[]>('/whitelist'),
        apiGet<WLRule[]>('/blacklist-rules'),
      ]);
      setWhiteRules(w);
      setBlackRules(b);
    } catch (e) { console.error(e); }
  }

  async function loadProcesses() {
    setLoadingProcs(true);
    try {
      // API returns array directly: [{pid, comm, exe, ppid, ...}, ...]
      const data = await apiGet<ProcessInfo[]>('/processes');
      const procList = Array.isArray(data) ? data : [];
      // Deduplicate by comm+exe
      const seen = new Set<string>();
      const unique = procList.filter(p => {
        const name = p.comm || p.name || '';
        const key = `${name}|${p.exe}`;
        if (!name || name === '[kernel]' || seen.has(key)) return false;
        seen.add(key);
        return true;
      });
      unique.sort((a, b) => (a.comm || a.name || '').localeCompare(b.comm || b.name || ''));
      setProcesses(unique);
    } catch (e) { console.error(e); }
    setLoadingProcs(false);
  }

  async function addRule() {
    if (!form.comm && !form.path) return;
    const endpoint = tab === 'white' ? '/whitelist' : '/blacklist-rules';
    await apiPost(endpoint, form);
    setForm({ comm: '', path: '', scope: 'all', reason: '' });
    setShowForm(false);
    setShowPicker(false);
    setSelectedProc(null);
    reload();
  }

  async function deleteRule(idx: number) {
    const endpoint = tab === 'white' ? `/whitelist/${idx}` : `/blacklist-rules/${idx}`;
    await apiDelete(endpoint);
    reload();
  }

  function selectProcess(p: ProcessInfo) {
    const name = p.comm || p.name || '';
    setForm({ ...form, comm: name, path: p.exe || '' });
    setSelectedProc(p);
  }

  const rules = tab === 'white' ? whiteRules : blackRules;
  const Icon = tab === 'white' ? ShieldCheck : ShieldBan;
  const tabLabel = tab === 'white' ? '화이트리스트' : '블랙리스트';

  const filteredProcs = procSearch
    ? processes.filter(p => {
        const name = (p.comm || p.name || '').toLowerCase();
        const exe = (p.exe || '').toLowerCase();
        const q = procSearch.toLowerCase();
        return name.includes(q) || exe.includes(q);
      })
    : processes;

  return (
    <div className="page">
      <div className="page-header">
        <h1><Icon size={22} /> {tabLabel} 관리</h1>
        <div className="toolbar">
          <button className={`filter-pill ${tab === 'white' ? 'active' : ''}`}
                  onClick={() => { setTab('white'); setShowPicker(false); setShowForm(false); }}>
            <ShieldCheck size={12} /> 화이트리스트
          </button>
          <button className={`filter-pill ${tab === 'black' ? 'active' : ''}`}
                  onClick={() => { setTab('black'); setShowPicker(false); setShowForm(false); }}>
            <ShieldBan size={12} /> 블랙리스트
          </button>
          <button className="btn" onClick={reload}>
            <RefreshCw size={14} /> 새로고침
          </button>
        </div>
      </div>

      <div className="settings-section">
        <h2>{tab === 'white' ? '🛡️ 허용 규칙' : '🚫 차단 규칙'} ({rules.length}개)</h2>
        <p className="settings-desc">
          {tab === 'white'
            ? '화이트리스트에 등록된 프로세스/경로는 선택한 검사(EDR + YARA)에서 제외됩니다.'
            : '블랙리스트에 등록된 프로세스/경로는 추가적인 감시 대상이 됩니다.'}
        </p>

        <div className="toolbar" style={{gap: 8, marginBottom: 12}}>
          <button className="btn btn-primary" onClick={() => { setShowForm(!showForm); setShowPicker(false); setSelectedProc(null); }}>
            <Plus size={14} /> 직접 입력
          </button>
          <button className="btn" onClick={() => {
            const next = !showPicker;
            setShowPicker(next);
            setShowForm(false);
            setSelectedProc(null);
            if (next) loadProcesses();
          }}>
            <UserCheck size={14} /> 프로세스 선택
          </button>
        </div>

        {/* Process Picker */}
        {showPicker && (
          <div className="card" style={{padding: 16, marginBottom: 16}}>
            <div style={{display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12}}>
              <Search size={14} />
              <input type="text" value={procSearch}
                     onChange={e => setProcSearch(e.target.value)}
                     placeholder="프로세스 검색..." className="input"
                     style={{flex: 1}} />
              <button className="btn btn-sm" onClick={loadProcesses} disabled={loadingProcs}>
                <RefreshCw size={12} />
              </button>
              <span style={{fontSize: 11, color: 'var(--text-dim)'}}>{processes.length}개</span>
            </div>
            <div style={{maxHeight: 260, overflow: 'auto', marginBottom: selectedProc ? 0 : 0}}>
              {loadingProcs ? (
                <div className="empty">로딩 중...</div>
              ) : filteredProcs.length === 0 ? (
                <div className="empty">프로세스 없음</div>
              ) : (
                <table className="data-table" style={{fontSize: 12}}>
                  <thead><tr><th>이름</th><th>경로</th><th></th></tr></thead>
                  <tbody>
                    {filteredProcs.slice(0, 80).map((p, i) => {
                      const name = p.comm || p.name || '';
                      const isSelected = selectedProc && (selectedProc.comm || selectedProc.name) === name;
                      return (
                        <tr key={i} style={{cursor: 'pointer', background: isSelected ? 'var(--accent-bg)' : undefined}}
                            onClick={() => selectProcess(p)}>
                          <td className="mono">{name}</td>
                          <td className="mono" style={{maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}} title={p.exe}>{p.exe || '-'}</td>
                          <td><button className="btn btn-sm" style={{padding: '2px 8px', fontSize: 11}}>{isSelected ? '✓' : '선택'}</button></td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              )}
            </div>
            {/* After selection, show scope/reason form */}
            {selectedProc && (
              <div style={{marginTop: 12, padding: 12, background: 'var(--bg-primary)', borderRadius: 8, borderTop: '2px solid var(--accent)'}}>
                <div style={{fontSize: 12, opacity: 0.7, marginBottom: 8}}>
                  선택됨: <strong>{form.comm}</strong> {form.path && <>({form.path})</>}
                </div>
                <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8}}>
                  <div>
                    <label style={{fontSize: 12, opacity: 0.7}}>적용 범위</label>
                    <select value={form.scope} onChange={e => setForm({...form, scope: e.target.value})} className="input">
                      {SCOPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                    </select>
                  </div>
                  <div>
                    <label style={{fontSize: 12, opacity: 0.7}}>사유</label>
                    <input type="text" value={form.reason}
                           onChange={e => setForm({...form, reason: e.target.value})}
                           placeholder="예: AI 에이전트" className="input" />
                  </div>
                </div>
                <button className="btn btn-primary" onClick={addRule}>
                  <Plus size={14} /> {tabLabel}에 추가
                </button>
              </div>
            )}
          </div>
        )}

        {/* Manual input form */}
        {showForm && (
          <div className="card" style={{padding: 16, marginBottom: 16}}>
            <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8}}>
              <div>
                <label style={{fontSize: 12, opacity: 0.7}}>프로세스 이름 (comm)</label>
                <input type="text" value={form.comm}
                       onChange={e => setForm({...form, comm: e.target.value})}
                       placeholder="예: notify-send" className="input" />
              </div>
              <div>
                <label style={{fontSize: 12, opacity: 0.7}}>파일 경로 (와일드카드 가능)</label>
                <input type="text" value={form.path}
                       onChange={e => setForm({...form, path: e.target.value})}
                       placeholder="예: /proc/self/fd/*" className="input" />
              </div>
            </div>
            <div style={{display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, marginBottom: 8}}>
              <div>
                <label style={{fontSize: 12, opacity: 0.7}}>적용 범위</label>
                <select value={form.scope} onChange={e => setForm({...form, scope: e.target.value})} className="input">
                  {SCOPE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                </select>
              </div>
              <div>
                <label style={{fontSize: 12, opacity: 0.7}}>사유</label>
                <input type="text" value={form.reason}
                       onChange={e => setForm({...form, reason: e.target.value})}
                       placeholder="예: AI 에이전트" className="input" />
              </div>
            </div>
            <button className="btn btn-primary" onClick={addRule}>
              <Plus size={14} /> {tabLabel}에 추가
            </button>
          </div>
        )}

        {rules.length === 0 ? (
          <div className="empty">등록된 규칙이 없습니다.</div>
        ) : (
          <div className="card">
            <div className="card-body">
              <table className="data-table">
                <thead><tr>
                  <th>프로세스</th><th>경로</th><th>적용 범위</th><th>사유</th><th></th>
                </tr></thead>
                <tbody>
                  {rules.map((r, i) => (
                    <tr key={i}>
                      <td className="mono">{r.comm || '-'}</td>
                      <td className="mono" style={{maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}} title={r.path}>{r.path || '-'}</td>
                      <td><span className={`event-badge ${r.scope === 'all' ? 'info' : 'warning'}`}>{SCOPE_OPTIONS.find(o => o.value === r.scope)?.label || r.scope}</span></td>
                      <td>{r.reason || '-'}</td>
                      <td>
                        <button className="btn btn-sm" onClick={() => deleteRule(i)} style={{color: 'var(--critical)', padding: '2px 6px'}}>
                          <Trash2 size={12} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
