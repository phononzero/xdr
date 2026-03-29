import { useState, useEffect, useCallback } from 'react'
import { Shield, AlertTriangle, Trash2, Ban, CheckCircle, RefreshCw, Search } from 'lucide-react'
import { apiGet, apiPost } from '../api/client'

interface KernelModule {
  name: string; size: number; size_kb: number; used_count: number;
  used_by: string[]; state: string; taint: string; version: string;
  safety: string; is_builtin: boolean; removable: boolean;
  whitelisted: boolean; blacklisted: boolean;
}

export default function AssetModules() {
  const [modules, setModules] = useState<KernelModule[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<string>('all')
  const [actionMsg, setActionMsg] = useState<{ok:boolean,message:string}|null>(null)

  const fetchModules = useCallback(async () => {
    try { setLoading(true); setModules(await apiGet('/assets/modules')) }
    catch {} finally { setLoading(false) }
  }, [])

  useEffect(() => { fetchModules() }, [fetchModules])

  const handleUnload = async (name: string) => {
    if (!confirm(`'${name}' 모듈을 언로드하시겠습니까?`)) return
    const res = await apiPost<{ok:boolean,message:string,needs_reboot?:boolean}>('/assets/modules/unload', { name })
    setActionMsg(res); fetchModules()
    setTimeout(() => setActionMsg(null), 5000)
  }

  const handleBlock = async (name: string) => {
    if (!confirm(`'${name}' 모듈을 블랙리스트에 추가하시겠습니까? (재부팅 후 적용)`)) return
    const res = await apiPost<{ok:boolean,message:string}>('/assets/modules/block', { name })
    setActionMsg(res); fetchModules()
    setTimeout(() => setActionMsg(null), 5000)
  }

  const handleUnblock = async (name: string) => {
    const res = await apiPost<{ok:boolean,message:string}>('/assets/modules/unblock', { name })
    setActionMsg(res); fetchModules()
    setTimeout(() => setActionMsg(null), 5000)
  }

  const filtered = modules.filter(m => {
    if (search && !m.name.toLowerCase().includes(search.toLowerCase())) return false
    if (filter === 'safe') return m.safety === 'safe'
    if (filter === 'suspicious') return m.safety === 'suspicious'
    if (filter === 'unknown') return m.safety === 'unknown'
    if (filter === 'blacklisted') return m.blacklisted
    return true
  })

  const stats = { total: modules.length,
    safe: modules.filter(m => m.safety === 'safe').length,
    suspicious: modules.filter(m => m.safety === 'suspicious').length,
    unknown: modules.filter(m => m.safety === 'unknown').length,
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><Shield size={20} /> 커널 모듈 관리</h1>
        <button className="btn btn-secondary" onClick={fetchModules}><RefreshCw size={14} /> 새로고침</button>
      </div>

      {actionMsg && (
        <div className={`alert ${actionMsg.ok ? 'alert-success' : 'alert-danger'}`}>
          {actionMsg.message}
        </div>
      )}

      <div className="stats-row">
        <div className="stat-card" onClick={() => setFilter('all')}><span className="stat-value">{stats.total}</span><span className="stat-label">전체</span></div>
        <div className="stat-card safe" onClick={() => setFilter('safe')}><span className="stat-value">{stats.safe}</span><span className="stat-label">안전</span></div>
        <div className="stat-card warning" onClick={() => setFilter('suspicious')}><span className="stat-value">{stats.suspicious}</span><span className="stat-label">의심</span></div>
        <div className="stat-card" onClick={() => setFilter('unknown')}><span className="stat-value">{stats.unknown}</span><span className="stat-label">미분류</span></div>
      </div>

      <div className="search-bar">
        <Search size={14} />
        <input type="text" placeholder="모듈 이름 검색..." value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {loading ? <div className="loading">로딩 중...</div> : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>상태</th><th>모듈 이름</th><th>크기</th>
                <th>사용</th><th>Taint</th><th>작업</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(m => (
                <tr key={m.name} className={m.blacklisted ? 'row-danger' : m.safety === 'suspicious' ? 'row-warning' : ''}>
                  <td>
                    <span className={`badge badge-${m.safety === 'safe' ? 'success' : m.safety === 'suspicious' ? 'warning' : 'secondary'}`}>
                      {m.safety === 'safe' ? '안전' : m.safety === 'suspicious' ? '의심' : '미분류'}
                    </span>
                  </td>
                  <td>
                    <span className="mono">{m.name}</span>
                    {m.is_builtin && <span className="badge badge-info" style={{marginLeft:4,fontSize:'0.65rem'}}>내장</span>}
                    {m.blacklisted && <span className="badge badge-danger" style={{marginLeft:4,fontSize:'0.65rem'}}>차단</span>}
                    {m.version && <span className="text-muted" style={{marginLeft:4,fontSize:'0.7rem'}}>v{m.version}</span>}
                  </td>
                  <td className="text-muted">{m.size_kb} KB</td>
                  <td>{m.used_count > 0
                    ? <span className="text-muted">{m.used_count} ({m.used_by.join(', ')})</span>
                    : <span className="text-dim">미사용</span>}
                  </td>
                  <td>{m.taint ? <span className="badge badge-warning">{m.taint}</span> : <span className="text-dim">—</span>}</td>
                  <td className="actions">
                    {m.removable && !m.blacklisted && (
                      <button className="btn btn-sm btn-danger" onClick={() => handleUnload(m.name)} title="언로드">
                        <Trash2 size={12} />
                      </button>
                    )}
                    {!m.blacklisted ? (
                      <button className="btn btn-sm btn-warning" onClick={() => handleBlock(m.name)} title="블랙리스트">
                        <Ban size={12} />
                      </button>
                    ) : (
                      <button className="btn btn-sm btn-success" onClick={() => handleUnblock(m.name)} title="차단해제">
                        <CheckCircle size={12} />
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {filtered.length === 0 && <div className="empty-state">일치하는 모듈이 없습니다</div>}
        </div>
      )}
    </div>
  )
}
