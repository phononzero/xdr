import { useState, useEffect, useCallback } from 'react'
import { Package, RefreshCw, Search, Shield, AlertTriangle } from 'lucide-react'
import { apiGet } from '../api/client'

interface InstalledPackage {
  name: string; version: string; status: string; description: string;
  running: boolean; whitelisted: boolean; blacklisted: boolean;
}

export default function AssetPackages() {
  const [packages, setPackages] = useState<InstalledPackage[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<string>('all')

  const fetchPackages = useCallback(async () => {
    try { setLoading(true); setPackages(await apiGet('/assets/packages')) }
    catch {} finally { setLoading(false) }
  }, [])

  useEffect(() => { fetchPackages() }, [fetchPackages])

  const filtered = packages.filter(p => {
    if (search && !p.name.toLowerCase().includes(search.toLowerCase()) &&
        !p.description.toLowerCase().includes(search.toLowerCase())) return false
    if (filter === 'running') return p.running
    if (filter === 'blacklisted') return p.blacklisted
    return true
  })

  const stats = { total: packages.length,
    running: packages.filter(p => p.running).length,
    blacklisted: packages.filter(p => p.blacklisted).length,
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><Package size={20} /> 패키지 관리</h1>
        <button className="btn btn-secondary" onClick={fetchPackages}><RefreshCw size={14} /> 새로고침</button>
      </div>

      <div className="stats-row">
        <div className="stat-card" onClick={() => setFilter('all')}><span className="stat-value">{stats.total}</span><span className="stat-label">설치됨</span></div>
        <div className="stat-card safe" onClick={() => setFilter('running')}><span className="stat-value">{stats.running}</span><span className="stat-label">실행중</span></div>
        <div className="stat-card warning" onClick={() => setFilter('blacklisted')}><span className="stat-value">{stats.blacklisted}</span><span className="stat-label">블랙리스트</span></div>
      </div>

      <div className="search-bar">
        <Search size={14} />
        <input type="text" placeholder="패키지 이름 또는 설명 검색..." value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {loading ? <div className="loading">패키지 목록 로딩 중... (수초 소요)</div> : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr><th>상태</th><th>패키지</th><th>버전</th><th>설명</th></tr>
            </thead>
            <tbody>
              {filtered.slice(0, 500).map(p => (
                <tr key={p.name} className={p.blacklisted ? 'row-danger' : ''}>
                  <td>
                    {p.blacklisted ? <span className="badge badge-danger"><AlertTriangle size={10} /> 차단</span>
                    : p.running ? <span className="badge badge-success">실행중</span>
                    : <span className="badge badge-secondary">설치됨</span>}
                  </td>
                  <td className="mono">{p.name}</td>
                  <td className="text-muted">{p.version}</td>
                  <td className="text-muted" style={{maxWidth:300,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{p.description}</td>
                </tr>
              ))}
            </tbody>
          </table>
          <div className="text-muted" style={{padding:'8px',textAlign:'center'}}>
            {filtered.length > 500 ? `${filtered.length}개 중 500개 표시` : `${filtered.length}개`}
          </div>
        </div>
      )}
    </div>
  )
}
