import { useState, useEffect, useCallback } from 'react'
import { ScrollText, RefreshCw, Search, Filter } from 'lucide-react'
import { apiGet } from '../api/client'

interface LogEntry {
  timestamp: string; event_type: string; category: string;
  name: string; detail: string; result: string;
  [key: string]: any;
}

const EVENT_LABELS: Record<string,{label:string,color:string}> = {
  MODULE_LOAD: { label: '모듈 로드', color: 'var(--info)' },
  MODULE_UNLOAD: { label: '모듈 언로드', color: 'var(--warning)' },
  MODULE_BLOCK: { label: '모듈 차단', color: 'var(--critical)' },
  PACKAGE_INSTALL: { label: '패키지 설치', color: 'var(--info)' },
  PACKAGE_REMOVE: { label: '패키지 제거', color: 'var(--warning)' },
  HW_CONNECT: { label: 'HW 연결', color: 'var(--success)' },
  HW_DISCONNECT: { label: 'HW 연결해제', color: 'var(--text-muted)' },
  HW_BLOCK: { label: 'HW 차단', color: 'var(--critical)' },
  SCAN_RESULT: { label: '스캔 결과', color: 'var(--accent)' },
  ACTION: { label: '관리자 작업', color: 'var(--success)' },
  POLICY_CHANGE: { label: '정책 변경', color: 'var(--warning)' },
}

export default function AssetLogs() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const [catFilter, setCatFilter] = useState<string>('')
  const [stats, setStats] = useState<{total:number,by_type:Record<string,number>,by_category:Record<string,number>}>({total:0,by_type:{},by_category:{}})

  const fetchLogs = useCallback(async () => {
    try {
      setLoading(true)
      const params = new URLSearchParams()
      if (typeFilter) params.set('type', typeFilter)
      if (catFilter) params.set('category', catFilter)
      if (search) params.set('search', search)
      params.set('limit', '500')
      setLogs(await apiGet(`/assets/logs?${params}`))
      setStats(await apiGet('/assets/logs/stats'))
    } catch {} finally { setLoading(false) }
  }, [typeFilter, catFilter, search])

  useEffect(() => { fetchLogs() }, [fetchLogs])

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><ScrollText size={20} /> 자산 로그</h1>
        <button className="btn btn-secondary" onClick={fetchLogs}><RefreshCw size={14} /></button>
      </div>

      <div className="stats-row">
        <div className="stat-card"><span className="stat-value">{stats.total}</span><span className="stat-label">전체 이벤트</span></div>
        {Object.entries(stats.by_category || {}).map(([cat, cnt]) => (
          <div key={cat} className="stat-card" onClick={() => setCatFilter(catFilter === cat ? '' : cat)} style={catFilter === cat ? {borderColor:'var(--accent)'} : {}}>
            <span className="stat-value">{cnt}</span><span className="stat-label">{cat}</span>
          </div>
        ))}
      </div>

      <div className="filter-row">
        <div className="search-bar" style={{flex:1}}>
          <Search size={14} />
          <input type="text" placeholder="로그 검색..." value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <select className="select-input" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">모든 유형</option>
          {Object.entries(EVENT_LABELS).map(([k, v]) => (
            <option key={k} value={k}>{v.label}</option>
          ))}
        </select>
      </div>

      {loading ? <div className="loading">로딩 중...</div> : (
        <div className="table-container">
          <table className="data-table">
            <thead><tr><th>시간</th><th>유형</th><th>카테고리</th><th>이름</th><th>상세</th><th>결과</th></tr></thead>
            <tbody>
              {logs.map((log, i) => {
                const ev = EVENT_LABELS[log.event_type] || { label: log.event_type, color: 'var(--text-muted)' }
                return (
                  <tr key={i}>
                    <td className="text-muted" style={{whiteSpace:'nowrap',fontSize:'0.75rem'}}>
                      {new Date(log.timestamp).toLocaleString('ko-KR', {month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit'})}
                    </td>
                    <td><span className="badge" style={{background:`color-mix(in srgb, ${ev.color} 15%, transparent)`, color:ev.color, border:`1px solid color-mix(in srgb, ${ev.color} 30%, transparent)`}}>{ev.label}</span></td>
                    <td><span className="badge badge-secondary">{log.category}</span></td>
                    <td className="mono">{log.name}</td>
                    <td className="text-muted" style={{maxWidth:250,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{log.detail}</td>
                    <td>{log.result && (
                      <span className={`badge badge-${log.result === 'success' ? 'success' : log.result === 'fail' ? 'danger' : 'secondary'}`}>{log.result}</span>
                    )}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
          {logs.length === 0 && <div className="empty-state">로그 없음</div>}
        </div>
      )}
    </div>
  )
}
