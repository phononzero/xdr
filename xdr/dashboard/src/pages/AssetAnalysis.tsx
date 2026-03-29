import { useState, useEffect, useCallback } from 'react'
import { ScanSearch, RefreshCw, Shield, AlertTriangle, XCircle, CheckCircle } from 'lucide-react'
import { apiGet, apiPost } from '../api/client'

interface ScanItem { name: string; category: string; verdict: string; reason: string; details: Record<string,any> }
interface ScanSummary { total: number; safe: number; suspicious: number; malicious: number; unknown: number }
interface ScanResult {
  timestamp: string; duration_ms: number;
  modules: ScanItem[]; packages: ScanItem[]; hardware: ScanItem[];
  summary: { modules: ScanSummary; packages: ScanSummary; hardware: ScanSummary }
}

const VERDICT_STYLE: Record<string,{color:string,icon:any,label:string}> = {
  safe: { color: 'var(--success)', icon: CheckCircle, label: '안전' },
  suspicious: { color: 'var(--warning)', icon: AlertTriangle, label: '의심' },
  malicious: { color: 'var(--critical)', icon: XCircle, label: '악성' },
  unknown: { color: 'var(--text-muted)', icon: Shield, label: '미분류' },
}

export default function AssetAnalysis() {
  const [results, setResults] = useState<ScanResult|null>(null)
  const [loading, setLoading] = useState(true)
  const [scanning, setScanning] = useState(false)
  const [activeTab, setActiveTab] = useState<string>('modules')

  const fetchResults = useCallback(async () => {
    try { setLoading(true); const r = await apiGet<ScanResult>('/assets/scan/status'); if (r?.timestamp) setResults(r) }
    catch {} finally { setLoading(false) }
  }, [])

  useEffect(() => { fetchResults() }, [fetchResults])

  const triggerScan = async () => {
    setScanning(true)
    try { const r = await apiPost<ScanResult>('/assets/scan/trigger'); setResults(r) }
    catch {} finally { setScanning(false) }
  }

  const summaryCards = results?.summary
    ? Object.entries(results.summary).map(([cat, s]) => ({ cat, ...s }))
    : []

  const items = results?.[activeTab as keyof Pick<ScanResult,'modules'|'packages'|'hardware'>] as ScanItem[] || []
  const nonSafe = items.filter(i => i.verdict !== 'safe')

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><ScanSearch size={20} /> 보안 분석</h1>
        <div style={{display:'flex',gap:8,alignItems:'center'}}>
          {results?.timestamp && <span className="text-muted" style={{fontSize:'0.75rem'}}>마지막: {new Date(results.timestamp).toLocaleString('ko-KR')}</span>}
          <button className="btn btn-primary" onClick={triggerScan} disabled={scanning}>
            {scanning ? '스캔 중...' : <><ScanSearch size={14} /> 수동 스캔</>}
          </button>
        </div>
      </div>

      {results?.summary && (
        <div className="stats-row">
          {summaryCards.map(s => (
            <div key={s.cat} className="stat-card" onClick={() => setActiveTab(s.cat)}>
              <div style={{display:'flex',gap:8,alignItems:'baseline'}}>
                <span className="stat-value">{s.total}</span>
                <span className="stat-label">{s.cat === 'modules' ? '커널' : s.cat === 'packages' ? '패키지' : '하드웨어'}</span>
              </div>
              <div style={{display:'flex',gap:6,marginTop:4,fontSize:'0.75rem'}}>
                <span style={{color:'var(--success)'}}>✓{s.safe}</span>
                {s.suspicious > 0 && <span style={{color:'var(--warning)'}}>⚠{s.suspicious}</span>}
                {s.malicious > 0 && <span style={{color:'var(--critical)'}}>✗{s.malicious}</span>}
              </div>
            </div>
          ))}
          {results?.duration_ms !== undefined && (
            <div className="stat-card"><span className="stat-value">{results.duration_ms}ms</span><span className="stat-label">소요 시간</span></div>
          )}
        </div>
      )}

      <div className="tabs">
        {['modules','packages','hardware'].map(t => (
          <button key={t} className={`tab ${activeTab === t ? 'active' : ''}`} onClick={() => setActiveTab(t)}>
            {t === 'modules' ? '커널 모듈' : t === 'packages' ? '패키지' : '하드웨어'}
            {results?.summary?.[t as keyof typeof results.summary]?.suspicious ? ` ⚠` : ''}
          </button>
        ))}
      </div>

      {loading && !results ? <div className="loading">로딩 중...</div> : !results ? (
        <div className="empty-state">
          <p>아직 스캔 결과가 없습니다</p>
          <button className="btn btn-primary" onClick={triggerScan}>첫 스캔 실행</button>
        </div>
      ) : (
        <div className="table-container">
          {nonSafe.length > 0 && (
            <div className="alert alert-warning" style={{margin:'8px 0'}}>
              ⚠ {nonSafe.length}개 항목이 안전하지 않습니다
            </div>
          )}
          <table className="data-table">
            <thead><tr><th>판정</th><th>이름</th><th>사유</th></tr></thead>
            <tbody>
              {items.filter(i => i.verdict !== 'safe').concat(items.filter(i => i.verdict === 'safe')).slice(0, 300).map((item, idx) => {
                const vs = VERDICT_STYLE[item.verdict] || VERDICT_STYLE.unknown
                const Icon = vs.icon
                return (
                  <tr key={idx} className={item.verdict === 'malicious' ? 'row-danger' : item.verdict === 'suspicious' ? 'row-warning' : ''}>
                    <td><span className="badge" style={{background:`color-mix(in srgb, ${vs.color} 15%, transparent)`, color:vs.color, border:`1px solid color-mix(in srgb, ${vs.color} 30%, transparent)`}}><Icon size={10}/> {vs.label}</span></td>
                    <td className="mono">{item.name}</td>
                    <td className="text-muted">{item.reason}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
