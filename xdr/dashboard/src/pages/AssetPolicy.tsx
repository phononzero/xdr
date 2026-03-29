import { useState, useEffect, useCallback } from 'react'
import { ListChecks, Plus, Trash2, RefreshCw } from 'lucide-react'
import { apiGet, apiPost } from '../api/client'

interface PolicyData {
  modules: { whitelist: string[]; blacklist: string[] };
  packages: { whitelist: string[]; blacklist: string[] };
  hardware: { whitelist: {vendor?:string,product?:string,name:string}[]; blacklist: {vendor?:string,product?:string,name:string}[] };
}

const SECTIONS = [
  { key: 'modules', label: '커널 모듈' },
  { key: 'packages', label: '패키지' },
  { key: 'hardware', label: '하드웨어' },
] as const

export default function AssetPolicy() {
  const [policy, setPolicy] = useState<PolicyData|null>(null)
  const [loading, setLoading] = useState(true)
  const [activeTab, setActiveTab] = useState<string>('modules')
  const [newItem, setNewItem] = useState('')
  const [listType, setListType] = useState<'whitelist'|'blacklist'>('whitelist')
  const [actionMsg, setActionMsg] = useState<{ok:boolean,message:string}|null>(null)

  const fetchPolicy = useCallback(async () => {
    try { setLoading(true); setPolicy(await apiGet('/assets/policy')) }
    catch {} finally { setLoading(false) }
  }, [])

  useEffect(() => { fetchPolicy() }, [fetchPolicy])

  const handleAdd = async () => {
    if (!newItem.trim()) return
    const item = activeTab === 'hardware'
      ? { name: newItem.trim() }
      : newItem.trim()
    const res = await apiPost<{ok:boolean,message:string}>('/assets/policy/add', {
      section: activeTab, list_type: listType, item
    })
    setActionMsg(res); setNewItem(''); fetchPolicy()
    setTimeout(() => setActionMsg(null), 3000)
  }

  const handleRemove = async (item: string, lt: string) => {
    await apiPost('/assets/policy/remove', { section: activeTab, list_type: lt, item })
    fetchPolicy()
  }

  const section = policy?.[activeTab as keyof PolicyData]

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><ListChecks size={20} /> 화이트/블랙리스트 관리</h1>
        <button className="btn btn-secondary" onClick={fetchPolicy}><RefreshCw size={14} /></button>
      </div>

      {actionMsg && <div className={`alert ${actionMsg.ok ? 'alert-success' : 'alert-danger'}`}>{actionMsg.message}</div>}

      <div className="tabs">
        {SECTIONS.map(s => (
          <button key={s.key} className={`tab ${activeTab === s.key ? 'active' : ''}`} onClick={() => setActiveTab(s.key)}>{s.label}</button>
        ))}
      </div>

      {loading ? <div className="loading">로딩 중...</div> : section && (
        <div className="policy-content">
          <div className="add-form">
            <select value={listType} onChange={e => setListType(e.target.value as 'whitelist'|'blacklist')} className="select-input">
              <option value="whitelist">화이트리스트</option>
              <option value="blacklist">블랙리스트</option>
            </select>
            <input type="text" value={newItem} onChange={e => setNewItem(e.target.value)} placeholder={`${activeTab === 'hardware' ? '디바이스 이름' : '이름'} 입력...`} className="text-input"
              onKeyDown={e => e.key === 'Enter' && handleAdd()} />
            <button className="btn btn-primary" onClick={handleAdd}><Plus size={14} /> 추가</button>
          </div>

          <div className="policy-lists">
            <div className="policy-list">
              <h3 className="list-title safe">✅ 화이트리스트 ({(section.whitelist as any[]).length})</h3>
              {(section.whitelist as any[]).map((item, i) => {
                const name = typeof item === 'string' ? item : item.name
                return (
                  <div key={i} className="policy-item">
                    <span className="mono">{name}</span>
                    <button className="btn btn-sm btn-ghost" onClick={() => handleRemove(name, 'whitelist')}><Trash2 size={12} /></button>
                  </div>
                )
              })}
              {(section.whitelist as any[]).length === 0 && <div className="empty-state">항목 없음</div>}
            </div>

            <div className="policy-list">
              <h3 className="list-title danger">🚫 블랙리스트 ({(section.blacklist as any[]).length})</h3>
              {(section.blacklist as any[]).map((item, i) => {
                const name = typeof item === 'string' ? item : item.name
                return (
                  <div key={i} className="policy-item danger">
                    <span className="mono">{name}</span>
                    <button className="btn btn-sm btn-ghost" onClick={() => handleRemove(name, 'blacklist')}><Trash2 size={12} /></button>
                  </div>
                )
              })}
              {(section.blacklist as any[]).length === 0 && <div className="empty-state">항목 없음</div>}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
