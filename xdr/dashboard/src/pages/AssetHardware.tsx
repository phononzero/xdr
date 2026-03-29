import { useState, useEffect, useCallback } from 'react'
import { Usb, Monitor, Keyboard, RefreshCw, Search, Ban, CheckCircle } from 'lucide-react'
import { apiGet, apiPost } from '../api/client'

interface HardwareDevice {
  type: string; name: string; bus_id?: string;
  vendor_id?: string; product_id?: string;
  manufacturer?: string; product_name?: string;
  device_class?: string; handlers?: string;
  whitelisted: boolean; blacklisted: boolean;
}

export default function AssetHardware() {
  const [devices, setDevices] = useState<HardwareDevice[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState<string>('all')
  const [actionMsg, setActionMsg] = useState<{ok:boolean,message:string}|null>(null)

  const fetchDevices = useCallback(async () => {
    try { setLoading(true); setDevices(await apiGet('/assets/hardware')) }
    catch {} finally { setLoading(false) }
  }, [])

  useEffect(() => { fetchDevices() }, [fetchDevices])

  const handleBlock = async (d: HardwareDevice) => {
    if (!d.vendor_id || !d.product_id) { setActionMsg({ok:false,message:'USB만 차단 가능'}); return }
    if (!confirm(`'${d.name}' 차단하시겠습니까?`)) return
    const res = await apiPost<{ok:boolean,message:string}>('/assets/hardware/block', {
      vendor_id: d.vendor_id, product_id: d.product_id, name: d.name
    })
    setActionMsg(res); fetchDevices()
    setTimeout(() => setActionMsg(null), 5000)
  }

  const handleUnblock = async (d: HardwareDevice) => {
    const res = await apiPost<{ok:boolean,message:string}>('/assets/hardware/unblock', {
      vendor_id: d.vendor_id, product_id: d.product_id, name: d.name
    })
    setActionMsg(res); fetchDevices()
    setTimeout(() => setActionMsg(null), 5000)
  }

  const typeIcon = (t: string) => {
    if (t === 'usb') return <Usb size={14} />
    if (t === 'input') return <Keyboard size={14} />
    return <Monitor size={14} />
  }

  const filtered = devices.filter(d => {
    if (search && !d.name.toLowerCase().includes(search.toLowerCase())) return false
    if (typeFilter !== 'all' && d.type !== typeFilter) return false
    return true
  })

  const stats = {
    usb: devices.filter(d => d.type === 'usb').length,
    pci: devices.filter(d => d.type === 'pci').length,
    input: devices.filter(d => d.type === 'input').length,
  }

  return (
    <div className="page-container">
      <div className="page-header">
        <h1><Monitor size={20} /> 하드웨어 관리</h1>
        <button className="btn btn-secondary" onClick={fetchDevices}><RefreshCw size={14} /> 새로고침</button>
      </div>

      {actionMsg && (
        <div className={`alert ${actionMsg.ok ? 'alert-success' : 'alert-danger'}`}>{actionMsg.message}</div>
      )}

      <div className="stats-row">
        <div className="stat-card" onClick={() => setTypeFilter('all')}><span className="stat-value">{devices.length}</span><span className="stat-label">전체</span></div>
        <div className="stat-card" onClick={() => setTypeFilter('usb')}><span className="stat-value">{stats.usb}</span><span className="stat-label">USB</span></div>
        <div className="stat-card" onClick={() => setTypeFilter('pci')}><span className="stat-value">{stats.pci}</span><span className="stat-label">PCI</span></div>
        <div className="stat-card" onClick={() => setTypeFilter('input')}><span className="stat-value">{stats.input}</span><span className="stat-label">입력</span></div>
      </div>

      <div className="search-bar">
        <Search size={14} />
        <input type="text" placeholder="디바이스 검색..." value={search} onChange={e => setSearch(e.target.value)} />
      </div>

      {loading ? <div className="loading">로딩 중...</div> : (
        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr><th>유형</th><th>디바이스</th><th>ID</th><th>상태</th><th>작업</th></tr>
            </thead>
            <tbody>
              {filtered.map((d, i) => (
                <tr key={`${d.type}-${d.bus_id || i}`} className={d.blacklisted ? 'row-danger' : ''}>
                  <td>{typeIcon(d.type)} <span className="badge badge-secondary">{d.type.toUpperCase()}</span></td>
                  <td>
                    <div>{d.name}</div>
                    {d.manufacturer && <div className="text-muted" style={{fontSize:'0.75rem'}}>{d.manufacturer}</div>}
                  </td>
                  <td className="mono text-muted">
                    {d.vendor_id && d.product_id ? `${d.vendor_id}:${d.product_id}` : d.bus_id || '—'}
                  </td>
                  <td>
                    {d.blacklisted ? <span className="badge badge-danger">차단</span>
                    : d.whitelisted ? <span className="badge badge-success">허용</span>
                    : <span className="badge badge-secondary">활성</span>}
                  </td>
                  <td className="actions">
                    {d.type === 'usb' && d.vendor_id && d.product_id && (
                      !d.blacklisted ? (
                        <button className="btn btn-sm btn-danger" onClick={() => handleBlock(d)} title="차단">
                          <Ban size={12} />
                        </button>
                      ) : (
                        <button className="btn btn-sm btn-success" onClick={() => handleUnblock(d)} title="해제">
                          <CheckCircle size={12} />
                        </button>
                      )
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
