import { useState, useEffect, useCallback, useRef } from 'react'
import { LayoutDashboard, ShieldBan, Lock, Cpu, Network, Settings, Sun, Moon, Shield, Activity, ShieldCheck, ScrollText, LogOut, Boxes, Package, Monitor, ListChecks, ScanSearch, FileText } from 'lucide-react'
import { connectSSE, apiGet, isAuthenticated as checkIsAuth, logout, checkAuth, type XDREvent, type XDRStatus, type BlocklistData } from './api/client'
import Dashboard from './pages/Dashboard'
import BlockRules from './pages/BlockRules'
import BlockedList from './pages/BlockedList'
import Processes from './pages/Processes'
import NetworkPage from './pages/Network'
import SettingsPage from './pages/Settings'
import IntegrityPage from './pages/Integrity'
import WhitelistPage from './pages/Whitelist'
import LogSearchPage from './pages/LogSearch'
import LoginPage from './pages/Login'
import AssetModules from './pages/AssetModules'
import AssetPackages from './pages/AssetPackages'
import AssetHardware from './pages/AssetHardware'
import AssetPolicy from './pages/AssetPolicy'
import AssetAnalysis from './pages/AssetAnalysis'
import AssetLogs from './pages/AssetLogs'

type Page = 'dashboard' | 'block-rules' | 'blocked' | 'processes' | 'network' | 'settings' | 'integrity' | 'whitelist' | 'logs' | 'asset-modules' | 'asset-packages' | 'asset-hardware' | 'asset-policy' | 'asset-analysis' | 'asset-logs'

export default function App() {
  const [authenticated, setAuthenticated] = useState(checkIsAuth())
  const [page, setPage] = useState<Page>('dashboard')
  const [sseConnected, setSseConnected] = useState(false)
  const [events, setEvents] = useState<XDREvent[]>([])
  const [status, setStatus] = useState<XDRStatus | null>(null)
  const [blocklist, setBlocklist] = useState<BlocklistData | null>(null)
  const [health, setHealth] = useState<Record<string, unknown> | null>(null)
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('xdr-theme') as 'dark' | 'light') || 'dark'
  })
  const cleanupRef = useRef<(() => void) | null>(null)

  // Check auth on mount
  useEffect(() => {
    if (authenticated) {
      checkAuth().then(ok => { if (!ok) setAuthenticated(false); });
    }
  }, [])

  // Listen for 401 events from API client
  useEffect(() => {
    const handler = () => setAuthenticated(false);
    window.addEventListener('xdr-auth-expired', handler);
    return () => window.removeEventListener('xdr-auth-expired', handler);
  }, [])

  // Apply theme
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('xdr-theme', theme)
  }, [theme])

  const handleLogin = () => setAuthenticated(true)
  const handleLogout = async () => {
    await logout()
    setAuthenticated(false)
    setEvents([])
  }

  // Show login page if not authenticated
  if (!authenticated) {
    return <LoginPage onLogin={handleLogin} />
  }

  const handleEvent = useCallback((ev: XDREvent) => {
    setEvents(prev => {
      const next = [ev, ...prev];
      return next.length > 2000 ? next.slice(0, 2000) : next;
    });
  }, []);

  const refreshBlocklist = useCallback(() => {
    apiGet<BlocklistData>('/blocklists').then(setBlocklist).catch(() => {});
  }, []);

  // Load persisted events from SQLite on mount
  useEffect(() => {
    apiGet<{events: {timestamp: string; source: string; action: string; reason: string; detail: string; alert_level: number; pid: number; comm: string}[]}>('/logs?limit=500')
      .then(data => {
        if (data.events && data.events.length > 0) {
          const mapped: XDREvent[] = data.events.map(e => ({
            _time: e.timestamp,
            source: e.source || 'SYS',
            action: e.action,
            reason: e.reason,
            detail: e.detail,
            alert_level: e.alert_level || 1,
            pid: e.pid,
            comm: e.comm,
          } as XDREvent));
          setEvents(prev => {
            if (prev.length === 0) return mapped;
            // Merge: keep SSE events (newer) + append SQLite (older), dedup by _time
            const seen = new Set(prev.map(e => e._time));
            const older = mapped.filter(e => !seen.has(e._time));
            return [...prev, ...older].slice(0, 2000);
          });
        }
      }).catch(() => {});
  }, []);

  useEffect(() => {
    cleanupRef.current = connectSSE(handleEvent, setSseConnected);
    apiGet<XDRStatus>('/status').then(setStatus).catch(() => {});
    apiGet<Record<string, unknown>>('/health').then(setHealth).catch(() => {});
    refreshBlocklist();
    const t1 = setInterval(() => {
      apiGet<XDRStatus>('/status').then(setStatus).catch(() => {});
      apiGet<Record<string, unknown>>('/health').then(setHealth).catch(() => {});
    }, 10000);
    const t2 = setInterval(refreshBlocklist, 15000);
    return () => { cleanupRef.current?.(); clearInterval(t1); clearInterval(t2); };
  }, [handleEvent, refreshBlocklist]);

  const blockedCount = blocklist
    ? (blocklist.blocked_ips?.length || 0) + (blocklist.blocked_ports?.length || 0) +
      (blocklist.blocked_pids?.length || 0) + (blocklist.blocked_paths?.length || 0) +
      (blocklist.blocked_hashes?.length || 0) + Object.keys(blocklist.known_macs || {}).length
    : 0;

  const tabs: { id: Page; label: string; icon: React.ReactNode; badge?: number; section?: string }[] = [
    { id: 'dashboard', label: '대시보드', icon: <LayoutDashboard size={18} /> },
    { id: 'logs', label: '로그 조회', icon: <ScrollText size={18} /> },
    { id: 'block-rules', label: '차단 등록', icon: <ShieldBan size={18} /> },
    { id: 'blocked', label: '차단 목록', icon: <Lock size={18} />, badge: blockedCount || undefined },
    { id: 'processes', label: '프로세스', icon: <Cpu size={18} /> },
    { id: 'network', label: '네트워크', icon: <Network size={18} /> },
    { id: 'integrity', label: '무결성', icon: <Shield size={18} /> },
    { id: 'whitelist', label: '허용/차단', icon: <ShieldCheck size={18} /> },
    { id: 'asset-modules', label: '커널 모듈', icon: <Boxes size={18} />, section: '자산 관리' },
    { id: 'asset-packages', label: '패키지', icon: <Package size={18} /> },
    { id: 'asset-hardware', label: '하드웨어', icon: <Monitor size={18} /> },
    { id: 'asset-policy', label: '정책 관리', icon: <ListChecks size={18} /> },
    { id: 'asset-analysis', label: '보안 분석', icon: <ScanSearch size={18} /> },
    { id: 'asset-logs', label: '자산 로그', icon: <FileText size={18} /> },
    { id: 'settings', label: '설정', icon: <Settings size={18} /> },
  ];

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="sidebar-logo">
          <h1>🛡️ XDR</h1>
          <div className="subtitle">Endpoint & Network Detection</div>
        </div>
        <nav className="sidebar-nav">
          {tabs.map((t, i) => (
            <div key={t.id}>
              {t.section && (
                <div className="nav-section">{t.section}</div>
              )}
              <button
                className={`nav-item ${page === t.id ? 'active' : ''}`}
                onClick={() => setPage(t.id)}
              >
                {t.icon}
                <span>{t.label}</span>
                {t.badge ? <span className="nav-badge">{t.badge}</span> : null}
              </button>
            </div>
          ))}
        </nav>

        {/* Theme toggle */}
        <div className="theme-toggle" onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}>
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          <span>{theme === 'dark' ? '라이트 모드' : '다크 모드'}</span>
        </div>

        {/* Logout */}
        <div className="theme-toggle" onClick={handleLogout} style={{color: 'var(--danger)'}}>
          <LogOut size={16} />
          <span>로그아웃</span>
        </div>

        <div className="sidebar-status">
          <div className="status-item">
            <span className={`status-dot ${status?.edr_loaded ? 'ok' : 'err'}`} />
            <span>EDR {status?.edr_loaded ? '로드됨' : '없음'}</span>
          </div>
          <div className="status-item">
            <span className={`status-dot ${status?.ndr_attached ? 'ok' : 'err'}`} />
            <span>NDR {status?.ndr_attached ? '연결됨' : '없음'}</span>
          </div>
          <div className="status-item">
            <span className={`status-dot ${sseConnected ? 'ok' : 'err'} pulse`} />
            <span>{sseConnected ? '실시간 연결' : '연결 끊김'}</span>
          </div>
          {status?.kernel && (
            <div className="status-item" style={{marginTop: 8}}>
              <span style={{color: 'var(--text-dim)', fontSize: 10}}>커널 {status.kernel}</span>
            </div>
          )}
          {health && (
            <div style={{marginTop: 8, padding: '8px 16px', borderTop: '1px solid var(--border)'}}>
              <div style={{fontSize: 10, color: 'var(--text-dim)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4}}>
                <Activity size={10}/> 모듈 상태
              </div>
              {Object.entries(health.modules as Record<string, string> || {}).map(([name, st]) => (
                <div key={name} className="status-item" style={{fontSize: 10}}
                     title={(health.details as Record<string, string>)?.[name] || ''}>
                  <span className={`status-dot ${st === 'running' ? 'ok' : (st === 'stopped' || st === 'failed') ? 'err' : 'warn'}`} />
                  <span>{name}{st === 'failed' ? ' ⚠' : ''}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </aside>

      <main className="main-content">
        {page === 'dashboard' && <Dashboard events={events} />}
        {page === 'block-rules' && <BlockRules blocklist={blocklist} onRefresh={refreshBlocklist} />}
        {page === 'blocked' && <BlockedList blocklist={blocklist} onRefresh={refreshBlocklist} />}
        {page === 'processes' && <Processes onRefreshBlocklist={refreshBlocklist} />}
        {page === 'network' && <NetworkPage onRefreshBlocklist={refreshBlocklist} />}
        {page === 'settings' && <SettingsPage />}
        {page === 'integrity' && <IntegrityPage />}
        {page === 'whitelist' && <WhitelistPage />}
        {page === 'logs' && <LogSearchPage />}
        {page === 'asset-modules' && <AssetModules />}
        {page === 'asset-packages' && <AssetPackages />}
        {page === 'asset-hardware' && <AssetHardware />}
        {page === 'asset-policy' && <AssetPolicy />}
        {page === 'asset-analysis' && <AssetAnalysis />}
        {page === 'asset-logs' && <AssetLogs />}
      </main>
    </div>
  );
}
