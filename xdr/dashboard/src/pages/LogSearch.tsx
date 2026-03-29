import { useState, useEffect, useCallback } from 'react';
import { Search, Calendar, ChevronLeft, ChevronRight, Download, RefreshCw, Filter } from 'lucide-react';
import { apiGet, downloadCSV } from '../api/client';

interface LogEvent {
  id: number;
  timestamp: string;
  source: string;
  action: string;
  reason: string;
  detail: string;
  alert_level: number;
  pid: number;
  comm: string;
}

interface LogResponse {
  events: LogEvent[];
  total: number;
  limit: number;
  offset: number;
}

const PAGE_SIZE = 50;
const AC: Record<number, string> = {1:'info', 2:'warning', 3:'critical'};
const AL: Record<number, string> = {1:'INFO', 2:'WARN', 3:'CRITICAL'};

const TABS = [
  { id: 'all', label: '전체', level: undefined },
  { id: 'critical', label: 'CRITICAL', level: 3 },
  { id: 'warning', label: 'WARNING', level: 2 },
  { id: 'info', label: 'INFO', level: 1 },
  { id: 'blocked', label: '차단됨', level: undefined },
  { id: 'block_failed', label: '차단실패', level: undefined },
];

export default function LogSearch() {
  const [tab, setTab] = useState('all');
  const [events, setEvents] = useState<LogEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState('');
  const [searchInput, setSearchInput] = useState('');
  const [dateFrom, setDateFrom] = useState('');
  const [dateTo, setDateTo] = useState('');
  const [loading, setLoading] = useState(false);
  const [sourceFilter, setSourceFilter] = useState('');

  const loadEvents = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('limit', String(PAGE_SIZE));
      params.set('offset', String(page * PAGE_SIZE));

      // Tab filters
      const tabDef = TABS.find(t => t.id === tab);
      if (tab === 'blocked') {
        params.set('q', 'KILL');
      } else if (tab === 'block_failed') {
        params.set('q', 'BLOCK_FAILED');
      } else if (tabDef?.level) {
        params.set('level', String(tabDef.level));
      }

      if (search) params.set('q', search);
      if (dateFrom) params.set('since', dateFrom + 'T00:00:00');
      if (dateTo) params.set('until', dateTo + 'T23:59:59');
      if (sourceFilter) params.set('source', sourceFilter);

      const data = await apiGet<LogResponse>(`/logs?${params}`);
      setEvents(data.events || []);
      setTotal(data.total || 0);
    } catch (e) {
      console.error('Log load error:', e);
    }
    setLoading(false);
  }, [tab, page, search, dateFrom, dateTo, sourceFilter]);

  useEffect(() => { loadEvents(); }, [loadEvents]);

  function handleSearch(e: React.FormEvent) {
    e.preventDefault();
    setSearch(searchInput);
    setPage(0);
  }

  function changeTab(t: string) {
    setTab(t);
    setPage(0);
    setSearch('');
    setSearchInput('');
  }

  const totalPages = Math.ceil(total / PAGE_SIZE);

  function eventDisplay(ev: LogEvent): string {
    if (ev.source === 'DETECTOR') return `${ev.reason}: ${ev.detail || ''}`;
    if (ev.source === 'YARA') return ev.detail || 'YARA match';
    if (ev.detail) return ev.detail;
    return `${ev.action || ''} ${ev.reason || ''} ${ev.comm || ''}`.trim();
  }

  return (
    <div className="page">
      <div className="page-header">
        <h1><Search size={22} /> 로그 조회</h1>
        <div className="toolbar">
          <button className="btn btn-sm" onClick={loadEvents} disabled={loading}>
            <RefreshCw size={14} className={loading ? 'spin' : ''}/> 새로고침
          </button>
          <button className="btn btn-sm" onClick={() => {
            downloadCSV('xdr_logs.csv', ['시간','소스','레벨','PID','프로세스','상세'],
              events.map(e => [e.timestamp, e.source, e.alert_level, e.pid, e.comm, eventDisplay(e)]));
          }}>
            <Download size={14} /> 내보내기
          </button>
        </div>
      </div>

      {/* Tabs */}
      <div className="toolbar" style={{gap: 4, marginBottom: 12}}>
        {TABS.map(t => (
          <button key={t.id}
            className={`filter-pill ${tab === t.id ? 'active' : ''}`}
            onClick={() => changeTab(t.id)}>
            {t.id === 'blocked' ? '🛑' : ''} {t.label}
          </button>
        ))}
        <span style={{flex: 1}} />
        <span style={{fontSize: 12, color: 'var(--text-dim)'}}>
          총 {total.toLocaleString()}건
        </span>
      </div>

      {/* Search + Filters */}
      <div className="card" style={{padding: 12, marginBottom: 12}}>
        <form onSubmit={handleSearch} style={{display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'end'}}>
          <div style={{flex: 2, minWidth: 200}}>
            <label style={{fontSize: 11, opacity: 0.6}}>🔍 검색 (PID, 프로세스, 키워드)</label>
            <input type="text" value={searchInput}
                   onChange={e => setSearchInput(e.target.value)}
                   placeholder="예: antigravity, 3175707, FILELESS..."
                   className="input" />
          </div>
          <div style={{minWidth: 130}}>
            <label style={{fontSize: 11, opacity: 0.6}}>📅 시작일</label>
            <input type="date" value={dateFrom} onChange={e => { setDateFrom(e.target.value); setPage(0); }} className="input" />
          </div>
          <div style={{minWidth: 130}}>
            <label style={{fontSize: 11, opacity: 0.6}}>📅 종료일</label>
            <input type="date" value={dateTo} onChange={e => { setDateTo(e.target.value); setPage(0); }} className="input" />
          </div>
          <div style={{minWidth: 100}}>
            <label style={{fontSize: 11, opacity: 0.6}}><Filter size={10} /> 소스</label>
            <select value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(0); }} className="input">
              <option value="">전체</option>
              <option value="EDR">EDR</option>
              <option value="DETECTOR">DETECTOR</option>
              <option value="YARA">YARA</option>
              <option value="SSL_PROBE">SSL_PROBE</option>
              <option value="NDR">NDR</option>
              <option value="CORRELATION">CORRELATION</option>
            </select>
          </div>
          <button type="submit" className="btn btn-primary" style={{height: 34}}>
            <Search size={14} /> 검색
          </button>
        </form>
      </div>

      {/* Results */}
      <div className="card">
        <div className="card-body" style={{maxHeight: 600, overflow: 'auto'}}>
          {loading ? (
            <div className="empty">로딩 중...</div>
          ) : events.length === 0 ? (
            <div className="empty">검색 결과가 없습니다.</div>
          ) : (
            <table className="data-table" style={{fontSize: 12}}>
              <thead>
                <tr>
                  <th style={{width: 80}}>시간</th>
                  <th style={{width: 90}}>소스</th>
                  <th style={{width: 50}}>PID</th>
                  <th style={{width: 80}}>프로세스</th>
                  <th>상세</th>
                </tr>
              </thead>
              <tbody>
                {events.map(ev => {
                  const lv = ev.alert_level || 1;
                  const cls = AC[lv] || 'info';
                  const time = ev.timestamp?.split('T')[1]?.substring(0, 8) || '';
                  const date = ev.timestamp?.split('T')[0] || '';
                  return (
                    <tr key={ev.id} className={lv >= 3 ? 'row-critical' : lv >= 2 ? 'row-warning' : ''}>
                      <td title={ev.timestamp}>
                        <div style={{fontSize: 10, opacity: 0.5}}>{date}</div>
                        <div>{time}</div>
                      </td>
                      <td>
                        <span className={`event-badge ${cls}`}>
                          {ev.source} {AL[lv] || 'INFO'}
                        </span>
                      </td>
                      <td className="mono">{ev.pid || '-'}</td>
                      <td className="mono">{ev.comm || '-'}</td>
                      <td style={{wordBreak: 'break-all', maxWidth: 400}}>{eventDisplay(ev)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        {totalPages > 1 && (
          <div style={{display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12, padding: 12, borderTop: '1px solid var(--border)'}}>
            <button className="btn btn-sm" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
              <ChevronLeft size={14} /> 이전
            </button>
            <span style={{fontSize: 12}}>
              {page + 1} / {totalPages} 페이지
            </span>
            <button className="btn btn-sm" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>
              다음 <ChevronRight size={14} />
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
