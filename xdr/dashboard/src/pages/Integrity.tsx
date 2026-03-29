import { useState, useEffect } from 'react';
import { Shield, RefreshCw, Search, Package, FileCheck, AlertTriangle, Clock, ChevronDown, ChevronUp } from 'lucide-react';
import { apiGet, apiPost } from '../api/client';

interface IntegrityStatus {
  current_version: number;
  file_count: number;
  baseline_count: number;
  diff_count: number;
  last_scan: string;
  kernel: string;
}

interface BaselineItem {
  file: string;
  version: number;
  created: string;
  trigger: string;
  file_count: number;
}

interface DiffItem {
  file: string;
  from_version: number;
  to_version: number;
  date: string;
  modified: number;
  added: number;
  removed: number;
}

interface PkgStatus {
  current_version: number;
  total_packages: number;
  snapshot_count: number;
  diff_count: number;
  last_scan: string;
}

interface PkgDiff {
  file: string;
  from_version: number;
  to_version: number;
  date: string;
  added: number;
  removed: number;
  upgraded: number;
  downgraded: number;
}

interface TimelineEntry {
  date: string;
  action: string;
  package: string;
  version: string;
}

export default function Integrity() {
  const [tab, setTab] = useState<'integrity' | 'packages'>('integrity');
  const [intStatus, setIntStatus] = useState<IntegrityStatus | null>(null);
  const [baselines, setBaselines] = useState<BaselineItem[]>([]);
  const [intDiffs, setIntDiffs] = useState<DiffItem[]>([]);
  const [pkgStatus, setPkgStatus] = useState<PkgStatus | null>(null);
  const [pkgDiffs, setPkgDiffs] = useState<PkgDiff[]>([]);
  const [timeline, setTimeline] = useState<TimelineEntry[]>([]);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<Record<string, unknown> | null>(null);
  const [expandedBaseline, setExpandedBaseline] = useState<number | null>(null);
  const [expandedDiff, setExpandedDiff] = useState<number | null>(null);
  const [baselineDetail, setBaselineDetail] = useState<Record<string, any> | null>(null);
  const [diffDetail, setDiffDetail] = useState<Record<string, any> | null>(null);

  useEffect(() => { reload(); }, []);

  async function reload() {
    try {
      const [is, bl, id, ps, pd, tl] = await Promise.all([
        apiGet<IntegrityStatus>('/integrity/status'),
        apiGet<BaselineItem[]>('/integrity/baselines'),
        apiGet<DiffItem[]>('/integrity/diffs'),
        apiGet<PkgStatus>('/packages/status'),
        apiGet<PkgDiff[]>('/packages/diffs'),
        apiGet<TimelineEntry[]>('/packages/timeline'),
      ]);
      setIntStatus(is);
      setBaselines(bl);
      setIntDiffs(id);
      setPkgStatus(ps);
      setPkgDiffs(pd);
      setTimeline(tl);
    } catch (e) {
      console.error('Load error:', e);
    }
  }

  async function runIntegrityScan() {
    setScanning(true);
    setScanResult(null);
    try {
      const r = await apiPost<Record<string, unknown>>('/integrity/scan', {});
      setScanResult(r);
      reload();
    } catch (e) {
      console.error('Scan error:', e);
    } finally {
      setScanning(false);
    }
  }

  async function runPkgScan() {
    setScanning(true);
    setScanResult(null);
    try {
      const r = await apiPost<Record<string, unknown>>('/packages/scan', {});
      setScanResult(r);
      reload();
    } catch (e) {
      console.error('Scan error:', e);
    } finally {
      setScanning(false);
    }
  }

  async function updateBaseline() {
    if (!confirm('현재 시스템 상태를 새 기준선으로 승인합니다. 계속하시겠습니까?')) return;
    setScanning(true);
    try {
      await apiPost('/integrity/update-baseline', {});
      reload();
    } catch (e) {
      console.error('Update error:', e);
    } finally {
      setScanning(false);
    }
  }

  async function loadBaselineDetail(filename: string, version: number) {
    if (expandedBaseline === version) {
      setExpandedBaseline(null); setBaselineDetail(null); return;
    }
    setExpandedBaseline(version); setBaselineDetail(null);
    try {
      const d = await apiGet<Record<string, any>>(`/integrity/baseline-detail/${filename}`);
      setBaselineDetail(d);
    } catch (e) { console.error(e); }
  }

  async function loadDiffDetail(filename: string, idx: number) {
    if (expandedDiff === idx) {
      setExpandedDiff(null); setDiffDetail(null); return;
    }
    setExpandedDiff(idx); setDiffDetail(null);
    try {
      const d = await apiGet<Record<string, any>>(`/integrity/diff-detail/${filename}`);
      setDiffDetail(d);
    } catch (e) { console.error(e); }
  }

  const fmtDate = (s: string) => {
    if (!s) return '-';
    try {
      return new Date(s).toLocaleString('ko-KR');
    } catch { return s; }
  };

  return (
    <div className="page">
      <div className="page-header">
        <h1><Shield size={22} /> 무결성 감시</h1>
        <div className="toolbar">
          <button className={`filter-pill ${tab === 'integrity' ? 'active' : ''}`}
                  onClick={() => setTab('integrity')}>
            <FileCheck size={12} /> 파일 해시
          </button>
          <button className={`filter-pill ${tab === 'packages' ? 'active' : ''}`}
                  onClick={() => setTab('packages')}>
            <Package size={12} /> 패키지
          </button>
          <button className="btn" onClick={reload}>
            <RefreshCw size={14} /> 새로고침
          </button>
        </div>
      </div>

      {scanResult && (
        <div className={`setting-saved ${(scanResult as Record<string, unknown>).unexplained ? 'scan-warning' : ''}`}>
          {(scanResult as Record<string, unknown>).status === 'clean'
            ? '✅ 모든 파일 무결성 확인 — 변조 없음'
            : (scanResult as Record<string, unknown>).status === 'unchanged'
            ? '✅ 패키지 변경 없음'
            : `⚠️ 변경 감지: 수정 ${(scanResult as Record<string, unknown>).modified || 0}, 추가 ${(scanResult as Record<string, unknown>).added || 0}, 제거 ${(scanResult as Record<string, unknown>).removed || 0}`
          }
        </div>
      )}

      {tab === 'integrity' ? (
        <>
          {/* Integrity Stats */}
          <div className="stats-grid">
            <div className="stat-card accent">
              <div className="stat-label">기준선 버전</div>
              <div className="stat-value">{intStatus?.current_version || 0}</div>
            </div>
            <div className="stat-card success">
              <div className="stat-label">감시 파일 수</div>
              <div className="stat-value">{intStatus?.file_count || 0}</div>
            </div>
            <div className="stat-card warning">
              <div className="stat-label">변경 이력</div>
              <div className="stat-value">{intStatus?.diff_count || 0}</div>
            </div>
            <div className="stat-card">
              <div className="stat-label">커널</div>
              <div className="stat-value" style={{fontSize: 14}}>{intStatus?.kernel || '-'}</div>
            </div>
          </div>

          {/* Actions */}
          <div className="settings-section">
            <h2><Search size={18} /> 해시 무결성 스캔</h2>
            <p className="settings-desc">
              현재 시스템 바이너리 해시를 기준선과 비교합니다.
              rkhunter처럼 /usr/bin, /usr/sbin, /boot 등 주요 파일의 SHA256을 검증합니다.
            </p>
            <div className="toolbar" style={{gap: 8}}>
              <button className="btn btn-primary" onClick={runIntegrityScan} disabled={scanning}>
                {scanning ? <RefreshCw size={14} className="spin" /> : <Search size={14} />}
                {scanning ? '스캔 중...' : '즉시 스캔'}
              </button>
              <button className="btn" onClick={updateBaseline} disabled={scanning}>
                <FileCheck size={14} /> 기준선 갱신
              </button>
            </div>
            <p className="settings-desc" style={{marginTop: 8, marginBottom: 0}}>
              마지막 스캔: {fmtDate(intStatus?.last_scan || '')}
            </p>
          </div>

          {/* Baselines */}
          <div className="settings-section">
            <h2><Clock size={18} /> 기준선 이력 (삭제 불가)</h2>
            {baselines.length === 0 ? (
              <div className="empty">아직 기준선이 없습니다. '즉시 스캔'을 눌러 초기 기준선을 생성하세요.</div>
            ) : (
              <div className="card">
                <div className="card-body">
                  <table className="data-table">
                    <thead><tr>
                      <th>버전</th><th>생성일</th><th>트리거</th><th>파일 수</th><th></th>
                    </tr></thead>
                    <tbody>
                      {baselines.map(b => (
                        <>
                        <tr key={b.version}
                            style={{cursor: 'pointer'}}
                            onClick={() => loadBaselineDetail(b.file, b.version)}>
                          <td><span className="mono">v{b.version}</span></td>
                          <td>{fmtDate(b.created)}</td>
                          <td><span className="event-badge info">{b.trigger}</span></td>
                          <td>{b.file_count}</td>
                          <td>{expandedBaseline === b.version ? <ChevronUp size={14}/> : <ChevronDown size={14}/>}</td>
                        </tr>
                        {expandedBaseline === b.version && baselineDetail && (
                          <tr><td colSpan={5} style={{padding: 0}}>
                            <div style={{maxHeight: 300, overflow: 'auto', background: 'var(--bg-secondary)', padding: '8px 12px'}}>
                              <table className="data-table" style={{fontSize: 11}}>
                                <thead><tr><th>파일 경로</th><th>SHA256</th><th>수정일</th><th>크기</th></tr></thead>
                                <tbody>
                                  {Object.entries(baselineDetail.entries || {}).map(([path, info]: [string, any]) => (
                                    <tr key={path}>
                                      <td className="mono" style={{maxWidth: 250, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}} title={path}>{path}</td>
                                      <td className="mono" style={{fontSize: 10, color: 'var(--accent)'}}>{info.sha256?.substring(0, 16)}...</td>
                                      <td>{fmtDate(info.mtime)}</td>
                                      <td>{info.size ? `${(info.size / 1024).toFixed(0)}KB` : '-'}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          </td></tr>
                        )}
                        </>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>

          {/* Diffs */}
          {intDiffs.length > 0 && (
            <div className="settings-section">
              <h2><AlertTriangle size={18} /> 변경 이력 (diff)</h2>
              <div className="card">
                <div className="card-body">
                  <table className="data-table">
                    <thead><tr>
                      <th>날짜</th><th>변경</th><th>수정</th><th>추가</th><th>제거</th>
                    </tr></thead>
                    <tbody>
                      {intDiffs.map((d, i) => (
                        <>
                        <tr key={i} style={{cursor: 'pointer'}} onClick={() => loadDiffDetail(d.file, i)}>
                          <td>{fmtDate(d.date)}</td>
                          <td><span className="mono">v{d.from_version}→v{d.to_version}</span></td>
                          <td style={{color: d.modified > 0 ? 'var(--warning)' : ''}}>{d.modified}</td>
                          <td style={{color: d.added > 0 ? 'var(--success)' : ''}}>{d.added}</td>
                          <td style={{color: d.removed > 0 ? 'var(--critical)' : ''}}>{d.removed}</td>
                        </tr>
                        {expandedDiff === i && diffDetail && (
                          <tr><td colSpan={5} style={{padding: 0}}>
                            <div style={{maxHeight: 300, overflow: 'auto', background: 'var(--bg-secondary)', padding: '8px 12px'}}>
                              {Object.keys(diffDetail.changes?.modified || {}).length > 0 && (<>
                                <h4 style={{margin: '4px 0', color: 'var(--warning)'}}>⚠️ 수정된 파일</h4>
                                <table className="data-table" style={{fontSize: 11}}>
                                  <thead><tr><th>파일</th><th>이전 해시</th><th>현재 해시</th></tr></thead>
                                  <tbody>
                                    {Object.entries(diffDetail.changes.modified).map(([path, info]: [string, any]) => (
                                      <tr key={path}>
                                        <td className="mono" title={path} style={{maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap'}}>{path}</td>
                                        <td className="mono" style={{fontSize: 10, color: 'var(--critical)'}}>{info.old_hash?.substring(0, 16)}...</td>
                                        <td className="mono" style={{fontSize: 10, color: 'var(--success)'}}>{info.new_hash?.substring(0, 16)}...</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </>)}
                              {Object.keys(diffDetail.changes?.added || {}).length > 0 && (<>
                                <h4 style={{margin: '8px 0 4px', color: 'var(--success)'}}>+ 추가된 파일</h4>
                                {Object.keys(diffDetail.changes.added).map(p => <div key={p} className="mono" style={{fontSize: 11}}>{p}</div>)}
                              </>)}
                              {Object.keys(diffDetail.changes?.removed || {}).length > 0 && (<>
                                <h4 style={{margin: '8px 0 4px', color: 'var(--critical)'}}>- 제거된 파일</h4>
                                {Object.keys(diffDetail.changes.removed).map(p => <div key={p} className="mono" style={{fontSize: 11}}>{p}</div>)}
                              </>)}
                            </div>
                          </td></tr>
                        )}
                        </>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}
        </>
      ) : (
        <>
          {/* Package Stats */}
          <div className="stats-grid">
            <div className="stat-card accent">
              <div className="stat-label">스냅샷 버전</div>
              <div className="stat-value">{pkgStatus?.current_version || 0}</div>
            </div>
            <div className="stat-card success">
              <div className="stat-label">설치된 패키지</div>
              <div className="stat-value">{pkgStatus?.total_packages || 0}</div>
            </div>
            <div className="stat-card warning">
              <div className="stat-label">변경 이력</div>
              <div className="stat-value">{pkgStatus?.diff_count || 0}</div>
            </div>
          </div>

          {/* Package scan */}
          <div className="settings-section">
            <h2><Package size={18} /> 패키지 스캔</h2>
            <p className="settings-desc">
              현재 설치된 패키지를 이전 스냅샷과 비교합니다.
              추가/제거/업그레이드/다운그레이드를 감지합니다.
            </p>
            <button className="btn btn-primary" onClick={runPkgScan} disabled={scanning}>
              {scanning ? <RefreshCw size={14} className="spin" /> : <Search size={14} />}
              {scanning ? '스캔 중...' : '패키지 스캔'}
            </button>
            <p className="settings-desc" style={{marginTop: 8, marginBottom: 0}}>
              마지막 스캔: {fmtDate(pkgStatus?.last_scan || '')}
            </p>
          </div>

          {/* Package Diffs */}
          {pkgDiffs.length > 0 && (
            <div className="settings-section">
              <h2><AlertTriangle size={18} /> 패키지 변경 이력</h2>
              <div className="card">
                <div className="card-body">
                  <table className="data-table">
                    <thead><tr>
                      <th>날짜</th><th>변경</th><th>추가</th><th>제거</th><th>업그레이드</th><th>다운그레이드</th>
                    </tr></thead>
                    <tbody>
                      {pkgDiffs.map((d, i) => (
                        <tr key={i}>
                          <td>{fmtDate(d.date)}</td>
                          <td><span className="mono">v{d.from_version}→v{d.to_version}</span></td>
                          <td style={{color: d.added > 0 ? 'var(--success)' : ''}}>{d.added}</td>
                          <td style={{color: d.removed > 0 ? 'var(--critical)' : ''}}>{d.removed}</td>
                          <td style={{color: d.upgraded > 0 ? 'var(--accent)' : ''}}>{d.upgraded}</td>
                          <td style={{color: d.downgraded > 0 ? 'var(--critical)' : ''}}>{d.downgraded}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          )}

          {/* Timeline */}
          {timeline.length > 0 && (
            <div className="settings-section">
              <h2><Clock size={18} /> 패키지 타임라인</h2>
              <div className="card">
                <div className="card-body" style={{maxHeight: 400}}>
                  {timeline.slice(0, 50).map((t, i) => (
                    <div key={i} className={`event-item ${t.action === 'downgrade' ? 'critical' : t.action === 'remove' ? 'warning' : 'info'}`}>
                      <div className="event-time">{fmtDate(t.date)}</div>
                      <div>
                        <span className={`event-badge ${t.action === 'downgrade' ? 'critical' : t.action === 'remove' ? 'warning' : 'info'}`}>
                          {t.action}
                        </span>
                      </div>
                      <div className="event-detail">
                        <strong>{t.package}</strong> {t.version}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
