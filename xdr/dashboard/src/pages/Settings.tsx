import { useState, useEffect } from 'react';
import { Settings, Shield, ShieldAlert, Sun, Moon, Download, ToggleLeft, ToggleRight } from 'lucide-react';
import { apiGet, apiPost, downloadCSV } from '../api/client';

interface Policy {
  [key: string]: unknown;
  auto_block: boolean;
  auto_block_memfd: boolean | null;
  auto_block_lolbins: boolean | null;
  auto_block_ptrace: boolean | null;
  auto_block_sequence: boolean | null;
  auto_block_container_escape: boolean | null;
  auto_block_rootkit: boolean | null;
  auto_block_lateral: boolean | null;
  lolbins_whitelist: string[];
  ptrace_whitelist: string[];
  allowed_modules: string[];
  scan_threshold: number;
  lateral_whitelist: string[];
}

const DETECTOR_LABELS: Record<string, { name: string; desc: string; icon: string }> = {
  auto_block_memfd: { name: '파일리스 탐지', desc: 'memfd_create, /proc/*/fd 실행 차단', icon: '🧬' },
  auto_block_lolbins: { name: 'LOLBins 탐지', desc: '시스템 바이너리 남용 (40+종 규칙)', icon: '🔧' },
  auto_block_ptrace: { name: 'Ptrace 감시', desc: '비부모 프로세스 인젝션 차단', icon: '🔬' },
  auto_block_sequence: { name: '시퀀스 탐지', desc: '행위 연쇄 패턴 (드롭퍼, 리버스쉘)', icon: '🔗' },
  auto_block_container_escape: { name: '컨테이너 탈출', desc: 'namespace/cgroup/docker socket 감시', icon: '📦' },
  auto_block_rootkit: { name: '커널 루트킷', desc: '모듈 화이트리스트, sysctl 변조 감지', icon: '🦠' },
  auto_block_lateral: { name: '횡이동 탐지', desc: '내부 포트 스캔, SSH/SMB 다중 접속', icon: '🌐' },
};

export default function SettingsPage() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saved, setSaved] = useState(false);

  useEffect(() => { loadPolicy(); }, []);

  async function loadPolicy() {
    try {
      const data = await apiGet<Policy>('/policy');
      setPolicy(data);
    } catch (e) {
      console.error('Policy load error:', e);
    } finally {
      setLoading(false);
    }
  }

  async function updateField(key: string, value: boolean | null) {
    if (!policy) return;
    setSaving(true);
    try {
      const updated = await apiPost<Policy>('/policy', { [key]: value });
      setPolicy(updated);
      setSaved(true);
      setTimeout(() => setSaved(false), 2000);
    } catch (e) {
      console.error('Policy update error:', e);
    } finally {
      setSaving(false);
    }
  }

  function getEffective(key: string): boolean {
    if (!policy) return false;
    const val = policy[key];
    if (val === null || val === undefined) return policy.auto_block;
    return val as boolean;
  }

  function handleDownload() {
    if (!policy) return;
    const headers = ['항목', '상태', '유효값'];
    const rows = [
      ['전체 자동차단', policy.auto_block ? 'ON' : 'OFF', ''],
      ...Object.keys(DETECTOR_LABELS).map(key => [
        DETECTOR_LABELS[key].name,
        policy[key] === null ? '전체 따름' :
          policy[key] ? 'ON' : 'OFF',
        getEffective(key) ? '차단' : '알람'
      ]),
    ];
    downloadCSV('xdr_policy.csv', headers, rows);
  }

  if (loading) return <div className="page-loading">로딩 중...</div>;
  if (!policy) return <div className="page-loading">정책 로드 실패</div>;

  return (
    <div className="page">
      <div className="page-header">
        <h1><Settings size={22} /> 설정</h1>
        <button className="btn btn-ghost" onClick={handleDownload}>
          <Download size={14} /> 다운로드
        </button>
      </div>

      {saved && (
        <div className="setting-saved">✅ 저장 완료</div>
      )}

      {/* Global Auto-Block */}
      <div className="settings-section">
        <h2><ShieldAlert size={18} /> 전체 자동차단 정책</h2>
        <p className="settings-desc">
          활성화 시 탐지된 위협을 자동으로 차단(SIGKILL/DROP)합니다.
          비활성화 시 알람만 발송합니다.
        </p>
        <div className="setting-row global-toggle">
          <div className="setting-info">
            <span className="setting-name">
              {policy.auto_block ? <Shield size={16} className="icon-on" /> : <Shield size={16} />}
              전체 자동차단
            </span>
            <span className={`setting-badge ${policy.auto_block ? 'badge-danger' : 'badge-safe'}`}>
              {policy.auto_block ? '⚡ 자동차단 ON' : '🔔 알람만'}
            </span>
          </div>
          <button
            className={`toggle-btn ${policy.auto_block ? 'toggle-on' : 'toggle-off'}`}
            onClick={() => updateField('auto_block', !policy.auto_block)}
            disabled={saving}
          >
            {policy.auto_block ? <ToggleRight size={28} /> : <ToggleLeft size={28} />}
          </button>
        </div>
      </div>

      {/* Per-Detector Toggles */}
      <div className="settings-section">
        <h2><ShieldAlert size={18} /> 개별 탐지기 설정</h2>
        <p className="settings-desc">
          NULL = 전체 정책을 따름. 개별적으로 ON/OFF 설정하면 전체 정책을 덮어씁니다.
        </p>
        <div className="detector-grid">
          {Object.entries(DETECTOR_LABELS).map(([key, label]) => {
            const val = policy[key];
            const effective = getEffective(key);
            return (
              <div key={key} className={`detector-card ${effective ? 'active-block' : ''}`}>
                <div className="detector-header">
                  <span className="detector-icon">{label.icon}</span>
                  <span className="detector-name">{label.name}</span>
                </div>
                <p className="detector-desc">{label.desc}</p>
                <div className="detector-status">
                  <span className={`status-pill ${effective ? 'pill-danger' : 'pill-safe'}`}>
                    {effective ? '차단' : '알람'}
                  </span>
                  <span className="status-source">
                    {val === null ? '(전체 따름)' : '(개별 설정)'}
                  </span>
                </div>
                <div className="detector-actions">
                  <button
                    className={`det-btn ${val === true ? 'det-active' : ''}`}
                    onClick={() => updateField(key, true)}
                    disabled={saving}
                  >차단</button>
                  <button
                    className={`det-btn ${val === false ? 'det-active' : ''}`}
                    onClick={() => updateField(key, false)}
                    disabled={saving}
                  >알람</button>
                  <button
                    className={`det-btn ${val === null ? 'det-active' : ''}`}
                    onClick={() => updateField(key, null)}
                    disabled={saving}
                  >전체 따름</button>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
