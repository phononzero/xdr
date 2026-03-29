/**
 * XDR API Client — JWT + HMAC-signed requests over TLS 1.3
 *
 * Auth flow:
 *   1. On load → check if JWT token exists in sessionStorage
 *   2. If not → redirect to login page
 *   3. On login → POST /api/auth/login with secret → store JWT
 *   4. All API calls → include Authorization: Bearer <token>
 *   5. On 401 → clear token, redirect to login
 */
const API_BASE = '/api';

// ── Token Management ────────────────────────────────────

const TOKEN_KEY = 'xdr_jwt_token';

export function getToken(): string | null {
  return sessionStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  sessionStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  sessionStorage.removeItem(TOKEN_KEY);
}

export function isAuthenticated(): boolean {
  return !!getToken();
}

// ── Auth API ────────────────────────────────────────────

export async function login(secret: string): Promise<{ success: boolean; error?: string }> {
  try {
    const res = await fetch(`${API_BASE}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret }),
    });
    const data = await res.json();
    if (res.ok && data.token) {
      setToken(data.token);
      return { success: true };
    }
    return { success: false, error: data.error || 'Login failed' };
  } catch (e) {
    return { success: false, error: 'Connection failed' };
  }
}

export async function logout(): Promise<void> {
  try {
    await fetch(`${API_BASE}/auth/logout`, {
      method: 'POST',
      headers: authHeaders(),
    });
  } catch {} // Ignore errors
  clearToken();
}

export async function checkAuth(): Promise<boolean> {
  const token = getToken();
  if (!token) return false;
  try {
    const res = await fetch(`${API_BASE}/auth/check`, {
      headers: authHeaders(),
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ── Request helpers ─────────────────────────────────────

function authHeaders(): Record<string, string> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  const token = getToken();
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  return headers;
}

async function handleResponse<T>(res: Response): Promise<T> {
  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new CustomEvent('xdr-auth-expired'));
    throw new Error('Authentication expired');
  }
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`);
  return res.json();
}

export async function apiGet<T>(path: string): Promise<T> {
  const url = `${API_BASE}${path}`;
  const res = await fetch(url, { headers: authHeaders() });
  return handleResponse<T>(res);
}

export async function apiPost<T>(path: string, data?: unknown): Promise<T> {
  const url = `${API_BASE}${path}`;
  const body = data ? JSON.stringify(data) : undefined;
  const res = await fetch(url, { method: 'POST', headers: authHeaders(), body });
  return handleResponse<T>(res);
}

export async function apiDelete<T>(path: string, data?: unknown): Promise<T> {
  const url = `${API_BASE}${path}`;
  const body = data ? JSON.stringify(data) : undefined;
  const res = await fetch(url, { method: 'DELETE', headers: authHeaders(), body });
  return handleResponse<T>(res);
}

// SSE connection for real-time events
export function connectSSE(onEvent: (data: XDREvent) => void, onStatus: (connected: boolean) => void): () => void {
  let es: EventSource | null = null;
  let retryTimer: ReturnType<typeof setTimeout> | null = null;

  function connect() {
    es = new EventSource(`${API_BASE}/stream`);
    es.onopen = () => onStatus(true);
    es.onmessage = (e) => {
      try { onEvent(JSON.parse(e.data)); } catch {}
    };
    es.onerror = () => {
      onStatus(false);
      es?.close();
      retryTimer = setTimeout(connect, 3000);
    };
  }

  connect();
  return () => { es?.close(); if (retryTimer) clearTimeout(retryTimer); };
}

// Download CSV utility
export function downloadCSV(filename: string, headers: string[], rows: (string | number)[][]) {
  const bom = '\uFEFF';
  let csv = bom + headers.join(',') + '\n';
  rows.forEach(r => {
    csv += r.map(c => '"' + String(c).replace(/"/g, '""') + '"').join(',') + '\n';
  });
  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

// Types
export interface XDREvent {
  source: string;
  event_type?: number;
  alert_level?: number;
  pid?: number;
  ppid?: number;
  ppid_comm?: string;
  comm?: string;
  filename?: string;
  cmdline?: string;
  path?: string;
  uid?: number;
  dst_ip?: string;
  dst_port?: number;
  src_ip?: string;
  src_port?: number;
  action?: string | number;
  target?: string;
  message?: string;
  reason?: string;
  mitre_id?: string;
  detail?: string;
  parent_chain?: Array<{pid: number; comm: string; path?: string}>;
  _time?: string;
  [key: string]: unknown;
}

export interface XDRStatus {
  edr_loaded: boolean;
  ndr_attached: boolean;
  engine: string;
  kernel: string;
  uptime: string;
}

export interface XDRStats {
  total: number;
  passed: number;
  dropped: number;
  critical_count?: number;
  warning_count?: number;
  event_count?: number;
}

export interface ProcessInfo {
  pid: number;
  ppid: number;
  uid: number;
  comm: string;
  exe: string;
  state: string;
  rss_kb: number;
  cmdline: string;
}

export interface ConnectionInfo {
  proto: string;
  state: string;
  local_addr: string;
  local_port: number;
  peer_addr: string;
  peer_port: number;
  pid: number;
  comm: string;
}

export interface BlocklistData {
  blocked_ips: string[];
  blocked_ports: number[];
  blocked_pids: number[];
  blocked_paths: string[];
  blocked_hashes: { hash: string; name?: string; reason?: string }[];
  known_macs: Record<string, string>;
}

export interface KernelUpdate {
  has_update: boolean;
  current: string;
  latest: string;
  last_check: string;
}
