import { useState, useEffect, useRef } from 'react'
import { Shield, Eye, EyeOff, Loader2, AlertTriangle } from 'lucide-react'
import { login } from '../api/client'

interface LoginPageProps {
  onLogin: () => void
}

export default function LoginPage({ onLogin }: LoginPageProps) {
  const [secret, setSecret] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [shake, setShake] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    inputRef.current?.focus()
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!secret.trim()) {
      setError('API 시크릿을 입력하세요')
      setShake(true)
      setTimeout(() => setShake(false), 500)
      return
    }

    setLoading(true)
    setError('')

    const result = await login(secret.trim())

    setLoading(false)
    if (result.success) {
      onLogin()
    } else {
      setError(result.error || '인증 실패')
      setShake(true)
      setTimeout(() => setShake(false), 500)
      setSecret('')
      inputRef.current?.focus()
    }
  }

  return (
    <div className="login-page">
      <div className={`login-card ${shake ? 'shake' : ''}`}>
        <div className="login-header">
          <div className="login-icon">
            <Shield size={40} />
          </div>
          <h1>XDR 보안 대시보드</h1>
          <p className="login-subtitle">Endpoint & Network Detection and Response</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="input-group">
            <label htmlFor="secret">API 시크릿</label>
            <div className="input-wrapper">
              <input
                ref={inputRef}
                id="secret"
                type={showSecret ? 'text' : 'password'}
                value={secret}
                onChange={e => setSecret(e.target.value)}
                placeholder="API 시크릿 키를 입력하세요"
                autoComplete="off"
                spellCheck={false}
                disabled={loading}
              />
              <button
                type="button"
                className="toggle-visibility"
                onClick={() => setShowSecret(!showSecret)}
                tabIndex={-1}
              >
                {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {error && (
            <div className="login-error">
              <AlertTriangle size={14} />
              <span>{error}</span>
            </div>
          )}

          <button type="submit" className="login-button" disabled={loading}>
            {loading ? (
              <>
                <Loader2 size={16} className="spinner" />
                인증 중...
              </>
            ) : (
              '로그인'
            )}
          </button>
        </form>

        <div className="login-footer">
          <p>시크릿 위치: <code>/opt/xdr/xdr-core/.api_secret</code></p>
          <p>이 시크릿은 서버 첫 실행 시 자동 생성됩니다</p>
        </div>
      </div>
    </div>
  )
}
