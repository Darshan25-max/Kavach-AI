import { useState, useRef } from 'react'
import {
  Search, Upload, AlertTriangle, CheckCircle, Download,
  Loader2, ChevronDown, ChevronUp, FileCode, MapPin,
  Wrench, Bug, ShieldAlert, Info
} from 'lucide-react'
import { scanApi } from '../services/api'

const LANGUAGES = [
  { value: null, label: 'Auto Detect' },
  { value: 'python', label: 'Python' },
  { value: 'javascript', label: 'JavaScript' },
  { value: 'typescript', label: 'TypeScript' },
  { value: 'java', label: 'Java' },
  { value: 'php', label: 'PHP' },
  { value: 'ruby', label: 'Ruby' },
  { value: 'go', label: 'Go' },
  { value: 'rust', label: 'Rust' },
  { value: 'csharp', label: 'C#' },
  { value: 'c', label: 'C' },
  { value: 'cpp', label: 'C++' },
  { value: 'sql', label: 'SQL' },
]

const SEVERITY = {
  critical: {
    badge: 'bg-red-500/15 text-red-400 border-red-500/30',
    left:   'border-l-red-500',
    glow:   'shadow-[0_0_12px_rgba(239,68,68,0.15)]',
    dot:    'bg-red-500',
  },
  high: {
    badge: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    left:  'border-l-orange-500',
    glow:  'shadow-[0_0_12px_rgba(249,115,22,0.12)]',
    dot:   'bg-orange-500',
  },
  medium: {
    badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    left:  'border-l-amber-500',
    glow:  '',
    dot:   'bg-amber-500',
  },
  low: {
    badge: 'bg-green-500/15 text-green-400 border-green-500/30',
    left:  'border-l-green-500',
    glow:  '',
    dot:   'bg-green-500',
  },
  info: {
    badge: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
    left:  'border-l-blue-500',
    glow:  '',
    dot:   'bg-blue-500',
  },
}

const isBug = (vuln) =>
  vuln.category?.startsWith('Bug-') || vuln.issue_type === 'BUG'

function IssueCard({ vuln, idx, expanded, onToggle }) {
  const sev = SEVERITY[vuln.severity] || SEVERITY.info
  const bug = isBug(vuln)

  return (
    <div
      className={`rounded-xl border border-slate-700/60 border-l-4 ${sev.left} bg-slate-900/70 overflow-hidden transition-all duration-200 ${sev.glow}`}
    >
      {/* ── Always-visible header ── */}
      <div className="p-4">
        {/* Top row: badges + expand toggle */}
        <div className="flex items-start justify-between gap-3 mb-2">
          <div className="flex flex-wrap items-center gap-2">
            {/* Type badge */}
            <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wide ${
              bug
                ? 'bg-purple-500/15 text-purple-400 border-purple-500/30'
                : 'bg-kavach-500/15 text-kavach-400 border-kavach-500/30'
            }`}>
              {bug ? <Bug size={9} /> : <ShieldAlert size={9} />}
              {bug ? 'Bug' : 'Security'}
            </span>

            {/* Severity badge */}
            <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border uppercase tracking-wide ${sev.badge}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${sev.dot}`} />
              {vuln.severity}
            </span>

            {/* CWE */}
            {vuln.cwe_id && (
              <span className="text-[10px] text-slate-500 font-mono bg-slate-800 px-1.5 py-0.5 rounded">
                {vuln.cwe_id}
              </span>
            )}
          </div>

          <button
            onClick={onToggle}
            className="text-slate-500 hover:text-slate-300 transition-colors flex-shrink-0 mt-0.5"
          >
            {expanded ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
          </button>
        </div>

        {/* Title */}
        <h4 className="text-sm font-semibold text-white leading-snug mb-2">
          {vuln.title}
        </h4>

        {/* ── Always visible: description + line ── */}
        <p className="text-xs text-slate-400 leading-relaxed mb-2">
          {vuln.description}
        </p>

        {vuln.line_number && (
          <div className="inline-flex items-center gap-1.5 text-[11px] text-slate-500 bg-slate-800/60 px-2 py-1 rounded-md">
            <MapPin size={10} className="text-kavach-400" />
            <span>Line <strong className="text-slate-300">{vuln.line_number}</strong></span>
          </div>
        )}
      </div>

      {/* ── Expandable: code snippet + fix ── */}
      {expanded && (
        <div className="px-4 pb-4 space-y-3 border-t border-slate-700/40 pt-3">
          {vuln.code_snippet && (
            <div>
              <p className="text-[10px] text-slate-500 uppercase tracking-wide font-semibold mb-1.5 flex items-center gap-1">
                <FileCode size={10} /> Affected Code
              </p>
              <pre className="bg-black/40 border border-slate-700/50 rounded-lg p-3 text-xs font-mono text-slate-300 overflow-x-auto leading-relaxed whitespace-pre-wrap">
                {vuln.code_snippet}
              </pre>
            </div>
          )}

          {vuln.fix_suggestion && (
            <div className="bg-green-500/5 border border-green-500/20 rounded-lg p-3">
              <p className="text-[10px] text-green-400 uppercase tracking-wide font-semibold mb-1.5 flex items-center gap-1">
                <Wrench size={10} /> How to Fix
              </p>
              <p className="text-xs text-slate-300 leading-relaxed whitespace-pre-wrap">
                {vuln.fix_suggestion}
              </p>
            </div>
          )}

          {vuln.category && (
            <span className="inline-block text-[10px] bg-slate-800 text-slate-500 px-2 py-0.5 rounded font-mono">
              {vuln.category}
            </span>
          )}
        </div>
      )}
    </div>
  )
}

export default function ScannerPage() {
  const [code, setCode] = useState('')
  const [language, setLanguage] = useState(null)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [expandedVuln, setExpandedVuln] = useState(null)
  const [activeTab, setActiveTab] = useState('all')
  const fileInputRef = useRef(null)

  const handleFileUpload = (e) => {
    const file = e.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = (ev) => {
      setCode(ev.target.result)
      const ext = file.name.split('.').pop()?.toLowerCase()
      const langMap = { py: 'python', js: 'javascript', ts: 'typescript', java: 'java', php: 'php', rb: 'ruby', go: 'go', rs: 'rust', cs: 'csharp', c: 'c', cpp: 'cpp', sql: 'sql' }
      if (ext && langMap[ext]) setLanguage(langMap[ext])
    }
    reader.readAsText(file)
  }

  const handleScan = async () => {
    if (!code.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)
    setExpandedVuln(null)
    setActiveTab('all')

    try {
      const response = await scanApi.submitScan(code, language)
      const scanId = response.data.id

      const pollInterval = setInterval(async () => {
        try {
          const pollRes = await scanApi.getScan(scanId)
          const data = pollRes.data
          if (data.status === 'completed') {
            setResult(data)
            setLoading(false)
            clearInterval(pollInterval)
          } else if (data.status === 'failed') {
            setError('Scan failed. Please try again.')
            setLoading(false)
            clearInterval(pollInterval)
          }
        } catch {
          clearInterval(pollInterval)
          setLoading(false)
          setError('Failed to fetch scan results')
        }
      }, 2000)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to submit scan')
      setLoading(false)
    }
  }

  const exportReport = () => {
    if (!result) return
    const report = {
      scan_id: result.id,
      language: result.language,
      timestamp: result.created_at,
      total_vulnerabilities: result.total_vulnerabilities,
      severity_breakdown: {
        critical: result.critical_count,
        high: result.high_count,
        medium: result.medium_count,
        low: result.low_count,
      },
      vulnerabilities: result.vulnerabilities,
    }
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `kavachai-scan-${result.id}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  // Tab filtering
  const allVulns = result?.vulnerabilities || []
  const secVulns = allVulns.filter(v => !isBug(v))
  const bugVulns = allVulns.filter(v => isBug(v))
  const visibleVulns = activeTab === 'security' ? secVulns : activeTab === 'bugs' ? bugVulns : allVulns

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Search className="w-8 h-8 text-kavach-400" />
          Code Vulnerability Scanner
        </h1>
        <p className="text-slate-400 mt-2">
          Paste or upload code to detect security vulnerabilities and bugs with AI-powered analysis
        </p>
      </div>

      <div className="grid lg:grid-cols-2 gap-8">
        {/* ── Left: Input ── */}
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <select
              value={language || ''}
              onChange={(e) => setLanguage(e.target.value || null)}
              className="input-field text-sm"
            >
              {LANGUAGES.map(({ value, label }) => (
                <option key={label} value={value || ''}>{label}</option>
              ))}
            </select>
            <button onClick={() => fileInputRef.current?.click()} className="btn-secondary flex items-center gap-2 text-sm">
              <Upload className="w-4 h-4" />
              Upload File
            </button>
            <input ref={fileInputRef} type="file"
              accept=".py,.js,.ts,.jsx,.tsx,.java,.php,.rb,.go,.rs,.cs,.c,.cpp,.sql"
              className="hidden" onChange={handleFileUpload} />
          </div>

          <div className="relative">
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Paste your code here..."
              className="w-full h-[500px] bg-slate-900 border border-slate-700 rounded-xl p-4 text-sm font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-kavach-500 focus:border-transparent resize-none"
              spellCheck={false}
            />
            {code && (
              <div className="absolute bottom-3 right-3 text-xs text-slate-500 bg-slate-800 px-2 py-1 rounded">
                {code.split('\n').length} lines
              </div>
            )}
          </div>

          <button
            onClick={handleScan}
            disabled={!code.trim() || loading}
            className="btn-primary w-full flex items-center justify-center gap-2 py-3 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? (
              <><Loader2 className="w-5 h-5 animate-spin" /> Scanning...</>
            ) : (
              <><Search className="w-5 h-5" /> Scan Code</>
            )}
          </button>
        </div>

        {/* ── Right: Results ── */}
        <div className="space-y-4">
          {/* Loading */}
          {loading && (
            <div className="card flex flex-col items-center justify-center h-[500px]">
              <div className="relative mb-4">
                <Shield className="w-16 h-16 text-kavach-400/30" />
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="w-8 h-8 border-2 border-kavach-400 border-t-transparent rounded-full animate-spin" />
                </div>
              </div>
              <p className="text-slate-400">Analyzing code for vulnerabilities and bugs...</p>
              <p className="text-xs text-slate-500 mt-1">This may take a few seconds</p>
            </div>
          )}

          {/* Error */}
          {error && (
            <div className="card border-red-500/30 bg-red-500/5">
              <div className="flex items-center gap-3 text-red-400">
                <AlertTriangle className="w-5 h-5" />
                <p>{error}</p>
              </div>
            </div>
          )}

          {/* Results */}
          {result && (
            <>
              {/* Summary card */}
              <div className="card">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="font-semibold flex items-center gap-2">
                    <FileCode className="w-5 h-5 text-kavach-400" />
                    Scan Results
                    <span className="text-xs text-slate-500 font-normal">· {result.language}</span>
                  </h3>
                  <button onClick={exportReport} className="btn-secondary text-xs flex items-center gap-1 px-3 py-1.5">
                    <Download className="w-3 h-3" /> Export
                  </button>
                </div>

                {/* Severity counts */}
                <div className="grid grid-cols-4 gap-2 mb-4">
                  {[
                    { label: 'Critical', count: result.critical_count, color: 'text-red-400',    bg: 'bg-red-500/10' },
                    { label: 'High',     count: result.high_count,     color: 'text-orange-400', bg: 'bg-orange-500/10' },
                    { label: 'Medium',   count: result.medium_count,   color: 'text-amber-400',  bg: 'bg-amber-500/10' },
                    { label: 'Low',      count: result.low_count,      color: 'text-green-400',  bg: 'bg-green-500/10' },
                  ].map(({ label, count, color, bg }) => (
                    <div key={label} className={`${bg} rounded-lg p-3 text-center`}>
                      <div className={`text-2xl font-bold ${color}`}>{count}</div>
                      <div className="text-xs text-slate-400">{label}</div>
                    </div>
                  ))}
                </div>

                {/* Type counts */}
                <div className="flex items-center gap-4 text-xs text-slate-400 pt-3 border-t border-slate-700/50">
                  <span className="flex items-center gap-1.5">
                    <ShieldAlert size={12} className="text-kavach-400" />
                    <span><strong className="text-white">{secVulns.length}</strong> security issues</span>
                  </span>
                  <span className="flex items-center gap-1.5">
                    <Bug size={12} className="text-purple-400" />
                    <span><strong className="text-white">{bugVulns.length}</strong> bugs</span>
                  </span>
                  <span className="ml-auto">
                    Total: <strong className="text-white">{result.total_vulnerabilities}</strong>
                  </span>
                </div>
              </div>

              {/* Tabs */}
              {allVulns.length > 0 && (
                <div className="flex gap-1 p-1 bg-slate-800/50 rounded-xl border border-slate-700/50">
                  {[
                    { id: 'all',      label: 'All',      count: allVulns.length },
                    { id: 'security', label: 'Security', count: secVulns.length },
                    { id: 'bugs',     label: 'Bugs',     count: bugVulns.length },
                  ].map(tab => (
                    <button
                      key={tab.id}
                      onClick={() => { setActiveTab(tab.id); setExpandedVuln(null) }}
                      className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 px-3 rounded-lg text-xs font-medium transition-all ${
                        activeTab === tab.id
                          ? 'bg-kavach-600 text-white'
                          : 'text-slate-400 hover:text-white'
                      }`}
                    >
                      {tab.label}
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-full ${
                        activeTab === tab.id ? 'bg-white/20' : 'bg-slate-700'
                      }`}>
                        {tab.count}
                      </span>
                    </button>
                  ))}
                </div>
              )}

              {/* Issue list */}
              <div className="space-y-2 max-h-[520px] overflow-y-auto pr-1">
                {allVulns.length === 0 ? (
                  <div className="card flex items-center gap-3 text-green-400">
                    <CheckCircle className="w-6 h-6" />
                    <p>No issues detected! Your code looks clean.</p>
                  </div>
                ) : visibleVulns.length === 0 ? (
                  <div className="card text-center text-slate-500 text-sm py-8">
                    No {activeTab} issues found.
                  </div>
                ) : (
                  visibleVulns.map((vuln, idx) => (
                    <IssueCard
                      key={vuln.id || idx}
                      vuln={vuln}
                      idx={idx}
                      expanded={expandedVuln === idx}
                      onToggle={() => setExpandedVuln(expandedVuln === idx ? null : idx)}
                    />
                  ))
                )}
              </div>
            </>
          )}

          {/* Empty state */}
          {!loading && !error && !result && (
            <div className="card flex flex-col items-center justify-center h-[500px] text-center">
              <Search className="w-12 h-12 text-slate-600 mb-4" />
              <p className="text-slate-400">Paste your code and click Scan to start analysis</p>
              <p className="text-xs text-slate-500 mt-2">
                Detects security vulnerabilities and bugs across 12+ languages
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function Shield(props) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.5} {...props}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}