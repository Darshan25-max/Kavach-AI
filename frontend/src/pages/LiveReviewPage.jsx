import { useState, useCallback, useRef } from 'react'
import Editor from '@monaco-editor/react'
import { Code2, Loader2, AlertTriangle, CheckCircle, Shield } from 'lucide-react'
import { scanApi } from '../services/api'

const LANGUAGES = [
  { value: 'python', label: 'Python', monaco: 'python' },
  { value: 'javascript', label: 'JavaScript', monaco: 'javascript' },
  { value: 'typescript', label: 'TypeScript', monaco: 'typescript' },
  { value: 'java', label: 'Java', monaco: 'java' },
  { value: 'php', label: 'PHP', monaco: 'php' },
  { value: 'go', label: 'Go', monaco: 'go' },
  { value: 'rust', label: 'Rust', monaco: 'rust' },
  { value: 'csharp', label: 'C#', monaco: 'csharp' },
  { value: 'c', label: 'C', monaco: 'c' },
  { value: 'cpp', label: 'C++', monaco: 'cpp' },
  { value: 'sql', label: 'SQL', monaco: 'sql' },
  { value: 'ruby', label: 'Ruby', monaco: 'ruby' },
]

const SeverityBadge = ({ severity }) => {
  const config = {
    critical: 'bg-red-500/15 text-red-400 border-red-500/30',
    high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
    medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
    low: 'bg-green-500/15 text-green-400 border-green-500/30',
    info: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  }
  return (
    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border uppercase tracking-wider ${config[severity] || config.info}`}>
      {severity}
    </span>
  )
}

const ScoreBadge = ({ score }) => {
  const colors = {
    A: 'text-green-400 bg-green-500/15 border-green-500/30',
    B: 'text-blue-400 bg-blue-500/15 border-blue-500/30',
    C: 'text-amber-400 bg-amber-500/15 border-amber-500/30',
    D: 'text-orange-400 bg-orange-500/15 border-orange-500/30',
    F: 'text-red-400 bg-red-500/15 border-red-500/30',
  }
  return (
    <div className={`px-4 py-2 rounded-xl border text-3xl font-black ${colors[score] || 'text-slate-400 bg-slate-500/15 border-slate-500/30'}`}>
      {score}
    </div>
  )
}

export default function LiveReviewPage() {
  const [language, setLanguage] = useState('python')
  const [code, setCode] = useState('# Write your code here...\n# Security issues will be detected in real-time\n')
  const [issues, setIssues] = useState([])
  const [loading, setLoading] = useState(false)
  const [score, setScore] = useState(null)
  const debounceRef = useRef(null)

  const selectedLang = LANGUAGES.find(l => l.value === language)

  const analyzeCode = useCallback(async (codeValue, lang) => {
    if (!codeValue.trim() || codeValue.trim().length < 10) {
      setIssues([])
      setScore(null)
      return
    }

    setLoading(true)
    try {
      const res = await scanApi.liveReview(codeValue, lang)
      setIssues(res.data.issues || [])
      setScore(res.data.overall_score)
    } catch {
      setIssues([])
      setScore(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleEditorChange = useCallback((value) => {
    setCode(value || '')
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      analyzeCode(value || '', language)
    }, 1500)
  }, [language, analyzeCode])

  const handleLanguageChange = (e) => {
    const newLang = e.target.value
    setLanguage(newLang)
    if (code.trim()) {
      analyzeCode(code, newLang)
    }
  }

  // Map issues to Monaco markers format
  const getMarkers = () => {
    return issues.map(issue => ({
      severity: issue.severity === 'critical' || issue.severity === 'high' ? 'error' : 'warning',
      startLineNumber: issue.line || 1,
      startColumn: 1,
      endLineNumber: issue.line || 1,
      endColumn: 1000,
      message: issue.message,
    }))
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <Code2 className="w-8 h-8 text-purple-400" />
          Live Code Review
        </h1>
        <p className="text-slate-400 mt-2">
          Real-time security analysis as you type - like a spell-checker for code security
        </p>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-4 mb-4">
        <select
          value={language}
          onChange={handleLanguageChange}
          className="input-field text-sm"
        >
          {LANGUAGES.map(({ value, label }) => (
            <option key={value} value={value}>{label}</option>
          ))}
        </select>
        <div className="flex items-center gap-2 text-sm">
          {loading && <Loader2 className="w-4 h-4 animate-spin text-kavach-400" />}
          <span className="text-slate-500">
            {issues.length > 0 ? `${issues.length} issues found` : 'No issues detected'}
          </span>
        </div>
        {score && (
          <div className="ml-auto flex items-center gap-3">
            <span className="text-sm text-slate-400">Security Score:</span>
            <ScoreBadge score={score} />
          </div>
        )}
      </div>

      {/* Editor + Issues Panel */}
      <div className="grid lg:grid-cols-3 gap-4">
        {/* Monaco Editor */}
        <div className="lg:col-span-2 border border-slate-700 rounded-xl overflow-hidden">
          <Editor
            height="600px"
            language={selectedLang?.monaco || 'plaintext'}
            value={code}
            onChange={handleEditorChange}
            theme="vs-dark"
            options={{
              minimap: { enabled: false },
              fontSize: 14,
              fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
              lineNumbers: 'on',
              scrollBeyondLastLine: false,
              automaticLayout: true,
              padding: { top: 16 },
            }}
            onMount={(editor, monaco) => {
              // Update markers when issues change
              const updateMarkers = () => {
                const markers = getMarkers()
                const model = editor.getModel()
                if (model) {
                  monaco.editor.setModelMarkers(model, 'kavachai', markers)
                }
              }
              // Initial setup
              updateMarkers()
            }}
          />
        </div>

        {/* Issues Panel */}
        <div className="border border-slate-700 rounded-xl bg-slate-800/30 overflow-hidden">
          <div className="p-4 border-b border-slate-700">
            <h3 className="font-semibold text-sm flex items-center gap-2">
              <Shield className="w-4 h-4 text-kavach-400" />
              Security Issues
            </h3>
          </div>
          <div className="p-4 space-y-3 max-h-[548px] overflow-y-auto">
            {issues.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-center">
                <CheckCircle className="w-10 h-10 text-green-500/50 mb-3" />
                <p className="text-sm text-slate-500">No security issues detected</p>
                <p className="text-xs text-slate-600 mt-1">Start typing to get live feedback</p>
              </div>
            ) : (
              issues.map((issue, idx) => (
                <div
                  key={idx}
                  className={`rounded-lg border p-3 cursor-pointer hover:bg-slate-700/30 transition-colors ${
                    issue.severity === 'critical' || issue.severity === 'high'
                      ? 'border-red-500/20 bg-red-500/5'
                      : 'border-slate-700 bg-slate-800/50'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1.5">
                    <SeverityBadge severity={issue.severity} />
                    <span className="text-xs text-slate-500 font-mono">Line {issue.line}</span>
                  </div>
                  <p className="text-sm text-slate-300">{issue.message}</p>
                  {issue.suggestion && (
                    <p className="text-xs text-kavach-400 mt-1.5">Fix: {issue.suggestion}</p>
                  )}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
