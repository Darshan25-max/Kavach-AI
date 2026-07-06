import { useState, useEffect, useRef } from 'react'
import { GitBranch, Search, Loader2, Shield, FileCode, AlertTriangle, CheckCircle, Folder } from 'lucide-react'
import { repoApi } from '../services/api'

const ScoreBadge = ({ score }) => {
  const colors = {
    A: 'text-green-400 bg-green-500/15 border-green-500/30',
    B: 'text-blue-400 bg-blue-500/15 border-blue-500/30',
    C: 'text-amber-400 bg-amber-500/15 border-amber-500/30',
    D: 'text-orange-400 bg-orange-500/15 border-orange-500/30',
    F: 'text-red-400 bg-red-500/15 border-red-500/30',
  }
  return (
    <div className={`px-6 py-3 rounded-xl border text-4xl font-black ${colors[score] || 'text-slate-400 bg-slate-500/15 border-slate-500/30'}`}>
      {score}
    </div>
  )
}

const SeverityCount = ({ label, count, color }) => (
  <div className={`${color}/10 rounded-lg p-3 text-center`}>
    <div className={`text-2xl font-bold ${color}`}>{count}</div>
    <div className="text-xs text-slate-400">{label}</div>
  </div>
)

export default function RepoAuditPage() {
  const [repoUrl, setRepoUrl] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [expandedFile, setExpandedFile] = useState(null)
  const pollRef = useRef(null)

  useEffect(() => {
    return () => {
      if (pollRef.current) clearInterval(pollRef.current)
    }
  }, [])

  const handleAnalyze = async () => {
    if (!repoUrl.trim()) return
    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const res = await repoApi.analyzeRepo(repoUrl)
      const repoScanId = res.data.id

      // Poll for results
      pollRef.current = setInterval(async () => {
        try {
          const statusRes = await repoApi.getRepoStatus(repoScanId)
          const status = statusRes.data

          if (status.status === 'completed') {
            const detailRes = await repoApi.getRepoAudit(repoScanId)
            setResult(detailRes.data)
            setLoading(false)
            clearInterval(pollRef.current)
          } else if (status.status === 'failed') {
            setError('Repository audit failed. Please try again.')
            setLoading(false)
            clearInterval(pollRef.current)
          }
        } catch {
          clearInterval(pollRef.current)
          setLoading(false)
          setError('Failed to fetch audit results')
        }
      }, 3000)
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to start repository audit')
      setLoading(false)
    }
  }

  const parseIssues = (issuesStr) => {
    try {
      return JSON.parse(issuesStr)
    } catch {
      return []
    }
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <GitBranch className="w-8 h-8 text-emerald-400" />
          Repository Security Audit
        </h1>
        <p className="text-slate-400 mt-2">
          Analyze GitHub repositories for security vulnerabilities with comprehensive reporting
        </p>
      </div>

      {/* URL Input */}
      <div className="card mb-8">
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1">
            <label className="block text-sm text-slate-400 mb-2">GitHub Repository URL</label>
            <input
              type="text"
              value={repoUrl}
              onChange={(e) => setRepoUrl(e.target.value)}
              placeholder="https://github.com/username/repository"
              className="input-field w-full"
              onKeyDown={(e) => e.key === 'Enter' && handleAnalyze()}
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={handleAnalyze}
              disabled={!repoUrl.trim() || loading}
              className="btn-primary flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" />
                  Analyze
                </>
              )}
            </button>
          </div>
        </div>
      </div>

      {/* Loading State */}
      {loading && (
        <div className="card flex flex-col items-center justify-center py-16">
          <div className="relative mb-6">
            <Shield className="w-20 h-20 text-kavach-400/30" />
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-10 h-10 border-3 border-kavach-400 border-t-transparent rounded-full animate-spin" />
            </div>
          </div>
          <h3 className="text-lg font-semibold mb-2">Analyzing Repository...</h3>
          <p className="text-slate-400 text-sm">Scanning files for security vulnerabilities</p>
          <div className="mt-4 w-64 h-2 bg-slate-700 rounded-full overflow-hidden">
            <div className="h-full bg-kavach-500 rounded-full animate-pulse" style={{ width: '60%' }} />
          </div>
        </div>
      )}

      {/* Error State */}
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
        <div className="space-y-6">
          {/* Overview */}
          <div className="card">
            <div className="flex flex-col md:flex-row items-start md:items-center gap-6">
              {/* Security Score */}
              <div className="text-center">
                <div className="text-xs text-slate-400 mb-2">Security Score</div>
                <ScoreBadge score={result.security_score || 'N/A'} />
              </div>

              {/* Stats */}
              <div className="flex-1 grid grid-cols-2 sm:grid-cols-4 gap-3">
                <SeverityCount label="Critical" count={result.critical_count} color="text-red-400" />
                <SeverityCount label="High" count={result.high_count} color="text-orange-400" />
                <SeverityCount label="Medium" count={result.medium_count} color="text-amber-400" />
                <SeverityCount label="Low" count={result.low_count} color="text-green-400" />
              </div>

              {/* Summary */}
              <div className="text-right">
                <div className="text-2xl font-bold">{result.total_vulnerabilities}</div>
                <div className="text-xs text-slate-400">Total Vulnerabilities</div>
                <div className="text-sm text-slate-500 mt-1">{result.total_files} files scanned</div>
              </div>
            </div>
          </div>

          {/* File Tree */}
          <div className="card">
            <h3 className="font-semibold mb-4 flex items-center gap-2">
              <Folder className="w-5 h-5 text-kavach-400" />
              File Results
            </h3>
            <div className="space-y-2">
              {result.file_results.map((file, idx) => {
                const issues = parseIssues(file.issues)
                const isExpanded = expandedFile === idx

                return (
                  <div key={file.id || idx} className="border border-slate-700 rounded-lg overflow-hidden">
                    <button
                      className="w-full flex items-center justify-between p-3 hover:bg-slate-700/30 transition-colors"
                      onClick={() => setExpandedFile(isExpanded ? null : idx)}
                    >
                      <div className="flex items-center gap-3">
                        <FileCode className="w-4 h-4 text-slate-400" />
                        <span className="text-sm font-mono">{file.file_path}</span>
                        <span className="text-xs text-slate-500">({file.language})</span>
                      </div>
                      <div className="flex items-center gap-3">
                        {file.vulnerability_count > 0 ? (
                          <span className="px-2 py-0.5 rounded-full text-xs bg-red-500/10 text-red-400 border border-red-500/30">
                            {file.vulnerability_count} issues
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-xs text-green-400">
                            <CheckCircle className="w-3 h-3" />
                            Clean
                          </span>
                        )}
                      </div>
                    </button>

                    {isExpanded && issues.length > 0 && (
                      <div className="border-t border-slate-700 p-3 bg-slate-800/30 space-y-2">
                        {issues.map((issue, issueIdx) => (
                          <div key={issueIdx} className="flex items-start gap-3 py-2 border-b border-slate-800 last:border-0">
                            <span className={`mt-0.5 px-1.5 py-0.5 rounded text-xs font-semibold uppercase ${
                              issue.severity === 'critical' ? 'bg-red-500/10 text-red-400' :
                              issue.severity === 'high' ? 'bg-orange-500/10 text-orange-400' :
                              issue.severity === 'medium' ? 'bg-amber-500/10 text-amber-400' :
                              'bg-green-500/10 text-green-400'
                            }`}>
                              {issue.severity}
                            </span>
                            <div className="flex-1">
                              <div className="text-sm font-medium">{issue.title}</div>
                              <div className="text-xs text-slate-400 mt-0.5">{issue.description}</div>
                              {issue.line_number && (
                                <div className="text-xs text-slate-500 mt-1">Line {issue.line_number}</div>
                              )}
                              {issue.fix_suggestion && (
                                <div className="text-xs text-kavach-400 mt-1">Fix: {issue.fix_suggestion}</div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!loading && !error && !result && (
        <div className="card flex flex-col items-center justify-center py-16 text-center">
          <GitBranch className="w-16 h-16 text-slate-600 mb-4" />
          <h3 className="text-lg font-semibold text-slate-400 mb-2">No Repository Analyzed</h3>
          <p className="text-sm text-slate-500 max-w-md">
            Enter a GitHub repository URL above to start a comprehensive security audit.
            We'll scan all source files for vulnerabilities and provide a detailed report.
          </p>
        </div>
      )}
    </div>
  )
}
