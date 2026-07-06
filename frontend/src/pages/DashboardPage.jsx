import { useState, useEffect } from 'react'
import { LayoutDashboard, AlertTriangle, Shield, FileCode, Loader2, ChevronRight } from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip } from 'recharts'
import { scanApi } from '../services/api'

const COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#22c55e',
  info: '#3b82f6',
}

export default function DashboardPage() {
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [selectedScan, setSelectedScan] = useState(null)

  useEffect(() => {
    loadScans()
  }, [])

  const loadScans = async () => {
    try {
      const res = await scanApi.getScans(1, 50)
      setScans(res.data.scans || [])
    } catch {
      setScans([])
    } finally {
      setLoading(false)
    }
  }

  const handleScanClick = async (scanId) => {
    try {
      const res = await scanApi.getScan(scanId)
      setSelectedScan(res.data)
    } catch {
      // ignore
    }
  }

  // Stats
  const totalScans = scans.length
  const totalVulns = scans.reduce((sum, s) => sum + s.total_vulnerabilities, 0)
  const criticalIssues = scans.reduce((sum, s) => sum + s.critical_count, 0)
  const highIssues = scans.reduce((sum, s) => sum + s.high_count, 0)

  // Severity distribution for pie chart
  const severityData = [
    { name: 'Critical', value: scans.reduce((s, v) => s + v.critical_count, 0), color: COLORS.critical },
    { name: 'High', value: scans.reduce((s, v) => s + v.high_count, 0), color: COLORS.high },
    { name: 'Medium', value: scans.reduce((s, v) => s + v.medium_count, 0), color: COLORS.medium },
    { name: 'Low', value: scans.reduce((s, v) => s + v.low_count, 0), color: COLORS.low },
  ].filter(d => d.value > 0)

  // Scan timeline data
  const timelineData = [...scans].reverse().map((s, i) => ({
    name: `#${s.id}`,
    vulnerabilities: s.total_vulnerabilities,
    critical: s.critical_count,
  }))

  const formatDate = (dateStr) => {
    try {
      return new Date(dateStr).toLocaleDateString('en-US', {
        month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit'
      })
    } catch {
      return dateStr
    }
  }

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex items-center justify-center h-96">
        <Loader2 className="w-8 h-8 animate-spin text-kavach-400" />
      </div>
    )
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
      {/* Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-3">
          <LayoutDashboard className="w-8 h-8 text-green-400" />
          Dashboard
        </h1>
        <p className="text-slate-400 mt-2">Overview of your code security scans</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        {[
          { label: 'Total Scans', value: totalScans, icon: FileCode, color: 'text-kavach-400', bg: 'bg-kavach-500/10' },
          { label: 'Vulnerabilities', value: totalVulns, icon: AlertTriangle, color: 'text-amber-400', bg: 'bg-amber-500/10' },
          { label: 'Critical Issues', value: criticalIssues, icon: Shield, color: 'text-red-400', bg: 'bg-red-500/10' },
          { label: 'High Issues', value: highIssues, icon: AlertTriangle, color: 'text-orange-400', bg: 'bg-orange-500/10' },
        ].map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="card">
            <div className="flex items-center justify-between mb-3">
              <span className="text-sm text-slate-400">{label}</span>
              <div className={`w-8 h-8 rounded-lg ${bg} flex items-center justify-center`}>
                <Icon className={`w-4 h-4 ${color}`} />
              </div>
            </div>
            <div className={`text-3xl font-bold ${color}`}>{value}</div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-8 mb-8">
        {/* Severity Distribution */}
        <div className="card">
          <h3 className="font-semibold mb-4">Severity Distribution</h3>
          {severityData.length > 0 ? (
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                  itemStyle={{ color: '#f1f5f9' }}
                />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[200px] flex items-center justify-center text-slate-500 text-sm">
              No scan data yet
            </div>
          )}
          <div className="flex flex-wrap gap-3 mt-2">
            {severityData.map(({ name, color }) => (
              <div key={name} className="flex items-center gap-1.5 text-xs text-slate-400">
                <div className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: color }} />
                {name}
              </div>
            ))}
          </div>
        </div>

        {/* Vulnerabilities Over Time */}
        <div className="card lg:col-span-2">
          <h3 className="font-semibold mb-4">Vulnerabilities Over Time</h3>
          {timelineData.length > 0 ? (
            <ResponsiveContainer width="100%" height={230}>
              <LineChart data={timelineData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="name" stroke="#64748b" fontSize={12} />
                <YAxis stroke="#64748b" fontSize={12} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '8px' }}
                  itemStyle={{ color: '#f1f5f9' }}
                />
                <Line type="monotone" dataKey="vulnerabilities" stroke="#3b82f6" strokeWidth={2} dot={{ fill: '#3b82f6' }} />
                <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={{ fill: '#ef4444' }} />
              </LineChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[230px] flex items-center justify-center text-slate-500 text-sm">
              No scan data yet. Run your first scan to see trends.
            </div>
          )}
        </div>
      </div>

      {/* Scan History */}
      <div className="card">
        <h3 className="font-semibold mb-4">Scan History</h3>
        {scans.length === 0 ? (
          <div className="py-12 text-center text-slate-500">
            <FileCode className="w-12 h-12 mx-auto mb-3 text-slate-600" />
            <p>No scans yet</p>
            <p className="text-xs text-slate-600 mt-1">Go to the Scanner page to run your first scan</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">ID</th>
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">Language</th>
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">Status</th>
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">Date</th>
                  <th className="text-center py-3 px-4 text-slate-400 font-medium">Critical</th>
                  <th className="text-center py-3 px-4 text-slate-400 font-medium">High</th>
                  <th className="text-center py-3 px-4 text-slate-400 font-medium">Medium</th>
                  <th className="text-center py-3 px-4 text-slate-400 font-medium">Low</th>
                  <th className="text-right py-3 px-4 text-slate-400 font-medium"></th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => (
                  <tr
                    key={scan.id}
                    className="border-b border-slate-800 hover:bg-slate-800/30 transition-colors"
                  >
                    <td className="py-3 px-4 font-mono text-kavach-400">#{scan.id}</td>
                    <td className="py-3 px-4 capitalize">{scan.language}</td>
                    <td className="py-3 px-4">
                      <span className={`px-2 py-0.5 rounded-full text-xs ${
                        scan.status === 'completed'
                          ? 'bg-green-500/10 text-green-400'
                          : scan.status === 'scanning'
                            ? 'bg-kavach-500/10 text-kavach-400'
                            : scan.status === 'failed'
                              ? 'bg-red-500/10 text-red-400'
                              : 'bg-slate-500/10 text-slate-400'
                      }`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-400">{formatDate(scan.created_at)}</td>
                    <td className="py-3 px-4 text-center">
                      <span className={scan.critical_count > 0 ? 'text-red-400 font-semibold' : 'text-slate-500'}>
                        {scan.critical_count}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={scan.high_count > 0 ? 'text-orange-400 font-semibold' : 'text-slate-500'}>
                        {scan.high_count}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={scan.medium_count > 0 ? 'text-amber-400 font-semibold' : 'text-slate-500'}>
                        {scan.medium_count}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={scan.low_count > 0 ? 'text-green-400' : 'text-slate-500'}>
                        {scan.low_count}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-right">
                      <button
                        onClick={() => handleScanClick(scan.id)}
                        className="text-kavach-400 hover:text-kavach-300 transition-colors"
                      >
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Selected Scan Detail */}
      {selectedScan && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setSelectedScan(null)}
        >
          <div className="bg-slate-800 border border-slate-700 rounded-2xl max-w-2xl w-full max-h-[80vh] overflow-y-auto p-6"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold">Scan #{selectedScan.id} Details</h3>
              <button onClick={() => setSelectedScan(null)} className="text-slate-400 hover:text-white">x</button>
            </div>
            <div className="grid grid-cols-4 gap-3 mb-4">
              <div className="bg-red-500/10 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-red-400">{selectedScan.critical_count}</div>
                <div className="text-xs text-slate-400">Critical</div>
              </div>
              <div className="bg-orange-500/10 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-orange-400">{selectedScan.high_count}</div>
                <div className="text-xs text-slate-400">High</div>
              </div>
              <div className="bg-amber-500/10 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-amber-400">{selectedScan.medium_count}</div>
                <div className="text-xs text-slate-400">Medium</div>
              </div>
              <div className="bg-green-500/10 rounded-lg p-3 text-center">
                <div className="text-2xl font-bold text-green-400">{selectedScan.low_count}</div>
                <div className="text-xs text-slate-400">Low</div>
              </div>
            </div>
            <div className="space-y-3">
              {(selectedScan.vulnerabilities || []).map((vuln, idx) => (
                <div key={idx} className="bg-slate-700/30 rounded-lg p-3 border border-slate-700">
                  <div className="flex items-center gap-2 mb-1">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-semibold border uppercase ${
                      vuln.severity === 'critical' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                      vuln.severity === 'high' ? 'bg-orange-500/10 text-orange-400 border-orange-500/30' :
                      vuln.severity === 'medium' ? 'bg-amber-500/10 text-amber-400 border-amber-500/30' :
                      'bg-green-500/10 text-green-400 border-green-500/30'
                    }`}>{vuln.severity}</span>
                    <span className="font-medium text-sm">{vuln.title}</span>
                  </div>
                  <p className="text-xs text-slate-400">{vuln.description}</p>
                  {vuln.fix_suggestion && (
                    <p className="text-xs text-kavach-400 mt-1">Fix: {vuln.fix_suggestion}</p>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
