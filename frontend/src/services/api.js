import axios from 'axios'

const API_BASE = '/api'

const api = axios.create({
  baseURL: API_BASE,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 120000, // 2 min timeout for AI analysis
})

// Scan API
export const scanApi = {
  submitScan: (code, language = null) =>
    api.post('/scan', { code, language }),

  getScan: (scanId) =>
    api.get(`/scan/${scanId}`),

  getScans: (page = 1, pageSize = 20) =>
    api.get('/scans', { params: { page, page_size: pageSize } }),

  liveReview: (code, language = null) =>
    api.post('/live-review', { code, language }),
}

// Repository API
export const repoApi = {
  analyzeRepo: (repoUrl) =>
    api.post('/repo/analyze', { repo_url: repoUrl }),

  getRepoAudit: (repoScanId) =>
    api.get(`/repo/${repoScanId}`),

  getRepoStatus: (repoScanId) =>
    api.get(`/repo/${repoScanId}/status`),
}

// Health API
export const healthApi = {
  check: () => api.get('/health'),
}

export default api
