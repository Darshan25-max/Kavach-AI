import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout/Layout'
import Home from './pages/Home'
import ScannerPage from './pages/ScannerPage'
import LiveReviewPage from './pages/LiveReviewPage'
import DashboardPage from './pages/DashboardPage'
import RepoAuditPage from './pages/RepoAuditPage'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Home />} />
        <Route path="scanner" element={<ScannerPage />} />
        <Route path="live-review" element={<LiveReviewPage />} />
        <Route path="dashboard" element={<DashboardPage />} />
        <Route path="repo-audit" element={<RepoAuditPage />} />
      </Route>
    </Routes>
  )
}

export default App
