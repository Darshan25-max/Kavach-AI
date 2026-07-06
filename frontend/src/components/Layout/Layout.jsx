import { Outlet, NavLink } from 'react-router-dom'
import { Shield, Search, Code2, LayoutDashboard, GitBranch, Menu, X } from 'lucide-react'
import { useState } from 'react'

const navItems = [
  { to: '/', label: 'Home', icon: Shield },
  { to: '/scanner', label: 'Scanner', icon: Search },
  { to: '/live-review', label: 'Live Review', icon: Code2 },
  { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { to: '/repo-audit', label: 'Repo Audit', icon: GitBranch },
]

export default function Layout() {
  const [mobileOpen, setMobileOpen] = useState(false)

  return (
    <div className="min-h-screen flex flex-col">
      {/* Navbar */}
      <nav className="sticky top-0 z-50 bg-kavach-950/80 backdrop-blur-xl border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            {/* Logo */}
            <NavLink to="/" className="flex items-center gap-3 group">
              <div className="w-9 h-9 rounded-lg bg-kavach-500/20 border border-kavach-500/40 flex items-center justify-center group-hover:bg-kavach-500/30 transition-all">
                <Shield className="w-5 h-5 text-kavach-400" />
              </div>
              <div>
                <span className="text-lg font-bold bg-gradient-to-r from-kavach-400 to-blue-300 bg-clip-text text-transparent">
                  KavachAI
                </span>
                <p className="text-[10px] text-slate-500 leading-none mt-0.5">
                  Detect vulnerabilities before attackers do.
                </p>
              </div>
            </NavLink>

            {/* Desktop Nav */}
            <div className="hidden md:flex items-center gap-1">
              {navItems.map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === '/'}
                  className={({ isActive }) =>
                    `flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-all ${
                      isActive
                        ? 'bg-kavach-500/15 text-kavach-400'
                        : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                    }`
                  }
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </NavLink>
              ))}
            </div>

            {/* Mobile menu button */}
            <button
              className="md:hidden p-2 text-slate-400 hover:text-white"
              onClick={() => setMobileOpen(!mobileOpen)}
            >
              {mobileOpen ? <X className="w-6 h-6" /> : <Menu className="w-6 h-6" />}
            </button>
          </div>
        </div>

        {/* Mobile Nav */}
        {mobileOpen && (
          <div className="md:hidden border-t border-slate-800 bg-kavach-950/95 backdrop-blur-xl">
            <div className="px-4 py-3 space-y-1">
              {navItems.map(({ to, label, icon: Icon }) => (
                <NavLink
                  key={to}
                  to={to}
                  end={to === '/'}
                  onClick={() => setMobileOpen(false)}
                  className={({ isActive }) =>
                    `flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                      isActive
                        ? 'bg-kavach-500/15 text-kavach-400'
                        : 'text-slate-400 hover:text-white hover:bg-slate-800/50'
                    }`
                  }
                >
                  <Icon className="w-4 h-4" />
                  {label}
                </NavLink>
              ))}
            </div>
          </div>
        )}
      </nav>

      {/* Main Content */}
      <main className="flex-1">
        <Outlet />
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-kavach-950/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-kavach-500" />
              <span className="text-sm text-slate-500">KavachAI — Detect Bugs before attackers do.</span>
            </div>
            <div className="text-xs text-slate-600">
              Securing code with AI intelligence
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
