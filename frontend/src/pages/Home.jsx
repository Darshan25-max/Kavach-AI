import { Link } from 'react-router-dom'
import { Shield, Search, Code2, GitBranch, Zap, Brain, Lock, ArrowRight, CheckCircle } from 'lucide-react'

const features = [
  {
    icon: Search,
    title: 'Code Scanner',
    description: 'Upload or paste code to detect vulnerabilities with AI-powered deep analysis. Get detailed reports with severity ratings and fix suggestions.',
    link: '/scanner',
    color: 'from-blue-500 to-cyan-500',
  },
  {
    icon: Code2,
    title: 'Live Code Review',
    description: 'Real-time security analysis as you type. Like a spell-checker for code security, catching vulnerabilities before they ship.',
    link: '/live-review',
    color: 'from-purple-500 to-pink-500',
  },
  {
    icon: GitBranch,
    title: 'Repo Security Audit',
    description: 'Analyze entire GitHub repositories for security issues. Get a comprehensive security score and per-file vulnerability breakdown.',
    link: '/repo-audit',
    color: 'from-green-500 to-emerald-500',
  },
]

const highlights = [
  { icon: Brain, text: 'AI-Powered Analysis' },
  { icon: Zap, text: 'Instant Vulnerability Detection' },
  { icon: Lock, text: 'CWE-Mapped Security Rules' },
  { icon: CheckCircle, text: 'Actionable Fix Suggestions' },
]

export default function Home() {
  return (
    <div className="relative">
      {/* Hero Section */}
      <section className="relative overflow-hidden">
        {/* Background Effects */}
        <div className="absolute inset-0 overflow-hidden">
          <div className="absolute top-1/4 -left-20 w-80 h-80 bg-kavach-500/10 rounded-full blur-3xl" />
          <div className="absolute bottom-1/4 -right-20 w-80 h-80 bg-purple-500/10 rounded-full blur-3xl" />
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-kavach-500/5 rounded-full blur-3xl" />
        </div>

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-24">
          <div className="text-center">
            {/* Shield Logo */}
            <div className="flex justify-center mb-8">
              <div className="animate-float">
                <div className="relative">
                  <Shield className="w-20 h-20 text-kavach-400" strokeWidth={1.5} />
                  <div className="absolute inset-0 flex items-center justify-center">
                    <Brain className="w-8 h-8 text-kavach-300" />
                  </div>
                  <div className="absolute inset-0 rounded-full glow-pulse" />
                </div>
              </div>
            </div>

            {/* Title */}
            <h1 className="text-5xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight mb-6">
              <span className="bg-gradient-to-r from-kavach-400 via-blue-300 to-purple-400 bg-clip-text text-transparent">
                KavachAI
              </span>
            </h1>

            <p className="text-xl sm:text-2xl text-slate-300 font-light mb-4">
              AI Powered Code Security Platform
            </p>

            <p className="text-base sm:text-lg text-slate-500 max-w-2xl mx-auto mb-10">
              Detect vulnerabilities, get AI-powered fix suggestions, and secure your codebase
              with intelligent security analysis.
            </p>

            {/* CTA Buttons */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16">
              <Link to="/scanner" className="btn-primary flex items-center gap-2 text-lg px-8 py-3">
                Start Scanning
                <ArrowRight className="w-5 h-5" />
              </Link>
              <Link to="/live-review" className="btn-secondary flex items-center gap-2 text-lg px-8 py-3">
                Try Live Review
              </Link>
            </div>

            {/* Highlights */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 max-w-3xl mx-auto">
              {highlights.map(({ icon: Icon, text }) => (
                <div key={text} className="flex items-center gap-2 text-sm text-slate-400">
                  <Icon className="w-4 h-4 text-kavach-400 flex-shrink-0" />
                  <span>{text}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 bg-slate-900/30">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold mb-4">
              Three Powerful Security Tools
            </h2>
            <p className="text-lg text-slate-400 max-w-2xl mx-auto">
              Everything you need to find and fix security vulnerabilities in your code
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {features.map(({ icon: Icon, title, description, link, color }) => (
              <Link
                key={title}
                to={link}
                className="card hover:border-slate-600 group transition-all duration-300 hover:-translate-y-1"
              >
                <div className={`w-12 h-12 rounded-xl bg-gradient-to-br ${color} flex items-center justify-center mb-4 opacity-80 group-hover:opacity-100 transition-opacity`}>
                  <Icon className="w-6 h-6 text-white" />
                </div>
                <h3 className="text-xl font-semibold mb-3 group-hover:text-kavach-400 transition-colors">
                  {title}
                </h3>
                <p className="text-slate-400 text-sm leading-relaxed mb-4">
                  {description}
                </p>
                <div className="flex items-center text-kavach-400 text-sm font-medium group-hover:gap-2 transition-all">
                  Get Started
                  <ArrowRight className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform" />
                </div>
              </Link>
            ))}
          </div>
        </div>
      </section>

      {/* How It Works */}
      <section className="py-20">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center mb-16">
            <h2 className="text-3xl sm:text-4xl font-bold mb-4">
              How It Works
            </h2>
            <p className="text-lg text-slate-400">
              Three steps to secure your code
            </p>
          </div>

          <div className="grid md:grid-cols-3 gap-8">
            {[
              { step: '01', title: 'Submit Code', desc: 'Paste your code, upload a file, or connect a GitHub repository' },
              { step: '02', title: 'AI Analysis', desc: 'Our AI engine scans for vulnerabilities using pattern matching and deep analysis' },
              { step: '03', title: 'Fix Issues', desc: 'Get detailed reports with severity ratings and actionable fix suggestions' },
            ].map(({ step, title, desc }) => (
              <div key={step} className="text-center">
                <div className="text-5xl font-black text-kavach-500/20 mb-4">{step}</div>
                <h3 className="text-xl font-semibold mb-2">{title}</h3>
                <p className="text-slate-400 text-sm">{desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>
    </div>
  )
}
