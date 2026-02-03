import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion } from 'motion/react'
import { Shield, Menu, X } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useAuth } from '@/hooks/useAuth'

export function Nav() {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const navigate = useNavigate()
  const { user } = useAuth()

  return (
    <motion.nav
      initial={{ opacity: 0, y: -20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5 }}
      className="fixed top-0 left-0 right-0 z-50 bg-[#0a0f1a]/80 backdrop-blur-xl border-b border-slate-800/50"
    >
      <div className="max-w-6xl mx-auto px-6">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <button
            onClick={() => navigate('/')}
            className="flex items-center gap-2 hover:opacity-80 transition-opacity"
          >
            <div className="p-1.5 rounded-lg bg-cyan-500/10">
              <Shield className="h-5 w-5 text-cyan-400" />
            </div>
            <span className="text-lg font-bold text-white">Rock PSOC</span>
          </button>

          {/* Desktop navigation */}
          <div className="hidden md:flex items-center gap-8">
            <a
              href="#features"
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              Features
            </a>
            <a
              href="#timeline"
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              Threat Timeline
            </a>
            <a
              href="#pricing"
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              Pricing
            </a>
            <a
              href="#compliance"
              className="text-sm text-slate-400 hover:text-white transition-colors"
            >
              Compliance
            </a>
          </div>

          {/* Auth buttons */}
          <div className="hidden md:flex items-center gap-3">
            {user ? (
              <Button
                onClick={() => navigate('/app')}
                size="sm"
                className="bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-medium"
              >
                Dashboard
              </Button>
            ) : (
              <>
                <Button
                  onClick={() => navigate('/auth')}
                  variant="ghost"
                  size="sm"
                  className="text-slate-400 hover:text-white hover:bg-slate-800"
                >
                  Sign In
                </Button>
                <Button
                  onClick={() => navigate('/auth')}
                  size="sm"
                  className="bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-medium"
                >
                  Get Started
                </Button>
              </>
            )}
          </div>

          {/* Mobile menu button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            className="md:hidden p-2 text-slate-400 hover:text-white"
          >
            {mobileMenuOpen ? (
              <X className="h-5 w-5" />
            ) : (
              <Menu className="h-5 w-5" />
            )}
          </button>
        </div>

        {/* Mobile menu */}
        {mobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            exit={{ opacity: 0, height: 0 }}
            className="md:hidden py-4 border-t border-slate-800"
          >
            <div className="flex flex-col gap-4">
              <a
                href="#features"
                className="text-sm text-slate-400 hover:text-white transition-colors"
                onClick={() => setMobileMenuOpen(false)}
              >
                Features
              </a>
              <a
                href="#timeline"
                className="text-sm text-slate-400 hover:text-white transition-colors"
                onClick={() => setMobileMenuOpen(false)}
              >
                Threat Timeline
              </a>
              <a
                href="#pricing"
                className="text-sm text-slate-400 hover:text-white transition-colors"
                onClick={() => setMobileMenuOpen(false)}
              >
                Pricing
              </a>
              <a
                href="#compliance"
                className="text-sm text-slate-400 hover:text-white transition-colors"
                onClick={() => setMobileMenuOpen(false)}
              >
                Compliance
              </a>
              <div className="flex flex-col gap-2 pt-4 border-t border-slate-800">
                {user ? (
                  <Button
                    onClick={() => {
                      navigate('/app')
                      setMobileMenuOpen(false)
                    }}
                    size="sm"
                    className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-medium"
                  >
                    Dashboard
                  </Button>
                ) : (
                  <>
                    <Button
                      onClick={() => {
                        navigate('/auth')
                        setMobileMenuOpen(false)
                      }}
                      variant="outline"
                      size="sm"
                      className="w-full border-slate-700 text-slate-300"
                    >
                      Sign In
                    </Button>
                    <Button
                      onClick={() => {
                        navigate('/auth')
                        setMobileMenuOpen(false)
                      }}
                      size="sm"
                      className="w-full bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-medium"
                    >
                      Get Started
                    </Button>
                  </>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </div>
    </motion.nav>
  )
}