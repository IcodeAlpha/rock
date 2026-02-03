import { useNavigate } from 'react-router-dom'
import { motion } from 'motion/react'
import { Shield, Activity, Zap, ChevronRight } from 'lucide-react'
import { Button } from '@/components/ui/button'

export function Hero() {
  const navigate = useNavigate()

  return (
    <section className="relative min-h-screen flex items-center justify-center overflow-hidden bg-[#0a0f1a]">
      {/* Animated grid background */}
      <div className="absolute inset-0 opacity-20">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `
                            linear-gradient(rgba(0, 212, 255, 0.03) 1px, transparent 1px),
                            linear-gradient(90deg, rgba(0, 212, 255, 0.03) 1px, transparent 1px)
                        `,
            backgroundSize: '60px 60px',
          }}
        />
      </div>

      {/* Radial gradient overlay */}
      <div className="absolute inset-0 bg-gradient-radial from-cyan-500/5 via-transparent to-transparent" />

      {/* Floating threat indicators */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {[...Array(6)].map((_, i) => (
          <motion.div
            key={i}
            className="absolute"
            initial={{
              x: Math.random() * 100 + '%',
              y: Math.random() * 100 + '%',
              opacity: 0,
            }}
            animate={{
              x: [
                Math.random() * 100 + '%',
                Math.random() * 100 + '%',
                Math.random() * 100 + '%',
              ],
              y: [
                Math.random() * 100 + '%',
                Math.random() * 100 + '%',
                Math.random() * 100 + '%',
              ],
              opacity: [0.2, 0.5, 0.2],
            }}
            transition={{
              duration: 20 + Math.random() * 10,
              repeat: Infinity,
              ease: 'linear',
            }}
          >
            <div
              className={`w-2 h-2 rounded-full ${
                i % 3 === 0
                  ? 'bg-red-500'
                  : i % 3 === 1
                    ? 'bg-amber-500'
                    : 'bg-cyan-500'
              } blur-sm`}
            />
          </motion.div>
        ))}
      </div>

      {/* Main content */}
      <div className="relative z-10 max-w-6xl mx-auto px-6 py-24 text-center">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.6 }}
          className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-cyan-500/30 bg-cyan-500/5 mb-8"
        >
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-cyan-500"></span>
          </span>
          <span className="text-cyan-400 text-sm font-mono tracking-wide">
            PREDICTIVE DEFENSE ACTIVE
          </span>
        </motion.div>

        {/* Main headline */}
        <motion.h1
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.1 }}
          className="text-5xl md:text-7xl lg:text-8xl font-bold tracking-tight mb-6"
        >
          <span className="text-white">See Threats</span>
          <br />
          <span className="bg-gradient-to-r from-cyan-400 via-cyan-300 to-emerald-400 bg-clip-text text-transparent">
            Before They Strike
          </span>
        </motion.h1>

        {/* Subheadline */}
        <motion.p
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.2 }}
          className="text-lg md:text-xl text-slate-400 max-w-2xl mx-auto mb-12 leading-relaxed"
        >
          Transform your SOC from reactive firefighting to proactive defense.
          AI-powered threat prediction engine that analyzes historical
          incidents, correlates OSINT intelligence, and forecasts cyber threats
          <span className="text-cyan-400 font-semibold">
            {' '}
            5-7 days before they occur
          </span>
          . Stop breaches before they start.
        </motion.p>

        {/* CTA buttons */}
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.7, delay: 0.3 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16"
        >
          <Button
            onClick={() => navigate('/auth')}
            size="lg"
            className="bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold px-8 py-6 text-lg rounded-lg group"
          >
            Get Started
            <ChevronRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
          </Button>
          <Button
            onClick={() => navigate('/auth')}
            variant="outline"
            size="lg"
            className="border-slate-700 hover:border-cyan-500/50 hover:bg-cyan-500/5 text-slate-300 px-8 py-6 text-lg rounded-lg"
          >
            Sign In to Dashboard
          </Button>
        </motion.div>

        {/* Stats row */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.4 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-8 max-w-3xl mx-auto"
        >
          <div className="flex flex-col items-center p-6 rounded-xl border border-slate-800 bg-slate-900/50 backdrop-blur">
            <Shield className="h-8 w-8 text-cyan-400 mb-3" />
            <span className="text-3xl font-bold text-white font-mono">94%</span>
            <span className="text-sm text-slate-500 mt-1">
              Threats Predicted
            </span>
          </div>
          <div className="flex flex-col items-center p-6 rounded-xl border border-slate-800 bg-slate-900/50 backdrop-blur">
            <Activity className="h-8 w-8 text-emerald-400 mb-3" />
            <span className="text-3xl font-bold text-white font-mono">73%</span>
            <span className="text-sm text-slate-500 mt-1">
              Less False Positives
            </span>
          </div>
          <div className="flex flex-col items-center p-6 rounded-xl border border-slate-800 bg-slate-900/50 backdrop-blur">
            <Zap className="h-8 w-8 text-amber-400 mb-3" />
            <span className="text-3xl font-bold text-white font-mono">
              5.2 Days
            </span>
            <span className="text-sm text-slate-500 mt-1">
              Avg. Early Warning
            </span>
          </div>
        </motion.div>
      </div>

      {/* Bottom gradient fade */}
      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-[#0a0f1a] to-transparent" />
    </section>
  )
}