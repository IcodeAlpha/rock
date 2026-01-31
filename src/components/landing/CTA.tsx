import { useNavigate } from 'react-router-dom'
import { motion } from 'motion/react'
import { ArrowRight, Shield, Zap, Clock } from 'lucide-react'
import { Button } from '@/components/ui/button'

export function CTA() {
  const navigate = useNavigate()

  return (
    <section className="relative py-24 bg-[#070b14] overflow-hidden">
      {/* Background effects */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-4xl mx-auto px-6 text-center">
        <motion.div
          initial={{ opacity: 0, y: 30 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
        >
          {/* Badge */}
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-cyan-500/30 bg-cyan-500/5 mb-8">
            <Zap className="h-4 w-4 text-cyan-400" />
            <span className="text-cyan-400 text-sm font-mono">
              START PREDICTING TODAY
            </span>
          </div>

          {/* Headline */}
          <h2 className="text-4xl md:text-6xl font-bold text-white mb-6">
            Stop Reacting.
            <br />
            <span className="bg-gradient-to-r from-cyan-400 to-emerald-400 bg-clip-text text-transparent">
              Start Predicting.
            </span>
          </h2>

          {/* Subheadline */}
          <p className="text-lg text-slate-400 max-w-2xl mx-auto mb-10">
            Join the security teams who've moved from reactive firefighting to
            proactive defense. See threats before they materialize and protect
            what matters most.
          </p>

          {/* CTA buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12">
            <Button
              onClick={() => navigate('/auth')}
              size="lg"
              className="bg-cyan-500 hover:bg-cyan-400 text-slate-900 font-semibold px-8 py-6 text-lg rounded-lg group"
            >
              Get Started
              <ArrowRight className="ml-2 h-5 w-5 group-hover:translate-x-1 transition-transform" />
            </Button>
            <Button
              onClick={() => navigate('/auth')}
              variant="outline"
              size="lg"
              className="border-slate-700 hover:border-cyan-500/50 hover:bg-cyan-500/5 text-slate-300 px-8 py-6 text-lg rounded-lg"
            >
              Request Demo
            </Button>
          </div>

          {/* Trust indicators */}
          <div className="flex flex-wrap items-center justify-center gap-8 text-sm text-slate-500">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-emerald-400" />
              <span>Enterprise-grade security</span>
            </div>
            <div className="flex items-center gap-2">
              <Clock className="h-4 w-4 text-cyan-400" />
              <span>Setup in under 30 minutes</span>
            </div>
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-400" />
              <span>SIEM integration included</span>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}