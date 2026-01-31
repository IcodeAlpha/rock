import { motion } from 'motion/react'
import { AlertTriangle, Clock, DollarSign, TrendingDown } from 'lucide-react'

const problems = [
  {
    icon: DollarSign,
    stat: '$4.5M+',
    label: 'Average cost per breach',
    description: 'Organizations pay millions after attacks occur',
  },
  {
    icon: TrendingDown,
    stat: '80%',
    label: 'Time on false positives',
    description: 'Analyst burnout from alert fatigue',
  },
  {
    icon: Clock,
    stat: 'Weeks',
    label: 'To detect and contain',
    description: 'Damage spreads while teams investigate',
  },
  {
    icon: AlertTriangle,
    stat: 'Zero',
    label: 'Predictive capability',
    description: 'Traditional SOCs are fundamentally reactive',
  },
]

export function ProblemStatement() {
  return (
    <section className="relative py-24 bg-[#070b14]">
      {/* Background pattern */}
      <div className="absolute inset-0 opacity-20">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, rgba(239, 68, 68, 0.15) 1px, transparent 0)`,
            backgroundSize: '40px 40px',
          }}
        />
      </div>

      <div className="relative max-w-6xl mx-auto px-6">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-red-500/30 bg-red-500/5 mb-6">
            <AlertTriangle className="h-4 w-4 text-red-400" />
            <span className="text-red-400 text-sm font-mono">
              THE REACTIVE SECURITY CRISIS
            </span>
          </div>
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Modern Cybersecurity is Broken
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Organizations detect threats only{' '}
            <strong className="text-red-400">after</strong> they've already
            begun causing damage. The cost of reactive security is
            unsustainable.
          </p>
        </motion.div>

        {/* Problem grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {problems.map((problem, index) => (
            <motion.div
              key={problem.label}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className="relative p-6 rounded-xl border border-red-900/30 bg-red-950/20 backdrop-blur"
            >
              {/* Icon */}
              <div className="inline-flex p-3 rounded-lg bg-red-500/10 mb-4">
                <problem.icon className="h-6 w-6 text-red-400" />
              </div>

              {/* Stat */}
              <div className="text-3xl font-bold text-red-400 font-mono mb-2">
                {problem.stat}
              </div>

              {/* Label */}
              <h3 className="text-sm font-semibold text-slate-300 mb-2">
                {problem.label}
              </h3>

              {/* Description */}
              <p className="text-xs text-slate-500 leading-relaxed">
                {problem.description}
              </p>
            </motion.div>
          ))}
        </div>

        {/* Bottom CTA */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="mt-16 text-center"
        >
          <p className="text-xl text-slate-300 mb-4">
            It's time to shift from{' '}
            <span className="text-red-400 line-through">detection</span> to{' '}
            <span className="text-cyan-400 font-semibold">prediction</span>
          </p>
          <p className="text-slate-500">
            Rock PSOC transforms security operations from reactive to proactive
          </p>
        </motion.div>
      </div>
    </section>
  )
}