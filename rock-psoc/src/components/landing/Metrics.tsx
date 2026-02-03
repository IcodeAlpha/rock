import { motion } from 'motion/react'
import {
  TrendingDown,
  Clock,
  Users,
  DollarSign,
  ArrowDown,
  ArrowUp,
} from 'lucide-react'

const metrics = [
  {
    icon: Clock,
    label: 'Mean Time to Awareness',
    value: '5.2',
    unit: 'days early',
    change: '+340%',
    changeType: 'positive',
    description: 'Average advance warning before threat materialization',
  },
  {
    icon: TrendingDown,
    label: 'False Positive Reduction',
    value: '73',
    unit: '%',
    change: '-73%',
    changeType: 'positive',
    description: 'Decrease in analyst time spent on non-threats',
  },
  {
    icon: DollarSign,
    label: 'Breach Cost Reduction',
    value: '2.4',
    unit: 'M avg saved',
    change: '-68%',
    changeType: 'positive',
    description: 'Average savings per prevented breach incident',
  },
  {
    icon: Users,
    label: 'Analyst Burnout Index',
    value: '42',
    unit: '% decrease',
    change: '-42%',
    changeType: 'positive',
    description: 'Reduction in overtime hours and alert fatigue indicators',
  },
]

export function Metrics() {
  return (
    <section className="relative py-24 bg-[#070b14]">
      {/* Background accent */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-cyan-500/5 rounded-full blur-3xl" />
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
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Measurable Impact
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Real results from enterprise deployments. Our customers see dramatic
            improvements in threat response times and analyst efficiency within
            90 days.
          </p>
        </motion.div>

        {/* Metrics grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {metrics.map((metric, index) => (
            <motion.div
              key={metric.label}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className="relative p-6 rounded-xl border border-slate-800 bg-slate-900/50 backdrop-blur group hover:border-cyan-500/30 transition-all duration-300"
            >
              {/* Icon */}
              <div className="flex items-center justify-between mb-4">
                <div className="p-2 rounded-lg bg-cyan-500/10">
                  <metric.icon className="h-5 w-5 text-cyan-400" />
                </div>
                <div
                  className={`flex items-center gap-1 text-sm font-mono ${
                    metric.changeType === 'positive'
                      ? 'text-emerald-400'
                      : 'text-red-400'
                  }`}
                >
                  {metric.changeType === 'positive' ? (
                    <ArrowUp className="h-3 w-3" />
                  ) : (
                    <ArrowDown className="h-3 w-3" />
                  )}
                  {metric.change}
                </div>
              </div>

              {/* Value */}
              <div className="mb-2">
                <span className="text-4xl font-bold text-white font-mono">
                  {metric.value}
                </span>
                <span className="text-lg text-slate-400 ml-1">
                  {metric.unit}
                </span>
              </div>

              {/* Label */}
              <h3 className="text-sm font-semibold text-slate-300 mb-2">
                {metric.label}
              </h3>

              {/* Description */}
              <p className="text-xs text-slate-500">{metric.description}</p>

              {/* Hover glow */}
              <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-cyan-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
            </motion.div>
          ))}
        </div>

        {/* Bottom quote */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="mt-16 text-center"
        >
          <blockquote className="text-xl text-slate-400 italic max-w-3xl mx-auto">
            "Rock PSOC transformed our SOC from a reactive cost center into a
            proactive strategic asset. We're now preventing breaches instead of
            investigating them. The 5-7 day advance warning gives us time to
            actually prepare defenses rather than scrambling after attacks
            begin."
          </blockquote>
          <div className="mt-4 text-sm text-slate-500">
            — CISO, Fortune 500 Healthcare Organization
          </div>
        </motion.div>
      </div>
    </section>
  )
}