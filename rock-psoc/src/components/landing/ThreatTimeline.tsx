import { motion } from 'motion/react'
import {
  AlertTriangle,
  Shield,
  Clock,
  TrendingUp,
  ExternalLink,
} from 'lucide-react'

const threats = [
  {
    day: 'Today',
    date: 'Active',
    threats: [
      {
        id: 1,
        title: 'Credential Stuffing Campaign',
        likelihood: 89,
        impact: 'HIGH',
        type: 'Authentication',
        status: 'monitoring',
        assets: ['Auth Services', 'User DB'],
      },
    ],
  },
  {
    day: '+2 Days',
    date: 'Predicted',
    threats: [
      {
        id: 2,
        title: 'Ransomware Variant Targeting Healthcare',
        likelihood: 76,
        impact: 'CRITICAL',
        type: 'Malware',
        status: 'predicted',
        assets: ['File Servers', 'Backup Systems'],
      },
    ],
  },
  {
    day: '+4 Days',
    date: 'Predicted',
    threats: [
      {
        id: 3,
        title: 'Supply Chain Compromise Vector',
        likelihood: 64,
        impact: 'HIGH',
        type: 'Supply Chain',
        status: 'predicted',
        assets: ['CI/CD Pipeline', 'Package Registry'],
      },
    ],
  },
  {
    day: '+6 Days',
    date: 'Predicted',
    threats: [
      {
        id: 4,
        title: 'DDoS Campaign Correlated with Geopolitical Event',
        likelihood: 52,
        impact: 'MEDIUM',
        type: 'Network',
        status: 'predicted',
        assets: ['Edge Network', 'CDN'],
      },
    ],
  },
]

function getImpactColor(impact: string) {
  switch (impact) {
    case 'CRITICAL':
      return 'text-red-400 bg-red-500/10 border-red-500/30'
    case 'HIGH':
      return 'text-amber-400 bg-amber-500/10 border-amber-500/30'
    case 'MEDIUM':
      return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30'
    default:
      return 'text-slate-400 bg-slate-500/10 border-slate-500/30'
  }
}

function getLikelihoodColor(likelihood: number) {
  if (likelihood >= 80) return 'bg-red-500'
  if (likelihood >= 60) return 'bg-amber-500'
  if (likelihood >= 40) return 'bg-yellow-500'
  return 'bg-slate-500'
}

export function ThreatTimeline() {
  return (
    <section className="relative py-24 bg-[#0a0f1a]">
      {/* Section header */}
      <div className="max-w-6xl mx-auto px-6 mb-16">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center"
        >
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-cyan-500/30 bg-cyan-500/5 mb-6">
            <Clock className="h-4 w-4 text-cyan-400" />
            <span className="text-cyan-400 text-sm font-mono">
              7-DAY THREAT HORIZON
            </span>
          </div>
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Predictive Threat Timeline
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            See what's coming before it arrives. Our AI correlates OSINT feeds,
            dark web signals, and historical patterns to forecast threats with
            probability scores.
          </p>
        </motion.div>
      </div>

      {/* Timeline */}
      <div className="max-w-6xl mx-auto px-6">
        <div className="relative">
          {/* Timeline line */}
          <div className="absolute left-8 md:left-1/2 top-0 bottom-0 w-px bg-gradient-to-b from-cyan-500/50 via-slate-700 to-transparent" />

          {threats.map((dayGroup, groupIndex) => (
            <motion.div
              key={dayGroup.day}
              initial={{ opacity: 0, x: groupIndex % 2 === 0 ? -30 : 30 }}
              whileInView={{ opacity: 1, x: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: groupIndex * 0.1 }}
              className={`relative flex items-start gap-8 mb-12 ${
                groupIndex % 2 === 0 ? 'md:flex-row' : 'md:flex-row-reverse'
              }`}
            >
              {/* Timeline node */}
              <div className="absolute left-8 md:left-1/2 -translate-x-1/2 w-4 h-4 rounded-full bg-slate-900 border-2 border-cyan-500 z-10">
                {groupIndex === 0 && (
                  <span className="absolute inset-0 rounded-full bg-cyan-500 animate-ping opacity-50" />
                )}
              </div>

              {/* Day label */}
              <div
                className={`hidden md:block w-1/2 ${groupIndex % 2 === 0 ? 'text-right pr-12' : 'text-left pl-12'}`}
              >
                <span className="text-2xl font-bold text-white font-mono">
                  {dayGroup.day}
                </span>
                <span
                  className={`ml-3 text-sm ${groupIndex === 0 ? 'text-cyan-400' : 'text-slate-500'}`}
                >
                  {dayGroup.date}
                </span>
              </div>

              {/* Threat cards */}
              <div
                className={`ml-16 md:ml-0 md:w-1/2 ${groupIndex % 2 === 0 ? 'md:pl-12' : 'md:pr-12'}`}
              >
                <div className="md:hidden mb-2">
                  <span className="text-xl font-bold text-white font-mono">
                    {dayGroup.day}
                  </span>
                  <span
                    className={`ml-2 text-sm ${groupIndex === 0 ? 'text-cyan-400' : 'text-slate-500'}`}
                  >
                    {dayGroup.date}
                  </span>
                </div>

                {dayGroup.threats.map((threat) => (
                  <div
                    key={threat.id}
                    className="group relative p-5 rounded-xl border border-slate-800 bg-slate-900/80 backdrop-blur hover:border-cyan-500/30 transition-all duration-300"
                  >
                    {/* Threat header */}
                    <div className="flex items-start justify-between gap-4 mb-4">
                      <div className="flex items-center gap-3">
                        <div
                          className={`p-2 rounded-lg ${
                            threat.impact === 'CRITICAL'
                              ? 'bg-red-500/10'
                              : 'bg-amber-500/10'
                          }`}
                        >
                          <AlertTriangle
                            className={`h-5 w-5 ${
                              threat.impact === 'CRITICAL'
                                ? 'text-red-400'
                                : 'text-amber-400'
                            }`}
                          />
                        </div>
                        <div>
                          <h4 className="text-white font-semibold group-hover:text-cyan-400 transition-colors">
                            {threat.title}
                          </h4>
                          <span className="text-sm text-slate-500">
                            {threat.type}
                          </span>
                        </div>
                      </div>
                      <ExternalLink className="h-4 w-4 text-slate-600 group-hover:text-cyan-400 transition-colors" />
                    </div>

                    {/* Metrics row */}
                    <div className="flex items-center gap-4 mb-4">
                      {/* Likelihood */}
                      <div className="flex-1">
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-xs text-slate-500">
                            Likelihood
                          </span>
                          <span className="text-sm font-mono text-white">
                            {threat.likelihood}%
                          </span>
                        </div>
                        <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${getLikelihoodColor(threat.likelihood)}`}
                            style={{ width: `${threat.likelihood}%` }}
                          />
                        </div>
                      </div>

                      {/* Impact badge */}
                      <div
                        className={`px-3 py-1 rounded-full border text-xs font-mono ${getImpactColor(threat.impact)}`}
                      >
                        {threat.impact}
                      </div>
                    </div>

                    {/* Affected assets */}
                    <div className="flex items-center gap-2 flex-wrap">
                      <Shield className="h-3.5 w-3.5 text-slate-600" />
                      {threat.assets.map((asset, i) => (
                        <span
                          key={i}
                          className="text-xs text-slate-500 bg-slate-800/50 px-2 py-0.5 rounded"
                        >
                          {asset}
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </motion.div>
          ))}
        </div>

        {/* View more indicator */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          className="text-center mt-8"
        >
          <div className="inline-flex items-center gap-2 text-slate-500 text-sm">
            <TrendingUp className="h-4 w-4" />
            <span>
              Predictions extend up to 7 days with decreasing confidence
            </span>
          </div>
        </motion.div>
      </div>
    </section>
  )
}