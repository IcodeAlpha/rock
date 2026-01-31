import { motion } from 'motion/react'
import {
  Building2,
  Shield,
  Briefcase,
  Users,
  GraduationCap,
  Scale,
} from 'lucide-react'

const primaryMarkets = [
  {
    icon: Shield,
    title: 'Government & Defense',
    description:
      'National cybersecurity agencies (CISAs, CERTs), defense ministries, military cyber units, and critical infrastructure protection.',
    examples: ['Power Grids', 'Water Systems', 'Transportation'],
  },
  {
    icon: Building2,
    title: 'Enterprise Security',
    description:
      'Fortune 500 companies with mature SOCs, financial services, banking institutions, and healthcare organizations requiring HIPAA compliance.',
    examples: ['Financial Services', 'Healthcare', 'Fortune 500'],
  },
  {
    icon: Briefcase,
    title: 'MSSPs',
    description:
      'Managed Security Service Providers offering SOC-as-a-Service and white-label predictive intelligence to their clients.',
    examples: ['SOC-as-a-Service', 'White-Label', 'Multi-Tenant'],
  },
]

const secondaryMarkets = [
  {
    icon: Scale,
    title: 'Insurance Companies',
    subtitle: 'Cyber risk assessment and premium calculation',
  },
  {
    icon: Users,
    title: 'Law Enforcement',
    subtitle: 'Threat intelligence sharing and investigation support',
  },
  {
    icon: GraduationCap,
    title: 'Academia',
    subtitle: 'Security research platforms and educational programs',
  },
]

export function TargetMarkets() {
  return (
    <section className="relative py-24 bg-[#0a0f1a]">
      <div className="max-w-6xl mx-auto px-6">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Built for Mission-Critical Security
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Trusted by organizations protecting critical infrastructure,
            sensitive data, and national security interests.
          </p>
        </motion.div>

        {/* Primary markets */}
        <div className="mb-16">
          <motion.h3
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="text-2xl font-semibold text-cyan-400 mb-8"
          >
            Primary Markets
          </motion.h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {primaryMarkets.map((market, index) => (
              <motion.div
                key={market.title}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="p-6 rounded-xl border border-slate-800 bg-slate-900/50 hover:border-cyan-500/30 transition-colors"
              >
                <div className="inline-flex p-3 rounded-lg bg-cyan-500/10 mb-4">
                  <market.icon className="h-6 w-6 text-cyan-400" />
                </div>
                <h4 className="text-xl font-semibold text-white mb-3">
                  {market.title}
                </h4>
                <p className="text-slate-400 text-sm mb-4 leading-relaxed">
                  {market.description}
                </p>
                <div className="flex flex-wrap gap-2">
                  {market.examples.map((example) => (
                    <span
                      key={example}
                      className="px-2 py-1 rounded text-xs bg-slate-800/50 text-slate-400 border border-slate-700"
                    >
                      {example}
                    </span>
                  ))}
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Secondary markets */}
        <div>
          <motion.h3
            initial={{ opacity: 0, x: -20 }}
            whileInView={{ opacity: 1, x: 0 }}
            viewport={{ once: true }}
            className="text-2xl font-semibold text-emerald-400 mb-8"
          >
            Secondary Markets
          </motion.h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {secondaryMarkets.map((market, index) => (
              <motion.div
                key={market.title}
                initial={{ opacity: 0, y: 20 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.1 }}
                className="flex gap-4 p-5 rounded-xl border border-slate-800/50 bg-slate-900/30 hover:border-emerald-500/20 transition-colors"
              >
                <div className="flex-shrink-0 p-2 rounded-lg bg-emerald-500/10 h-fit">
                  <market.icon className="h-5 w-5 text-emerald-400" />
                </div>
                <div>
                  <h4 className="text-white font-semibold mb-1">
                    {market.title}
                  </h4>
                  <p className="text-sm text-slate-500">{market.subtitle}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}