import { motion } from 'motion/react'
import { Code2, Database, Zap, Shield, Cloud, Cpu } from 'lucide-react'

const stackCategories = [
  {
    icon: Code2,
    title: 'Frontend',
    technologies: [
      'React 19',
      'TypeScript',
      'Tailwind CSS',
      'shadcn/ui',
      'Recharts',
      'Motion',
    ],
  },
  {
    icon: Database,
    title: 'Backend & Data',
    technologies: [
      'Node.js',
      'PostgreSQL',
      'Redis',
      'Edge Functions',
      'Real-time Sync',
    ],
  },
  {
    icon: Cpu,
    title: 'AI & ML',
    technologies: [
      'TensorFlow',
      'PyTorch',
      'Pattern Recognition',
      'Adaptive Learning',
      'NLP Models',
    ],
  },
  {
    icon: Cloud,
    title: 'Infrastructure',
    technologies: [
      'SOC 2 Type II',
      'AES-256 Encryption',
      'TLS 1.3',
      'CDN',
      'Auto-scaling',
    ],
  },
  {
    icon: Zap,
    title: 'Integrations',
    technologies: [
      'Splunk',
      'QRadar',
      'Sentinel',
      'Shodan API',
      'VirusTotal',
      'AlienVault OTX',
    ],
  },
  {
    icon: Shield,
    title: 'Security & Compliance',
    technologies: ['GDPR', 'HIPAA', 'FedRAMP', 'ISO 27001', 'PCI DSS', 'RBAC'],
  },
]

export function TechStack() {
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
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-purple-500/30 bg-purple-500/5 mb-6">
            <Code2 className="h-4 w-4 text-purple-400" />
            <span className="text-purple-400 text-sm font-mono">
              TECHNOLOGY STACK
            </span>
          </div>
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Built on Modern Infrastructure
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Enterprise-grade technology stack designed for scale, security, and
            real-time performance.
          </p>
        </motion.div>

        {/* Stack grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {stackCategories.map((category, index) => (
            <motion.div
              key={category.title}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className="p-6 rounded-xl border border-slate-800 bg-slate-900/50 hover:border-purple-500/30 transition-colors"
            >
              {/* Icon and title */}
              <div className="flex items-center gap-3 mb-4">
                <div className="p-2 rounded-lg bg-purple-500/10">
                  <category.icon className="h-5 w-5 text-purple-400" />
                </div>
                <h3 className="text-lg font-semibold text-white">
                  {category.title}
                </h3>
              </div>

              {/* Technologies */}
              <div className="flex flex-wrap gap-2">
                {category.technologies.map((tech) => (
                  <span
                    key={tech}
                    className="px-2 py-1 rounded text-xs bg-slate-800/50 text-slate-400 border border-slate-700 hover:border-purple-500/30 hover:text-purple-400 transition-colors"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Bottom stats */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="mt-16 grid grid-cols-1 md:grid-cols-3 gap-6"
        >
          <div className="text-center p-6 rounded-xl border border-slate-800 bg-slate-900/30">
            <div className="text-3xl font-bold text-purple-400 font-mono mb-2">
              99.9%
            </div>
            <div className="text-sm text-slate-500">Uptime SLA</div>
          </div>
          <div className="text-center p-6 rounded-xl border border-slate-800 bg-slate-900/30">
            <div className="text-3xl font-bold text-cyan-400 font-mono mb-2">
              &lt;100ms
            </div>
            <div className="text-sm text-slate-500">API Response Time</div>
          </div>
          <div className="text-center p-6 rounded-xl border border-slate-800 bg-slate-900/30">
            <div className="text-3xl font-bold text-emerald-400 font-mono mb-2">
              24/7
            </div>
            <div className="text-sm text-slate-500">Enterprise Support</div>
          </div>
        </motion.div>
      </div>
    </section>
  )
}