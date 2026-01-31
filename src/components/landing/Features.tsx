import { motion } from 'motion/react'
import {
  Brain,
  Globe,
  Workflow,
  BarChart3,
  Bell,
  Lock,
  Radar,
  Database,
  FileUp,
  Users,
  Shield,
  Layers,
} from 'lucide-react'

const features = [
  {
    icon: Brain,
    title: 'AI Threat Prediction Engine',
    description:
      'Upload historical incident logs (CSV, JSON, PDF, images). Pattern recognition generates predictions with severity, probability, confidence scores, and 5-7 day timeframes.',
    color: 'cyan',
  },
  {
    icon: Globe,
    title: 'OSINT Reconnaissance Center',
    description:
      'Integrated tools: Shodan, theHarvester, Maltego, Google Dorking, WHOIS, DNS Recon, Reverse Image Search, and Censys for comprehensive intelligence gathering.',
    color: 'emerald',
  },
  {
    icon: Workflow,
    title: 'Sequential Response Protocols',
    description:
      'Military-style 5-level response system from Alert & Monitor to Critical Emergency. Convert predictions directly to tracked incidents with team assignment.',
    color: 'amber',
  },
  {
    icon: BarChart3,
    title: 'Risk Heatmaps & Analytics',
    description:
      'Visual asset vulnerability matrices showing risk concentration by category. Real-time dashboards with threat timelines and impact scoring.',
    color: 'purple',
  },
  {
    icon: Radar,
    title: 'SIEM Integration',
    description:
      'Seamless ingestion of historical incident data from Splunk, QRadar, Sentinel, and other major SIEM platforms for comprehensive analysis.',
    color: 'rose',
  },
  {
    icon: Database,
    title: 'Adaptive Learning Models',
    description:
      'Continuous model refinement based on prediction accuracy. Reduces false positives by 73% and improves threat scoring over time with feedback loops.',
    color: 'blue',
  },
  {
    icon: FileUp,
    title: 'Multi-Format File Analysis',
    description:
      'Upload security logs, incident reports, and threat intelligence in CSV, JSON, PDF, or image formats. AI extracts patterns and generates actionable predictions.',
    color: 'indigo',
  },
  {
    icon: Users,
    title: 'Team Management & RBAC',
    description:
      'Role-based access control with Admin, Analyst, and Viewer roles. Invite team members, manage permissions, and track audit trails.',
    color: 'violet',
  },
  {
    icon: Bell,
    title: 'Real-Time Alerts & Sync',
    description:
      'Context-aware notifications with severity-based prioritization. Live updates across all team members without page refresh via real-time sync.',
    color: 'orange',
  },
  {
    icon: Layers,
    title: 'Contextual Threat Intelligence',
    description:
      'Organization profile-based threat correlation with relevance scoring. Filter by industry, systems, geography, and threat actors of concern.',
    color: 'teal',
  },
  {
    icon: Shield,
    title: 'AI-Powered Report Generation',
    description:
      'Generate comprehensive security reports via AI. View reports in modal before downloading. Weekly summaries, monthly reports, and incident analysis.',
    color: 'pink',
  },
  {
    icon: Lock,
    title: 'Enterprise Compliance',
    description:
      'Full GDPR compliance, SOC 2 Type II, ISO 27001, HIPAA, FedRAMP, and PCI DSS certified. Data sovereignty controls and audit logging built in.',
    color: 'slate',
  },
]

const colorMap: Record<string, { bg: string; text: string; border: string }> = {
  cyan: {
    bg: 'bg-cyan-500/10',
    text: 'text-cyan-400',
    border: 'group-hover:border-cyan-500/30',
  },
  emerald: {
    bg: 'bg-emerald-500/10',
    text: 'text-emerald-400',
    border: 'group-hover:border-emerald-500/30',
  },
  amber: {
    bg: 'bg-amber-500/10',
    text: 'text-amber-400',
    border: 'group-hover:border-amber-500/30',
  },
  purple: {
    bg: 'bg-purple-500/10',
    text: 'text-purple-400',
    border: 'group-hover:border-purple-500/30',
  },
  rose: {
    bg: 'bg-rose-500/10',
    text: 'text-rose-400',
    border: 'group-hover:border-rose-500/30',
  },
  blue: {
    bg: 'bg-blue-500/10',
    text: 'text-blue-400',
    border: 'group-hover:border-blue-500/30',
  },
  orange: {
    bg: 'bg-orange-500/10',
    text: 'text-orange-400',
    border: 'group-hover:border-orange-500/30',
  },
  slate: {
    bg: 'bg-slate-500/10',
    text: 'text-slate-400',
    border: 'group-hover:border-slate-500/30',
  },
  indigo: {
    bg: 'bg-indigo-500/10',
    text: 'text-indigo-400',
    border: 'group-hover:border-indigo-500/30',
  },
  violet: {
    bg: 'bg-violet-500/10',
    text: 'text-violet-400',
    border: 'group-hover:border-violet-500/30',
  },
  teal: {
    bg: 'bg-teal-500/10',
    text: 'text-teal-400',
    border: 'group-hover:border-teal-500/30',
  },
  pink: {
    bg: 'bg-pink-500/10',
    text: 'text-pink-400',
    border: 'group-hover:border-pink-500/30',
  },
}

export function Features() {
  return (
    <section className="relative py-24 bg-[#070b14]">
      {/* Subtle grid pattern */}
      <div className="absolute inset-0 opacity-30">
        <div
          className="absolute inset-0"
          style={{
            backgroundImage: `radial-gradient(circle at 1px 1px, rgba(100, 116, 139, 0.15) 1px, transparent 0)`,
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
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Enterprise-Grade Capabilities
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Built for SOC teams protecting critical infrastructure. Every
            feature designed to reduce mean time to threat awareness and analyst
            burnout.
          </p>
        </motion.div>

        {/* Features grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {features.map((feature, index) => {
            const colors = colorMap[feature.color]
            return (
              <motion.div
                key={feature.title}
                initial={{ opacity: 0, y: 30 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ duration: 0.5, delay: index * 0.05 }}
                className={`group relative p-6 rounded-xl border border-slate-800/50 bg-slate-900/30 backdrop-blur hover:bg-slate-900/50 transition-all duration-300 ${colors.border}`}
              >
                {/* Icon */}
                <div className={`inline-flex p-3 rounded-lg ${colors.bg} mb-4`}>
                  <feature.icon className={`h-6 w-6 ${colors.text}`} />
                </div>

                {/* Content */}
                <h3 className="text-lg font-semibold text-white mb-2 group-hover:text-cyan-400 transition-colors">
                  {feature.title}
                </h3>
                <p className="text-sm text-slate-500 leading-relaxed">
                  {feature.description}
                </p>

                {/* Hover glow effect */}
                <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-cyan-500/5 to-transparent opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none" />
              </motion.div>
            )
          })}
        </div>
      </div>
    </section>
  )
}