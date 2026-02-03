import { motion } from 'motion/react'
import {
  Shield,
  FileCheck,
  Eye,
  Trash2,
  Lock,
  Server,
  Globe,
  Clock,
} from 'lucide-react'
import { useNavigate } from 'react-router-dom'

const complianceFeatures = [
  {
    icon: FileCheck,
    title: 'Data Processing Agreements',
    description:
      'Standard contractual clauses and DPAs ready for enterprise deployment.',
  },
  {
    icon: Eye,
    title: 'Consent Management',
    description:
      'Granular consent tracking for all data subjects with audit trails.',
  },
  {
    icon: Trash2,
    title: 'Right to Erasure',
    description:
      'Automated data deletion workflows supporting GDPR Article 17 requests.',
  },
  {
    icon: Lock,
    title: 'Data Minimization',
    description:
      'Only collect and process data necessary for threat prediction.',
  },
  {
    icon: Server,
    title: 'Data Sovereignty',
    description:
      'Choose your data residency: EU, US, or on-premises deployment.',
  },
  {
    icon: Globe,
    title: 'Cross-Border Transfers',
    description:
      'SCCs and adequacy decisions for compliant international data flows.',
  },
]

const certifications = [
  { name: 'SOC 2 Type II', status: 'In Progress' },
  { name: 'ISO 27001', status: 'In Progress' },
  { name: 'GDPR', status: 'Compliant' },
  { name: 'HIPAA', status: 'Planned' },
  { name: 'FedRAMP', status: 'Planned' },
  { name: 'PCI DSS', status: 'Planned' },
]

export function Compliance() {
  const navigate = useNavigate()

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
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-emerald-500/30 bg-emerald-500/5 mb-6">
            <Shield className="h-4 w-4 text-emerald-400" />
            <span className="text-emerald-400 text-sm font-mono">
              COMPLIANCE & PRIVACY
            </span>
          </div>
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Built for Regulated Industries
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            Full GDPR compliance, data sovereignty controls, and
            enterprise-grade security. Deploy with confidence in healthcare,
            finance, and critical infrastructure.
          </p>
        </motion.div>

        {/* Compliance features grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-16">
          {complianceFeatures.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.05 }}
              className="flex gap-4 p-5 rounded-xl border border-slate-800/50 bg-slate-900/30 hover:border-emerald-500/20 transition-colors"
            >
              <div className="flex-shrink-0 p-2 rounded-lg bg-emerald-500/10 h-fit">
                <feature.icon className="h-5 w-5 text-emerald-400" />
              </div>
              <div>
                <h3 className="text-white font-semibold mb-1">
                  {feature.title}
                </h3>
                <p className="text-sm text-slate-500">{feature.description}</p>
              </div>
            </motion.div>
          ))}
        </div>

        {/* Certifications bar */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="p-6 rounded-xl border border-slate-800 bg-slate-900/50"
        >
          <div className="flex flex-col gap-6">
            <div className="flex items-center gap-3">
              <Clock className="h-6 w-6 text-amber-400" />
              <div>
                <span className="text-white font-semibold block">
                  Certification-Ready Infrastructure
                </span>
                <span className="text-sm text-slate-500">
                  New startup actively pursuing enterprise certifications
                </span>
              </div>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
              {certifications.map((cert) => (
                <div
                  key={cert.name}
                  className="flex flex-col items-center gap-2 p-3 rounded-lg border border-slate-700 bg-slate-800/50"
                >
                  <span className="text-sm font-mono text-slate-300 text-center">
                    {cert.name}
                  </span>
                  <span
                    className={`text-xs px-2 py-0.5 rounded-full ${
                      cert.status === 'Compliant'
                        ? 'bg-emerald-500/20 text-emerald-400'
                        : cert.status === 'In Progress'
                          ? 'bg-amber-500/20 text-amber-400'
                          : 'bg-slate-500/20 text-slate-400'
                    }`}
                  >
                    {cert.status}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* Security measures note */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="mt-8 p-6 rounded-xl border border-cyan-500/30 bg-cyan-500/5"
        >
          <div className="flex items-start gap-3">
            <Shield className="h-5 w-5 text-cyan-400 flex-shrink-0 mt-0.5" />
            <div>
              <h4 className="text-white font-semibold mb-2">
                Enterprise-Grade Security from Day One
              </h4>
              <p className="text-sm text-slate-400 leading-relaxed mb-3">
                While formal third-party audits are in progress, Rock PSOC is
                built on industry-standard security practices including AES-256
                encryption, TLS 1.3, role-based access controls, comprehensive
                audit logging, and data sovereignty options.
              </p>
              <p className="text-sm text-slate-400 leading-relaxed">
                Our infrastructure follows SOC 2 Type II and ISO 27001
                frameworks, with formal certification audits scheduled for Q2
                2026.
              </p>
            </div>
          </div>
        </motion.div>

        {/* Legal links note */}
        <motion.div
          initial={{ opacity: 0 }}
          whileInView={{ opacity: 1 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.2 }}
          className="mt-8 text-center text-sm text-slate-500"
        >
          Review our{' '}
          <button
            onClick={() => navigate('/privacy')}
            className="text-cyan-400 hover:underline"
          >
            Privacy Policy
          </button>{' '}
          and{' '}
          <button
            onClick={() => navigate('/terms')}
            className="text-cyan-400 hover:underline"
          >
            Terms of Service
          </button>{' '}
          for complete legal documentation. For Data Processing Agreements (DPA)
          and Standard Contractual Clauses (SCC), contact our compliance team.
        </motion.div>
      </div>
    </section>
  )
}