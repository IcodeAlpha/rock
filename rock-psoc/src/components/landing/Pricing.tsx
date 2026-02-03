import { motion } from 'motion/react'
import { Check, Zap, Building2, Crown, Shield } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { Button } from '@/components/ui/button'

const tiers = [
  {
    name: 'Starter',
    icon: Zap,
    price: '$499',
    period: '/month',
    description: 'Perfect for small security teams getting started',
    target: 'SMBs & Startups',
    features: [
      '5 team members',
      '100 predictions per month',
      'Basic OSINT tools',
      'Email support',
      'Standard response protocols',
      '30-day data retention',
      'Community access',
    ],
    cta: 'Get Started',
    popular: false,
  },
  {
    name: 'Professional',
    icon: Building2,
    price: '$2,499',
    period: '/month',
    description: 'For growing organizations with mature SOCs',
    target: 'Mid-Market',
    features: [
      '25 team members',
      'Unlimited predictions',
      'Full OSINT suite',
      'Priority support (24/5)',
      'Advanced response automation',
      '90-day data retention',
      'SIEM integrations',
      'Custom alert rules',
      'API access',
    ],
    cta: 'Get Started',
    popular: true,
  },
  {
    name: 'Enterprise',
    icon: Crown,
    price: 'Custom',
    period: '',
    description: 'For large organizations protecting critical infrastructure',
    target: 'Large Orgs & Fortune 500',
    features: [
      'Unlimited team members',
      'Unlimited predictions',
      'White-label options',
      'Dedicated support (24/7)',
      'Custom integrations',
      'Custom data retention',
      'On-premise deployment',
      'SLA guarantees',
      'Compliance certifications',
      'Dedicated success manager',
    ],
    cta: 'Contact Sales',
    popular: false,
  },
  {
    name: 'Government',
    icon: Shield,
    price: 'Custom',
    period: '',
    description: 'For public sector and defense organizations',
    target: 'Government & Defense',
    features: [
      'FedRAMP authorized',
      'Air-gapped deployment',
      'Classified data handling',
      'Government-only threat feeds',
      'Compliance reporting',
      'Dedicated infrastructure',
      'Security clearance support',
      'Custom SLAs',
    ],
    cta: 'Request Information',
    popular: false,
  },
]

export function Pricing() {
  const navigate = useNavigate()

  return (
    <section className="relative py-24 bg-[#070b14]">
      {/* Background gradient */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-1/2 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
        <div className="absolute top-1/2 right-1/4 w-96 h-96 bg-emerald-500/5 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-7xl mx-auto px-6">
        {/* Section header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6 }}
          className="text-center mb-16"
        >
          <h2 className="text-4xl md:text-5xl font-bold text-white mb-4">
            Flexible Pricing for Every Organization
          </h2>
          <p className="text-slate-400 text-lg max-w-2xl mx-auto">
            From startups to government agencies. Contact us to discuss your
            specific requirements and deployment options.
          </p>
        </motion.div>

        {/* Pricing grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {tiers.map((tier, index) => (
            <motion.div
              key={tier.name}
              initial={{ opacity: 0, y: 30 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className={`relative p-6 rounded-2xl border backdrop-blur ${
                tier.popular
                  ? 'border-cyan-500/50 bg-slate-900/80'
                  : 'border-slate-800 bg-slate-900/50'
              }`}
            >
              {/* Popular badge */}
              {tier.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                  <div className="px-3 py-1 rounded-full bg-cyan-500 text-slate-900 text-xs font-semibold">
                    MOST POPULAR
                  </div>
                </div>
              )}

              {/* Icon */}
              <div className="inline-flex p-3 rounded-lg bg-cyan-500/10 mb-4">
                <tier.icon className="h-6 w-6 text-cyan-400" />
              </div>

              {/* Tier name and target */}
              <h3 className="text-2xl font-bold text-white mb-1">
                {tier.name}
              </h3>
              <p className="text-sm text-cyan-400 mb-3">{tier.target}</p>

              {/* Price */}
              <div className="mb-4">
                <span className="text-4xl font-bold text-white">
                  {tier.price}
                </span>
                {tier.period && (
                  <span className="text-slate-400">{tier.period}</span>
                )}
              </div>

              {/* Description */}
              <p className="text-sm text-slate-400 mb-6">{tier.description}</p>

              {/* CTA button */}
              <Button
                onClick={() => navigate('/auth')}
                className={`w-full mb-6 ${
                  tier.popular
                    ? 'bg-cyan-500 hover:bg-cyan-400 text-slate-900'
                    : 'bg-slate-800 hover:bg-slate-700 text-white'
                }`}
              >
                {tier.cta}
              </Button>

              {/* Features list */}
              <ul className="space-y-3">
                {tier.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-2">
                    <Check className="h-4 w-4 text-cyan-400 flex-shrink-0 mt-0.5" />
                    <span className="text-sm text-slate-400">{feature}</span>
                  </li>
                ))}
              </ul>
            </motion.div>
          ))}
        </div>

        {/* Bottom note */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          transition={{ duration: 0.6, delay: 0.4 }}
          className="mt-12 text-center"
        >
          <p className="text-slate-500 text-sm">
            All plans include enterprise-grade infrastructure, AES-256
            encryption, and GDPR compliance.
          </p>
          <p className="text-slate-500 text-sm mt-2">
            Annual billing available with 20% discount. Volume pricing for 100+
            users.
          </p>
        </motion.div>
      </div>
    </section>
  )
}