import { useNavigate } from 'react-router-dom'
import { Shield, Github, Linkedin, Twitter } from 'lucide-react'

const footerLinks = {
  product: [
    { label: 'Features', href: '/#features' },
    { label: 'Pricing', href: '/#pricing' },
    { label: 'Threat Timeline', href: '/#timeline' },
    { label: 'Compliance', href: '/#compliance' },
  ],
  company: [
    { label: 'About', href: '/#about' },
    { label: 'Blog', href: '/#blog' },
    { label: 'Careers', href: '/#careers' },
    { label: 'Contact', href: '/#contact' },
  ],
  legal: [
    { label: 'Privacy Policy', href: '/privacy', isRoute: true },
    { label: 'Terms of Service', href: '/terms', isRoute: true },
    { label: 'Cookie Policy', href: '/privacy#cookies', isRoute: true },
    { label: 'GDPR', href: '/privacy#gdpr', isRoute: true },
  ],
  resources: [
    { label: 'Documentation', href: '/#docs' },
    { label: 'API Reference', href: '/#api' },
    { label: 'Status', href: '/#status' },
    { label: 'Support', href: '/#support' },
  ],
}

export function Footer() {
  const navigate = useNavigate()

  return (
    <footer className="relative bg-[#050810] border-t border-slate-800/50">
      <div className="max-w-6xl mx-auto px-6 py-16">
        {/* Main footer content */}
        <div className="grid grid-cols-2 md:grid-cols-6 gap-8 mb-12">
          {/* Brand column */}
          <div className="col-span-2">
            <div className="flex items-center gap-2 mb-4">
              <div className="p-2 rounded-lg bg-cyan-500/10">
                <Shield className="h-6 w-6 text-cyan-400" />
              </div>
              <span className="text-xl font-bold text-white">Rock PSOC</span>
            </div>
            <p className="text-sm text-slate-500 mb-6 max-w-xs">
              AI-powered predictive security operations. See threats before they
              strike.
            </p>
            <div className="flex items-center gap-4">
              <a
                href="#twitter"
                className="p-2 rounded-lg bg-slate-800/50 text-slate-500 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
              >
                <Twitter className="h-4 w-4" />
              </a>
              <a
                href="#linkedin"
                className="p-2 rounded-lg bg-slate-800/50 text-slate-500 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
              >
                <Linkedin className="h-4 w-4" />
              </a>
              <a
                href="#github"
                className="p-2 rounded-lg bg-slate-800/50 text-slate-500 hover:text-cyan-400 hover:bg-slate-800 transition-colors"
              >
                <Github className="h-4 w-4" />
              </a>
            </div>
          </div>

          {/* Product links */}
          <div>
            <h4 className="text-sm font-semibold text-white mb-4">Product</h4>
            <ul className="space-y-3">
              {footerLinks.product.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    className="text-sm text-slate-500 hover:text-cyan-400 transition-colors"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Company links */}
          <div>
            <h4 className="text-sm font-semibold text-white mb-4">Company</h4>
            <ul className="space-y-3">
              {footerLinks.company.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    className="text-sm text-slate-500 hover:text-cyan-400 transition-colors"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>

          {/* Legal links */}
          <div>
            <h4 className="text-sm font-semibold text-white mb-4">Legal</h4>
            <ul className="space-y-3">
              {footerLinks.legal.map((link) => (
                <li key={link.label}>
                  {link.isRoute ? (
                    <button
                      onClick={() => navigate(link.href)}
                      className="text-sm text-slate-500 hover:text-cyan-400 transition-colors"
                    >
                      {link.label}
                    </button>
                  ) : (
                    <a
                      href={link.href}
                      className="text-sm text-slate-500 hover:text-cyan-400 transition-colors"
                    >
                      {link.label}
                    </a>
                  )}
                </li>
              ))}
            </ul>
          </div>

          {/* Resources links */}
          <div>
            <h4 className="text-sm font-semibold text-white mb-4">Resources</h4>
            <ul className="space-y-3">
              {footerLinks.resources.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    className="text-sm text-slate-500 hover:text-cyan-400 transition-colors"
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Bottom bar */}
        <div className="pt-8 border-t border-slate-800/50">
          <div className="flex flex-col md:flex-row items-center justify-between gap-4">
            <div className="text-sm text-slate-600">
              © {new Date().getFullYear()} Rock PSOC. All rights reserved.
            </div>
            <div className="flex items-center gap-6 text-sm text-slate-600">
              <span className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                All systems operational
              </span>
              <span>SOC 2 Type II Certified</span>
            </div>
          </div>
        </div>
      </div>
    </footer>
  )
}