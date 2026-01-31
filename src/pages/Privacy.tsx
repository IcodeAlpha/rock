import { useNavigate } from 'react-router-dom';
import { Shield, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Helmet } from 'react-helmet';

const Privacy = () => {
  const navigate = useNavigate();

  return (
    <>
      <Helmet>
        <title>Privacy Policy - Rock PSOC</title>
      </Helmet>

      <div className="min-h-screen bg-background">
        {/* Header */}
        <header className="border-b border-border/40 bg-background/80 backdrop-blur-xl sticky top-0 z-50">
          <div className="max-w-4xl mx-auto px-6 py-4">
            <div className="flex items-center justify-between">
              <button onClick={() => navigate('/')} className="flex items-center gap-2">
                <div className="p-1.5 rounded-lg bg-primary/10">
                  <Shield className="h-5 w-5 text-primary" />
                </div>
                <span className="text-lg font-bold text-foreground">Rock PSOC</span>
              </button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate('/')}
                className="text-muted-foreground hover:text-foreground"
              >
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Home
              </Button>
            </div>
          </div>
        </header>

        {/* Content */}
        <main className="max-w-4xl mx-auto px-6 py-16">
          <div className="animate-fade-in">
            <h1 className="text-4xl font-bold text-foreground mb-4">Privacy Policy</h1>
            <p className="text-muted-foreground mb-8">
              Last updated:{' '}
              {new Date().toLocaleDateString('en-US', {
                month: 'long',
                day: 'numeric',
                year: 'numeric',
              })}
            </p>

            <div className="prose prose-invert max-w-none space-y-12">
              <section id="introduction">
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  1. Introduction
                </h2>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  Rock PSOC ("we," "our," or "us") is committed to protecting your
                  privacy and ensuring the security of your personal data. This
                  Privacy Policy explains how we collect, use, disclose, and
                  safeguard your information when you use our AI-powered
                  predictive security operations platform.
                </p>
                <p className="text-muted-foreground leading-relaxed">
                  We comply with the General Data Protection Regulation (GDPR), Data Protection Act (DPA) and other applicable
                  data protection laws.
                </p>
              </section>

              <section id="data-collection">
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  2. Data We Collect
                </h2>
                <h3 className="text-lg font-medium text-foreground/80 mb-3">
                  2.1 Information You Provide
                </h3>
                <ul className="list-disc list-inside text-muted-foreground space-y-2 mb-4">
                  <li>Account information (email, name, organization)</li>
                  <li>Security incident data from your SIEM systems</li>
                  <li>Configuration preferences and alert settings</li>
                  <li>Communications with our support team</li>
                </ul>

                <h3 className="text-lg font-medium text-foreground/80 mb-3">
                  2.2 Automatically Collected Data
                </h3>
                <ul className="list-disc list-inside text-muted-foreground space-y-2 mb-4">
                  <li>Usage analytics and platform interaction data</li>
                  <li>Device and browser information</li>
                  <li>IP addresses and geolocation data</li>
                  <li>Log files and diagnostic information</li>
                </ul>

                <h3 className="text-lg font-medium text-foreground/80 mb-3">
                  2.3 Third-Party Data Sources
                </h3>
                <ul className="list-disc list-inside text-muted-foreground space-y-2">
                  <li>OSINT feeds (publicly available threat intelligence)</li>
                  <li>Dark web monitoring services (anonymized threat data)</li>
                  <li>Malware intelligence feeds</li>
                  <li>Geopolitical signal aggregators</li>
                </ul>
              </section>

              <section id="gdpr">
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  3. GDPR Compliance
                </h2>
                <h3 className="text-lg font-medium text-foreground/80 mb-3">
                  3.1 Legal Basis for Processing
                </h3>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  We process your personal data based on the following legal grounds:
                </p>
                <ul className="list-disc list-inside text-muted-foreground space-y-2 mb-4">
                  <li>
                    <strong className="text-foreground/90">Contract Performance:</strong>{' '}
                    Processing necessary to provide our services
                  </li>
                  <li>
                    <strong className="text-foreground/90">Legitimate Interests:</strong>{' '}
                    Improving our platform and preventing security threats
                  </li>
                  <li>
                    <strong className="text-foreground/90">Consent:</strong> Where you have
                    explicitly agreed to specific processing
                  </li>
                  <li>
                    <strong className="text-foreground/90">Legal Obligation:</strong> Compliance
                    with applicable laws and regulations
                  </li>
                </ul>

                <h3 className="text-lg font-medium text-foreground/80 mb-3">
                  3.2 Your Rights Under GDPR
                </h3>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  As a data subject, you have the following rights:
                </p>
                <ul className="list-disc list-inside text-muted-foreground space-y-2">
                  <li>
                    <strong className="text-foreground/90">Right of Access:</strong> Request a copy
                    of your personal data
                  </li>
                  <li>
                    <strong className="text-foreground/90">Right to Rectification:</strong> Correct
                    inaccurate or incomplete data
                  </li>
                  <li>
                    <strong className="text-foreground/90">Right to Erasure:</strong> Request
                    deletion of your personal data
                  </li>
                  <li>
                    <strong className="text-foreground/90">Right to Restrict Processing:</strong>{' '}
                    Limit how we use your data
                  </li>
                  <li>
                    <strong className="text-foreground/90">Right to Data Portability:</strong>{' '}
                    Receive your data in a structured format
                  </li>
                  <li>
                    <strong className="text-foreground/90">Right to Object:</strong> Object to
                    processing based on legitimate interests
                  </li>
                  <li>
                    <strong className="text-foreground/90">Right to Withdraw Consent:</strong>{' '}
                    Withdraw consent at any time
                  </li>
                </ul>
              </section>

              <section id="data-security">
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  4. Data Security
                </h2>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  We implement industry-leading security measures to protect your data:
                </p>
                <ul className="list-disc list-inside text-muted-foreground space-y-2">
                  <li>AES-256 encryption at rest and TLS 1.3 in transit</li>
                  <li>SOC 2 Type II certified infrastructure</li>
                  <li>Regular penetration testing and security audits</li>
                  <li>Role-based access controls and audit logging</li>
                  <li>Data residency options (EU, US, or on-premises)</li>
                </ul>
              </section>

              <section id="contact">
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  5. Contact Us
                </h2>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  For privacy-related inquiries or to exercise your rights:
                </p>
                <div className="glass-panel border-primary/20 rounded-lg p-6">
                  <p className="text-foreground mb-2">
                    <strong>Data Protection Officer</strong>
                  </p>
                  <p className="text-muted-foreground">Email: privacy@rockpsoc.com</p>
                  <p className="text-muted-foreground">Address: Rock PSOC Security Inc.</p>
                  <p className="text-muted-foreground mb-4">
                    123 Security Boulevard, Suite 500
                  </p>
                  <p className="text-muted-foreground text-sm">
                    We will respond to your request within 30 days as required by GDPR.
                  </p>
                </div>
              </section>

              <section>
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  6. Changes to This Policy
                </h2>
                <p className="text-muted-foreground leading-relaxed">
                  We may update this Privacy Policy periodically. We will notify you of
                  material changes via email or through the platform. Your continued use of
                  Rock PSOC after changes constitutes acceptance of the updated policy.
                </p>
              </section>
            </div>
          </div>
        </main>

        {/* Footer */}
        <footer className="border-t border-border/40 py-8">
          <div className="max-w-4xl mx-auto px-6 text-center text-sm text-muted-foreground">
            © {new Date().getFullYear()} Rock PSOC. All rights reserved.
          </div>
        </footer>
      </div>
    </>
  );
};

export default Privacy;