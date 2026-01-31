import { useNavigate } from 'react-router-dom';
import { Shield, ArrowLeft } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Helmet } from 'react-helmet';

const Terms = () => {
  const navigate = useNavigate();

  return (
    <>
      <Helmet>
        <title>Terms of Service - Rock PSOC</title>
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
            <h1 className="text-4xl font-bold text-foreground mb-4">Terms of Service</h1>
            <p className="text-muted-foreground mb-8">
              Last updated:{' '}
              {new Date().toLocaleDateString('en-US', {
                month: 'long',
                day: 'numeric',
                year: 'numeric',
              })}
            </p>

            <div className="prose prose-invert max-w-none space-y-12">
              <section>
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  1. Acceptance of Terms
                </h2>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  By accessing or using Rock PSOC's AI-powered predictive security operations
                  platform ("Service"), you agree to be bound by these Terms of Service
                  ("Terms"). If you are using the Service on behalf of an organization, you
                  represent that you have authority to bind that organization to these Terms.
                </p>
                <p className="text-muted-foreground leading-relaxed">
                  If you do not agree to these Terms, you may not access or use the Service.
                </p>
              </section>

              <section>
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  2. Description of Service
                </h2>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  Rock PSOC provides an AI-powered predictive security operations platform that:
                </p>
                <ul className="list-disc list-inside text-muted-foreground space-y-2">
                  <li>Ingests and analyzes security incident data from SIEM systems</li>
                  <li>Correlates data with OSINT feeds and threat intelligence</li>
                  <li>Generates probability-scored threat predictions</li>
                  <li>Provides automated response workflow capabilities</li>
                  <li>Offers risk visualization and analyst workload metrics</li>
                </ul>
              </section>

              <section>
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  3. Acceptable Use
                </h2>
                <p className="text-muted-foreground leading-relaxed mb-4">You agree not to:</p>
                <ul className="list-disc list-inside text-muted-foreground space-y-2">
                  <li>Use the Service for any unlawful purpose</li>
                  <li>Attempt to gain unauthorized access to any systems</li>
                  <li>Interfere with or disrupt the Service or servers</li>
                  <li>Reverse engineer, decompile, or disassemble the Service</li>
                  <li>Share account credentials with unauthorized parties</li>
                  <li>Use the Service to develop competing products</li>
                  <li>Upload malicious code or content</li>
                  <li>Violate any applicable laws or regulations</li>
                </ul>
              </section>

              <section>
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  4. Data Ownership & Processing
                </h2>
                <h3 className="text-lg font-medium text-foreground/80 mb-3">4.1 Your Data</h3>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  You retain all ownership rights to the security data you upload to the
                  Service. By using the Service, you grant us a limited license to process
                  your data solely for providing the Service.
                </p>

                <h3 className="text-lg font-medium text-foreground/80 mb-3">
                  4.2 Aggregated Data
                </h3>
                <p className="text-muted-foreground leading-relaxed">
                  We may use anonymized, aggregated data to improve our threat prediction
                  models. This data cannot be used to identify you or your organization.
                </p>
              </section>

              <section>
                <h2 className="text-2xl font-semibold text-foreground mb-4">5. Disclaimers</h2>
                <div className="bg-warning/10 border border-warning/30 rounded-lg p-6 mb-4">
                  <p className="text-warning-foreground leading-relaxed">
                    <strong>IMPORTANT:</strong> The Service provides threat predictions based
                    on AI analysis. These predictions are probabilistic and should not be the
                    sole basis for security decisions. We do not guarantee the accuracy of
                    predictions or that all threats will be detected.
                  </p>
                </div>
                <p className="text-muted-foreground leading-relaxed">
                  THE SERVICE IS PROVIDED "AS IS" WITHOUT WARRANTIES OF ANY KIND, EXPRESS OR
                  IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
                  FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT.
                </p>
              </section>

              <section>
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  6. Limitation of Liability
                </h2>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  TO THE MAXIMUM EXTENT PERMITTED BY LAW, ROCK PSOC SHALL NOT BE LIABLE FOR:
                </p>
                <ul className="list-disc list-inside text-muted-foreground space-y-2">
                  <li>Indirect, incidental, special, or consequential damages</li>
                  <li>Loss of profits, data, or business opportunities</li>
                  <li>Security breaches that occur despite using the Service</li>
                  <li>Damages exceeding fees paid in the 12 months preceding the claim</li>
                </ul>
              </section>

              <section>
                <h2 className="text-2xl font-semibold text-foreground mb-4">7. Termination</h2>
                <p className="text-muted-foreground leading-relaxed mb-4">
                  Either party may terminate this agreement:
                </p>
                <ul className="list-disc list-inside text-muted-foreground space-y-2 mb-4">
                  <li>With 30 days' written notice</li>
                  <li>Immediately for material breach</li>
                  <li>Immediately if required by law</li>
                </ul>
                <p className="text-muted-foreground leading-relaxed">
                  Upon termination, you may export your data within 30 days. After this period,
                  we will delete your data in accordance with our retention policy.
                </p>
              </section>

              <section>
                <h2 className="text-2xl font-semibold text-foreground mb-4">
                  8. Contact
                </h2>
                <div className="glass-panel border-primary/20 rounded-lg p-6">
                  <p className="text-foreground mb-2">
                    <strong>Rock PSOC Security Inc.</strong>
                  </p>
                  <p className="text-muted-foreground">Email: legal@rockpsoc.com</p>
                  <p className="text-muted-foreground">
                    Address: 123 Security Boulevard, Suite 500
                  </p>
                </div>
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

export default Terms;