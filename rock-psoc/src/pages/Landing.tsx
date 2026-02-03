import { Helmet } from 'react-helmet'
import {
  Nav,
  Hero,
  ProblemStatement,
  Features,
  ThreatTimeline,
  RiskHeatmap,
  Metrics,
  TargetMarkets,
  Pricing,
  TechStack,
  Compliance,
  CTA,
  Footer,
} from '@/components/landing'

function Landing() {
  return (
    <>
      <Helmet>
        <title>Rock PSOC - Predictive Security Operations Center</title>
        <meta
          name="description"
          content="AI-powered threat prediction engine. See threats before they strike with 5-7 day advance warning."
        />
        <meta
          name="keywords"
          content="cybersecurity, threat prediction, SOC, PSOC, AI security"
        />
      </Helmet>

      <div className="min-h-screen bg-[#0a0f1a]">
        <Nav />
        <main>
          <Hero />
          <ProblemStatement />
          <div id="features">
            <Features />
          </div>
          <div id="timeline">
            <ThreatTimeline />
          </div>
          <RiskHeatmap />
          <Metrics />
          <TargetMarkets />
          <div id="pricing">
            <Pricing />
          </div>
          <TechStack />
          <div id="compliance">
            <Compliance />
          </div>
          <CTA />
        </main>
        <Footer />
      </div>
    </>
  )
}

export default Landing