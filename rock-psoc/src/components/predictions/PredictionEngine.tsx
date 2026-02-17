import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Brain, Zap, Loader2, CheckCircle, Network, Shield, Bug } from 'lucide-react';
import { cn } from '@/lib/utils';
import aiBrainBanner from '@/assets/ai-brain-banner.png';
import { createThreat } from '@/services/api';
import { predictIntrusion, predictPhishing, predictVulnerability } from '@/services/api';
import { Severity } from '@/types/psoc';
import { toast } from 'sonner';

interface PredictionEngineProps {
  onAnalysisComplete: () => void;
}

export function PredictionEngine({ onAnalysisComplete }: PredictionEngineProps) {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [lastAnalysis, setLastAnalysis] = useState<Date | null>(null);
  const [predictionsGenerated, setPredictionsGenerated] = useState(0);

  // Intrusion Detection Form State
  const [intrusionFeatures, setIntrusionFeatures] = useState({
    src_bytes: 1032,
    dst_bytes: 0,
    wrong_fragment: 8,
    protocol: 373,
    service: 647,
    duration: 0,
    land: 0,
    urgent: 0,
    hot: 0,
    num_failed_logins: 0,
  });

  // Phishing Detection Form State
  const [phishingFeatures, setPhishingFeatures] = useState({
    url_length: 189,
    domain_length: 85,
    num_dots: 8,
    has_https: 0,
    has_ip: 1,
    num_subdomains: 4,
    has_suspicious_keyword: 1,
  });

  // Vulnerability Assessment Form State
  const [vulnFeatures, setVulnFeatures] = useState({
    days_since_added: 5,
    is_ransomware: 1,
    has_due_date: 1,
    days_until_due: 3,
    description_length: 220,
  });

  const runIntrusionDetection = async () => {
    setIsAnalyzing(true);
    try {
      console.log('🔍 Running Intrusion Detection...');
      
      const prediction = await predictIntrusion(intrusionFeatures);
      console.log('Intrusion prediction:', prediction);

      // Save to database
      await createThreat({
        title: `Network Intrusion: ${prediction.attack_type}`,
        description: `ML model detected ${prediction.attack_type} with ${prediction.confidence * 100}% confidence`,
        severity: prediction.severity as Severity,
        probability: prediction.confidence,
        confidence: prediction.confidence,
        impact: prediction.severity,
        timeframe: 'Immediate',
        affected_systems: '{"Network Infrastructure","Firewall","IDS/IPS"}',
        source: 'ML Intrusion Detection',
        status: 'active',
      });

      setPredictionsGenerated(1);
      setLastAnalysis(new Date());
      toast.success(`Detected: ${prediction.attack_type}`);
      onAnalysisComplete();
      
    } catch (error) {
      console.error('Intrusion detection failed:', error);
      toast.error('Failed to run intrusion detection');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const runPhishingDetection = async () => {
    setIsAnalyzing(true);
    try {
      console.log('🎣 Running Phishing Detection...');
      
      const prediction = await predictPhishing(phishingFeatures);
      console.log('Phishing prediction:', prediction);

      // Save to database
      await createThreat({
        title: `Phishing URL Detected`,
        description: `ML model flagged URL as ${prediction.label} with ${(prediction.phishing_probability * 100).toFixed(1)}% probability`,
        severity: prediction.is_phishing ? 'high' : 'low',
        probability: prediction.phishing_probability,
        confidence: prediction.confidence,
        impact: prediction.is_phishing ? 'high' : 'low',
        timeframe: '24-48 hours',
        affected_systems: '{"Email Gateway","Web Proxy","User Endpoints"}',
        source: 'ML Phishing Detection',
        status: 'active',
      });

      setPredictionsGenerated(1);
      setLastAnalysis(new Date());
      toast.success(prediction.is_phishing ? '⚠️ Phishing URL!' : '✅ Legitimate URL');
      onAnalysisComplete();
      
    } catch (error) {
      console.error('Phishing detection failed:', error);
      toast.error('Failed to run phishing detection');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const runVulnerabilityAssessment = async () => {
    setIsAnalyzing(true);
    try {
      console.log('🐛 Running Vulnerability Assessment...');
      
      const prediction = await predictVulnerability(vulnFeatures);
      console.log('Vulnerability prediction:', prediction);

      // Save to database
      await createThreat({
        title: `Vulnerability Risk Assessment`,
        description: `ML model calculated risk score of ${prediction.risk_score.toFixed(1)} (${prediction.severity} severity)`,
        severity: prediction.severity.toLowerCase() as Severity,
        probability: prediction.risk_score / 100,
        confidence: prediction.confidence,
        impact: prediction.severity.toLowerCase(),
        timeframe: prediction.severity === 'High' ? '1-3 days' : '1-2 weeks',
        affected_systems: '{"Application Servers","Database","API Gateway"}',
        source: 'ML Vulnerability Assessment',
        status: 'active',
      });

      setPredictionsGenerated(1);
      setLastAnalysis(new Date());
      toast.success(`Risk Score: ${prediction.risk_score.toFixed(1)} (${prediction.severity})`);
      onAnalysisComplete();
      
    } catch (error) {
      console.error('Vulnerability assessment failed:', error);
      toast.error('Failed to run vulnerability assessment');
    } finally {
      setIsAnalyzing(false);
    }
  };

  const formatLastAnalysis = () => {
    if (!lastAnalysis) return 'Never';
    const diff = Date.now() - lastAnalysis.getTime();
    const minutes = Math.floor(diff / 60000);
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes} min ago`;
    const hours = Math.floor(minutes / 60);
    return `${hours} hour${hours > 1 ? 's' : ''} ago`;
  };

  return (
    <div className="relative p-6 rounded-xl border border-primary/30 overflow-hidden">
      {/* Background Image */}
      <div 
        className="absolute inset-0 opacity-20"
        style={{
          backgroundImage: `url(${aiBrainBanner})`,
          backgroundSize: 'cover',
          backgroundPosition: 'center',
        }}
      />
      <div className="absolute inset-0 bg-gradient-to-r from-background via-background/80 to-background/60" />
      
      <div className="relative">
        <div className="flex items-start gap-4 mb-6">
          <div className={cn(
            "w-16 h-16 rounded-xl flex items-center justify-center transition-all duration-300",
            isAnalyzing 
              ? "bg-primary/20 animate-pulse" 
              : "bg-primary/10"
          )}>
            <Brain className={cn(
              "w-8 h-8 text-primary transition-all",
              isAnalyzing && "animate-pulse"
            )} />
          </div>

          <div className="flex-1">
            <h3 className="text-lg font-semibold mb-1">ML Prediction Engine</h3>
            <p className="text-sm text-muted-foreground">
              Real-time threat detection using trained machine learning models
            </p>
          </div>

          <div className="text-right">
            <div className="text-xs text-muted-foreground mb-1">Last Analysis</div>
            <div className="text-sm font-medium">{formatLastAnalysis()}</div>
            {predictionsGenerated > 0 && (
              <div className="flex items-center gap-1 text-xs text-success mt-1">
                <CheckCircle className="w-3 h-3" />
                {predictionsGenerated} prediction generated
              </div>
            )}
          </div>
        </div>

        <Tabs defaultValue="intrusion" className="w-full">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="intrusion">
              <Network className="w-4 h-4 mr-2" />
              Intrusion
            </TabsTrigger>
            <TabsTrigger value="phishing">
              <Shield className="w-4 h-4 mr-2" />
              Phishing
            </TabsTrigger>
            <TabsTrigger value="vulnerability">
              <Bug className="w-4 h-4 mr-2" />
              Vulnerability
            </TabsTrigger>
          </TabsList>

          {/* Intrusion Detection Tab */}
          <TabsContent value="intrusion" className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Source Bytes</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.src_bytes}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, src_bytes: parseInt(e.target.value)})}
                />
              </div>
              <div>
                <Label>Destination Bytes</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.dst_bytes}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, dst_bytes: parseInt(e.target.value)})}
                />
              </div>
              <div>
                <Label>Wrong Fragments</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.wrong_fragment}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, wrong_fragment: parseInt(e.target.value)})}
                />
              </div>
              <div>
                <Label>Protocol</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.protocol}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, protocol: parseInt(e.target.value)})}
                />
              </div>
            </div>
            <Button 
              variant="cyber" 
              onClick={runIntrusionDetection} 
              disabled={isAnalyzing}
              className="w-full"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Detect Network Intrusion
                </>
              )}
            </Button>
          </TabsContent>

          {/* Phishing Detection Tab */}
          <TabsContent value="phishing" className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>URL Length</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.url_length}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, url_length: parseInt(e.target.value)})}
                />
              </div>
              <div>
                <Label>Domain Length</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.domain_length}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, domain_length: parseInt(e.target.value)})}
                />
              </div>
              <div>
                <Label>Number of Dots</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.num_dots}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, num_dots: parseInt(e.target.value)})}
                />
              </div>
              <div>
                <Label>Has HTTPS (0/1)</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.has_https}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, has_https: parseInt(e.target.value)})}
                />
              </div>
            </div>
            <Button 
              variant="cyber" 
              onClick={runPhishingDetection} 
              disabled={isAnalyzing}
              className="w-full"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Detect Phishing URL
                </>
              )}
            </Button>
          </TabsContent>

          {/* Vulnerability Assessment Tab */}
          <TabsContent value="vulnerability" className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Days Since Added</Label>
                <Input 
                  type="number" 
                  value={vulnFeatures.days_since_added}
                  onChange={(e) => setVulnFeatures({...vulnFeatures, days_since_added: parseInt(e.target.value)})}
                />
              </div>
              <div>
                <Label>Is Ransomware (0/1)</Label>
                <Input 
                  type="number" 
                  value={vulnFeatures.is_ransomware}
                  onChange={(e) => setVulnFeatures({...vulnFeatures, is_ransomware: parseInt(e.target.value)})}
                />
              </div>
              <div>
                <Label>Has Due Date (0/1)</Label>
                <Input 
                  type="number" 
                  value={vulnFeatures.has_due_date}
                  onChange={(e) => setVulnFeatures({...vulnFeatures, has_due_date: parseInt(e.target.value)})}
                />
              </div>
              <div>
                <Label>Days Until Due</Label>
                <Input 
                  type="number" 
                  value={vulnFeatures.days_until_due}
                  onChange={(e) => setVulnFeatures({...vulnFeatures, days_until_due: parseInt(e.target.value)})}
                />
              </div>
            </div>
            <Button 
              variant="cyber" 
              onClick={runVulnerabilityAssessment} 
              disabled={isAnalyzing}
              className="w-full"
            >
              {isAnalyzing ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Assess Vulnerability Risk
                </>
              )}
            </Button>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}