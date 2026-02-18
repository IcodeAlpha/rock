import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Switch } from '@/components/ui/switch';
import { Brain, Zap, Loader2, CheckCircle, Network, Shield, Bug, Settings2 } from 'lucide-react';
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
  
  // Advanced mode toggles for each type
  const [intrusionAdvanced, setIntrusionAdvanced] = useState(false);
  const [phishingAdvanced, setPhishingAdvanced] = useState(false);
  const [vulnAdvanced, setVulnAdvanced] = useState(false);

  // Intrusion Detection Features
  const [intrusionFeatures, setIntrusionFeatures] = useState({
    // Simple mode (6 features shown by default)
    src_bytes: 1032,
    dst_bytes: 0,
    wrong_fragment: 8,
    protocol: 6,
    duration: 0,
    num_failed_logins: 0,
    
    // Advanced mode only (20+ more features)
    service: 80,
    land: 0,
    urgent: 0,
    hot: 0,
    logged_in: 0,
    num_compromised: 0,
    root_shell: 0,
    su_attempted: 0,
    num_root: 0,
    num_file_creations: 0,
    num_shells: 0,
    num_access_files: 0,
    num_outbound_cmds: 0,
    is_host_login: 0,
    is_guest_login: 0,
    count: 150,
    srv_count: 25,
    serror_rate: 0.0,
    srv_serror_rate: 0.0,
    rerror_rate: 0.0,
    srv_rerror_rate: 0.0,
    same_srv_rate: 1.0,
    diff_srv_rate: 0.0,
    srv_diff_host_rate: 0.0,
    dst_host_count: 255,
    dst_host_srv_count: 255,
    dst_host_same_srv_rate: 1.0,
    dst_host_diff_srv_rate: 0.0,
    dst_host_same_src_port_rate: 1.0,
    dst_host_srv_diff_host_rate: 0.0,
    dst_host_serror_rate: 0.0,
    dst_host_srv_serror_rate: 0.0,
    dst_host_rerror_rate: 0.0,
    dst_host_srv_rerror_rate: 0.0,
  });

  // Phishing Detection Features
  const [phishingURL, setPhishingURL] = useState('');
  const [phishingFeatures, setPhishingFeatures] = useState({
    // Simple mode (6 features shown by default)
    url_length: 189,
    num_dots: 8,
    has_https: 0,
    has_ip: 1,
    num_subdomains: 4,
    has_suspicious_keyword: 1,
    
    // Advanced mode only (20+ more features)
    domain_length: 85,
    path_length: 90,
    query_length: 10,
    num_hyphens: 5,
    num_underscores: 2,
    num_slashes: 6,
    num_at_symbols: 1,
    num_question_marks: 2,
    has_http: 1,
    has_port: 0,
    has_suspicious_tld: 1,
    digit_ratio: 0.15,
    has_double_slash_in_path: 1,
    has_url_shortener: 0,
  });

  // Vulnerability Assessment Features
  const [vulnFeatures, setVulnFeatures] = useState({
    // Simple mode
    days_since_added: 5,
    is_ransomware: 1,
    days_until_due: 3,
    
    // Advanced mode only
    has_due_date: 1,
    vendor_encoded: 12,
    product_encoded: 45,
    description_length: 220,
    cvss_score: 9.8,
    exploitability_score: 3.9,
    impact_score: 5.9,
    has_exploit_available: 1,
    has_patch_available: 0,
    affected_versions_count: 15,
    cwe_id: 79,
    is_remote: 1,
    requires_auth: 0,
    complexity: 1, // Low = 1, Medium = 2, High = 3
  });

  const runIntrusionDetection = async () => {
    setIsAnalyzing(true);
    try {
      console.log('🔍 Running Intrusion Detection...');
      
      const prediction = await predictIntrusion(intrusionFeatures);
      console.log('Intrusion prediction:', prediction);

      await createThreat({
        title: `Network Intrusion: ${prediction.attack_type}`,
        description: `ML model detected ${prediction.attack_type} with ${(prediction.confidence * 100).toFixed(1)}% confidence. Analyzed ${intrusionAdvanced ? '26' : '6'} network features.`,
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
      toast.success(`Detected: ${prediction.attack_type} (${(prediction.confidence * 100).toFixed(1)}% confidence)`);
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

      await createThreat({
        title: prediction.is_phishing ? `⚠️ Phishing URL Detected` : `✅ Legitimate URL`,
        description: `ML model analyzed ${phishingAdvanced ? '26' : '6'} URL features${phishingURL ? ` for: ${phishingURL}` : ''}. Classification: ${prediction.label} with ${(prediction.confidence * 100).toFixed(1)}% confidence.`,
        severity: prediction.is_phishing ? 'high' : 'low',
        probability: prediction.phishing_probability,
        confidence: prediction.confidence,
        impact: prediction.is_phishing ? 'high' : 'low',
        timeframe: prediction.is_phishing ? '24-48 hours' : 'N/A',
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

      await createThreat({
        title: `Vulnerability Risk: ${prediction.severity} (Score: ${prediction.risk_score.toFixed(1)})`,
        description: `ML model assessed ${vulnAdvanced ? '15+' : '3'} vulnerability attributes. Risk score: ${prediction.risk_score.toFixed(1)}/100 with ${(prediction.confidence * 100).toFixed(1)}% confidence.`,
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

          {/* INTRUSION DETECTION TAB */}
          <TabsContent value="intrusion" className="space-y-4">
            <div className="flex items-center justify-between py-2 border-b border-border">
              <div className="flex items-center gap-2">
                <Settings2 className="w-4 h-4 text-muted-foreground" />
                <span className="text-sm font-medium">
                  {intrusionAdvanced ? 'Advanced Mode (26 features)' : 'Simple Mode (6 features)'}
                </span>
              </div>
              <Switch 
                checked={intrusionAdvanced} 
                onCheckedChange={setIntrusionAdvanced}
              />
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 max-h-96 overflow-y-auto pr-2">
              {/* Simple Mode - 6 features always visible */}
              <div>
                <Label>Source Bytes</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.src_bytes}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, src_bytes: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Destination Bytes</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.dst_bytes}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, dst_bytes: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Wrong Fragments</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.wrong_fragment}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, wrong_fragment: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Protocol Type</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.protocol}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, protocol: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Duration (s)</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.duration}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, duration: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Failed Logins</Label>
                <Input 
                  type="number" 
                  value={intrusionFeatures.num_failed_logins}
                  onChange={(e) => setIntrusionFeatures({...intrusionFeatures, num_failed_logins: parseInt(e.target.value) || 0})}
                />
              </div>

              {/* Advanced Mode - Conditional */}
              {intrusionAdvanced && (
                <>
                  <div>
                    <Label>Service</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.service}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, service: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Duration (s)</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.duration}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, duration: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Land (0/1)</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.land}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, land: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Urgent Packets</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.urgent}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, urgent: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Hot Indicators</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.hot}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, hot: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Failed Logins</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.num_failed_logins}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, num_failed_logins: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Logged In (0/1)</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.logged_in}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, logged_in: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Compromised</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.num_compromised}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, num_compromised: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Root Shell (0/1)</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.root_shell}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, root_shell: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Connection Count</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.count}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, count: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Service Count</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.srv_count}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, srv_count: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>SYN Error Rate</Label>
                    <Input 
                      type="number" 
                      step="0.01"
                      value={intrusionFeatures.serror_rate}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, serror_rate: parseFloat(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Same Service Rate</Label>
                    <Input 
                      type="number" 
                      step="0.01"
                      value={intrusionFeatures.same_srv_rate}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, same_srv_rate: parseFloat(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Dst Host Count</Label>
                    <Input 
                      type="number" 
                      value={intrusionFeatures.dst_host_count}
                      onChange={(e) => setIntrusionFeatures({...intrusionFeatures, dst_host_count: parseInt(e.target.value) || 0})}
                    />
                  </div>
                </>
              )}
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
                  Analyzing {intrusionAdvanced ? '26' : '6'} features...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Detect Network Intrusion
                </>
              )}
            </Button>
          </TabsContent>

          {/* PHISHING DETECTION TAB */}
          <TabsContent value="phishing" className="space-y-4">
            <div className="flex items-center justify-between py-2 border-b border-border">
              <div className="flex items-center gap-2">
                <Settings2 className="w-4 h-4 text-muted-foreground" />
                <span className="text-sm font-medium">
                  {phishingAdvanced ? 'Advanced Mode (26 features)' : 'Simple Mode (6 features)'}
                </span>
              </div>
              <Switch 
                checked={phishingAdvanced} 
                onCheckedChange={setPhishingAdvanced}
              />
            </div>

            {/* URL Input Field */}
            <div className="p-4 border border-primary/30 rounded-lg bg-primary/5">
              <Label className="mb-2">Paste URL to Analyze (Optional)</Label>
              <Input 
                type="url"
                placeholder="https://example.com/suspicious-login-verify"
                value={phishingURL}
                onChange={(e) => {
                  const url = e.target.value;
                  setPhishingURL(url);
                  
                  // Auto-extract features from URL
                  if (url) {
                    setPhishingFeatures({
                      ...phishingFeatures,
                      url_length: url.length,
                      num_dots: (url.match(/\./g) || []).length,
                      has_https: url.startsWith('https') ? 1 : 0,
                      has_http: url.startsWith('http://') ? 1 : 0,
                      has_ip: /\d+\.\d+\.\d+\.\d+/.test(url) ? 1 : 0,
                      num_slashes: (url.match(/\//g) || []).length,
                      num_hyphens: (url.match(/-/g) || []).length,
                      num_at_symbols: (url.match(/@/g) || []).length,
                      has_suspicious_keyword: /(verify|update|secure|login|account|confirm)/i.test(url) ? 1 : 0,
                    });
                  }
                }}
                className="font-mono text-sm"
              />
              <p className="text-xs text-muted-foreground mt-2">
                Features will auto-populate from the URL or use manual values below
              </p>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 max-h-96 overflow-y-auto pr-2">
              {/* Simple Mode - 6 features */}
              <div>
                <Label>URL Length</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.url_length}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, url_length: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Number of Dots</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.num_dots}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, num_dots: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Has HTTPS (0/1)</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.has_https}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, has_https: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Has IP Address (0/1)</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.has_ip}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, has_ip: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Number of Subdomains</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.num_subdomains}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, num_subdomains: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Suspicious Keyword (0/1)</Label>
                <Input 
                  type="number" 
                  value={phishingFeatures.has_suspicious_keyword}
                  onChange={(e) => setPhishingFeatures({...phishingFeatures, has_suspicious_keyword: parseInt(e.target.value) || 0})}
                />
              </div>

              {/* Advanced Mode */}
              {phishingAdvanced && (
                <>
                  <div>
                    <Label>Domain Length</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.domain_length}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, domain_length: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Path Length</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.path_length}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, path_length: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Query Length</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.query_length}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, query_length: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Number of Hyphens</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.num_hyphens}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, num_hyphens: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Number of Underscores</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.num_underscores}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, num_underscores: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Number of Slashes</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.num_slashes}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, num_slashes: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>@ Symbols</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.num_at_symbols}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, num_at_symbols: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Question Marks</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.num_question_marks}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, num_question_marks: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Has HTTP (0/1)</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.has_http}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, has_http: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Number of Subdomains</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.num_subdomains}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, num_subdomains: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Has Port (0/1)</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.has_port}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, has_port: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Suspicious TLD (0/1)</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.has_suspicious_tld}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, has_suspicious_tld: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Digit Ratio</Label>
                    <Input 
                      type="number" 
                      step="0.01"
                      value={phishingFeatures.digit_ratio}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, digit_ratio: parseFloat(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Double Slash (0/1)</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.has_double_slash_in_path}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, has_double_slash_in_path: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>URL Shortener (0/1)</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.has_url_shortener}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, has_url_shortener: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Suspicious Keyword (0/1)</Label>
                    <Input 
                      type="number" 
                      value={phishingFeatures.has_suspicious_keyword}
                      onChange={(e) => setPhishingFeatures({...phishingFeatures, has_suspicious_keyword: parseInt(e.target.value) || 0})}
                    />
                  </div>
                </>
              )}
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
                  Analyzing {phishingAdvanced ? '26' : '6'} features...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Detect Phishing URL
                </>
              )}
            </Button>
          </TabsContent>

          {/* VULNERABILITY ASSESSMENT TAB */}
          <TabsContent value="vulnerability" className="space-y-4">
            <div className="flex items-center justify-between py-2 border-b border-border">
              <div className="flex items-center gap-2">
                <Settings2 className="w-4 h-4 text-muted-foreground" />
                <span className="text-sm font-medium">
                  {vulnAdvanced ? 'Advanced Mode (15+ features)' : 'Simple Mode (3 features)'}
                </span>
              </div>
              <Switch 
                checked={vulnAdvanced} 
                onCheckedChange={setVulnAdvanced}
              />
            </div>

            <div className="grid grid-cols-2 md:grid-cols-3 gap-4 max-h-96 overflow-y-auto pr-2">
              {/* Simple Mode */}
              <div>
                <Label>Days Since Added</Label>
                <Input 
                  type="number" 
                  value={vulnFeatures.days_since_added}
                  onChange={(e) => setVulnFeatures({...vulnFeatures, days_since_added: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Is Ransomware (0/1)</Label>
                <Input 
                  type="number" 
                  value={vulnFeatures.is_ransomware}
                  onChange={(e) => setVulnFeatures({...vulnFeatures, is_ransomware: parseInt(e.target.value) || 0})}
                />
              </div>
              <div>
                <Label>Days Until Due</Label>
                <Input 
                  type="number" 
                  value={vulnFeatures.days_until_due}
                  onChange={(e) => setVulnFeatures({...vulnFeatures, days_until_due: parseInt(e.target.value) || 0})}
                />
              </div>

              {/* Advanced Mode */}
              {vulnAdvanced && (
                <>
                  <div>
                    <Label>Has Due Date (0/1)</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.has_due_date}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, has_due_date: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Vendor Encoded</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.vendor_encoded}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, vendor_encoded: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Product Encoded</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.product_encoded}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, product_encoded: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Description Length</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.description_length}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, description_length: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>CVSS Score</Label>
                    <Input 
                      type="number" 
                      step="0.1"
                      value={vulnFeatures.cvss_score}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, cvss_score: parseFloat(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Exploitability Score</Label>
                    <Input 
                      type="number" 
                      step="0.1"
                      value={vulnFeatures.exploitability_score}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, exploitability_score: parseFloat(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Impact Score</Label>
                    <Input 
                      type="number" 
                      step="0.1"
                      value={vulnFeatures.impact_score}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, impact_score: parseFloat(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Exploit Available (0/1)</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.has_exploit_available}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, has_exploit_available: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Patch Available (0/1)</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.has_patch_available}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, has_patch_available: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Affected Versions</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.affected_versions_count}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, affected_versions_count: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>CWE ID</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.cwe_id}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, cwe_id: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Is Remote (0/1)</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.is_remote}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, is_remote: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Requires Auth (0/1)</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.requires_auth}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, requires_auth: parseInt(e.target.value) || 0})}
                    />
                  </div>
                  <div>
                    <Label>Complexity (1-3)</Label>
                    <Input 
                      type="number" 
                      value={vulnFeatures.complexity}
                      onChange={(e) => setVulnFeatures({...vulnFeatures, complexity: parseInt(e.target.value) || 0})}
                    />
                  </div>
                </>
              )}
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
                  Analyzing {vulnAdvanced ? '15+' : '3'} features...
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