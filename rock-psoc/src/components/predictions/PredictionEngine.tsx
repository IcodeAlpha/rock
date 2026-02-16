import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Brain, Zap, Loader2, CheckCircle } from 'lucide-react';
import { cn } from '@/lib/utils';
import aiBrainBanner from '@/assets/ai-brain-banner.png';
import { createThreat } from '@/services/api';
import { Severity } from '@/types/psoc';

interface PredictionEngineProps {
  onAnalysisComplete: () => void;
}

// Simulated AI prediction scenarios
const predictionScenarios = [
  {
    title: 'Potential Ransomware Campaign Targeting Organization',
    description: 'OSINT analysis indicates elevated ransomware activity in your industry sector. Pattern matching suggests high probability of targeted phishing attempts.',
    severity: 'critical' as Severity,
    probability: 0.78,
    confidence: 0.85,
    impact: 'critical',
    timeframe: '3-5 days',
    affected_systems: ['Email Gateway', 'File Servers', 'Backup Systems'],
    source: 'AI Prediction Engine',
  },
  {
    title: 'DDoS Attack Vector Identified',
    description: 'Network traffic analysis reveals reconnaissance patterns consistent with DDoS preparation targeting public-facing infrastructure.',
    severity: 'high' as Severity,
    probability: 0.65,
    confidence: 0.72,
    impact: 'high',
    timeframe: '5-7 days',
    affected_systems: ['Web Gateway', 'Load Balancer', 'CDN Edge Nodes'],
    source: 'AI Prediction Engine',
  },
  {
    title: 'Credential Stuffing Campaign Detected',
    description: 'Authentication logs show patterns indicating automated credential testing from distributed sources.',
    severity: 'high' as Severity,
    probability: 0.71,
    confidence: 0.80,
    impact: 'high',
    timeframe: '24-48 hours',
    affected_systems: ['Authentication Service', 'User Directory', 'Customer Portal'],
    source: 'AI Prediction Engine',
  },
  {
    title: 'SQL Injection Probes Increasing',
    description: 'Web application firewall logs indicate systematic SQL injection testing against public endpoints.',
    severity: 'medium' as Severity,
    probability: 0.55,
    confidence: 0.68,
    impact: 'medium',
    timeframe: '7-10 days',
    affected_systems: ['Customer Portal', 'API Gateway', 'Database Cluster'],
    source: 'AI Prediction Engine',
  },
  {
    title: 'Insider Threat Behavior Pattern',
    description: 'User behavior analytics flagged unusual data access patterns from privileged accounts during off-hours.',
    severity: 'medium' as Severity,
    probability: 0.48,
    confidence: 0.62,
    impact: 'medium',
    timeframe: '1-2 weeks',
    affected_systems: ['Data Warehouse', 'HR Systems', 'Financial Systems'],
    source: 'AI Prediction Engine',
  },
];

export function PredictionEngine({ onAnalysisComplete }: PredictionEngineProps) {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [progress, setProgress] = useState(0);
  const [stage, setStage] = useState('');
  const [lastAnalysis, setLastAnalysis] = useState<Date | null>(null);
  const [predictionsGenerated, setPredictionsGenerated] = useState(0);

  const stages = [
    'Ingesting historical data...',
    'Analyzing pattern correlations...',
    'Querying OSINT intelligence feeds...',
    'Running AI prediction models...',
    'Calculating probability scores...',
    'Generating threat assessment...',
  ];

  const runAnalysis = async () => {
    console.log('🚀 runAnalysis started');
    setIsAnalyzing(true);
    setProgress(0);

    // Progress through stages
    for (let i = 0; i < stages.length; i++) {
      setStage(stages[i]);
      await new Promise(resolve => setTimeout(resolve, 800));
      setProgress(((i + 1) / stages.length) * 100);
    }

    // Generate 1-3 random predictions
    const numPredictions = Math.floor(Math.random() * 3) + 1;
    const shuffled = [...predictionScenarios].sort(() => Math.random() - 0.5);
    const selectedPredictions = shuffled.slice(0, numPredictions);

    console.log('📊 About to create', numPredictions, 'predictions');

    // Save predictions to backend
    let successCount = 0;
    for (const prediction of selectedPredictions) {
      try {
        console.log('Creating prediction:', prediction);
        const result = await createThreat({
          title: prediction.title,
          description: prediction.description,
          severity: prediction.severity,
          probability: prediction.probability,
          confidence: prediction.confidence,
          impact: prediction.impact,
          timeframe: prediction.timeframe,
          affected_systems: prediction.affected_systems,
          source: prediction.source,
          status: 'active',
        });
        
        console.log('Created successfully:', result);
        if (result) {
          successCount++;
        }
      } catch (error) {
        console.error('Failed to create prediction:', error);
      }
    }

    setLastAnalysis(new Date());
    setPredictionsGenerated(successCount);
    setIsAnalyzing(false);
    console.log('✅ Analysis complete! Created', successCount, 'predictions');
    onAnalysisComplete();
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
      
      <div className="relative flex items-start gap-4">
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
          <h3 className="text-lg font-semibold mb-1">AI Prediction Engine</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Analyze historical incident data and OSINT feeds to predict potential threats 5-7 days in advance.
          </p>

          {isAnalyzing ? (
            <div className="space-y-3">
              <div className="flex items-center gap-2 text-sm">
                <Loader2 className="w-4 h-4 animate-spin text-primary" />
                <span className="text-primary font-medium">{stage}</span>
              </div>
              <div className="h-2 bg-secondary rounded-full overflow-hidden">
                <div 
                  className="h-full bg-gradient-to-r from-primary to-primary/60 transition-all duration-300 ease-out"
                  style={{ width: `${progress}%` }}
                />
              </div>
              <p className="text-xs text-muted-foreground">{Math.round(progress)}% complete</p>
            </div>
          ) : (
            <Button variant="cyber" onClick={runAnalysis}>
              <Zap className="w-4 h-4 mr-2" />
              Predict Potential Incidents
            </Button>
          )}
        </div>

        {!isAnalyzing && (
          <div className="text-right">
            <div className="text-xs text-muted-foreground mb-1">Last Analysis</div>
            <div className="text-sm font-medium">{formatLastAnalysis()}</div>
            {predictionsGenerated > 0 && (
              <div className="flex items-center gap-1 text-xs text-success mt-1">
                <CheckCircle className="w-3 h-3" />
                {predictionsGenerated} prediction{predictionsGenerated > 1 ? 's' : ''} generated
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}