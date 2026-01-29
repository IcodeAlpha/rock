import { useState } from 'react';
import { ThreatAnalysisUpload } from '@/components/analysis/ThreatAnalysisUpload';
import { AnalysisReport } from '@/components/analysis/AnalysisReport';
import { PredictionCard } from '@/components/dashboard/PredictionCard';
import { PredictionModal } from '@/components/predictions/PredictionModal';
import { PredictionEngine } from '@/components/predictions/PredictionEngine';
import { usePredictions } from '@/hooks/usePredictions';
import { ThreatPrediction, ThreatAnalysis } from '@/types/psoc';
import { Brain, FileSearch, TrendingUp, Loader2 } from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

export function PredictionsView() {
  const { predictions, isLoading, convertToIncident } = usePredictions();
  const [analyses, setAnalyses] = useState<ThreatAnalysis[]>([]);
  const [selectedPrediction, setSelectedPrediction] = useState<ThreatPrediction | null>(null);

  const handleAnalysisComplete = (analysis: ThreatAnalysis) => {
    setAnalyses(prev => [analysis, ...prev]);
  };

  const handleConvertToIncident = (prediction: ThreatPrediction) => {
    convertToIncident.mutate(prediction);
  };

  const handleAnalysisToIncident = (analysis: ThreatAnalysis) => {
    toast({
      title: "Incident Created",
      description: `Analysis of "${analysis.fileName}" has been converted to an incident.`,
    });
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="w-7 h-7 text-primary" />
            Threat Predictions
          </h1>
          <p className="text-muted-foreground mt-1">
            AI-powered threat forecasting and file analysis
          </p>
        </div>
      </div>

      <Tabs defaultValue="predictions" className="w-full">
        <TabsList className="grid w-full max-w-md grid-cols-2">
          <TabsTrigger value="predictions" className="flex items-center gap-2">
            <TrendingUp className="w-4 h-4" />
            AI Predictions
          </TabsTrigger>
          <TabsTrigger value="analysis" className="flex items-center gap-2">
            <FileSearch className="w-4 h-4" />
            File Analysis
          </TabsTrigger>
        </TabsList>

        <TabsContent value="predictions" className="mt-6">
          {/* Prediction Engine */}
          <PredictionEngine onAnalysisComplete={() => {
            toast({
              title: "Analysis Complete",
              description: "New threat predictions have been generated and saved.",
            });
          }} />

          {/* Predictions Grid */}
          <div className="mt-6">
            <h2 className="text-lg font-semibold mb-4">
              Active Predictions ({predictions.length})
              {isLoading && <Loader2 className="inline w-4 h-4 ml-2 animate-spin" />}
            </h2>
            {predictions.length === 0 && !isLoading ? (
              <div className="p-8 rounded-lg border border-dashed border-border text-center">
                <Brain className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
                <p className="text-muted-foreground">
                  No active predictions. Run the AI Prediction Engine above to generate threat forecasts.
                </p>
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
                {predictions.map((prediction) => (
                  <PredictionCard
                    key={prediction.id}
                    prediction={prediction}
                    onViewDetails={setSelectedPrediction}
                    onConvertToIncident={handleConvertToIncident}
                  />
                ))}
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="analysis" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Upload Section */}
            <ThreatAnalysisUpload onAnalysisComplete={handleAnalysisComplete} />

            {/* Analysis Results */}
            <div className="space-y-4">
              <h2 className="text-lg font-semibold flex items-center gap-2">
                <FileSearch className="w-5 h-5 text-primary" />
                Analysis Results ({analyses.length})
              </h2>
              
              {analyses.length === 0 ? (
                <div className="rounded-xl border border-dashed border-border p-8 text-center">
                  <FileSearch className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
                  <p className="text-muted-foreground">
                    No analysis results yet. Upload files to begin threat analysis.
                  </p>
                </div>
              ) : (
                <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2">
                  {analyses.map((analysis) => (
                    <AnalysisReport 
                      key={analysis.id} 
                      analysis={analysis}
                      onConvertToIncident={handleAnalysisToIncident}
                    />
                  ))}
                </div>
              )}
            </div>
          </div>
        </TabsContent>
      </Tabs>

      {/* Prediction Modal */}
      <PredictionModal
        prediction={selectedPrediction}
        isOpen={!!selectedPrediction}
        onClose={() => setSelectedPrediction(null)}
        onConvertToIncident={handleConvertToIncident}
      />
    </div>
  );
}
