import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Label } from '@/components/ui/label';
import { cn } from '@/lib/utils';
import { 
  FileText, 
  ChevronRight, 
  ChevronLeft,
  Check,
  Calendar,
  BarChart3,
  AlertTriangle,
  TrendingUp,
  Loader2
} from 'lucide-react';

interface GenerateReportWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (options: ReportOptions) => Promise<void>;
  isGenerating?: boolean;
}

export interface ReportOptions {
  reportType: 'weekly' | 'monthly' | 'incident' | 'executive';
  dateRange: string;
  includeMetrics: string[];
}

const reportTypes = [
  { id: 'weekly', name: 'Weekly Summary', icon: Calendar, description: 'Last 7 days security overview' },
  { id: 'monthly', name: 'Monthly Report', icon: BarChart3, description: 'Comprehensive monthly analysis' },
  { id: 'incident', name: 'Incident Report', icon: AlertTriangle, description: 'Detailed incident analysis' },
  { id: 'executive', name: 'Executive Summary', icon: TrendingUp, description: 'High-level strategic overview' },
];

const metricOptions = [
  { id: 'incidents', label: 'Incidents' },
  { id: 'alerts', label: 'Alerts' },
  { id: 'predictions', label: 'Predictions' },
  { id: 'response_times', label: 'Response Times' },
  { id: 'threats_prevented', label: 'Threats Prevented' },
  { id: 'osint_intel', label: 'OSINT Intelligence' },
];

export function GenerateReportWizard({ isOpen, onClose, onSubmit, isGenerating }: GenerateReportWizardProps) {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState<ReportOptions>({
    reportType: 'weekly',
    dateRange: 'Last 7 days',
    includeMetrics: ['incidents', 'alerts', 'predictions'],
  });

  const totalSteps = 2;

  const handleNext = () => {
    if (step < totalSteps) setStep(step + 1);
  };

  const handleBack = () => {
    if (step > 1) setStep(step - 1);
  };

  const handleSubmit = async () => {
    await onSubmit(formData);
    setStep(1);
  };

  const toggleMetric = (metric: string) => {
    setFormData(prev => ({
      ...prev,
      includeMetrics: prev.includeMetrics.includes(metric)
        ? prev.includeMetrics.filter(m => m !== metric)
        : [...prev.includeMetrics, metric]
    }));
  };

  const getDateRange = (type: string) => {
    switch (type) {
      case 'weekly': return 'Last 7 days';
      case 'monthly': return 'Last 30 days';
      case 'incident': return 'As needed';
      case 'executive': return 'Last quarter';
      default: return 'Custom';
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-primary" />
            Generate AI Security Report
          </DialogTitle>
        </DialogHeader>

        {/* Progress Bar */}
        <div className="flex items-center gap-2 mb-6">
          {Array.from({ length: totalSteps }).map((_, i) => (
            <div key={i} className="flex items-center flex-1">
              <div className={cn(
                "w-8 h-8 rounded-full flex items-center justify-center text-sm font-medium border-2 transition-all",
                step > i + 1 ? "bg-primary border-primary text-primary-foreground" :
                step === i + 1 ? "border-primary text-primary" : "border-border text-muted-foreground"
              )}>
                {step > i + 1 ? <Check className="w-4 h-4" /> : i + 1}
              </div>
              {i < totalSteps - 1 && (
                <div className={cn(
                  "h-0.5 flex-1 mx-2 transition-all",
                  step > i + 1 ? "bg-primary" : "bg-border"
                )} />
              )}
            </div>
          ))}
        </div>

        {/* Step Content */}
        <div className="min-h-[280px]">
          {/* Step 1: Report Type */}
          {step === 1 && (
            <div className="space-y-4">
              <div className="text-center mb-6">
                <h3 className="text-lg font-semibold">Report Type</h3>
                <p className="text-sm text-muted-foreground">Select the type of report to generate</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                {reportTypes.map((type) => {
                  const Icon = type.icon;
                  return (
                    <button
                      key={type.id}
                      type="button"
                      onClick={() => {
                        setFormData(prev => ({ 
                          ...prev, 
                          reportType: type.id as any,
                          dateRange: getDateRange(type.id)
                        }));
                      }}
                      className={cn(
                        "p-4 rounded-lg border text-left transition-all",
                        formData.reportType === type.id 
                          ? "border-primary bg-primary/10 ring-2 ring-primary ring-offset-2 ring-offset-background"
                          : "border-border hover:border-primary/50"
                      )}
                    >
                      <div className="flex items-center gap-2 mb-1">
                        <Icon className="w-4 h-4 text-primary" />
                        <span className="font-medium">{type.name}</span>
                      </div>
                      <div className="text-xs text-muted-foreground">{type.description}</div>
                    </button>
                  );
                })}
              </div>
            </div>
          )}

          {/* Step 2: Metrics & Review */}
          {step === 2 && (
            <div className="space-y-6">
              <div className="text-center mb-6">
                <h3 className="text-lg font-semibold">Include Metrics</h3>
                <p className="text-sm text-muted-foreground">Select data to include in the report</p>
              </div>

              <div className="grid grid-cols-3 gap-2">
                {metricOptions.map((metric) => (
                  <Button
                    key={metric.id}
                    type="button"
                    variant={formData.includeMetrics.includes(metric.id) ? 'cyber' : 'outline'}
                    size="sm"
                    onClick={() => toggleMetric(metric.id)}
                  >
                    {formData.includeMetrics.includes(metric.id) && (
                      <Check className="w-3 h-3 mr-1" />
                    )}
                    {metric.label}
                  </Button>
                ))}
              </div>

              {/* Summary */}
              <div className="p-4 rounded-lg bg-secondary/30 border border-border">
                <h4 className="font-semibold mb-3">Report Configuration</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Type:</span>
                    <span className="font-medium capitalize">{formData.reportType} Report</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Period:</span>
                    <span className="font-medium">{formData.dateRange}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Metrics:</span>
                    <span className="font-medium">{formData.includeMetrics.length} selected</span>
                  </div>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-primary/10 border border-primary/30 text-sm">
                <p className="text-primary font-medium">AI-Powered Analysis</p>
                <p className="text-muted-foreground mt-1">
                  The report will be generated using AI to analyze your security data and provide actionable insights.
                </p>
              </div>
            </div>
          )}
        </div>

        {/* Navigation */}
        <div className="flex justify-between pt-4 border-t border-border">
          <Button 
            variant="ghost" 
            onClick={step === 1 ? onClose : handleBack}
            disabled={isGenerating}
          >
            <ChevronLeft className="w-4 h-4 mr-2" />
            {step === 1 ? 'Cancel' : 'Back'}
          </Button>

          {step < totalSteps ? (
            <Button 
              variant="cyber" 
              onClick={handleNext}
            >
              Next
              <ChevronRight className="w-4 h-4 ml-2" />
            </Button>
          ) : (
            <Button 
              variant="cyber" 
              onClick={handleSubmit}
              disabled={isGenerating}
            >
              {isGenerating ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <Check className="w-4 h-4 mr-2" />
                  Generate Report
                </>
              )}
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
