import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { 
  Bell, 
  ChevronRight, 
  ChevronLeft,
  Check,
  Shield,
  Network,
  Database,
  Users,
  AlertTriangle,
  Bug
} from 'lucide-react';

interface CreateAlertWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (alert: AlertFormData) => void;
}

export interface AlertFormData {
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  type: string;
  source: string;
}

const alertTypes = [
  { id: 'security', name: 'Security Alert', icon: Shield, description: 'Access violations, authentication issues' },
  { id: 'network', name: 'Network Alert', icon: Network, description: 'Traffic anomalies, connection issues' },
  { id: 'malware', name: 'Malware Detection', icon: Bug, description: 'Virus, ransomware, trojan detection' },
  { id: 'access', name: 'Access Control', icon: Users, description: 'Unauthorized access attempts' },
  { id: 'data', name: 'Data Alert', icon: Database, description: 'Data breach, exfiltration attempts' },
  { id: 'system', name: 'System Alert', icon: AlertTriangle, description: 'System failures, misconfigurations' },
];

const severityOptions = [
  { value: 'low', label: 'Low', color: 'bg-success/20 text-success border-success/30' },
  { value: 'medium', label: 'Medium', color: 'bg-warning/20 text-warning border-warning/30' },
  { value: 'high', label: 'High', color: 'bg-severity-high/20 text-severity-high border-severity-high/30' },
  { value: 'critical', label: 'Critical', color: 'bg-destructive/20 text-destructive border-destructive/30' },
];

export function CreateAlertWizard({ isOpen, onClose, onSubmit }: CreateAlertWizardProps) {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState<AlertFormData>({
    title: '',
    description: '',
    severity: 'medium',
    type: '',
    source: '',
  });

  const totalSteps = 3;

  const handleNext = () => {
    if (step < totalSteps) setStep(step + 1);
  };

  const handleBack = () => {
    if (step > 1) setStep(step - 1);
  };

  const handleSubmit = () => {
    onSubmit(formData);
    onClose();
    setStep(1);
    setFormData({
      title: '',
      description: '',
      severity: 'medium',
      type: '',
      source: '',
    });
  };

  const canProceed = () => {
    switch (step) {
      case 1: return formData.type.length > 0;
      case 2: return formData.title.length > 0 && formData.source.length > 0;
      case 3: return formData.severity;
      default: return false;
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Bell className="w-5 h-5 text-primary" />
            Create New Alert
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
          {/* Step 1: Alert Type */}
          {step === 1 && (
            <div className="space-y-4">
              <div className="text-center mb-6">
                <h3 className="text-lg font-semibold">Alert Type</h3>
                <p className="text-sm text-muted-foreground">Select the type of alert</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                {alertTypes.map((type) => {
                  const Icon = type.icon;
                  return (
                    <button
                      key={type.id}
                      type="button"
                      onClick={() => setFormData(prev => ({ ...prev, type: type.name }))}
                      className={cn(
                        "p-4 rounded-lg border text-left transition-all",
                        formData.type === type.name 
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

          {/* Step 2: Alert Details */}
          {step === 2 && (
            <div className="space-y-4">
              <div className="text-center mb-6">
                <h3 className="text-lg font-semibold">Alert Details</h3>
                <p className="text-sm text-muted-foreground">Describe the alert</p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="title">Alert Title *</Label>
                <Input
                  id="title"
                  placeholder="e.g., Multiple failed login attempts detected"
                  value={formData.title}
                  onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  placeholder="Provide additional details about the alert..."
                  rows={3}
                  value={formData.description}
                  onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="source">Alert Source *</Label>
                <Input
                  id="source"
                  placeholder="e.g., Firewall, SIEM, EDR, IDS"
                  value={formData.source}
                  onChange={(e) => setFormData(prev => ({ ...prev, source: e.target.value }))}
                />
              </div>
            </div>
          )}

          {/* Step 3: Severity & Review */}
          {step === 3 && (
            <div className="space-y-6">
              <div className="text-center mb-6">
                <h3 className="text-lg font-semibold">Severity & Review</h3>
                <p className="text-sm text-muted-foreground">Set severity and review before creating</p>
              </div>

              <div className="space-y-3">
                <Label>Severity Level</Label>
                <div className="grid grid-cols-4 gap-2">
                  {severityOptions.map((option) => (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => setFormData(prev => ({ ...prev, severity: option.value as any }))}
                      className={cn(
                        "p-3 rounded-lg border text-center transition-all",
                        formData.severity === option.value 
                          ? option.color + " ring-2 ring-offset-2 ring-offset-background"
                          : "border-border hover:border-primary/50"
                      )}
                    >
                      <div className="font-medium">{option.label}</div>
                    </button>
                  ))}
                </div>
              </div>

              {/* Summary */}
              <div className="p-4 rounded-lg bg-secondary/30 border border-border">
                <h4 className="font-semibold mb-3">Alert Summary</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Type:</span>
                    <span className="font-medium">{formData.type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Title:</span>
                    <span className="font-medium truncate max-w-[200px]">{formData.title}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Severity:</span>
                    <Badge variant={formData.severity}>{formData.severity}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Source:</span>
                    <span className="font-medium">{formData.source}</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Navigation */}
        <div className="flex justify-between pt-4 border-t border-border">
          <Button 
            variant="ghost" 
            onClick={step === 1 ? onClose : handleBack}
          >
            <ChevronLeft className="w-4 h-4 mr-2" />
            {step === 1 ? 'Cancel' : 'Back'}
          </Button>

          {step < totalSteps ? (
            <Button 
              variant="cyber" 
              onClick={handleNext}
              disabled={!canProceed()}
            >
              Next
              <ChevronRight className="w-4 h-4 ml-2" />
            </Button>
          ) : (
            <Button 
              variant="cyber" 
              onClick={handleSubmit}
              disabled={!canProceed()}
            >
              <Check className="w-4 h-4 mr-2" />
              Create Alert
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
