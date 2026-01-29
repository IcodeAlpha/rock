import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { 
  AlertTriangle, 
  ChevronRight, 
  ChevronLeft,
  Check,
  Users,
  Shield,
  FileText,
  Zap
} from 'lucide-react';

interface CreateIncidentWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (incident: IncidentFormData) => void;
}

export interface IncidentFormData {
  title: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  priority: 'low' | 'medium' | 'high' | 'urgent';
  assignedTeam: string;
  assignedTo: string;
  source: string;
  affectedSystems: string[];
}

const teams = [
  { id: 'soc', name: 'Security Operations', icon: Shield },
  { id: 'ir', name: 'Incident Response', icon: AlertTriangle },
  { id: 'network', name: 'Network Security', icon: Zap },
  { id: 'threat', name: 'Threat Intelligence', icon: FileText },
];

const severityOptions = [
  { value: 'low', label: 'Low', description: 'Minor impact, no immediate action required', color: 'bg-success/20 text-success border-success/30' },
  { value: 'medium', label: 'Medium', description: 'Moderate impact, action needed within 24h', color: 'bg-warning/20 text-warning border-warning/30' },
  { value: 'high', label: 'High', description: 'Significant impact, immediate attention needed', color: 'bg-severity-high/20 text-severity-high border-severity-high/30' },
  { value: 'critical', label: 'Critical', description: 'Severe impact, requires immediate escalation', color: 'bg-destructive/20 text-destructive border-destructive/30' },
];

export function CreateIncidentWizard({ isOpen, onClose, onSubmit }: CreateIncidentWizardProps) {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState<IncidentFormData>({
    title: '',
    description: '',
    severity: 'medium',
    priority: 'medium',
    assignedTeam: '',
    assignedTo: '',
    source: 'manual',
    affectedSystems: [],
  });
  const [systemInput, setSystemInput] = useState('');

  const totalSteps = 4;

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
      priority: 'medium',
      assignedTeam: '',
      assignedTo: '',
      source: 'manual',
      affectedSystems: [],
    });
  };

  const addSystem = () => {
    if (systemInput.trim() && !formData.affectedSystems.includes(systemInput.trim())) {
      setFormData(prev => ({
        ...prev,
        affectedSystems: [...prev.affectedSystems, systemInput.trim()]
      }));
      setSystemInput('');
    }
  };

  const removeSystem = (system: string) => {
    setFormData(prev => ({
      ...prev,
      affectedSystems: prev.affectedSystems.filter(s => s !== system)
    }));
  };

  const canProceed = () => {
    switch (step) {
      case 1: return formData.title.length > 0;
      case 2: return formData.severity && formData.priority;
      case 3: return formData.assignedTeam.length > 0;
      case 4: return true;
      default: return false;
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-warning" />
            Create New Incident
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
        <div className="min-h-[300px]">
          {/* Step 1: Basic Info */}
          {step === 1 && (
            <div className="space-y-4">
              <div className="text-center mb-6">
                <h3 className="text-lg font-semibold">Incident Details</h3>
                <p className="text-sm text-muted-foreground">Describe the security incident</p>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="title">Incident Title *</Label>
                <Input
                  id="title"
                  placeholder="e.g., Suspicious login attempts from unknown IP"
                  value={formData.title}
                  onChange={(e) => setFormData(prev => ({ ...prev, title: e.target.value }))}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  placeholder="Provide detailed information about the incident..."
                  rows={4}
                  value={formData.description}
                  onChange={(e) => setFormData(prev => ({ ...prev, description: e.target.value }))}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="source">Source</Label>
                <Input
                  id="source"
                  placeholder="e.g., SIEM Alert, User Report, Automated Scan"
                  value={formData.source}
                  onChange={(e) => setFormData(prev => ({ ...prev, source: e.target.value }))}
                />
              </div>
            </div>
          )}

          {/* Step 2: Severity & Priority */}
          {step === 2 && (
            <div className="space-y-6">
              <div className="text-center mb-6">
                <h3 className="text-lg font-semibold">Severity & Priority</h3>
                <p className="text-sm text-muted-foreground">Assess the impact and urgency</p>
              </div>

              <div className="space-y-3">
                <Label>Severity Level</Label>
                <div className="grid grid-cols-2 gap-3">
                  {severityOptions.map((option) => (
                    <button
                      key={option.value}
                      type="button"
                      onClick={() => setFormData(prev => ({ ...prev, severity: option.value as any }))}
                      className={cn(
                        "p-4 rounded-lg border text-left transition-all",
                        formData.severity === option.value 
                          ? option.color + " ring-2 ring-offset-2 ring-offset-background"
                          : "border-border hover:border-primary/50"
                      )}
                    >
                      <div className="font-medium">{option.label}</div>
                      <div className="text-xs text-muted-foreground mt-1">{option.description}</div>
                    </button>
                  ))}
                </div>
              </div>

              <div className="space-y-3">
                <Label>Priority</Label>
                <div className="flex gap-2">
                  {['low', 'medium', 'high', 'urgent'].map((p) => (
                    <Button
                      key={p}
                      type="button"
                      variant={formData.priority === p ? 'cyber' : 'outline'}
                      onClick={() => setFormData(prev => ({ ...prev, priority: p as any }))}
                      className="flex-1"
                    >
                      {p.charAt(0).toUpperCase() + p.slice(1)}
                    </Button>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Assignment */}
          {step === 3 && (
            <div className="space-y-6">
              <div className="text-center mb-6">
                <h3 className="text-lg font-semibold">Team Assignment</h3>
                <p className="text-sm text-muted-foreground">Assign the incident to a response team</p>
              </div>

              <div className="grid grid-cols-2 gap-3">
                {teams.map((team) => {
                  const Icon = team.icon;
                  return (
                    <button
                      key={team.id}
                      type="button"
                      onClick={() => setFormData(prev => ({ ...prev, assignedTeam: team.name }))}
                      className={cn(
                        "p-4 rounded-lg border text-left transition-all flex items-center gap-3",
                        formData.assignedTeam === team.name 
                          ? "border-primary bg-primary/10 ring-2 ring-primary ring-offset-2 ring-offset-background"
                          : "border-border hover:border-primary/50"
                      )}
                    >
                      <Icon className="w-5 h-5 text-primary" />
                      <span className="font-medium">{team.name}</span>
                    </button>
                  );
                })}
              </div>

              <div className="space-y-2">
                <Label htmlFor="assignedTo">Assign to Individual (Optional)</Label>
                <Input
                  id="assignedTo"
                  placeholder="e.g., John Smith"
                  value={formData.assignedTo}
                  onChange={(e) => setFormData(prev => ({ ...prev, assignedTo: e.target.value }))}
                />
              </div>
            </div>
          )}

          {/* Step 4: Affected Systems */}
          {step === 4 && (
            <div className="space-y-6">
              <div className="text-center mb-6">
                <h3 className="text-lg font-semibold">Affected Systems</h3>
                <p className="text-sm text-muted-foreground">Identify impacted infrastructure</p>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Add affected system..."
                  value={systemInput}
                  onChange={(e) => setSystemInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && (e.preventDefault(), addSystem())}
                />
                <Button type="button" variant="cyber" onClick={addSystem}>Add</Button>
              </div>

              {formData.affectedSystems.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {formData.affectedSystems.map((system) => (
                    <Badge 
                      key={system} 
                      variant="secondary"
                      className="cursor-pointer hover:bg-destructive/20"
                      onClick={() => removeSystem(system)}
                    >
                      {system} ×
                    </Badge>
                  ))}
                </div>
              )}

              {/* Summary */}
              <div className="mt-6 p-4 rounded-lg bg-secondary/30 border border-border">
                <h4 className="font-semibold mb-3">Incident Summary</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Title:</span>
                    <span className="font-medium">{formData.title}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Severity:</span>
                    <Badge variant={formData.severity}>{formData.severity}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Priority:</span>
                    <span className="font-medium">{formData.priority}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Assigned to:</span>
                    <span className="font-medium">{formData.assignedTeam}</span>
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
              Create Incident
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
