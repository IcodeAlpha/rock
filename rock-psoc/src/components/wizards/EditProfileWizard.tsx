import { useState, useEffect } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import { 
  Building2, 
  ChevronRight, 
  ChevronLeft,
  Check,
  Factory,
  Cpu,
  Globe,
  Shield,
  Users
} from 'lucide-react';

interface EditProfileWizardProps {
  isOpen: boolean;
  onClose: () => void;
  onSubmit: (profile: OrgProfileData) => void;
  initialData?: OrgProfileData;
}

export interface OrgProfileData {
  name: string;
  industry: string;
  industryVerticals: string[];
  criticalSystems: string[];
  suppliers: string[];
  geographies: string[];
  technologies: string[];
  threatActorsOfConcern: string[];
}

const industries = [
  'Critical Infrastructure', 'Financial Services', 'Healthcare', 'Government',
  'Technology', 'Energy', 'Manufacturing', 'Retail', 'Education', 'Telecommunications'
];

const commonSystems = [
  'Active Directory', 'Exchange Server', 'SAP ERP', 'Oracle', 'SCADA/ICS',
  'VMware vSphere', 'Kubernetes', 'AWS', 'Azure', 'Google Cloud'
];

const threatActors = [
  'APT29', 'APT41', 'Lazarus Group', 'Sandworm', 'FIN7', 'Volt Typhoon',
  'Kimsuky', 'Cozy Bear', 'Fancy Bear', 'DarkSide'
];

export function EditProfileWizard({ isOpen, onClose, onSubmit, initialData }: EditProfileWizardProps) {
  const [step, setStep] = useState(1);
  const [formData, setFormData] = useState<OrgProfileData>(initialData || {
    name: '',
    industry: '',
    industryVerticals: [],
    criticalSystems: [],
    suppliers: [],
    geographies: [],
    technologies: [],
    threatActorsOfConcern: [],
  });
  const [inputValues, setInputValues] = useState({
    vertical: '',
    system: '',
    supplier: '',
    geography: '',
    technology: '',
    actor: '',
  });

  useEffect(() => {
    if (initialData) {
      setFormData(initialData);
    }
  }, [initialData]);

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
  };

  const addToArray = (field: keyof OrgProfileData, value: string) => {
    if (value.trim() && Array.isArray(formData[field]) && !(formData[field] as string[]).includes(value.trim())) {
      setFormData(prev => ({
        ...prev,
        [field]: [...(prev[field] as string[]), value.trim()]
      }));
    }
  };

  const removeFromArray = (field: keyof OrgProfileData, value: string) => {
    setFormData(prev => ({
      ...prev,
      [field]: (prev[field] as string[]).filter(v => v !== value)
    }));
  };

  const toggleArrayItem = (field: keyof OrgProfileData, value: string) => {
    const arr = formData[field] as string[];
    if (arr.includes(value)) {
      removeFromArray(field, value);
    } else {
      addToArray(field, value);
    }
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Building2 className="w-5 h-5 text-primary" />
            Organization Risk Profile
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
        <div className="min-h-[320px]">
          {/* Step 1: Basic Info */}
          {step === 1 && (
            <div className="space-y-4">
              <div className="text-center mb-6">
                <Factory className="w-8 h-8 mx-auto text-primary mb-2" />
                <h3 className="text-lg font-semibold">Organization Info</h3>
                <p className="text-sm text-muted-foreground">Basic organization details</p>
              </div>

              <div className="space-y-2">
                <Label htmlFor="name">Organization Name</Label>
                <Input
                  id="name"
                  placeholder="e.g., Acme Corporation"
                  value={formData.name}
                  onChange={(e) => setFormData(prev => ({ ...prev, name: e.target.value }))}
                />
              </div>

              <div className="space-y-2">
                <Label>Primary Industry</Label>
                <div className="flex flex-wrap gap-2">
                  {industries.map((ind) => (
                    <Button
                      key={ind}
                      type="button"
                      variant={formData.industry === ind ? 'cyber' : 'outline'}
                      size="sm"
                      onClick={() => setFormData(prev => ({ ...prev, industry: ind }))}
                    >
                      {ind}
                    </Button>
                  ))}
                </div>
              </div>

              <div className="space-y-2">
                <Label>Industry Verticals</Label>
                <div className="flex gap-2">
                  <Input
                    placeholder="Add vertical..."
                    value={inputValues.vertical}
                    onChange={(e) => setInputValues(prev => ({ ...prev, vertical: e.target.value }))}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        addToArray('industryVerticals', inputValues.vertical);
                        setInputValues(prev => ({ ...prev, vertical: '' }));
                      }
                    }}
                  />
                  <Button 
                    type="button" 
                    variant="outline"
                    onClick={() => {
                      addToArray('industryVerticals', inputValues.vertical);
                      setInputValues(prev => ({ ...prev, vertical: '' }));
                    }}
                  >
                    Add
                  </Button>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {formData.industryVerticals.map((v) => (
                    <Badge key={v} variant="secondary" className="cursor-pointer" onClick={() => removeFromArray('industryVerticals', v)}>
                      {v} ×
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 2: Critical Systems & Tech */}
          {step === 2 && (
            <div className="space-y-4">
              <div className="text-center mb-6">
                <Cpu className="w-8 h-8 mx-auto text-primary mb-2" />
                <h3 className="text-lg font-semibold">Technology Stack</h3>
                <p className="text-sm text-muted-foreground">Critical systems and technologies</p>
              </div>

              <div className="space-y-2">
                <Label>Critical Systems (click to toggle)</Label>
                <div className="flex flex-wrap gap-2">
                  {commonSystems.map((sys) => (
                    <Button
                      key={sys}
                      type="button"
                      variant={formData.criticalSystems.includes(sys) ? 'destructive' : 'outline'}
                      size="sm"
                      onClick={() => toggleArrayItem('criticalSystems', sys)}
                    >
                      {sys}
                    </Button>
                  ))}
                </div>
                <div className="flex gap-2 mt-2">
                  <Input
                    placeholder="Add custom system..."
                    value={inputValues.system}
                    onChange={(e) => setInputValues(prev => ({ ...prev, system: e.target.value }))}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        addToArray('criticalSystems', inputValues.system);
                        setInputValues(prev => ({ ...prev, system: '' }));
                      }
                    }}
                  />
                  <Button 
                    type="button" 
                    variant="outline"
                    onClick={() => {
                      addToArray('criticalSystems', inputValues.system);
                      setInputValues(prev => ({ ...prev, system: '' }));
                    }}
                  >
                    Add
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label>Key Suppliers/Vendors</Label>
                <div className="flex gap-2">
                  <Input
                    placeholder="Add supplier..."
                    value={inputValues.supplier}
                    onChange={(e) => setInputValues(prev => ({ ...prev, supplier: e.target.value }))}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        addToArray('suppliers', inputValues.supplier);
                        setInputValues(prev => ({ ...prev, supplier: '' }));
                      }
                    }}
                  />
                  <Button 
                    type="button" 
                    variant="outline"
                    onClick={() => {
                      addToArray('suppliers', inputValues.supplier);
                      setInputValues(prev => ({ ...prev, supplier: '' }));
                    }}
                  >
                    Add
                  </Button>
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {formData.suppliers.map((s) => (
                    <Badge key={s} variant="secondary" className="cursor-pointer" onClick={() => removeFromArray('suppliers', s)}>
                      {s} ×
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 3: Geographies */}
          {step === 3 && (
            <div className="space-y-4">
              <div className="text-center mb-6">
                <Globe className="w-8 h-8 mx-auto text-primary mb-2" />
                <h3 className="text-lg font-semibold">Geographic Presence</h3>
                <p className="text-sm text-muted-foreground">Regions where you operate</p>
              </div>

              <div className="space-y-2">
                <Label>Operating Regions</Label>
                <div className="flex gap-2">
                  <Input
                    placeholder="Add region..."
                    value={inputValues.geography}
                    onChange={(e) => setInputValues(prev => ({ ...prev, geography: e.target.value }))}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        addToArray('geographies', inputValues.geography);
                        setInputValues(prev => ({ ...prev, geography: '' }));
                      }
                    }}
                  />
                  <Button 
                    type="button" 
                    variant="outline"
                    onClick={() => {
                      addToArray('geographies', inputValues.geography);
                      setInputValues(prev => ({ ...prev, geography: '' }));
                    }}
                  >
                    Add
                  </Button>
                </div>
                <div className="flex flex-wrap gap-2 mt-2">
                  {['North America', 'Europe', 'Asia Pacific', 'Middle East', 'Africa', 'Latin America'].map((region) => (
                    <Button
                      key={region}
                      type="button"
                      variant={formData.geographies.includes(region) ? 'cyber' : 'outline'}
                      size="sm"
                      onClick={() => toggleArrayItem('geographies', region)}
                    >
                      {region}
                    </Button>
                  ))}
                </div>
                <div className="flex flex-wrap gap-1 mt-2">
                  {formData.geographies.filter(g => !['North America', 'Europe', 'Asia Pacific', 'Middle East', 'Africa', 'Latin America'].includes(g)).map((g) => (
                    <Badge key={g} variant="secondary" className="cursor-pointer" onClick={() => removeFromArray('geographies', g)}>
                      {g} ×
                    </Badge>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Step 4: Threat Actors */}
          {step === 4 && (
            <div className="space-y-4">
              <div className="text-center mb-6">
                <Shield className="w-8 h-8 mx-auto text-destructive mb-2" />
                <h3 className="text-lg font-semibold">Threat Actors of Concern</h3>
                <p className="text-sm text-muted-foreground">Known threats targeting your sector</p>
              </div>

              <div className="space-y-2">
                <Label>Threat Actors (click to toggle)</Label>
                <div className="flex flex-wrap gap-2">
                  {threatActors.map((actor) => (
                    <Button
                      key={actor}
                      type="button"
                      variant={formData.threatActorsOfConcern.includes(actor) ? 'destructive' : 'outline'}
                      size="sm"
                      onClick={() => toggleArrayItem('threatActorsOfConcern', actor)}
                    >
                      {actor}
                    </Button>
                  ))}
                </div>
                <div className="flex gap-2 mt-2">
                  <Input
                    placeholder="Add custom threat actor..."
                    value={inputValues.actor}
                    onChange={(e) => setInputValues(prev => ({ ...prev, actor: e.target.value }))}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        e.preventDefault();
                        addToArray('threatActorsOfConcern', inputValues.actor);
                        setInputValues(prev => ({ ...prev, actor: '' }));
                      }
                    }}
                  />
                  <Button 
                    type="button" 
                    variant="outline"
                    onClick={() => {
                      addToArray('threatActorsOfConcern', inputValues.actor);
                      setInputValues(prev => ({ ...prev, actor: '' }));
                    }}
                  >
                    Add
                  </Button>
                </div>
              </div>

              {/* Summary */}
              <div className="mt-4 p-4 rounded-lg bg-secondary/30 border border-border">
                <h4 className="font-semibold mb-3">Profile Summary</h4>
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Organization:</span>
                    <span className="font-medium">{formData.name || 'Not set'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Industry:</span>
                    <span className="font-medium">{formData.industry || 'Not set'}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Critical Systems:</span>
                    <span className="font-medium">{formData.criticalSystems.length}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-muted-foreground">Threat Actors:</span>
                    <span className="font-medium">{formData.threatActorsOfConcern.length}</span>
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
            >
              Next
              <ChevronRight className="w-4 h-4 ml-2" />
            </Button>
          ) : (
            <Button 
              variant="cyber" 
              onClick={handleSubmit}
            >
              <Check className="w-4 h-4 mr-2" />
              Save Profile
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
