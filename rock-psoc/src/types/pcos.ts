export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type IncidentStatus = 'active' | 'investigating' | 'contained' | 'resolved';

export type ResponseLevel = 1 | 2 | 3 | 4 | 5;

export interface ThreatPrediction {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  probability: number;
  confidence: number;
  impactScore: number;
  timeframe: string;
  affectedSystems: string[];
  indicators: string[];
  osintCorrelations: OSINTCorrelation[];
  predictedAt: Date;
  attackVector: string;
  recommendedActions: string[];
}

export interface OSINTCorrelation {
  source: string;
  indicator: string;
  matchScore: number;
  lastSeen: Date;
  type: 'malware' | 'botnet' | 'phishing' | 'darkweb' | 'exploit' | 'apt';
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  createdAt: Date;
  updatedAt: Date;
  affectedSystems: string[];
  assignedTeam: string;
  responseLevel: ResponseLevel;
  relatedPredictionId?: string;
  timeline: IncidentEvent[];
}

export interface IncidentEvent {
  id: string;
  timestamp: Date;
  action: string;
  actor: string;
  details: string;
}

export interface Alert {
  id: string;
  title: string;
  message: string;
  severity: Severity;
  timestamp: Date;
  acknowledged: boolean;
  source: string;
  relatedIncidentId?: string;
}

export interface ResponseProtocol {
  level: ResponseLevel;
  name: string;
  description: string;
  teams: string[];
  actions: string[];
  escalationTime: string;
  color: string;
}

export interface ProtocolStep {
  id: string;
  action: string;
  completed: boolean;
  completedAt?: Date;
  completedBy?: string;
}

export interface ActiveProtocol {
  level: ResponseLevel;
  startedAt: Date;
  currentStepIndex: number;
  steps: ProtocolStep[];
  status: 'in_progress' | 'completed' | 'escalated';
}

export interface DashboardStats {
  activePredictions: number;
  activeIncidents: number;
  unresolvedAlerts: number;
  avgConfidenceScore: number;
  threatsPreventedThisMonth: number;
  costSavedEstimate: number;
}

export interface ThreatAnalysis {
  id: string;
  fileName: string;
  fileType: 'document' | 'screenshot' | 'log' | 'other';
  uploadedAt: Date;
  status: 'analyzing' | 'completed' | 'failed';
  findings: AnalysisFinding[];
  overallSeverity: Severity;
  summary: string;
  recommendations: string[];
}

export interface AnalysisFinding {
  id: string;
  type: 'threat' | 'vulnerability' | 'suspicious' | 'info';
  title: string;
  description: string;
  severity: Severity;
  location?: string;
  confidence: number;
}
