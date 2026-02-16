/**
 * TypeScript Types for Backend API Responses
 * 
 * Location: src/types/api.ts
 */

// ============================================
// HEALTH
// ============================================

export interface HealthResponse {
  status: string;
  timestamp: string;
  environment: string;
  services: {
    supabase: string;
    ml_api: string;
    ml_api_url: string;
  };
}

// ============================================
// THREATS / PREDICTIONS
// ============================================

export interface Threat {
  id: string; // UUID
  organization_id: string | null;
  title: string;
  description: string | null;
  severity: 'low' | 'medium' | 'high' | 'critical';
  probability: number;
  confidence: number | null;
  confidence_score: number | null;
  impact: string | null;
  timeframe: string | null;
  predicted_timeframe: string | null;
  affected_systems: string | string[] | null;
  status: string;
  source: string;
  converted_to_incident_id: string | null;
  indicators: Record<string, unknown> | null;
  created_at: string;
  updated_at: string;
}

export interface ThreatsResponse {
  data: Threat[];
  count: number;
  limit: number;
  offset: number;
}

// ============================================
// STATISTICS
// ============================================

export interface StatsResponse {
  total_threats: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  by_title: Record<string, number>;
  recent_24h: number;
  top_titles: Array<[string, number]>;
}

export interface SeverityBreakdownResponse {
  severity_breakdown: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  total: number;
}

export interface TimelineResponse {
  timeline: Array<{
    date: string;
    count: number;
  }>;
  total_days: number;
  total_threats: number;
}

// ============================================
// ML PREDICTIONS
// ============================================

export interface IntrusionPrediction {
  attack_type: string;
  attack_index: number;
  severity: string;
  confidence: number;
  probabilities: number[];
  all_classes: string[];
}

export interface PhishingPrediction {
  label: 'Phishing' | 'Legitimate';
  is_phishing: boolean;
  confidence: number;
  phishing_probability: number;
}

export interface VulnerabilityPrediction {
  risk_score: number;
  severity: 'Low' | 'Medium' | 'High';
  severity_index: number;
  confidence: number;
}

export interface BatchPredictionResponse {
  predictions: Array<{
    index: number;
    type: string;
    prediction?: IntrusionPrediction | PhishingPrediction | VulnerabilityPrediction;
    error?: string;
  }>;
  total: number;
}

// ============================================
// ERROR
// ============================================

export interface ApiErrorResponse {
  detail: string;
}