/**
 * API Client for FastAPI Backend
 * Handles all HTTP requests to the backend API (port 8001)
 * 
 * Location: src/services/api.ts
 */

import type { 
  Threat, 
  ThreatsResponse, 
  HealthResponse,
  StatsResponse,
  SeverityBreakdownResponse,
  TimelineResponse,
  IntrusionPrediction,
  PhishingPrediction,
  VulnerabilityPrediction,
  BatchPredictionResponse
} from '@/types/api';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001/api';

// ============================================
// ERROR HANDLING
// ============================================

class ApiError extends Error {
  constructor(
    message: string,
    public status: number,
    public data?: unknown
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

async function handleResponse<T>(response: Response): Promise<T> {
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: response.statusText }));
    throw new ApiError(
      error.detail || 'Request failed',
      response.status,
      error
    );
  }
  
  // Handle 204 No Content
  if (response.status === 204) {
    return null as T;
  }
  
  return response.json();
}

// ============================================
// HEALTH & STATUS
// ============================================

export async function checkHealth(): Promise<HealthResponse> {
  const response = await fetch(`${API_BASE_URL}/health`);
  return handleResponse<HealthResponse>(response);
}

// ============================================
// THREATS / PREDICTIONS
// ============================================

export interface ThreatFilters {
  limit?: number;
  offset?: number;
  severity?: string;
  status?: string;
}

export async function getThreats(filters: ThreatFilters = {}): Promise<ThreatsResponse> {
  const params = new URLSearchParams();
  if (filters.limit) params.append('limit', filters.limit.toString());
  if (filters.offset) params.append('offset', filters.offset.toString());
  if (filters.severity) params.append('severity', filters.severity);
  if (filters.status) params.append('status', filters.status);
  
  const response = await fetch(`${API_BASE_URL}/threats?${params}`);
  return handleResponse<ThreatsResponse>(response);
}

export async function getThreatById(id: string): Promise<Threat> {
  const response = await fetch(`${API_BASE_URL}/threats/${id}`);
  return handleResponse<Threat>(response);
}

export async function createThreat(data: Partial<Threat>): Promise<Threat> {
  const response = await fetch(`${API_BASE_URL}/threats`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return handleResponse<Threat>(response);
}

export async function updateThreat(id: string, data: Partial<Threat>): Promise<Threat> {
  const response = await fetch(`${API_BASE_URL}/threats/${id}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  return handleResponse<Threat>(response);
}

export async function deleteThreat(id: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/threats/${id}`, {
    method: 'DELETE',
  });
  return handleResponse<void>(response);
}

// ============================================
// STATISTICS
// ============================================

export async function getStats(): Promise<StatsResponse> {
  const response = await fetch(`${API_BASE_URL}/stats`);
  return handleResponse<StatsResponse>(response);
}

export async function getSeverityBreakdown(): Promise<SeverityBreakdownResponse> {
  const response = await fetch(`${API_BASE_URL}/stats/severity`);
  return handleResponse<SeverityBreakdownResponse>(response);
}

export async function getTimeline(): Promise<TimelineResponse> {
  const response = await fetch(`${API_BASE_URL}/stats/timeline`);
  return handleResponse<TimelineResponse>(response);
}

// ============================================
// ML PREDICTIONS
// ============================================

export interface IntrusionFeatures {
  src_bytes?: number;
  dst_bytes?: number;
  wrong_fragment?: number;
  protocol?: number;
  service?: number;
  duration?: number;
  land?: number;
  urgent?: number;
  hot?: number;
  num_failed_logins?: number;
  [key: string]: number | undefined;
}

export interface PhishingFeatures {
  url_length?: number;
  domain_length?: number;
  path_length?: number;
  query_length?: number;
  num_dots?: number;
  num_hyphens?: number;
  num_underscores?: number;
  num_slashes?: number;
  num_at_symbols?: number;
  num_question_marks?: number;
  has_https?: number;
  has_http?: number;
  has_ip?: number;
  num_subdomains?: number;
  has_port?: number;
  has_suspicious_tld?: number;
  digit_ratio?: number;
  has_double_slash_in_path?: number;
  has_url_shortener?: number;
  has_suspicious_keyword?: number;
  [key: string]: number | undefined;
}

export interface VulnerabilityFeatures {
  days_since_added?: number;
  is_ransomware?: number;
  has_due_date?: number;
  days_until_due?: number;
  vendor_encoded?: number;
  product_encoded?: number;
  description_length?: number;
  [key: string]: number | undefined;
}

export async function predictIntrusion(features: IntrusionFeatures): Promise<IntrusionPrediction> {
  const response = await fetch(`${API_BASE_URL}/predict/intrusion`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ features }),
  });
  return handleResponse<IntrusionPrediction>(response);
}

export async function predictPhishing(features: PhishingFeatures): Promise<PhishingPrediction> {
  const response = await fetch(`${API_BASE_URL}/predict/phishing`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ features }),
  });
  return handleResponse<PhishingPrediction>(response);
}

export async function predictVulnerability(features: VulnerabilityFeatures): Promise<VulnerabilityPrediction> {
  const response = await fetch(`${API_BASE_URL}/predict/vulnerability`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ features }),
  });
  return handleResponse<VulnerabilityPrediction>(response);
}

export async function batchPredict(requests: Array<{ type: string; features: Record<string, number | undefined> }>): Promise<BatchPredictionResponse> {
  const response = await fetch(`${API_BASE_URL}/predict/batch`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(requests),
  });
  return handleResponse<BatchPredictionResponse>(response);
}

// Export ApiError for error handling
export { ApiError };