/**
 * React Hook: Make ML Predictions via Backend API
 * 
 * Location: src/hooks/useMLPredictions.ts
 */

import { useState, useCallback } from 'react';
import { 
  predictIntrusion, 
  predictPhishing, 
  predictVulnerability,
  type IntrusionFeatures,
  type PhishingFeatures,
  type VulnerabilityFeatures
} from '@/services/api';
import type { 
  IntrusionPrediction, 
  PhishingPrediction, 
  VulnerabilityPrediction 
} from '@/types/api';
import { toast } from 'sonner';

export function useMLPredictions() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Predict network intrusion
  const predictNetworkIntrusion = useCallback(async (
    features: IntrusionFeatures
  ): Promise<IntrusionPrediction | null> => {
    try {
      setLoading(true);
      setError(null);
      
      const prediction = await predictIntrusion(features);
      toast.success(`Detected: ${prediction.attack_type}`);
      
      return prediction;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Intrusion prediction failed';
      setError(message);
      toast.error(message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  // Predict phishing URL
  const predictPhishingURL = useCallback(async (
    features: PhishingFeatures
  ): Promise<PhishingPrediction | null> => {
    try {
      setLoading(true);
      setError(null);
      
      const prediction = await predictPhishing(features);
      
      if (prediction.is_phishing) {
        toast.warning(`Phishing detected! (${(prediction.phishing_probability * 100).toFixed(1)}% confidence)`);
      } else {
        toast.success(`URL appears legitimate (${(prediction.confidence * 100).toFixed(1)}% confidence)`);
      }
      
      return prediction;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Phishing prediction failed';
      setError(message);
      toast.error(message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  // Predict vulnerability risk
  const predictVulnerabilityRisk = useCallback(async (
    features: VulnerabilityFeatures
  ): Promise<VulnerabilityPrediction | null> => {
    try {
      setLoading(true);
      setError(null);
      
      const prediction = await predictVulnerability(features);
      toast.success(`Risk Score: ${prediction.risk_score.toFixed(1)} (${prediction.severity})`);
      
      return prediction;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Vulnerability prediction failed';
      setError(message);
      toast.error(message);
      return null;
    } finally {
      setLoading(false);
    }
  }, []);

  return {
    loading,
    error,
    predictNetworkIntrusion,
    predictPhishingURL,
    predictVulnerabilityRisk,
  };
}