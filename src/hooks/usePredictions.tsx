import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from './useOrganization';
import { toast } from '@/hooks/use-toast';
import { ThreatPrediction, Severity } from '@/types/psoc';

interface DBPrediction {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  probability: number;
  confidence: number;
  impact: string | null;
  timeframe: string | null;
  affected_systems: string[] | null;
  status: string;
  source: string | null;
  organization_id: string | null;
  converted_to_incident_id: string | null;
  created_at: string;
  updated_at: string;
}

// Transform DB prediction to app ThreatPrediction type
function mapDBToThreatPrediction(db: DBPrediction): ThreatPrediction {
  return {
    id: db.id,
    title: db.title,
    description: db.description || '',
    severity: db.severity as Severity,
    probability: Math.round(db.probability * 100),
    confidence: Math.round(db.confidence * 100),
    impactScore: db.impact === 'critical' ? 9 : db.impact === 'high' ? 7 : db.impact === 'medium' ? 5 : 3,
    timeframe: db.timeframe || '24-48 hours',
    affectedSystems: db.affected_systems || [],
    indicators: [], // Not stored in DB currently
    osintCorrelations: [], // Not stored in DB currently
    predictedAt: new Date(db.created_at),
    attackVector: 'AI-Predicted Attack Vector',
    recommendedActions: [
      'Review affected systems',
      'Implement recommended security controls',
      'Monitor for additional indicators',
    ],
  };
}

export function usePredictions() {
  const { organizationId } = useOrganization();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['predictions', organizationId],
    queryFn: async () => {
      if (!organizationId) return [];
      
      const { data, error } = await supabase
        .from('predictions')
        .select('*')
        .eq('organization_id', organizationId)
        .eq('status', 'active')
        .order('created_at', { ascending: false });

      if (error) throw error;
      return (data || []).map(mapDBToThreatPrediction);
    },
    enabled: !!organizationId,
  });

  // Real-time subscription for predictions
  useEffect(() => {
    if (!organizationId) return;

    const channel = supabase
      .channel('predictions-realtime')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'predictions',
          filter: `organization_id=eq.${organizationId}`,
        },
        (payload) => {
          console.log('Predictions realtime update:', payload);
          queryClient.invalidateQueries({ queryKey: ['predictions', organizationId] });
          queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [organizationId, queryClient]);

  const createPrediction = useMutation({
    mutationFn: async (prediction: {
      title: string;
      description: string;
      severity: Severity;
      probability: number;
      confidence: number;
      impact: string;
      timeframe: string;
      affected_systems: string[];
      source?: string;
    }) => {
      if (!organizationId) throw new Error('No organization');
      
      const { data, error } = await supabase
        .from('predictions')
        .insert({
          organization_id: organizationId,
          title: prediction.title,
          description: prediction.description,
          severity: prediction.severity,
          probability: prediction.probability / 100,
          confidence: prediction.confidence / 100,
          impact: prediction.impact,
          timeframe: prediction.timeframe,
          affected_systems: prediction.affected_systems,
          source: prediction.source || 'AI Prediction Engine',
          status: 'active',
        })
        .select()
        .single();

      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['predictions'] });
    },
    onError: (error) => {
      toast({
        title: 'Error creating prediction',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  const convertToIncident = useMutation({
    mutationFn: async (prediction: ThreatPrediction) => {
      if (!organizationId) throw new Error('No organization');

      // Generate incident number
      const incidentNumber = `INC-${Date.now().toString().slice(-6)}`;

      // Create the incident
      const { data: incident, error: incidentError } = await supabase
        .from('incidents')
        .insert({
          incident_number: incidentNumber,
          organization_id: organizationId,
          prediction_id: prediction.id,
          title: prediction.title,
          description: prediction.description,
          severity: prediction.severity,
          status: 'active',
          assigned_team: 'Security Operations',
          response_level: prediction.severity === 'critical' ? 3 : prediction.severity === 'high' ? 2 : 1,
          source: 'prediction',
          timeline: [{
            id: `evt-${Date.now()}`,
            timestamp: new Date().toISOString(),
            action: 'Incident Created from Prediction',
            actor: 'PSOC System',
            details: `Converted from prediction with ${prediction.probability}% probability`,
          }],
        })
        .select()
        .single();

      if (incidentError) throw incidentError;

      // Update prediction status
      const { error: updateError } = await supabase
        .from('predictions')
        .update({ 
          status: 'converted',
          converted_to_incident_id: incident.id,
        })
        .eq('id', prediction.id);

      if (updateError) throw updateError;

      return incident;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['predictions'] });
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      toast({
        title: 'Incident Created',
        description: 'Prediction has been converted to an active incident.',
      });
    },
    onError: (error) => {
      toast({
        title: 'Error converting to incident',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  return {
    predictions: query.data || [],
    isLoading: query.isLoading,
    error: query.error,
    createPrediction,
    convertToIncident,
  };
}
