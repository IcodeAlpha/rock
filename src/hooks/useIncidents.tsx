import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from './useOrganization';
import { toast } from '@/hooks/use-toast';
import { Incident, IncidentStatus, Severity, IncidentEvent, ResponseLevel } from '@/types/psoc';
import { Json } from '@/integrations/supabase/types';

interface DBIncident {
  id: string;
  incident_number: string;
  title: string;
  description: string | null;
  severity: string;
  status: string;
  assigned_team: string | null;
  assigned_to: string | null;
  response_level: number | null;
  timeline: Json | null;
  organization_id: string | null;
  prediction_id: string | null;
  source: string | null;
  priority: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
}

function parseTimeline(timeline: Json | null): IncidentEvent[] {
  if (!timeline || !Array.isArray(timeline)) return [];
  return timeline.map((event: unknown) => {
    const e = event as Record<string, unknown>;
    return {
      id: String(e.id || `evt-${Date.now()}`),
      timestamp: new Date(String(e.timestamp || new Date())),
      action: String(e.action || ''),
      actor: String(e.actor || 'System'),
      details: String(e.details || ''),
    };
  });
}

function mapDBToIncident(db: DBIncident): Incident {
  return {
    id: db.id,
    title: db.title,
    description: db.description || '',
    severity: db.severity as Severity,
    status: db.status as IncidentStatus,
    createdAt: new Date(db.created_at),
    updatedAt: new Date(db.updated_at),
    affectedSystems: [],
    assignedTeam: db.assigned_team || 'Unassigned',
    responseLevel: (db.response_level || 1) as ResponseLevel,
    relatedPredictionId: db.prediction_id || undefined,
    timeline: parseTimeline(db.timeline),
  };
}

export function useIncidents() {
  const { organizationId } = useOrganization();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['incidents', organizationId],
    queryFn: async () => {
      if (!organizationId) return [];
      
      const { data, error } = await supabase
        .from('incidents')
        .select('*')
        .eq('organization_id', organizationId)
        .order('created_at', { ascending: false });

      if (error) throw error;
      return (data || []).map(mapDBToIncident);
    },
    enabled: !!organizationId,
  });

  // Real-time subscription for incidents
  useEffect(() => {
    if (!organizationId) return;

    const channel = supabase
      .channel('incidents-realtime')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'incidents',
          filter: `organization_id=eq.${organizationId}`,
        },
        (payload) => {
          console.log('Incidents realtime update:', payload);
          queryClient.invalidateQueries({ queryKey: ['incidents', organizationId] });
          queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [organizationId, queryClient]);

  const createIncident = useMutation({
    mutationFn: async (incident: {
      title: string;
      description: string;
      severity: Severity;
      assignedTeam: string;
      source: string;
    }) => {
      if (!organizationId) throw new Error('No organization');

      // Generate incident number
      const incidentNumber = `INC-${Date.now().toString().slice(-6)}`;
      
      const { data, error } = await supabase
        .from('incidents')
        .insert({
          incident_number: incidentNumber,
          organization_id: organizationId,
          title: incident.title,
          description: incident.description,
          severity: incident.severity,
          status: 'active',
          assigned_team: incident.assignedTeam,
          source: incident.source,
          response_level: 1,
          timeline: [{
            id: `evt-${Date.now()}`,
            timestamp: new Date().toISOString(),
            action: 'Incident Created',
            actor: 'System',
            details: `Source: ${incident.source}`,
          }],
        })
        .select()
        .single();

      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      toast({
        title: 'Incident Created',
        description: 'New incident has been logged.',
      });
    },
    onError: (error) => {
      toast({
        title: 'Error creating incident',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  const resolveIncident = useMutation({
    mutationFn: async (incidentId: string) => {
      if (!organizationId) throw new Error('No organization');

      // Get current incident to update timeline
      const { data: current } = await supabase
        .from('incidents')
        .select('timeline')
        .eq('id', incidentId)
        .single();

      const currentTimeline = Array.isArray(current?.timeline) ? current.timeline : [];
      const newTimeline = [
        ...currentTimeline,
        {
          id: `evt-${Date.now()}`,
          timestamp: new Date().toISOString(),
          action: 'Incident Resolved',
          actor: 'Analyst',
          details: 'Incident marked as resolved',
        },
      ];

      const { error } = await supabase
        .from('incidents')
        .update({ 
          status: 'resolved',
          resolved_at: new Date().toISOString(),
          timeline: newTimeline,
        })
        .eq('id', incidentId);

      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
      toast({
        title: 'Incident Resolved',
        description: 'The incident has been marked as resolved.',
      });
    },
    onError: (error) => {
      toast({
        title: 'Error resolving incident',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  const updateStatus = useMutation({
    mutationFn: async ({ incidentId, status }: { incidentId: string; status: IncidentStatus }) => {
      const { error } = await supabase
        .from('incidents')
        .update({ status })
        .eq('id', incidentId);

      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['incidents'] });
    },
  });

  return {
    incidents: query.data || [],
    isLoading: query.isLoading,
    error: query.error,
    createIncident,
    resolveIncident,
    updateStatus,
  };
}
