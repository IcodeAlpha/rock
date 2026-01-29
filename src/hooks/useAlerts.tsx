import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from './useOrganization';
import { toast } from '@/hooks/use-toast';
import { Alert, Severity } from '@/types/psoc';

interface DBAlert {
  id: string;
  title: string;
  description: string | null;
  severity: string;
  source: string;
  status: string;
  type: string | null;
  acknowledged: boolean | null;
  acknowledged_at: string | null;
  acknowledged_by: string | null;
  organization_id: string | null;
  created_at: string;
}

function mapDBToAlert(db: DBAlert): Alert {
  return {
    id: db.id,
    title: db.title,
    message: db.description || '',
    severity: db.severity as Severity,
    timestamp: new Date(db.created_at),
    acknowledged: db.acknowledged || false,
    source: db.source,
  };
}

export function useAlerts() {
  const { organizationId } = useOrganization();
  const queryClient = useQueryClient();

  const query = useQuery({
    queryKey: ['alerts', organizationId],
    queryFn: async () => {
      if (!organizationId) return [];
      
      const { data, error } = await supabase
        .from('alerts')
        .select('*')
        .eq('organization_id', organizationId)
        .eq('status', 'active')
        .order('created_at', { ascending: false });

      if (error) throw error;
      return (data || []).map(mapDBToAlert);
    },
    enabled: !!organizationId,
  });

  // Real-time subscription for alerts
  useEffect(() => {
    if (!organizationId) return;

    const channel = supabase
      .channel('alerts-realtime')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'alerts',
          filter: `organization_id=eq.${organizationId}`,
        },
        (payload) => {
          console.log('Alerts realtime update:', payload);
          queryClient.invalidateQueries({ queryKey: ['alerts', organizationId] });
          queryClient.invalidateQueries({ queryKey: ['dashboard-stats'] });
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(channel);
    };
  }, [organizationId, queryClient]);

  const createAlert = useMutation({
    mutationFn: async (alert: {
      title: string;
      description: string;
      severity: Severity;
      source: string;
    }) => {
      if (!organizationId) throw new Error('No organization');
      
      const { data, error } = await supabase
        .from('alerts')
        .insert({
          organization_id: organizationId,
          title: alert.title,
          description: alert.description,
          severity: alert.severity,
          source: alert.source,
          status: 'active',
          acknowledged: false,
        })
        .select()
        .single();

      if (error) throw error;
      return data;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      toast({
        title: 'Alert Created',
        description: 'New alert has been logged.',
      });
    },
    onError: (error) => {
      toast({
        title: 'Error creating alert',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  const acknowledgeAlert = useMutation({
    mutationFn: async (alertId: string) => {
      const { error } = await supabase
        .from('alerts')
        .update({ 
          acknowledged: true,
          acknowledged_at: new Date().toISOString(),
        })
        .eq('id', alertId);

      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      toast({
        title: 'Alert Acknowledged',
        description: 'The alert has been marked as acknowledged.',
      });
    },
    onError: (error) => {
      toast({
        title: 'Error acknowledging alert',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  const dismissAlert = useMutation({
    mutationFn: async (alertId: string) => {
      const { error } = await supabase
        .from('alerts')
        .update({ status: 'dismissed' })
        .eq('id', alertId);

      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      toast({
        title: 'Alert Dismissed',
        description: 'The alert has been removed.',
      });
    },
    onError: (error) => {
      toast({
        title: 'Error dismissing alert',
        description: error.message,
        variant: 'destructive',
      });
    },
  });

  const acknowledgeAll = useMutation({
    mutationFn: async () => {
      if (!organizationId) throw new Error('No organization');
      
      const { error } = await supabase
        .from('alerts')
        .update({ 
          acknowledged: true,
          acknowledged_at: new Date().toISOString(),
        })
        .eq('organization_id', organizationId)
        .eq('acknowledged', false);

      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['alerts'] });
      toast({
        title: 'All Alerts Acknowledged',
        description: 'All unacknowledged alerts have been marked as acknowledged.',
      });
    },
  });

  return {
    alerts: query.data || [],
    isLoading: query.isLoading,
    error: query.error,
    createAlert,
    acknowledgeAlert,
    dismissAlert,
    acknowledgeAll,
  };
}
