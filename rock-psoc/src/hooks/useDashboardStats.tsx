import { useQuery } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from './useOrganization';
import { DashboardStats } from '@/types/psoc';

export function useDashboardStats() {
  const { organizationId } = useOrganization();

  return useQuery({
    queryKey: ['dashboard-stats', organizationId],
    queryFn: async (): Promise<DashboardStats> => {
      if (!organizationId) {
        return {
          activePredictions: 0,
          activeIncidents: 0,
          unresolvedAlerts: 0,
          avgConfidenceScore: 0,
          threatsPreventedThisMonth: 0,
          costSavedEstimate: 0,
        };
      }

      // Fetch predictions count
      const { count: predictionsCount } = await supabase
        .from('predictions')
        .select('*', { count: 'exact', head: true })
        .eq('organization_id', organizationId)
        .eq('status', 'active');

      // Fetch active incidents count
      const { count: incidentsCount } = await supabase
        .from('incidents')
        .select('*', { count: 'exact', head: true })
        .eq('organization_id', organizationId)
        .neq('status', 'resolved');

      // Fetch unacknowledged alerts count
      const { count: alertsCount } = await supabase
        .from('alerts')
        .select('*', { count: 'exact', head: true })
        .eq('organization_id', organizationId)
        .eq('acknowledged', false)
        .eq('status', 'active');

      // Fetch average confidence from predictions
      const { data: predictions } = await supabase
        .from('predictions')
        .select('confidence')
        .eq('organization_id', organizationId)
        .eq('status', 'active');

      const avgConfidence = predictions && predictions.length > 0
        ? Math.round(predictions.reduce((sum, p) => sum + (p.confidence * 100), 0) / predictions.length)
        : 0;

      // Count resolved incidents this month (threats prevented)
      const startOfMonth = new Date();
      startOfMonth.setDate(1);
      startOfMonth.setHours(0, 0, 0, 0);

      const { count: resolvedCount } = await supabase
        .from('incidents')
        .select('*', { count: 'exact', head: true })
        .eq('organization_id', organizationId)
        .eq('status', 'resolved')
        .gte('resolved_at', startOfMonth.toISOString());

      return {
        activePredictions: predictionsCount || 0,
        activeIncidents: incidentsCount || 0,
        unresolvedAlerts: alertsCount || 0,
        avgConfidenceScore: avgConfidence,
        threatsPreventedThisMonth: resolvedCount || 0,
        costSavedEstimate: (resolvedCount || 0) * 350000, // Estimated $350k per prevented threat
      };
    },
    enabled: !!organizationId,
    staleTime: 30000, // 30 seconds
  });
}
