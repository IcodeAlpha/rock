/**
 * React Hook: Fetch Dashboard Statistics from Backend
 * 
 * Location: src/hooks/useBackendStats.ts
 */

import { useState, useEffect, useCallback } from 'react';
import { getStats, getSeverityBreakdown, getTimeline } from '@/services/api';
import type { StatsResponse, SeverityBreakdownResponse, TimelineResponse } from '@/types/api';
import { toast } from 'sonner';

export function useBackendStats() {
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [severityBreakdown, setSeverityBreakdown] = useState<SeverityBreakdownResponse | null>(null);
  const [timeline, setTimeline] = useState<TimelineResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  // Fetch all stats
  const fetchStats = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      const [statsData, severityData, timelineData] = await Promise.all([
        getStats(),
        getSeverityBreakdown(),
        getTimeline(),
      ]);
      
      setStats(statsData);
      setSeverityBreakdown(severityData);
      setTimeline(timelineData);
      
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to fetch statistics';
      setError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  }, []);

  // Initial fetch
  useEffect(() => {
    fetchStats();
  }, [fetchStats]);

  // Refresh stats
  const refresh = useCallback(() => {
    fetchStats();
  }, [fetchStats]);

  return {
    stats,
    severityBreakdown,
    timeline,
    loading,
    error,
    refresh,
  };
}