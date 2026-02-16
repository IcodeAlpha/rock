/**
 * React Hook: Fetch Threats from Backend API
 * Replaces direct Supabase queries with backend API calls
 * 
 * Location: src/hooks/useBackendThreats.ts
 */

import { useState, useEffect, useCallback } from 'react';
import { getThreats, getThreatById, createThreat, updateThreat, deleteThreat, type ThreatFilters } from '@/services/api';
import type { Threat, ThreatsResponse } from '@/types/api';
import { toast } from 'sonner';

export function useBackendThreats(initialFilters: ThreatFilters = {}) {
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filters, setFilters] = useState<ThreatFilters>(initialFilters);

  // Fetch threats
  const fetchThreats = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      
      const response: ThreatsResponse = await getThreats(filters);
      setThreats(response.data);
      
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to fetch threats';
      setError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  }, [filters]);

  // Initial fetch
  useEffect(() => {
    fetchThreats();
  }, [fetchThreats]);

  // Refresh threats
  const refresh = useCallback(() => {
    fetchThreats();
  }, [fetchThreats]);

  // Update filters
  const updateFilters = useCallback((newFilters: Partial<ThreatFilters>) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
  }, []);

  // Get single threat
  const getById = useCallback(async (id: string): Promise<Threat | null> => {
    try {
      const threat = await getThreatById(id);
      return threat;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to fetch threat';
      toast.error(message);
      return null;
    }
  }, []);

  // Create threat
  const create = useCallback(async (data: Partial<Threat>): Promise<Threat | null> => {
    try {
      const newThreat = await createThreat(data);
      toast.success('Threat created successfully');
      await fetchThreats(); // Refresh list
      return newThreat;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to create threat';
      toast.error(message);
      return null;
    }
  }, [fetchThreats]);

  // Update threat
  const update = useCallback(async (id: string, data: Partial<Threat>): Promise<Threat | null> => {
    try {
      const updatedThreat = await updateThreat(id, data);
      toast.success('Threat updated successfully');
      await fetchThreats(); // Refresh list
      return updatedThreat;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to update threat';
      toast.error(message);
      return null;
    }
  }, [fetchThreats]);

  // Delete threat
  const remove = useCallback(async (id: string): Promise<boolean> => {
    try {
      await deleteThreat(id);
      toast.success('Threat deleted successfully');
      await fetchThreats(); // Refresh list
      return true;
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to delete threat';
      toast.error(message);
      return false;
    }
  }, [fetchThreats]);

  return {
    threats,
    loading,
    error,
    filters,
    refresh,
    updateFilters,
    getById,
    create,
    update,
    remove,
  };
}