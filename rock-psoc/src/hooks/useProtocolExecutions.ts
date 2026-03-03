import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { useEffect } from 'react';
import { supabase } from '@/integrations/supabase/client';
import { useOrganization } from './useOrganization';
import { useAuth } from './useAuth';
import { toast } from '@/hooks/use-toast';
import { responseProtocols } from '@/data/mockData';
import { Tables } from '@/integrations/supabase/types';

export interface ProtocolExecution {
  id: string;
  organization_id: string;
  incident_id: string | null;
  level: number;
  protocol_name: string;
  status: string;
  started_by: string;
  started_at: string;
  completed_at: string | null;
  created_at: string;
  steps?: ProtocolStep[];
}

export interface ProtocolStep {
  id: string;
  execution_id: string;
  step_index: number;
  action: string;
  assigned_to: string | null;
  assigned_role: string | null;
  status: string;
  completed_by: string | null;
  completed_at: string | null;
  created_at: string;
  comments?: ProtocolComment[];
  assigned_profile?: { full_name: string | null; email: string } | null;
  completed_profile?: { full_name: string | null; email: string } | null;
}

export interface ProtocolComment {
  id: string;
  step_id: string;
  author_id: string;
  content: string;
  created_at: string;
  author_profile?: { full_name: string | null; email: string } | null;
}

type ProfileRow = Pick<Tables<'profiles'>, 'id' | 'full_name' | 'email'>;
type StepRow = Tables<'protocol_steps'>;
type CommentRow = Tables<'protocol_comments'>;

export function useProtocolExecutions() {
  const { organizationId } = useOrganization();
  const { user } = useAuth();
  const queryClient = useQueryClient();

  // Fetch active executions
  const executionsQuery = useQuery({
    queryKey: ['protocol-executions', organizationId],
    queryFn: async () => {
      if (!organizationId) return [];

      const { data: executions, error } = await supabase
        .from('protocol_executions')
        .select('*')
        .eq('organization_id', organizationId)
        .order('created_at', { ascending: false });

      if (error) throw error;
      return (executions || []) as ProtocolExecution[];
    },
    enabled: !!organizationId,
  });

  // Fetch steps for a specific execution
  const useExecutionSteps = (executionId: string | null) => {
    return useQuery({
      queryKey: ['protocol-steps', executionId],
      queryFn: async () => {
        if (!executionId) return [];

        const { data: steps, error } = await supabase
          .from('protocol_steps')
          .select('*')
          .eq('execution_id', executionId)
          .order('step_index', { ascending: true });

        if (error) throw error;

        // Fetch profiles for assigned_to and completed_by
        const userIds = new Set<string>();
        (steps || []).forEach((s: StepRow) => {
          if (s.assigned_to) userIds.add(s.assigned_to);
          if (s.completed_by) userIds.add(s.completed_by);
        });

        const profileMap: Record<string, { full_name: string | null; email: string }> = {};
        if (userIds.size > 0) {
          const { data: profiles } = await supabase
            .from('profiles')
            .select('id, full_name, email')
            .in('id', Array.from(userIds));
          (profiles || []).forEach((p: ProfileRow) => { profileMap[p.id] = p; });
        }

        // Fetch comments for all steps
        const stepIds = (steps || []).map((s: StepRow) => s.id);
        const commentsMap: Record<string, ProtocolComment[]> = {};
        if (stepIds.length > 0) {
          const { data: comments } = await supabase
            .from('protocol_comments')
            .select('*')
            .in('step_id', stepIds)
            .order('created_at', { ascending: true });

          const commentAuthorIds = new Set<string>();
          (comments || []).forEach((c: CommentRow) => commentAuthorIds.add(c.author_id));

          const commentProfileMap: Record<string, { full_name: string | null; email: string }> = {};
          if (commentAuthorIds.size > 0) {
            const { data: cProfiles } = await supabase
              .from('profiles')
              .select('id, full_name, email')
              .in('id', Array.from(commentAuthorIds));
            (cProfiles || []).forEach((p: ProfileRow) => { commentProfileMap[p.id] = p; });
          }

          (comments || []).forEach((c: CommentRow) => {
            if (!commentsMap[c.step_id]) commentsMap[c.step_id] = [];
            commentsMap[c.step_id].push({
              ...c,
              author_profile: commentProfileMap[c.author_id] || null,
            });
          });
        }

        return (steps || []).map((s: StepRow) => ({
          ...s,
          assigned_profile: s.assigned_to ? profileMap[s.assigned_to] || null : null,
          completed_profile: s.completed_by ? profileMap[s.completed_by] || null : null,
          comments: commentsMap[s.id] || [],
        })) as ProtocolStep[];
      },
      enabled: !!executionId,
    });
  };

  // Real-time subscriptions
  useEffect(() => {
    if (!organizationId) return;

    const channel = supabase
      .channel('protocols-realtime')
      .on('postgres_changes', {
        event: '*',
        schema: 'public',
        table: 'protocol_executions',
        filter: `organization_id=eq.${organizationId}`,
      }, () => {
        queryClient.invalidateQueries({ queryKey: ['protocol-executions', organizationId] });
      })
      .on('postgres_changes', {
        event: '*',
        schema: 'public',
        table: 'protocol_steps',
      }, (payload: { new?: Partial<StepRow>; old?: Partial<StepRow> }) => {
        const executionId = payload.new?.execution_id || payload.old?.execution_id;
        if (executionId) {
          queryClient.invalidateQueries({ queryKey: ['protocol-steps', executionId] });
        }
      })
      .on('postgres_changes', {
        event: '*',
        schema: 'public',
        table: 'protocol_comments',
      }, () => {
        queryClient.invalidateQueries({ queryKey: ['protocol-steps'] });
      })
      .subscribe();

    return () => { supabase.removeChannel(channel); };
  }, [organizationId, queryClient]);

  // Start a new protocol execution
  const startExecution = useMutation({
    mutationFn: async ({ level, incidentId }: { level: number; incidentId?: string }) => {
      if (!organizationId || !user) throw new Error('Not authenticated');

      const protocol = responseProtocols.find(p => p.level === level);
      if (!protocol) throw new Error('Invalid protocol level');

      const { data: execution, error: execError } = await supabase
        .from('protocol_executions')
        .insert({
          organization_id: organizationId,
          incident_id: incidentId || null,
          level,
          protocol_name: protocol.name,
          started_by: user.id,
        })
        .select()
        .single();

      if (execError) throw execError;

      const defaultRoleMap: Record<number, string> = {
        1: 'analyst',
        2: 'analyst',
        3: 'admin',
        4: 'admin',
        5: 'admin',
      };

      const steps = protocol.actions.map((action, i) => ({
        execution_id: execution.id,
        step_index: i,
        action,
        assigned_role: defaultRoleMap[level] || 'analyst',
      }));

      const { error: stepsError } = await supabase
        .from('protocol_steps')
        .insert(steps);

      if (stepsError) throw stepsError;

      return execution;
    },
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ['protocol-executions'] });
      toast({ title: `Level ${vars.level} Protocol Started`, description: 'Team members can now collaborate on steps.' });
    },
    onError: (error: Error) => {
      toast({ title: 'Failed to start protocol', description: error.message, variant: 'destructive' });
    },
  });

  // Complete a step
  const completeStep = useMutation({
    mutationFn: async ({ stepId, executionId }: { stepId: string; executionId: string }) => {
      if (!user) throw new Error('Not authenticated');

      const { error } = await supabase
        .from('protocol_steps')
        .update({
          status: 'completed',
          completed_by: user.id,
          completed_at: new Date().toISOString(),
        })
        .eq('id', stepId);

      if (error) throw error;

      const { data: allSteps } = await supabase
        .from('protocol_steps')
        .select('status')
        .eq('execution_id', executionId);

      const allComplete = allSteps?.every(s => s.status === 'completed');
      if (allComplete) {
        await supabase
          .from('protocol_executions')
          .update({ status: 'completed', completed_at: new Date().toISOString() })
          .eq('id', executionId);
      }
    },
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ['protocol-steps', vars.executionId] });
      queryClient.invalidateQueries({ queryKey: ['protocol-executions'] });
    },
    onError: (error: Error) => {
      toast({ title: 'Failed to complete step', description: error.message, variant: 'destructive' });
    },
  });

  // Assign a step to a team member
  const assignStep = useMutation({
    mutationFn: async ({ stepId, userId, executionId }: { stepId: string; userId: string; executionId: string }) => {
      const { error } = await supabase
        .from('protocol_steps')
        .update({ assigned_to: userId, status: 'in_progress' })
        .eq('id', stepId);

      if (error) throw error;
    },
    onSuccess: (_, vars) => {
      queryClient.invalidateQueries({ queryKey: ['protocol-steps', vars.executionId] });
    },
  });

  // Add a comment to a step
  const addComment = useMutation({
    mutationFn: async ({ stepId, content }: { stepId: string; content: string }) => {
      if (!user) throw new Error('Not authenticated');

      const { error } = await supabase
        .from('protocol_comments')
        .insert({
          step_id: stepId,
          author_id: user.id,
          content,
        });

      if (error) throw error;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['protocol-steps'] });
    },
    onError: (error: Error) => {
      toast({ title: 'Failed to add comment', description: error.message, variant: 'destructive' });
    },
  });

  const activeExecutions = executionsQuery.data?.filter(e => e.status === 'in_progress') || [];
  const completedExecutions = executionsQuery.data?.filter(e => e.status === 'completed') || [];

  return {
    executions: executionsQuery.data || [],
    activeExecutions,
    completedExecutions,
    isLoading: executionsQuery.isLoading,
    startExecution,
    completeStep,
    assignStep,
    addComment,
    useExecutionSteps,
  };
}