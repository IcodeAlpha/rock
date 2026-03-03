import { useState } from 'react';
import { ProtocolExecution, ProtocolStep, useProtocolExecutions } from '@/hooks/useProtocolExecutions';
import { useOrganization } from '@/hooks/useOrganization';
import { useAuth } from '@/hooks/useAuth';
import { useQuery } from '@tanstack/react-query';
import { supabase } from '@/integrations/supabase/client';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { cn } from '@/lib/utils';
import {
  CheckCircle, Circle, MessageSquare, Send, User, Clock,
  Shield, ChevronDown, ChevronUp, Loader2
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

interface ActiveExecutionPanelProps {
  execution: ProtocolExecution;
}

export function ActiveExecutionPanel({ execution }: ActiveExecutionPanelProps) {
  const { completeStep, assignStep, addComment, useExecutionSteps } = useProtocolExecutions();
  const { organizationId, canEdit } = useOrganization();
  const { user } = useAuth();
  const { data: steps = [], isLoading } = useExecutionSteps(execution.id);
  const [expandedStep, setExpandedStep] = useState<string | null>(null);
  const [commentText, setCommentText] = useState<Record<string, string>>({});

  // Fetch team members for assignment
  const { data: teamMembers = [] } = useQuery({
    queryKey: ['team-members-list', organizationId],
    queryFn: async () => {
      if (!organizationId) return [];
      const { data } = await supabase
        .from('organization_members')
        .select('user_id, role')
        .eq('organization_id', organizationId);

      if (!data) return [];

      const { data: profiles } = await supabase
        .from('profiles')
        .select('id, full_name, email')
        .in('id', data.map(m => m.user_id));

      return (profiles || []).map(p => ({
        ...p,
        role: data.find(m => m.user_id === p.id)?.role || 'viewer',
      }));
    },
    enabled: !!organizationId,
  });

  const completedCount = steps.filter(s => s.status === 'completed').length;
  const progress = steps.length > 0 ? (completedCount / steps.length) * 100 : 0;

  const handleAddComment = async (stepId: string) => {
    const text = commentText[stepId]?.trim();
    if (!text) return;
    await addComment.mutateAsync({ stepId, content: text });
    setCommentText(prev => ({ ...prev, [stepId]: '' }));
  };

  const getInitials = (name: string | null, email: string) => {
    if (name) return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
    return email.slice(0, 2).toUpperCase();
  };

  if (isLoading) {
    return (
      <div className="rounded-xl border border-border bg-card/50 p-8 flex items-center justify-center">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-primary/30 bg-card/50 backdrop-blur-sm overflow-hidden">
      {/* Header */}
      <div className="p-4 border-b border-border bg-primary/5">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            <h3 className="font-semibold">Level {execution.level}: {execution.protocol_name}</h3>
            <Badge variant={execution.status === 'completed' ? 'default' : 'secondary'}>
              {execution.status === 'completed' ? 'Completed' : 'In Progress'}
            </Badge>
          </div>
          <div className="text-xs text-muted-foreground flex items-center gap-1">
            <Clock className="w-3 h-3" />
            Started {formatDistanceToNow(new Date(execution.started_at), { addSuffix: true })}
          </div>
        </div>

        {/* Progress bar */}
        <div className="flex items-center gap-3">
          <div className="flex-1 h-2 bg-secondary rounded-full overflow-hidden">
            <div
              className="h-full bg-primary rounded-full transition-all duration-500"
              style={{ width: `${progress}%` }}
            />
          </div>
          <span className="text-xs font-medium text-muted-foreground">
            {completedCount}/{steps.length}
          </span>
        </div>
      </div>

      {/* Steps */}
      <div className="divide-y divide-border">
        {steps.map((step) => {
          const isExpanded = expandedStep === step.id;
          const isCompleted = step.status === 'completed';
          const isAssignedToMe = step.assigned_to === user?.id;

          return (
            <div key={step.id} className={cn(
              "transition-all",
              isCompleted && "bg-success/5",
              isAssignedToMe && !isCompleted && "bg-primary/5"
            )}>
              {/* Step row */}
              <div className="p-3 flex items-center gap-3">
                {/* Status icon */}
                {isCompleted ? (
                  <CheckCircle className="w-5 h-5 text-success flex-shrink-0" />
                ) : step.status === 'in_progress' ? (
                  <div className="w-5 h-5 rounded-full border-2 border-primary flex items-center justify-center flex-shrink-0">
                    <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
                  </div>
                ) : (
                  <Circle className="w-5 h-5 text-muted-foreground flex-shrink-0" />
                )}

                {/* Action text */}
                <span className={cn(
                  "text-sm flex-1",
                  isCompleted && "text-success line-through",
                )}>
                  {step.action}
                </span>

                {/* Assignment */}
                <div className="flex items-center gap-2">
                  {step.assigned_profile ? (
                    <div className="flex items-center gap-1">
                      <Avatar className="w-6 h-6">
                        <AvatarFallback className="text-[10px]">
                          {getInitials(step.assigned_profile.full_name, step.assigned_profile.email)}
                        </AvatarFallback>
                      </Avatar>
                      <span className="text-xs text-muted-foreground hidden sm:inline">
                        {step.assigned_profile.full_name || step.assigned_profile.email}
                      </span>
                    </div>
                  ) : canEdit && !isCompleted ? (
                    <Select
                      onValueChange={(userId) => assignStep.mutate({
                        stepId: step.id,
                        userId,
                        executionId: execution.id,
                      })}
                    >
                      <SelectTrigger className="h-7 w-32 text-xs">
                        <SelectValue placeholder="Assign..." />
                      </SelectTrigger>
                      <SelectContent>
                        {teamMembers.map(m => (
                          <SelectItem key={m.id} value={m.id}>
                            <span className="text-xs">{m.full_name || m.email}</span>
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : (
                    <Badge variant="outline" className="text-[10px]">
                      {step.assigned_role || 'Unassigned'}
                    </Badge>
                  )}

                  {/* Complete button */}
                  {!isCompleted && canEdit && (
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 px-2"
                      onClick={() => completeStep.mutate({ stepId: step.id, executionId: execution.id })}
                      disabled={completeStep.isPending}
                    >
                      <CheckCircle className="w-4 h-4" />
                    </Button>
                  )}

                  {/* Completed info */}
                  {isCompleted && step.completed_profile && (
                    <span className="text-xs text-muted-foreground">
                      by {step.completed_profile.full_name || step.completed_profile.email}
                    </span>
                  )}

                  {/* Comment toggle */}
                  <Button
                    size="sm"
                    variant="ghost"
                    className="h-7 px-2"
                    onClick={() => setExpandedStep(isExpanded ? null : step.id)}
                  >
                    <MessageSquare className="w-4 h-4" />
                    {step.comments && step.comments.length > 0 && (
                      <span className="ml-1 text-xs">{step.comments.length}</span>
                    )}
                    {isExpanded ? <ChevronUp className="w-3 h-3 ml-1" /> : <ChevronDown className="w-3 h-3 ml-1" />}
                  </Button>
                </div>
              </div>

              {/* Comments section */}
              {isExpanded && (
                <div className="px-3 pb-3 ml-8 border-t border-border/50 pt-2 space-y-2">
                  {step.comments && step.comments.length > 0 ? (
                    step.comments.map(comment => (
                      <div key={comment.id} className="flex items-start gap-2 text-xs">
                        <Avatar className="w-5 h-5 mt-0.5">
                          <AvatarFallback className="text-[8px]">
                            {comment.author_profile
                              ? getInitials(comment.author_profile.full_name, comment.author_profile.email)
                              : <User className="w-3 h-3" />}
                          </AvatarFallback>
                        </Avatar>
                        <div className="flex-1">
                          <div className="flex items-center gap-2">
                            <span className="font-medium">
                              {comment.author_profile?.full_name || comment.author_profile?.email || 'Unknown'}
                            </span>
                            <span className="text-muted-foreground">
                              {formatDistanceToNow(new Date(comment.created_at), { addSuffix: true })}
                            </span>
                          </div>
                          <p className="text-muted-foreground mt-0.5">{comment.content}</p>
                        </div>
                      </div>
                    ))
                  ) : (
                    <p className="text-xs text-muted-foreground">No comments yet</p>
                  )}

                  {/* Add comment */}
                  <div className="flex items-center gap-2 mt-2">
                    <Input
                      className="h-7 text-xs"
                      placeholder="Add a note..."
                      value={commentText[step.id] || ''}
                      onChange={(e) => setCommentText(prev => ({ ...prev, [step.id]: e.target.value }))}
                      onKeyDown={(e) => e.key === 'Enter' && handleAddComment(step.id)}
                    />
                    <Button
                      size="sm"
                      variant="ghost"
                      className="h-7 px-2"
                      onClick={() => handleAddComment(step.id)}
                      disabled={addComment.isPending || !commentText[step.id]?.trim()}
                    >
                      <Send className="w-3 h-3" />
                    </Button>
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
