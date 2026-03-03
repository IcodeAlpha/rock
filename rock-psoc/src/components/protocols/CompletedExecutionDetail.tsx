import { useState } from 'react';
import { ProtocolExecution, ProtocolStep, useProtocolExecutions } from '@/hooks/useProtocolExecutions';
import { Badge } from '@/components/ui/badge';
import { Avatar, AvatarFallback } from '@/components/ui/avatar';
import { cn } from '@/lib/utils';
import {
  CheckCircle, ChevronDown, ChevronUp, Clock, Shield,
  MessageSquare, User, Loader2
} from 'lucide-react';
import { formatDistanceToNow, format } from 'date-fns';

interface CompletedExecutionDetailProps {
  execution: ProtocolExecution;
}

export function CompletedExecutionDetail({ execution }: CompletedExecutionDetailProps) {
  const [expanded, setExpanded] = useState(false);
  const { useExecutionSteps } = useProtocolExecutions();
  const { data: steps = [], isLoading } = useExecutionSteps(expanded ? execution.id : null);

  const getInitials = (name: string | null, email: string) => {
    if (name) return name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2);
    return email.slice(0, 2).toUpperCase();
  };

  const duration = execution.completed_at && execution.started_at
    ? formatDistanceToNow(new Date(execution.started_at), { addSuffix: false })
    : null;

  return (
    <div className="rounded-xl border border-border bg-card/50 overflow-hidden transition-all">
      {/* Summary row — clickable */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full p-4 flex items-center justify-between text-left hover:bg-muted/30 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="w-7 h-7 rounded-lg bg-success/20 text-success text-sm font-bold flex items-center justify-center">
            {execution.level}
          </span>
          <div>
            <div className="flex items-center gap-2">
              <span className="font-medium">{execution.protocol_name}</span>
              <Badge variant="default" className="text-[10px]">Completed</Badge>
            </div>
            {execution.incident_id && (
              <p className="text-xs text-muted-foreground mt-0.5">Linked to incident</p>
            )}
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="text-right text-sm text-muted-foreground hidden sm:block">
            {execution.completed_at && (
              <p>{format(new Date(execution.completed_at), 'MMM d, yyyy HH:mm')}</p>
            )}
            {duration && <p className="text-xs">Duration: ~{duration}</p>}
          </div>
          {expanded ? (
            <ChevronUp className="w-4 h-4 text-muted-foreground" />
          ) : (
            <ChevronDown className="w-4 h-4 text-muted-foreground" />
          )}
        </div>
      </button>

      {/* Expanded audit trail */}
      {expanded && (
        <div className="border-t border-border">
          {isLoading ? (
            <div className="p-6 flex items-center justify-center">
              <Loader2 className="w-5 h-5 animate-spin text-muted-foreground" />
            </div>
          ) : (
            <>
              {/* Timeline header */}
              <div className="px-4 py-3 bg-muted/20 flex items-center gap-2 text-xs text-muted-foreground">
                <Clock className="w-3.5 h-3.5" />
                <span>
                  Started {format(new Date(execution.started_at), 'MMM d, yyyy HH:mm')}
                  {execution.completed_at && (
                    <> · Completed {format(new Date(execution.completed_at), 'MMM d, yyyy HH:mm')}</>
                  )}
                </span>
              </div>

              {/* Steps audit trail */}
              <div className="divide-y divide-border">
                {steps.map((step, idx) => (
                  <StepAuditRow key={step.id} step={step} index={idx} getInitials={getInitials} />
                ))}
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

function StepAuditRow({
  step,
  index,
  getInitials,
}: {
  step: ProtocolStep;
  index: number;
  getInitials: (name: string | null, email: string) => string;
}) {
  const [showComments, setShowComments] = useState(false);
  const hasComments = step.comments && step.comments.length > 0;

  return (
    <div className="bg-success/5">
      <div className="p-3 flex items-start gap-3">
        {/* Step number */}
        <div className="flex flex-col items-center gap-1 pt-0.5">
          <CheckCircle className="w-5 h-5 text-success flex-shrink-0" />
        </div>

        {/* Action & metadata */}
        <div className="flex-1 min-w-0">
          <p className="text-sm">{step.action}</p>

          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 mt-1 text-xs text-muted-foreground">
            {/* Assigned to */}
            {step.assigned_profile && (
              <span className="flex items-center gap-1">
                <User className="w-3 h-3" />
                Assigned: {step.assigned_profile.full_name || step.assigned_profile.email}
              </span>
            )}
            {!step.assigned_profile && step.assigned_role && (
              <span className="flex items-center gap-1">
                <Shield className="w-3 h-3" />
                Role: {step.assigned_role}
              </span>
            )}

            {/* Completed by */}
            {step.completed_profile && (
              <span className="flex items-center gap-1">
                <CheckCircle className="w-3 h-3 text-success" />
                Completed by: {step.completed_profile.full_name || step.completed_profile.email}
              </span>
            )}

            {/* Completed at */}
            {step.completed_at && (
              <span className="flex items-center gap-1">
                <Clock className="w-3 h-3" />
                {format(new Date(step.completed_at), 'MMM d, HH:mm')}
              </span>
            )}
          </div>
        </div>

        {/* Comments toggle */}
        {hasComments && (
          <button
            onClick={() => setShowComments(!showComments)}
            className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors px-2 py-1 rounded-md hover:bg-muted/50"
          >
            <MessageSquare className="w-3.5 h-3.5" />
            <span>{step.comments!.length}</span>
            {showComments ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </button>
        )}
      </div>

      {/* Comments */}
      {showComments && hasComments && (
        <div className="ml-11 mr-3 mb-3 space-y-2 border-l-2 border-border pl-3">
          {step.comments!.map(comment => (
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
                    {format(new Date(comment.created_at), 'MMM d, HH:mm')}
                  </span>
                </div>
                <p className="text-muted-foreground mt-0.5">{comment.content}</p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
