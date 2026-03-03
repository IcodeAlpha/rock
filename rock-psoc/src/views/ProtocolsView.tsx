import { useState } from 'react';
import { useProtocolExecutions } from '@/hooks/useProtocolExecutions';
import { useOrganization } from '@/hooks/useOrganization';
import { responseProtocols } from '@/data/mockData';
import { ActiveExecutionPanel } from '@/components/protocols/ActiveExecutionPanel';
import { StartProtocolDialog } from '@/components/protocols/StartProtocolDialog';
import { CompletedExecutionDetail } from '@/components/protocols/CompletedExecutionDetail';
import { Shield, Play, History, BookOpen, Plus, Users, Clock, Loader2 } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { formatDistanceToNow } from 'date-fns';

export function ProtocolsView() {
  const [startOpen, setStartOpen] = useState(false);
  const { activeExecutions, completedExecutions, isLoading } = useProtocolExecutions();
  const { canEdit } = useOrganization();

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="w-7 h-7 text-primary" />
            Response Protocols
          </h1>
          <p className="text-muted-foreground mt-1">
            Collaborative incident response — assign, track, and comment in real-time
          </p>
        </div>
        {canEdit && (
          <Button onClick={() => setStartOpen(true)} className="gap-2">
            <Plus className="w-4 h-4" />
            Launch Protocol
          </Button>
        )}
      </div>

      <Tabs defaultValue="active" className="w-full">
        <TabsList className="grid w-full max-w-lg grid-cols-3">
          <TabsTrigger value="active" className="flex items-center gap-2">
            <Play className="w-4 h-4" />
            Active
            {activeExecutions.length > 0 && (
              <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-[10px]">
                {activeExecutions.length}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="history" className="flex items-center gap-2">
            <History className="w-4 h-4" />
            History
          </TabsTrigger>
          <TabsTrigger value="guide" className="flex items-center gap-2">
            <BookOpen className="w-4 h-4" />
            Guide
          </TabsTrigger>
        </TabsList>

        {/* Active Protocols */}
        <TabsContent value="active" className="mt-6">
          {isLoading ? (
            <div className="flex items-center justify-center p-12">
              <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
            </div>
          ) : activeExecutions.length === 0 ? (
            <div className="p-12 text-center rounded-lg border border-dashed border-border">
              <Shield className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
              <p className="text-muted-foreground mb-4">No active response protocols</p>
              {canEdit && (
                <Button variant="outline" onClick={() => setStartOpen(true)}>
                  <Play className="w-4 h-4 mr-2" />
                  Launch a Protocol
                </Button>
              )}
            </div>
          ) : (
            <div className="space-y-6">
              {activeExecutions.map(exec => (
                <ActiveExecutionPanel key={exec.id} execution={exec} />
              ))}
            </div>
          )}
        </TabsContent>

        {/* History */}
        <TabsContent value="history" className="mt-6">
          <div className="space-y-4">
            <h2 className="text-lg font-semibold">Completed Protocol Executions</h2>
            <p className="text-sm text-muted-foreground">Click any execution to view the full audit trail with step assignments, completions, and comments.</p>
            {completedExecutions.length === 0 ? (
              <div className="p-12 text-center rounded-lg border border-dashed border-border">
                <History className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
                <p className="text-muted-foreground">No completed protocols yet</p>
              </div>
            ) : (
              <div className="space-y-3">
                {completedExecutions.map((exec) => (
                  <CompletedExecutionDetail key={exec.id} execution={exec} />
                ))}
              </div>
            )}
          </div>
        </TabsContent>

        {/* Guide */}
        <TabsContent value="guide" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {responseProtocols.map((protocol) => (
              <div key={protocol.level} className="p-4 rounded-lg border border-border bg-card/50">
                <div className="flex items-center gap-2 mb-3">
                  <span className="w-8 h-8 rounded-lg bg-primary/20 text-primary font-bold flex items-center justify-center">
                    {protocol.level}
                  </span>
                  <h3 className="font-medium">{protocol.name}</h3>
                </div>
                <p className="text-sm text-muted-foreground mb-3">{protocol.description}</p>

                <div className="space-y-2">
                  <p className="text-xs font-medium text-muted-foreground">Actions:</p>
                  <ul className="space-y-1">
                    {protocol.actions.map((action, i) => (
                      <li key={i} className="text-xs text-muted-foreground flex items-start gap-2">
                        <span className="text-primary">•</span>
                        {action}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="mt-3 pt-3 border-t border-border">
                  <p className="text-xs text-muted-foreground">
                    <strong>Teams:</strong> {protocol.teams.join(', ')}
                  </p>
                  <p className="text-xs text-muted-foreground mt-1">
                    <strong>Escalation:</strong> {protocol.escalationTime}
                  </p>
                </div>
              </div>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      <StartProtocolDialog open={startOpen} onOpenChange={setStartOpen} />
    </div>
  );
}
