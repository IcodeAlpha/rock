import { useState } from 'react';
import { responseProtocols } from '@/data/mockData';
import { SequentialProtocolPanel } from '@/components/dashboard/SequentialProtocolPanel';
import { Shield, Play, History, BookOpen } from 'lucide-react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { toast } from '@/hooks/use-toast';

interface ProtocolHistory {
  id: string;
  level: number;
  name: string;
  startedAt: Date;
  completedAt: Date;
  duration: string;
  triggeredBy: string;
}

const mockHistory: ProtocolHistory[] = [
  {
    id: 'hist-1',
    level: 3,
    name: 'Escalate & Mobilize',
    startedAt: new Date(Date.now() - 86400000),
    completedAt: new Date(Date.now() - 82800000),
    duration: '1h 0m',
    triggeredBy: 'Malware Detection Incident',
  },
  {
    id: 'hist-2',
    level: 2,
    name: 'Investigate & Contain',
    startedAt: new Date(Date.now() - 172800000),
    completedAt: new Date(Date.now() - 165600000),
    duration: '2h 0m',
    triggeredBy: 'Suspicious Login Attempts',
  },
];

export function ProtocolsView() {
  const [history] = useState(mockHistory);

  const handleProtocolComplete = (level: number) => {
    toast({
      title: `Level ${level} Protocol Complete`,
      description: `Response protocol has been successfully completed.`,
    });
  };

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
            Structured incident response procedures
          </p>
        </div>
      </div>

      <Tabs defaultValue="active" className="w-full">
        <TabsList className="grid w-full max-w-lg grid-cols-3">
          <TabsTrigger value="active" className="flex items-center gap-2">
            <Play className="w-4 h-4" />
            Active Response
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

        <TabsContent value="active" className="mt-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <SequentialProtocolPanel 
              protocols={responseProtocols}
              onProtocolComplete={handleProtocolComplete}
            />

            <div className="space-y-4">
              <h2 className="text-lg font-semibold">Protocol Information</h2>
              <div className="p-4 rounded-lg border border-border bg-card/50">
                <h3 className="font-medium mb-2">How Sequential Protocols Work</h3>
                <ul className="space-y-2 text-sm text-muted-foreground">
                  <li className="flex items-start gap-2">
                    <span className="text-primary">1.</span>
                    Start with Level 1 (Alert & Monitor) for initial threat assessment
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary">2.</span>
                    Complete all steps within each level before escalating
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary">3.</span>
                    Higher levels unlock only after completing previous levels
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary">4.</span>
                    Each step must be marked complete to proceed
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-primary">5.</span>
                    Reset protocols after incident resolution
                  </li>
                </ul>
              </div>

              <div className="p-4 rounded-lg border border-warning/30 bg-warning/10">
                <h3 className="font-medium text-warning mb-2">Important Notes</h3>
                <ul className="space-y-1 text-sm text-muted-foreground">
                  <li>• Document all actions taken during response</li>
                  <li>• Notify relevant stakeholders at each escalation</li>
                  <li>• Preserve evidence for post-incident analysis</li>
                  <li>• Follow organizational policies and procedures</li>
                </ul>
              </div>
            </div>
          </div>
        </TabsContent>

        <TabsContent value="history" className="mt-6">
          <div className="space-y-4">
            <h2 className="text-lg font-semibold">Protocol Execution History</h2>
            {history.length === 0 ? (
              <div className="p-12 text-center rounded-lg border border-dashed border-border">
                <History className="w-12 h-12 mx-auto text-muted-foreground mb-3" />
                <p className="text-muted-foreground">No protocol history yet</p>
              </div>
            ) : (
              <div className="space-y-3">
                {history.map((item) => (
                  <div
                    key={item.id}
                    className="p-4 rounded-lg border border-border bg-card/50"
                  >
                    <div className="flex items-center justify-between">
                      <div>
                        <div className="flex items-center gap-2 mb-1">
                          <span className="w-6 h-6 rounded bg-success/20 text-success text-sm font-bold flex items-center justify-center">
                            {item.level}
                          </span>
                          <span className="font-medium">{item.name}</span>
                        </div>
                        <p className="text-sm text-muted-foreground">{item.triggeredBy}</p>
                      </div>
                      <div className="text-right text-sm text-muted-foreground">
                        <p>Duration: {item.duration}</p>
                        <p>{item.completedAt.toLocaleDateString()}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="guide" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {responseProtocols.map((protocol) => (
              <div
                key={protocol.level}
                className="p-4 rounded-lg border border-border bg-card/50"
              >
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
    </div>
  );
}
