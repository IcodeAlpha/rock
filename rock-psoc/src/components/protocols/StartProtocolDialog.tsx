import { useState } from 'react';
import { useProtocolExecutions } from '@/hooks/useProtocolExecutions';
import { useIncidents } from '@/hooks/useIncidents';
import { responseProtocols } from '@/data/mockData';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Label } from '@/components/ui/label';
import { Shield, Play, Loader2, Link } from 'lucide-react';

interface StartProtocolDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function StartProtocolDialog({ open, onOpenChange }: StartProtocolDialogProps) {
  const [selectedLevel, setSelectedLevel] = useState<string>('1');
  const [selectedIncident, setSelectedIncident] = useState<string>('none');
  const { startExecution, activeExecutions } = useProtocolExecutions();
  const { incidents } = useIncidents();

  const activeIncidents = incidents.filter(i => i.status !== 'resolved');
  const activeLevels = activeExecutions.map(e => e.level);

  const handleStart = async () => {
    const level = parseInt(selectedLevel);
    await startExecution.mutateAsync({
      level,
      incidentId: selectedIncident !== 'none' ? selectedIncident : undefined,
    });
    onOpenChange(false);
    setSelectedLevel('1');
    setSelectedIncident('none');
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-primary" />
            Launch Response Protocol
          </DialogTitle>
          <DialogDescription>
            Start a collaborative protocol execution. Team members will be able to track progress, assign steps, and add notes in real-time.
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4 py-4">
          <div className="space-y-2">
            <Label>Protocol Level</Label>
            <Select value={selectedLevel} onValueChange={setSelectedLevel}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {responseProtocols.map(p => (
                  <SelectItem
                    key={p.level}
                    value={p.level.toString()}
                    disabled={activeLevels.includes(p.level)}
                  >
                    <div className="flex items-center gap-2">
                      <span className="font-bold">L{p.level}</span>
                      <span>{p.name}</span>
                      {activeLevels.includes(p.level) && (
                        <span className="text-xs text-muted-foreground">(active)</span>
                      )}
                    </div>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {responseProtocols.find(p => p.level === parseInt(selectedLevel)) && (
              <p className="text-xs text-muted-foreground">
                {responseProtocols.find(p => p.level === parseInt(selectedLevel))?.description}
              </p>
            )}
          </div>

          <div className="space-y-2">
            <Label className="flex items-center gap-1">
              <Link className="w-3 h-3" />
              Link to Incident (optional)
            </Label>
            <Select value={selectedIncident} onValueChange={setSelectedIncident}>
              <SelectTrigger>
                <SelectValue placeholder="Standalone protocol" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">Standalone (no incident)</SelectItem>
                {activeIncidents.map(inc => (
                  <SelectItem key={inc.id} value={inc.id}>
                    {inc.title}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button
            onClick={handleStart}
            disabled={startExecution.isPending}
          >
            {startExecution.isPending ? (
              <Loader2 className="w-4 h-4 mr-2 animate-spin" />
            ) : (
              <Play className="w-4 h-4 mr-2" />
            )}
            Launch Protocol
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
