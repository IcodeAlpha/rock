import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { cn } from '@/lib/utils';
import { 
  Terminal, 
  Play, 
  Loader2,
  Copy,
  Check,
  ExternalLink
} from 'lucide-react';
import { toast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

interface OSINTToolModalProps {
  isOpen: boolean;
  onClose: () => void;
  tool: {
    id: string;
    name: string;
    description: string;
    usage: string;
    example: string;
  } | null;
}

export function OSINTToolModal({ isOpen, onClose, tool }: OSINTToolModalProps) {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleRunQuery = async () => {
    if (!query.trim() || !tool) return;

    setIsLoading(true);
    setResults('');

    try {
      const { data, error } = await supabase.functions.invoke('osint-query', {
        body: { tool: tool.id, query: query.trim() }
      });

      if (error) throw error;

      setResults(data.results || 'No results returned.');
      toast({
        title: "Query Complete",
        description: `${tool.name} query executed successfully.`,
      });
    } catch (error) {
      console.error('OSINT query error:', error);
      toast({
        title: "Query Failed",
        description: error instanceof Error ? error.message : "Failed to execute query",
        variant: "destructive",
      });
      setResults('Error executing query. Please try again.');
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyResults = () => {
    navigator.clipboard.writeText(results);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
    toast({
      title: "Copied",
      description: "Results copied to clipboard.",
    });
  };

  const handleClose = () => {
    setQuery('');
    setResults('');
    onClose();
  };

  if (!tool) return null;

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-hidden flex flex-col">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-primary" />
            {tool.name}
          </DialogTitle>
        </DialogHeader>

        <div className="space-y-4 flex-1 overflow-y-auto">
          {/* Tool Info */}
          <div className="p-3 rounded-lg bg-secondary/30 border border-border text-sm">
            <p className="text-muted-foreground">{tool.description}</p>
            <div className="mt-2 pt-2 border-t border-border">
              <p className="text-xs text-muted-foreground"><strong>Usage:</strong> {tool.usage}</p>
            </div>
          </div>

          {/* Query Input */}
          <div className="space-y-2">
            <Label htmlFor="query">Query / Target</Label>
            <div className="flex gap-2">
              <Input
                id="query"
                placeholder={tool.example}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleRunQuery()}
                className="font-mono"
              />
              <Button
                variant="cyber"
                onClick={handleRunQuery}
                disabled={isLoading || !query.trim()}
              >
                {isLoading ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Play className="w-4 h-4" />
                )}
              </Button>
            </div>
            <p className="text-xs text-muted-foreground">
              Example: <code className="bg-secondary px-1 rounded">{tool.example}</code>
            </p>
          </div>

          {/* Results */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label>Results</Label>
              {results && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={handleCopyResults}
                >
                  {copied ? (
                    <Check className="w-4 h-4 mr-1 text-success" />
                  ) : (
                    <Copy className="w-4 h-4 mr-1" />
                  )}
                  {copied ? 'Copied' : 'Copy'}
                </Button>
              )}
            </div>
            <div className={cn(
              "min-h-[200px] max-h-[300px] overflow-y-auto p-4 rounded-lg border font-mono text-sm whitespace-pre-wrap",
              results ? "bg-secondary/30 border-border" : "bg-muted/30 border-dashed border-border"
            )}>
              {isLoading ? (
                <div className="flex items-center justify-center h-full">
                  <Loader2 className="w-6 h-6 animate-spin text-primary" />
                  <span className="ml-2 text-muted-foreground">Running query...</span>
                </div>
              ) : results ? (
                results
              ) : (
                <div className="flex items-center justify-center h-full text-muted-foreground">
                  Enter a query and click run to see results
                </div>
              )}
            </div>
          </div>

          {/* Disclaimer */}
          <div className="p-3 rounded-lg bg-warning/10 border border-warning/30 text-xs">
            <p className="text-warning font-medium">Simulated Results</p>
            <p className="text-muted-foreground mt-1">
              Results are AI-generated simulations for demonstration purposes. For production use, connect to real OSINT APIs.
            </p>
          </div>
        </div>

        <div className="flex justify-end pt-4 border-t border-border">
          <Button variant="ghost" onClick={handleClose}>
            Close
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
