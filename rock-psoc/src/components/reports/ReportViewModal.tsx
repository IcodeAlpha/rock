import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Download, FileText, Calendar, Clock } from 'lucide-react';
import { format } from 'date-fns';
import { Badge } from '@/components/ui/badge';

interface Report {
  id: string;
  title: string;
  type: 'weekly' | 'monthly' | 'incident' | 'custom';
  generatedAt: Date;
  period: string;
  status: 'ready' | 'generating';
  content?: string;
}

interface ReportViewModalProps {
  report: Report | null;
  isOpen: boolean;
  onClose: () => void;
  onDownload: (report: Report) => void;
}

const typeColors = {
  weekly: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  monthly: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  incident: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  custom: 'bg-green-500/20 text-green-400 border-green-500/30',
};

// Mock content for demo purposes
const getMockContent = (report: Report) => {
  const baseContent = `
# ${report.title}

## Executive Summary
This report covers the security operations and threat landscape for the period: ${report.period}.

## Key Findings

### Threat Overview
- Total threats detected: 47
- Critical threats: 3
- High severity threats: 12
- Medium severity threats: 32

### Incident Response
- Total incidents: 8
- Resolved incidents: 6
- Average response time: 2.4 hours
- Containment rate: 94%

### Predictions Accuracy
- Predictions generated: 15
- Converted to incidents: 4
- Prevention rate: 73%

## Detailed Analysis

### Top Threat Categories
1. **Phishing Attempts** - 18 detected
   - Email-based attacks targeting employee credentials
   - Mitigation: Enhanced email filtering deployed

2. **Malware Detection** - 12 detected
   - Primarily ransomware variants
   - Mitigation: Endpoint protection updated

3. **Network Intrusion Attempts** - 9 detected
   - Scanning activities from known threat actors
   - Mitigation: Firewall rules updated

### Geographic Distribution
- North America: 45%
- Europe: 30%
- Asia Pacific: 20%
- Other: 5%

## Recommendations

1. Implement additional email security training
2. Update endpoint detection signatures
3. Review network segmentation policies
4. Conduct tabletop exercise for incident response

## Conclusion
Overall security posture remains strong with a 15% improvement in threat detection compared to the previous period.

---
Generated: ${format(report.generatedAt, 'MMMM d, yyyy HH:mm')}
Report ID: ${report.id}
`;
  return baseContent;
};

export function ReportViewModal({ report, isOpen, onClose, onDownload }: ReportViewModalProps) {
  if (!report) return null;

  const content = report.content || getMockContent(report);

  const handleDownload = () => {
    onDownload(report);
    onClose();
  };

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[85vh] flex flex-col">
        <DialogHeader className="border-b border-border pb-4">
          <div className="flex items-start justify-between">
            <div className="space-y-2">
              <div className="flex items-center gap-2">
                <FileText className="w-5 h-5 text-primary" />
                <DialogTitle className="text-xl">{report.title}</DialogTitle>
              </div>
              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                <div className="flex items-center gap-1">
                  <Calendar className="w-4 h-4" />
                  <span>{report.period}</span>
                </div>
                <div className="flex items-center gap-1">
                  <Clock className="w-4 h-4" />
                  <span>{format(report.generatedAt, 'MMM d, yyyy HH:mm')}</span>
                </div>
              </div>
            </div>
            <Badge className={typeColors[report.type]} variant="outline">
              {report.type.charAt(0).toUpperCase() + report.type.slice(1)}
            </Badge>
          </div>
        </DialogHeader>

        <ScrollArea className="flex-1 py-4">
          <div className="prose prose-invert prose-sm max-w-none">
            <pre className="whitespace-pre-wrap font-sans text-sm leading-relaxed text-foreground bg-transparent p-0 border-none">
              {content}
            </pre>
          </div>
        </ScrollArea>

        <DialogFooter className="border-t border-border pt-4">
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          <Button variant="cyber" onClick={handleDownload}>
            <Download className="w-4 h-4 mr-2" />
            Download Report
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
