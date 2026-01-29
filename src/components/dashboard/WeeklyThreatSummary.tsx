import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { TrendingUp, TrendingDown, AlertTriangle, Shield, Activity, FileWarning, Download } from 'lucide-react';
import { cn } from '@/lib/utils';
import { toast } from 'sonner';

interface WeeklyThreatSummaryProps {
  className?: string;
}

export function WeeklyThreatSummary({ className }: WeeklyThreatSummaryProps) {
  const summaryData = {
    totalThreats: 27,
    threatsChange: -12,
    criticalThreats: 3,
    resolvedIncidents: 8,
    avgResponseTime: '2.4h',
    topThreatType: 'Phishing Attempts',
    riskScore: 68,
  };

  const isPositiveTrend = summaryData.threatsChange < 0;

  const handleDownload = () => {
    const reportContent = `
WEEKLY THREAT SUMMARY REPORT
Generated: ${new Date().toLocaleString()}
Period: Last 7 Days
=====================================

OVERVIEW
--------
Total Threats Detected: ${summaryData.totalThreats}
Change vs Last Week: ${summaryData.threatsChange}%
Critical Threats: ${summaryData.criticalThreats}
Resolved Incidents: ${summaryData.resolvedIncidents}

PERFORMANCE METRICS
-------------------
Average Response Time: ${summaryData.avgResponseTime}
Top Threat Type: ${summaryData.topThreatType}
Current Risk Score: ${summaryData.riskScore}/100

RISK ASSESSMENT
---------------
Status: ${summaryData.riskScore > 70 ? 'HIGH RISK' : summaryData.riskScore > 40 ? 'MODERATE RISK' : 'LOW RISK'}
Trend: ${isPositiveTrend ? 'IMPROVING' : 'DECLINING'}

=====================================
End of Report
    `.trim();

    const blob = new Blob([reportContent], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `threat-summary-${new Date().toISOString().split('T')[0]}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    toast.success('Weekly summary downloaded');
  };

  return (
    <div className={cn("rounded-xl border border-border bg-card/50 backdrop-blur-sm", className)}>
      <div className="p-4 border-b border-border">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-primary" />
            <h3 className="font-semibold">Weekly Threat Summary</h3>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={handleDownload}
              title="Download Summary"
            >
              <Download className="w-4 h-4" />
            </Button>
            <Badge variant="outline" className="text-xs">
              Last 7 days
            </Badge>
          </div>
        </div>
      </div>

      <div className="p-4 space-y-4">
        {/* Main Stat */}
        <div className="flex items-center justify-between p-3 rounded-lg bg-secondary/30">
          <div>
            <p className="text-xs text-muted-foreground">Total Threats Detected</p>
            <p className="text-2xl font-bold">{summaryData.totalThreats}</p>
          </div>
          <div className={cn(
            "flex items-center gap-1 text-sm font-medium",
            isPositiveTrend ? "text-success" : "text-destructive"
          )}>
            {isPositiveTrend ? (
              <TrendingDown className="w-4 h-4" />
            ) : (
              <TrendingUp className="w-4 h-4" />
            )}
            {Math.abs(summaryData.threatsChange)}% vs last week
          </div>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 gap-3">
          <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="w-4 h-4 text-destructive" />
              <span className="text-xs text-muted-foreground">Critical</span>
            </div>
            <p className="text-lg font-semibold text-destructive">{summaryData.criticalThreats}</p>
          </div>
          
          <div className="p-3 rounded-lg bg-success/10 border border-success/20">
            <div className="flex items-center gap-2 mb-1">
              <Shield className="w-4 h-4 text-success" />
              <span className="text-xs text-muted-foreground">Resolved</span>
            </div>
            <p className="text-lg font-semibold text-success">{summaryData.resolvedIncidents}</p>
          </div>
        </div>

        {/* Additional Info */}
        <div className="space-y-2">
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Avg Response Time</span>
            <span className="font-medium">{summaryData.avgResponseTime}</span>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Top Threat Type</span>
            <Badge variant="high" className="text-xs">
              <FileWarning className="w-3 h-3 mr-1" />
              {summaryData.topThreatType}
            </Badge>
          </div>
          <div className="flex items-center justify-between text-sm">
            <span className="text-muted-foreground">Risk Score</span>
            <div className="flex items-center gap-2">
              <div className="w-16 h-2 rounded-full bg-secondary overflow-hidden">
                <div 
                  className={cn(
                    "h-full rounded-full transition-all",
                    summaryData.riskScore > 70 ? "bg-destructive" :
                    summaryData.riskScore > 40 ? "bg-warning" : "bg-success"
                  )}
                  style={{ width: `${summaryData.riskScore}%` }}
                />
              </div>
              <span className="font-medium">{summaryData.riskScore}/100</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
