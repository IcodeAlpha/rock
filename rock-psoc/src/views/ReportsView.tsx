import { useState } from 'react';
import { dashboardStats } from '@/data/mockData';
import { Button } from '@/components/ui/button';
import { 
  FileText, 
  Download, 
  Calendar,
  TrendingUp,
  Shield,
  AlertTriangle,
  Clock,
  BarChart3,
  Eye
} from 'lucide-react';
import { format, subDays } from 'date-fns';
import { ReportViewModal } from '@/components/reports/ReportViewModal';
import { useToast } from '@/hooks/use-toast';

interface Report {
  id: string;
  title: string;
  type: 'weekly' | 'monthly' | 'incident' | 'custom';
  generatedAt: Date;
  period: string;
  status: 'ready' | 'generating';
  content?: string;
}

const mockReports: Report[] = [
  {
    id: 'rpt-1',
    title: 'Weekly Threat Summary',
    type: 'weekly',
    generatedAt: new Date(),
    period: `${format(subDays(new Date(), 7), 'MMM d')} - ${format(new Date(), 'MMM d, yyyy')}`,
    status: 'ready',
  },
  {
    id: 'rpt-2',
    title: 'Monthly Security Report',
    type: 'monthly',
    generatedAt: subDays(new Date(), 2),
    period: 'December 2024',
    status: 'ready',
  },
  {
    id: 'rpt-3',
    title: 'Incident Response Report - INC-002',
    type: 'incident',
    generatedAt: subDays(new Date(), 1),
    period: 'Malware Detection Event',
    status: 'ready',
  },
];

export function ReportsView() {
  const [reports] = useState(mockReports);
  const [selectedReport, setSelectedReport] = useState<Report | null>(null);
  const [isViewModalOpen, setIsViewModalOpen] = useState(false);
  const { toast } = useToast();

  const handleViewReport = (report: Report) => {
    setSelectedReport(report);
    setIsViewModalOpen(true);
  };

  const handleDownload = (report: Report) => {
    toast({
      title: "Download Started",
      description: `Downloading ${report.title}...`,
    });
  };

  const summaryStats = [
    { label: 'Threats Predicted', value: dashboardStats.activePredictions, icon: TrendingUp, color: 'text-primary' },
    { label: 'Incidents Handled', value: dashboardStats.activeIncidents, icon: AlertTriangle, color: 'text-warning' },
    { label: 'Threats Prevented', value: dashboardStats.threatsPreventedThisMonth, icon: Shield, color: 'text-success' },
    { label: 'Avg Response Time', value: '2.4h', icon: Clock, color: 'text-muted-foreground' },
  ];

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <FileText className="w-7 h-7 text-primary" />
            Reports & Analytics
          </h1>
          <p className="text-muted-foreground mt-1">
            Security reports and performance analytics
          </p>
        </div>
        <Button variant="cyber">
          <FileText className="w-4 h-4 mr-2" />
          Generate New Report
        </Button>
      </div>

      {/* Quick Stats */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {summaryStats.map((stat) => {
          const Icon = stat.icon;
          return (
            <div 
              key={stat.label}
              className="p-4 rounded-lg border border-border bg-card/50"
            >
              <div className="flex items-center gap-2 mb-2">
                <Icon className={`w-5 h-5 ${stat.color}`} />
                <span className="text-xs text-muted-foreground">{stat.label}</span>
              </div>
              <p className="text-2xl font-bold">{stat.value}</p>
            </div>
          );
        })}
      </div>

      {/* Reports Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Available Reports */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Available Reports</h2>
          {reports.map((report) => (
            <div
              key={report.id}
              className="p-4 rounded-lg border border-border bg-card/50 hover:border-primary/30 transition-all"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <FileText className="w-4 h-4 text-primary" />
                    <span className="font-medium">{report.title}</span>
                  </div>
                  <p className="text-sm text-muted-foreground">{report.period}</p>
                  <p className="text-xs text-muted-foreground mt-1">
                    Generated: {format(report.generatedAt, 'MMM d, yyyy HH:mm')}
                  </p>
                </div>
                <div className="flex gap-2">
                  <Button variant="glass" size="sm" onClick={() => handleViewReport(report)}>
                    <Eye className="w-4 h-4 mr-1" />
                    View
                  </Button>
                  <Button variant="ghost" size="sm" onClick={() => handleDownload(report)}>
                    <Download className="w-4 h-4" />
                  </Button>
                </div>
              </div>
            </div>
          ))}
        </div>

        <ReportViewModal
          report={selectedReport}
          isOpen={isViewModalOpen}
          onClose={() => setIsViewModalOpen(false)}
          onDownload={handleDownload}
        />

        {/* Scheduled Reports */}
        <div className="space-y-4">
          <h2 className="text-lg font-semibold">Scheduled Reports</h2>
          <div className="p-4 rounded-lg border border-border bg-card/50">
            <div className="flex items-center gap-3 mb-4">
              <Calendar className="w-5 h-5 text-primary" />
              <span className="font-medium">Weekly Threat Summary</span>
            </div>
            <p className="text-sm text-muted-foreground">Every Monday at 9:00 AM</p>
            <p className="text-xs text-muted-foreground mt-1">Recipients: security-team@org.com</p>
          </div>

          <div className="p-4 rounded-lg border border-border bg-card/50">
            <div className="flex items-center gap-3 mb-4">
              <BarChart3 className="w-5 h-5 text-primary" />
              <span className="font-medium">Monthly Executive Summary</span>
            </div>
            <p className="text-sm text-muted-foreground">1st of each month</p>
            <p className="text-xs text-muted-foreground mt-1">Recipients: executives@org.com</p>
          </div>

          <div className="p-4 rounded-lg border border-dashed border-border text-center">
            <p className="text-sm text-muted-foreground">
              + Add Scheduled Report
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
