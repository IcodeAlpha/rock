import { useState } from 'react';
import { Sidebar } from '@/components/layout/Sidebar';
import { Header } from '@/components/layout/Header';
import { DashboardView } from '@/views/DashboardView';
import { PredictionsView } from '@/views/PredictionsView';
import { IncidentsView } from '@/views/IncidentsView';
import { AlertsView } from '@/views/AlertsView';
import { OSINTView } from '@/views/OSINTView';
import { ProtocolsView } from '@/views/ProtocolsView';
import { ReportsView } from '@/views/ReportsView';
import { SettingsView } from '@/views/SettingsView';
import { TeamView } from '@/views/TeamView';
import { PerformanceDashboard } from '@/components/performance/PerformanceDashboard';
import { cn } from '@/lib/utils';
import { Helmet } from 'react-helmet';

const Index = () => {
  const [activeView, setActiveView] = useState('dashboard');
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

  const renderView = () => {
    switch (activeView) {
      case 'dashboard': return <DashboardView onViewChange={setActiveView} />;
      case 'predictions': return <PredictionsView />;
      case 'incidents': return <IncidentsView />;
      case 'alerts': return <AlertsView />;
      case 'osint': return <OSINTView />;
      case 'response': return <ProtocolsView />;
      case 'reports': return <ReportsView />;
      case 'performance': return <PerformanceDashboard />;
      case 'settings': return <SettingsView />;
      case 'team': return <TeamView />;
      default: return <DashboardView onViewChange={setActiveView} />;
    }
  };

  return (
    <>
      <Helmet>
        <title>The Rock PSOC - Predictive Security Operations Center</title>
        <meta name="description" content="AI-powered predictive cybersecurity platform that forecasts threats 5-7 days in advance. The Rock PSOC transforms security operations from reactive to proactive." />
      </Helmet>
      
      <div className="min-h-screen bg-background grid-pattern">
        <div className="fixed inset-0 scanline pointer-events-none z-50 opacity-30" />
        <Sidebar activeView={activeView} onViewChange={setActiveView} />
        <main className={cn("transition-all duration-300", sidebarCollapsed ? "ml-20" : "ml-64")}>
          <Header />
          <div className="p-6">{renderView()}</div>
        </main>
      </div>
    </>
  );
};

export default Index;