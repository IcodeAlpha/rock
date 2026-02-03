import { Badge } from '@/components/ui/badge';
import { Globe, ExternalLink, Clock } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';

interface OSINTItem {
  id: string;
  source: string;
  indicator: string;
  type: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: Date;
  matchScore?: number;
}

const mockOSINTFeed: OSINTItem[] = [
  {
    id: 'osint-001',
    source: 'AlienVault OTX',
    indicator: 'Mirai Botnet C2 Infrastructure',
    type: 'botnet',
    severity: 'critical',
    timestamp: new Date(Date.now() - 1800000),
    matchScore: 92,
  },
  {
    id: 'osint-002',
    source: 'Recorded Future',
    indicator: 'DDoS-for-Hire Service Activity',
    type: 'darkweb',
    severity: 'high',
    timestamp: new Date(Date.now() - 3600000),
    matchScore: 78,
  },
  {
    id: 'osint-003',
    source: 'VirusTotal',
    indicator: 'LockBit 3.0 Sample Detected',
    type: 'malware',
    severity: 'critical',
    timestamp: new Date(Date.now() - 7200000),
    matchScore: 85,
  },
  {
    id: 'osint-004',
    source: 'CISA Alerts',
    indicator: 'CVE-2024-0012 Exploitation',
    type: 'exploit',
    severity: 'high',
    timestamp: new Date(Date.now() - 10800000),
  },
  {
    id: 'osint-005',
    source: 'PhishTank',
    indicator: 'Credential Harvesting Campaign',
    type: 'phishing',
    severity: 'medium',
    timestamp: new Date(Date.now() - 14400000),
  },
];

const typeConfig = {
  botnet: { color: 'bg-purple-500/20 text-purple-400', label: 'Botnet' },
  darkweb: { color: 'bg-red-500/20 text-red-400', label: 'Dark Web' },
  malware: { color: 'bg-orange-500/20 text-orange-400', label: 'Malware' },
  exploit: { color: 'bg-yellow-500/20 text-yellow-400', label: 'Exploit' },
  phishing: { color: 'bg-blue-500/20 text-blue-400', label: 'Phishing' },
  apt: { color: 'bg-pink-500/20 text-pink-400', label: 'APT' },
};

export function OSINTFeed() {
  const severityBadge = {
    critical: 'critical' as const,
    high: 'high' as const,
    medium: 'medium' as const,
    low: 'low' as const,
  };

  return (
    <div className="rounded-xl border border-border bg-card/50 backdrop-blur-sm overflow-hidden">
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-5 h-5 text-primary" />
          <h3 className="font-semibold">OSINT Intelligence Feed</h3>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
          <span className="text-xs text-muted-foreground">Live</span>
        </div>
      </div>

      <div className="divide-y divide-border max-h-96 overflow-y-auto">
        {mockOSINTFeed.map((item) => {
          const type = typeConfig[item.type as keyof typeof typeConfig];
          
          return (
            <div 
              key={item.id}
              className="p-4 transition-all duration-200 hover:bg-secondary/30 group cursor-pointer"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge variant={severityBadge[item.severity]} className="text-xs">
                      {item.severity}
                    </Badge>
                    <span className={`text-xs px-2 py-0.5 rounded ${type.color}`}>
                      {type.label}
                    </span>
                  </div>
                  
                  <h4 className="font-medium text-sm mb-1 group-hover:text-primary transition-colors">
                    {item.indicator}
                  </h4>
                  
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    <span className="font-mono">{item.source}</span>
                    <div className="flex items-center gap-1">
                      <Clock className="w-3 h-3" />
                      {formatDistanceToNow(item.timestamp, { addSuffix: true })}
                    </div>
                  </div>
                </div>

                <div className="text-right">
                  {item.matchScore && (
                    <div className="flex flex-col items-end">
                      <span className="text-lg font-bold text-primary">{item.matchScore}%</span>
                      <span className="text-xs text-muted-foreground">Match</span>
                    </div>
                  )}
                  <ExternalLink className="w-4 h-4 text-muted-foreground mt-2 opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
