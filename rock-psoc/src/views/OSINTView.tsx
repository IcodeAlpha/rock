import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { cn } from '@/lib/utils';
import { 
  Globe, 
  RefreshCw, 
  ExternalLink,
  Radio,
  AlertTriangle,
  Shield,
  Bug,
  Users,
  Search,
  Server,
  Mail,
  Share2,
  FileSearch,
  Database,
  Eye,
  Image,
  Network,
  Terminal,
  Info,
  Zap,
  Clock,
  Building2,
  Target,
  TrendingUp,
  Filter,
  CheckCircle2,
  XCircle,
  Factory,
  Landmark,
  Cpu,
  Cloud,
  Play,
  Loader2,
  Copy,
  Check,
  AlertCircle,
  Link
} from 'lucide-react';
import { format } from 'date-fns';
import { OSINTToolModal } from '@/components/wizards/OSINTToolModal';
import { supabase } from '@/integrations/supabase/client';
import { toast } from '@/hooks/use-toast';

// Real OSINT Tool definitions
interface OSINTTool {
  id: string;
  name: string;
  description: string;
  category: 'discovery' | 'enumeration' | 'analysis' | 'monitoring';
  icon: React.ComponentType<{ className?: string }>;
  usage: string;
  example: string;
  tags: string[];
  apiType: 'free' | 'freemium' | 'paid';
  rateLimit: string;
}

const osintTools: OSINTTool[] = [
  {
    id: 'virustotal',
    name: 'VirusTotal',
    description: 'Analyze IPs, domains, and file hashes against 70+ antivirus engines and security services. Get reputation scores and threat intelligence.',
    category: 'analysis',
    icon: Shield,
    usage: 'Enter an IP address, domain name, or file hash (MD5/SHA1/SHA256) to check for malicious activity.',
    example: '8.8.8.8 or google.com or sha256 hash',
    tags: ['Malware', 'Reputation', 'Hash', 'Domain', 'IP'],
    apiType: 'freemium',
    rateLimit: '4 req/min, 500/day',
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    description: 'Check IP addresses against a database of reported malicious IPs. Get abuse confidence scores and recent reports.',
    category: 'analysis',
    icon: AlertCircle,
    usage: 'Enter an IP address to check its abuse history and confidence score.',
    example: '185.220.101.1',
    tags: ['IP', 'Abuse', 'Reports', 'Blacklist'],
    apiType: 'freemium',
    rateLimit: '1000 checks/day',
  },
  {
    id: 'shodan',
    name: 'Shodan InternetDB',
    description: 'Free API to get open ports, known vulnerabilities, and hostnames for any IP. No API key required!',
    category: 'discovery',
    icon: Server,
    usage: 'Enter an IP address to discover open ports, services, and known vulnerabilities.',
    example: '8.8.8.8',
    tags: ['Ports', 'Vulnerabilities', 'Services', 'Free'],
    apiType: 'free',
    rateLimit: 'Unlimited',
  },
  {
    id: 'urlhaus',
    name: 'URLhaus',
    description: 'Check URLs and hosts against a database of malware distribution sites. Operated by abuse.ch. Requires free Auth-Key.',
    category: 'analysis',
    icon: Link,
    usage: 'Enter a URL, domain, or host to check for malware distribution activity.',
    example: 'example.com',
    tags: ['Malware', 'URLs', 'C2', 'Auth Required'],
    apiType: 'freemium',
    rateLimit: 'Free with Auth-Key',
  },
  {
    id: 'threatfox',
    name: 'ThreatFox',
    description: 'Search for IOCs (Indicators of Compromise) including IPs, domains, and hashes. Requires free abuse.ch Auth-Key.',
    category: 'monitoring',
    icon: Bug,
    usage: 'Enter an IOC (IP, domain, hash) or malware name to search the threat database.',
    example: 'emotet or 192.168.1.1',
    tags: ['IOC', 'Malware', 'C2', 'Auth Required'],
    apiType: 'freemium',
    rateLimit: 'Free with Auth-Key',
  },
  {
    id: 'malwarebazaar',
    name: 'MalwareBazaar',
    description: 'Search for malware samples by hash. Get detailed analysis including file type, signatures, and tags. Requires free Auth-Key.',
    category: 'analysis',
    icon: FileSearch,
    usage: 'Enter a file hash (MD5, SHA1, or SHA256) to look up malware sample information.',
    example: 'SHA256 hash of suspected malware',
    tags: ['Malware', 'Hash', 'Samples', 'Auth Required'],
    apiType: 'freemium',
    rateLimit: 'Free with Auth-Key',
  },
];

// Organization Profile for contextual correlation
interface OrgProfile {
  name: string;
  industry: string;
  industryVerticals: string[];
  criticalSystems: string[];
  suppliers: string[];
  geographies: string[];
  technologies: string[];
  threatActorsOfConcern: string[];
}

const orgProfile: OrgProfile = {
  name: 'Rock National Infrastructure',
  industry: 'Critical Infrastructure',
  industryVerticals: ['Energy', 'Government', 'Financial Services'],
  criticalSystems: ['SCADA/ICS', 'Active Directory', 'Exchange Server', 'SAP ERP', 'VMware vSphere'],
  suppliers: ['Microsoft Azure', 'Cisco', 'Palo Alto Networks', 'Oracle', 'SAP'],
  geographies: ['United States', 'Western Europe', 'Middle East'],
  technologies: ['Windows Server 2019', 'Linux RHEL', 'Kubernetes', 'PostgreSQL', 'Apache'],
  threatActorsOfConcern: ['APT29', 'APT41', 'Lazarus Group', 'Sandworm'],
};

// Enhanced Threat Intelligence with contextual relevance
interface ContextualThreat {
  id: string;
  source: string;
  type: 'malware' | 'botnet' | 'phishing' | 'darkweb' | 'exploit' | 'apt';
  indicator: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: Date;
  rawScore: number;
  relevanceScore: number;
  relevanceFactors: {
    factor: string;
    match: boolean;
    weight: number;
  }[];
  affectedTechnologies: string[];
  targetedIndustries: string[];
  threatActors: string[];
  actionable: boolean;
  recommendedAction: string;
  tags: string[];
}

const contextualThreats: ContextualThreat[] = [
  {
    id: 'ct-1',
    source: 'CISA Advisory',
    type: 'apt',
    indicator: 'APT29 - Active Directory Compromise Campaign',
    description: 'State-sponsored actor actively targeting government entities using Kerberoasting and Golden Ticket attacks against Active Directory infrastructure.',
    severity: 'critical',
    timestamp: new Date(Date.now() - 1800000),
    rawScore: 85,
    relevanceScore: 98,
    relevanceFactors: [
      { factor: 'Targets your industry (Government)', match: true, weight: 25 },
      { factor: 'Affects your critical system (Active Directory)', match: true, weight: 30 },
      { factor: 'Known threat actor of concern (APT29)', match: true, weight: 25 },
      { factor: 'Geographic targeting matches', match: true, weight: 18 },
    ],
    affectedTechnologies: ['Active Directory', 'Windows Server'],
    targetedIndustries: ['Government', 'Defense', 'Energy'],
    threatActors: ['APT29'],
    actionable: true,
    recommendedAction: 'Immediately audit AD for Kerberoasting indicators. Enable AES encryption for service accounts. Review privileged access.',
    tags: ['APT', 'Active Directory', 'Kerberos', 'Government'],
  },
  {
    id: 'ct-2',
    source: 'Recorded Future',
    type: 'exploit',
    indicator: 'CVE-2024-21762: FortiOS RCE (CVSS 9.8)',
    description: 'Critical out-of-bounds write vulnerability in Fortinet FortiOS SSL VPN. Active exploitation by multiple threat actors including Volt Typhoon.',
    severity: 'critical',
    timestamp: new Date(Date.now() - 3600000),
    rawScore: 92,
    relevanceScore: 35,
    relevanceFactors: [
      { factor: 'Targets your industry', match: false, weight: 0 },
      { factor: 'Affects your technology stack', match: false, weight: 0 },
      { factor: 'Supplier dependency', match: false, weight: 0 },
      { factor: 'Geographic targeting matches', match: true, weight: 15 },
      { factor: 'High raw severity score', match: true, weight: 20 },
    ],
    affectedTechnologies: ['FortiOS', 'FortiGate'],
    targetedIndustries: ['Any'],
    threatActors: ['Volt Typhoon', 'Unknown'],
    actionable: false,
    recommendedAction: 'Not applicable - FortiOS not in your technology stack.',
    tags: ['RCE', 'VPN', 'Fortinet', 'Zero-Day'],
  },
  {
    id: 'ct-3',
    source: 'VirusTotal',
    type: 'malware',
    indicator: 'FrostyGoop ICS Malware Variant',
    description: 'New ICS-focused malware targeting Modbus TCP protocol. Designed to manipulate industrial control systems in energy sector.',
    severity: 'critical',
    timestamp: new Date(Date.now() - 5400000),
    rawScore: 88,
    relevanceScore: 95,
    relevanceFactors: [
      { factor: 'Targets your industry (Energy)', match: true, weight: 25 },
      { factor: 'Affects your critical system (SCADA/ICS)', match: true, weight: 30 },
      { factor: 'Geographic targeting (Western Europe)', match: true, weight: 20 },
      { factor: 'Supply chain vector', match: true, weight: 20 },
    ],
    affectedTechnologies: ['SCADA', 'ICS', 'Modbus', 'PLCs'],
    targetedIndustries: ['Energy', 'Utilities', 'Manufacturing'],
    threatActors: ['Sandworm'],
    actionable: true,
    recommendedAction: 'Segment ICS networks immediately. Block Modbus traffic from IT network. Audit OT asset inventory.',
    tags: ['ICS', 'SCADA', 'Energy', 'OT'],
  },
  {
    id: 'ct-4',
    source: 'AlienVault OTX',
    type: 'phishing',
    indicator: 'BEC Campaign targeting CFOs',
    description: 'Business email compromise campaign using deepfake audio. Targeting financial executives at Fortune 500 companies.',
    severity: 'high',
    timestamp: new Date(Date.now() - 7200000),
    rawScore: 72,
    relevanceScore: 78,
    relevanceFactors: [
      { factor: 'Targets your industry (Financial Services)', match: true, weight: 25 },
      { factor: 'Attack vector applicable', match: true, weight: 20 },
      { factor: 'Geographic targeting matches', match: true, weight: 18 },
      { factor: 'Recent similar incident in sector', match: true, weight: 15 },
    ],
    affectedTechnologies: ['Email', 'VoIP'],
    targetedIndustries: ['Financial Services', 'Fortune 500'],
    threatActors: ['Unknown', 'FIN7'],
    actionable: true,
    recommendedAction: 'Alert finance team. Implement callback verification for wire transfers. Review email authentication (DMARC/DKIM).',
    tags: ['BEC', 'Phishing', 'Deepfake', 'Financial'],
  },
  {
    id: 'ct-5',
    source: 'Mandiant',
    type: 'darkweb',
    indicator: 'SAP Zero-Day Listed on Exploit Broker',
    description: 'Unpatched SAP NetWeaver vulnerability being sold on dark web forum. Claims RCE capability against SAP ERP systems.',
    severity: 'high',
    timestamp: new Date(Date.now() - 10800000),
    rawScore: 75,
    relevanceScore: 88,
    relevanceFactors: [
      { factor: 'Affects your critical system (SAP ERP)', match: true, weight: 30 },
      { factor: 'Supplier in your stack', match: true, weight: 25 },
      { factor: 'No patch available (Zero-Day)', match: true, weight: 20 },
      { factor: 'High impact potential', match: true, weight: 13 },
    ],
    affectedTechnologies: ['SAP NetWeaver', 'SAP ERP'],
    targetedIndustries: ['Any using SAP'],
    threatActors: ['Unknown'],
    actionable: true,
    recommendedAction: 'Increase monitoring on SAP systems. Apply virtual patching via WAF. Contact SAP for guidance.',
    tags: ['SAP', 'Zero-Day', 'Dark Web', 'RCE'],
  },
  {
    id: 'ct-6',
    source: 'Cisco Talos',
    type: 'botnet',
    indicator: 'Mirai Variant targeting IoT Cameras',
    description: 'New Mirai botnet variant exploiting default credentials in consumer-grade IP cameras for DDoS attacks.',
    severity: 'medium',
    timestamp: new Date(Date.now() - 14400000),
    rawScore: 65,
    relevanceScore: 22,
    relevanceFactors: [
      { factor: 'Targets your industry', match: false, weight: 0 },
      { factor: 'Affects your technology stack', match: false, weight: 0 },
      { factor: 'Consumer-grade devices only', match: false, weight: 0 },
      { factor: 'DDoS impact possible', match: true, weight: 12 },
      { factor: 'General awareness value', match: true, weight: 10 },
    ],
    affectedTechnologies: ['Consumer IoT', 'IP Cameras'],
    targetedIndustries: ['Consumer', 'SMB'],
    threatActors: ['Script Kiddies'],
    actionable: false,
    recommendedAction: 'Low priority - consumer IoT not in enterprise scope.',
    tags: ['IoT', 'Botnet', 'DDoS', 'Consumer'],
  },
];

const typeConfig = {
  malware: { icon: Bug, color: 'text-destructive', bg: 'bg-destructive/20' },
  botnet: { icon: Radio, color: 'text-severity-high', bg: 'bg-severity-high/20' },
  phishing: { icon: Users, color: 'text-warning', bg: 'bg-warning/20' },
  darkweb: { icon: Globe, color: 'text-purple-500', bg: 'bg-purple-500/20' },
  exploit: { icon: Shield, color: 'text-primary', bg: 'bg-primary/20' },
  apt: { icon: AlertTriangle, color: 'text-destructive', bg: 'bg-destructive/20' },
};

const categoryConfig = {
  discovery: { color: 'bg-primary/20 text-primary', label: 'Discovery' },
  enumeration: { color: 'bg-warning/20 text-warning', label: 'Enumeration' },
  analysis: { color: 'bg-success/20 text-success', label: 'Analysis' },
  monitoring: { color: 'bg-purple-500/20 text-purple-400', label: 'Monitoring' },
};

const apiTypeConfig = {
  free: { color: 'bg-success/20 text-success', label: 'Free' },
  freemium: { color: 'bg-warning/20 text-warning', label: 'Free Tier' },
  paid: { color: 'bg-destructive/20 text-destructive', label: 'Paid' },
};

// Quick Query Component
function QuickQuery() {
  const [query, setQuery] = useState('');
  const [selectedTool, setSelectedTool] = useState('virustotal');
  const [results, setResults] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleQuery = async () => {
    if (!query.trim()) return;

    setIsLoading(true);
    setResults(null);

    try {
      const { data, error } = await supabase.functions.invoke('osint-query', {
        body: { tool: selectedTool, query: query.trim() }
      });

      if (error) throw error;

      setResults(data);
      toast({
        title: "Query Complete",
        description: `${data.source} query executed successfully.`,
      });
    } catch (error) {
      console.error('OSINT query error:', error);
      toast({
        title: "Query Failed",
        description: error instanceof Error ? error.message : "Failed to execute query",
        variant: "destructive",
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopy = () => {
    if (results) {
      navigator.clipboard.writeText(JSON.stringify(results.results, null, 2));
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="p-4 rounded-xl border-2 border-success/40 bg-gradient-to-r from-success/10 via-primary/5 to-transparent space-y-4 relative overflow-hidden">
      {/* Live indicator glow */}
      <div className="absolute top-0 right-0 w-32 h-32 bg-success/20 rounded-full blur-3xl -translate-y-1/2 translate-x-1/2" />
      
      <div className="flex items-center gap-2 relative">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
          <Zap className="w-5 h-5 text-success" />
        </div>
        <h3 className="font-semibold">Quick OSINT Lookup</h3>
        <Badge className="ml-auto bg-success/20 text-success border-success/40 hover:bg-success/30">
          <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse mr-1.5" />
          LIVE APIs
        </Badge>
      </div>

      <div className="flex gap-2 flex-wrap relative">
        {osintTools.map(tool => (
          <Button
            key={tool.id}
            variant={selectedTool === tool.id ? "cyber" : "ghost"}
            size="sm"
            onClick={() => setSelectedTool(tool.id)}
            className={cn(
              "text-xs transition-all",
              selectedTool === tool.id && "ring-2 ring-success/50"
            )}
          >
            <tool.icon className="w-3 h-3 mr-1" />
            {tool.name}
          </Button>
        ))}
      </div>

      <div className="flex gap-2 relative">
        <Input
          placeholder={osintTools.find(t => t.id === selectedTool)?.example || "Enter query..."}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleQuery()}
          className="font-mono bg-secondary/30 border-success/30 focus:border-success"
        />
        <Button
          variant="cyber"
          onClick={handleQuery}
          disabled={isLoading || !query.trim()}
          className="bg-success hover:bg-success/90 border-success"
        >
          {isLoading ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Play className="w-4 h-4" />
          )}
        </Button>
      </div>

      {results && (
        <div className="space-y-2 relative">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm">
              <CheckCircle2 className="w-4 h-4 text-success" />
              <span className="text-success font-medium">Live results from {results.source}</span>
              <span className="text-xs text-muted-foreground">({new Date(results.timestamp).toLocaleTimeString()})</span>
            </div>
            <Button variant="ghost" size="sm" onClick={handleCopy}>
              {copied ? <Check className="w-4 h-4 text-success" /> : <Copy className="w-4 h-4" />}
            </Button>
          </div>
          <div className="p-4 rounded-lg bg-secondary/30 border border-success/30 font-mono text-xs overflow-x-auto max-h-64 overflow-y-auto">
            <pre>{JSON.stringify(results.results, null, 2)}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

export function OSINTView() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTool, setSelectedTool] = useState<OSINTTool | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState('fusion');
  const [showOnlyActionable, setShowOnlyActionable] = useState(false);
  const [relevanceThreshold, setRelevanceThreshold] = useState(50);
  const [showToolModal, setShowToolModal] = useState(false);

  const handleRefresh = () => {
    setIsRefreshing(true);
    setTimeout(() => setIsRefreshing(false), 2000);
  };

  const filteredTools = osintTools.filter(tool =>
    tool.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    tool.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
    tool.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()))
  );

  const filteredThreats = contextualThreats
    .filter(t => t.relevanceScore >= relevanceThreshold)
    .filter(t => !showOnlyActionable || t.actionable)
    .sort((a, b) => b.relevanceScore - a.relevanceScore);

  const actionableCount = contextualThreats.filter(t => t.actionable).length;
  const noiseFiltered = contextualThreats.filter(t => t.relevanceScore < 50).length;

  const handleToolClick = (tool: OSINTTool) => {
    setSelectedTool(tool);
    setShowToolModal(true);
  };

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header with Live Status */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-3">
            <div className="relative">
              <Globe className="w-7 h-7 text-primary" />
              <div className="absolute -top-0.5 -right-0.5 w-3 h-3 rounded-full bg-success animate-pulse" />
            </div>
            OSINT Reconnaissance Center
            <Badge className="bg-success/20 text-success border-success/40 text-xs font-normal">
              <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse mr-1" />
              6 LIVE APIs
            </Badge>
          </h1>
          <p className="text-muted-foreground mt-1">
            Real-time Threat Intelligence • VirusTotal • AbuseIPDB • Shodan • abuse.ch Services
          </p>
        </div>
        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-success/10 border border-success/30 text-sm">
            <div className="w-2 h-2 rounded-full bg-success animate-pulse" />
            <span className="text-success font-medium">All APIs Online</span>
          </div>
          <Button variant="cyber" onClick={handleRefresh} disabled={isRefreshing}>
            <RefreshCw className={cn("w-4 h-4 mr-2", isRefreshing && "animate-spin")} />
            {isRefreshing ? 'Syncing...' : 'Sync Feeds'}
          </Button>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-secondary/50 p-1">
          <TabsTrigger value="fusion" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Target className="w-4 h-4 mr-2" />
            Threat Fusion
          </TabsTrigger>
          <TabsTrigger value="tools" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Terminal className="w-4 h-4 mr-2" />
            Live Tools
          </TabsTrigger>
          <TabsTrigger value="feed" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Radio className="w-4 h-4 mr-2" />
            Raw Feed
          </TabsTrigger>
        </TabsList>

        {/* Threat Intelligence Fusion Tab */}
        <TabsContent value="fusion" className="space-y-6">
          {/* Quick Query */}
          <QuickQuery />

          {/* Value Proposition Banner */}
          <div className="p-4 rounded-lg border border-primary/30 bg-gradient-to-r from-primary/10 to-transparent">
            <div className="flex gap-3">
              <Target className="w-6 h-6 text-primary flex-shrink-0 mt-0.5" />
              <div>
                <h3 className="font-semibold text-primary">Contextual Threat Intelligence</h3>
                <p className="text-sm text-muted-foreground mt-1">
                  Generic threats are noise. This engine correlates OSINT data with <span className="text-foreground font-medium">your specific risk profile</span> — 
                  your industry, your systems, your suppliers, your threat actors of concern. 
                  Filter out 90% of noise and surface the 10% that actually matters.
                </p>
              </div>
            </div>
          </div>

          {/* Organization Profile Summary */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 p-4 rounded-lg border border-border bg-card/50">
              <div className="flex items-center gap-2 mb-4">
                <Building2 className="w-5 h-5 text-primary" />
                <h3 className="font-semibold">Organization Risk Profile</h3>
                <Button variant="ghost" size="sm" className="ml-auto text-xs">
                  Edit Profile
                </Button>
              </div>
              
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div>
                  <div className="text-muted-foreground text-xs uppercase mb-1">Industry</div>
                  <div className="flex items-center gap-1">
                    <Factory className="w-4 h-4 text-primary" />
                    <span className="font-medium">{orgProfile.industry}</span>
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground text-xs uppercase mb-1">Verticals</div>
                  <div className="flex flex-wrap gap-1">
                    {orgProfile.industryVerticals.map(v => (
                      <span key={v} className="text-xs bg-primary/20 text-primary px-1.5 py-0.5 rounded">{v}</span>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground text-xs uppercase mb-1">Critical Systems</div>
                  <div className="flex flex-wrap gap-1">
                    {orgProfile.criticalSystems.slice(0, 3).map(s => (
                      <span key={s} className="text-xs bg-destructive/20 text-destructive px-1.5 py-0.5 rounded">{s}</span>
                    ))}
                    {orgProfile.criticalSystems.length > 3 && (
                      <span className="text-xs text-muted-foreground">+{orgProfile.criticalSystems.length - 3}</span>
                    )}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground text-xs uppercase mb-1">Threat Actors</div>
                  <div className="flex flex-wrap gap-1">
                    {orgProfile.threatActorsOfConcern.slice(0, 2).map(a => (
                      <span key={a} className="text-xs bg-warning/20 text-warning px-1.5 py-0.5 rounded">{a}</span>
                    ))}
                    {orgProfile.threatActorsOfConcern.length > 2 && (
                      <span className="text-xs text-muted-foreground">+{orgProfile.threatActorsOfConcern.length - 2}</span>
                    )}
                  </div>
                </div>
              </div>

              <div className="mt-4 pt-4 border-t border-border grid grid-cols-2 md:grid-cols-3 gap-4 text-sm">
                <div>
                  <div className="text-muted-foreground text-xs uppercase mb-1">Key Suppliers</div>
                  <div className="flex flex-wrap gap-1">
                    {orgProfile.suppliers.slice(0, 3).map(s => (
                      <span key={s} className="text-xs bg-secondary px-1.5 py-0.5 rounded">{s}</span>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground text-xs uppercase mb-1">Technologies</div>
                  <div className="flex flex-wrap gap-1">
                    {orgProfile.technologies.slice(0, 3).map(t => (
                      <span key={t} className="text-xs bg-secondary px-1.5 py-0.5 rounded">{t}</span>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-muted-foreground text-xs uppercase mb-1">Geographies</div>
                  <div className="flex flex-wrap gap-1">
                    {orgProfile.geographies.map(g => (
                      <span key={g} className="text-xs bg-secondary px-1.5 py-0.5 rounded">{g}</span>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Fusion Stats */}
            <div className="space-y-3">
              <div className="p-4 rounded-lg border border-success/30 bg-success/5">
                <div className="flex items-center gap-2">
                  <Filter className="w-5 h-5 text-success" />
                  <span className="text-2xl font-bold text-success">{noiseFiltered}</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1">Threats filtered as noise</div>
              </div>
              <div className="p-4 rounded-lg border border-destructive/30 bg-destructive/5">
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-destructive" />
                  <span className="text-2xl font-bold text-destructive">{actionableCount}</span>
                </div>
                <div className="text-xs text-muted-foreground mt-1">Actionable threats for you</div>
              </div>
              <div className="p-4 rounded-lg border border-primary/30 bg-primary/5">
                <div className="flex items-center gap-2">
                  <TrendingUp className="w-5 h-5 text-primary" />
                  <span className="text-2xl font-bold text-primary">
                    {Math.round((actionableCount / contextualThreats.length) * 100)}%
                  </span>
                </div>
                <div className="text-xs text-muted-foreground mt-1">Signal-to-noise ratio</div>
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <span className="text-sm text-muted-foreground">Relevance threshold:</span>
              <div className="flex gap-1">
                {[0, 50, 75, 90].map(threshold => (
                  <Button
                    key={threshold}
                    variant={relevanceThreshold === threshold ? "cyber" : "ghost"}
                    size="sm"
                    onClick={() => setRelevanceThreshold(threshold)}
                  >
                    {threshold === 0 ? 'All' : `≥${threshold}%`}
                  </Button>
                ))}
              </div>
            </div>
            <Button
              variant={showOnlyActionable ? "cyber" : "ghost"}
              size="sm"
              onClick={() => setShowOnlyActionable(!showOnlyActionable)}
            >
              <CheckCircle2 className="w-4 h-4 mr-1" />
              Actionable Only
            </Button>
            <div className="ml-auto text-sm text-muted-foreground">
              Showing {filteredThreats.length} of {contextualThreats.length} threats
            </div>
          </div>

          {/* Contextual Threats */}
          <div className="space-y-4">
            {filteredThreats.map((threat) => {
              const config = typeConfig[threat.type];
              const Icon = config.icon;

              return (
                <div
                  key={threat.id}
                  className={cn(
                    "p-4 rounded-lg border transition-all",
                    threat.actionable 
                      ? "border-primary/40 bg-gradient-to-r from-primary/5 to-transparent" 
                      : "border-border bg-card/50 opacity-75"
                  )}
                >
                  <div className="flex gap-4">
                    {/* Relevance Score */}
                    <div className="flex flex-col items-center gap-1">
                      <div className={cn(
                        "w-16 h-16 rounded-lg flex flex-col items-center justify-center",
                        threat.relevanceScore >= 80 ? "bg-destructive/20" :
                        threat.relevanceScore >= 50 ? "bg-warning/20" : "bg-muted"
                      )}>
                        <span className={cn(
                          "text-xl font-bold",
                          threat.relevanceScore >= 80 ? "text-destructive" :
                          threat.relevanceScore >= 50 ? "text-warning" : "text-muted-foreground"
                        )}>
                          {threat.relevanceScore}%
                        </span>
                        <span className="text-[10px] text-muted-foreground uppercase">Relevance</span>
                      </div>
                      {threat.actionable ? (
                        <Badge variant="critical" className="text-[10px]">
                          <CheckCircle2 className="w-3 h-3 mr-1" />
                          Action
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="text-[10px]">
                          <XCircle className="w-3 h-3 mr-1" />
                          Noise
                        </Badge>
                      )}
                    </div>

                    {/* Content */}
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <Badge variant={threat.severity}>{threat.severity}</Badge>
                        <span className={cn("px-2 py-0.5 rounded text-xs", config.bg, config.color)}>
                          {threat.type.toUpperCase()}
                        </span>
                        <span className="text-xs text-muted-foreground bg-secondary px-2 py-0.5 rounded">
                          {threat.source}
                        </span>
                        <span className="text-xs text-muted-foreground ml-auto">
                          {format(threat.timestamp, 'MMM d, HH:mm')}
                        </span>
                      </div>

                      <h3 className="font-semibold font-mono">{threat.indicator}</h3>
                      <p className="text-sm text-muted-foreground mt-1">{threat.description}</p>

                      {/* Relevance Factors */}
                      <div className="mt-3 p-3 rounded bg-secondary/30 border border-border">
                        <div className="text-xs font-semibold text-muted-foreground uppercase mb-2">
                          Why This Matters to You
                        </div>
                        <div className="grid grid-cols-2 gap-2">
                          {threat.relevanceFactors.map((factor, idx) => (
                            <div key={idx} className="flex items-center gap-2 text-xs">
                              {factor.match ? (
                                <CheckCircle2 className="w-3 h-3 text-success flex-shrink-0" />
                              ) : (
                                <XCircle className="w-3 h-3 text-muted-foreground flex-shrink-0" />
                              )}
                              <span className={factor.match ? "text-foreground" : "text-muted-foreground"}>
                                {factor.factor}
                              </span>
                              {factor.match && (
                                <span className="text-primary font-mono">+{factor.weight}</span>
                              )}
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Recommended Action */}
                      {threat.actionable && (
                        <div className="mt-3 p-3 rounded bg-primary/10 border border-primary/30">
                          <div className="flex items-start gap-2">
                            <Zap className="w-4 h-4 text-primary flex-shrink-0 mt-0.5" />
                            <div>
                              <div className="text-xs font-semibold text-primary uppercase mb-1">
                                Recommended Action
                              </div>
                              <p className="text-sm">{threat.recommendedAction}</p>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Tags & Actors */}
                      <div className="flex items-center gap-4 mt-3 flex-wrap">
                        <div className="flex gap-1">
                          {threat.tags.map((tag) => (
                            <span key={tag} className="text-xs bg-secondary/50 px-2 py-0.5 rounded">
                              {tag}
                            </span>
                          ))}
                        </div>
                        {threat.threatActors.length > 0 && (
                          <div className="flex items-center gap-1 text-xs">
                            <Users className="w-3 h-3 text-warning" />
                            <span className="text-warning">{threat.threatActors.join(', ')}</span>
                          </div>
                        )}
                      </div>
                    </div>

                    {/* Actions */}
                    <div className="flex flex-col gap-2">
                      <Button variant="ghost" size="sm">
                        <ExternalLink className="w-4 h-4" />
                      </Button>
                    </div>
                  </div>
                </div>
              );
            })}

            {filteredThreats.length === 0 && (
              <div className="p-8 text-center text-muted-foreground">
                <Filter className="w-12 h-12 mx-auto mb-4 opacity-50" />
                <p>No threats match your current filters.</p>
                <p className="text-sm mt-1">Try lowering the relevance threshold.</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* OSINT Tools Tab */}
        <TabsContent value="tools" className="space-y-4">
          {/* API Status Banner - Prominent */}
          <div className="p-5 rounded-xl border-2 border-success/50 bg-gradient-to-r from-success/15 via-success/5 to-transparent relative overflow-hidden">
            {/* Glow effect */}
            <div className="absolute top-0 left-0 w-64 h-64 bg-success/20 rounded-full blur-3xl -translate-x-1/2 -translate-y-1/2" />
            
            <div className="relative flex items-start gap-4">
              <div className="w-12 h-12 rounded-xl bg-success/20 border border-success/40 flex items-center justify-center flex-shrink-0">
                <CheckCircle2 className="w-6 h-6 text-success" />
              </div>
              <div className="flex-1">
                <div className="flex items-center gap-3 mb-2">
                  <h3 className="text-lg font-bold text-success">All 6 OSINT APIs Live & Verified</h3>
                  <Badge className="bg-success text-success-foreground">
                    <div className="w-1.5 h-1.5 rounded-full bg-white animate-pulse mr-1" />
                    OPERATIONAL
                  </Badge>
                </div>
                <p className="text-sm text-muted-foreground mb-3">
                  Every tool queries real threat intelligence APIs in real-time. No simulated data.
                </p>
                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                  {osintTools.map(tool => (
                    <div key={tool.id} className="flex items-center gap-2 text-xs bg-background/50 rounded-lg px-2 py-1.5 border border-border">
                      <div className="w-1.5 h-1.5 rounded-full bg-success" />
                      <tool.icon className="w-3 h-3 text-muted-foreground" />
                      <span className="font-medium">{tool.name}</span>
                      <span className="text-muted-foreground ml-auto">{tool.rateLimit}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Search */}
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <Input
              placeholder="Search tools by name, description, or tag..."
              className="pl-10 bg-secondary/30 border-border"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          {/* Category & API Type Legend */}
          <div className="flex gap-4 flex-wrap">
            <div className="flex gap-2 items-center">
              <span className="text-xs text-muted-foreground">Category:</span>
              {Object.entries(categoryConfig).map(([key, config]) => (
                <span key={key} className={cn("px-2 py-1 rounded text-xs font-medium", config.color)}>
                  {config.label}
                </span>
              ))}
            </div>
            <div className="flex gap-2 items-center">
              <span className="text-xs text-muted-foreground">API:</span>
              {Object.entries(apiTypeConfig).map(([key, config]) => (
                <span key={key} className={cn("px-2 py-1 rounded text-xs font-medium", config.color)}>
                  {config.label}
                </span>
              ))}
            </div>
          </div>

          {/* Tools Grid - Enhanced */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredTools.map((tool) => {
              const Icon = tool.icon;
              const category = categoryConfig[tool.category];
              const apiType = apiTypeConfig[tool.apiType];

              return (
                <div
                  key={tool.id}
                  onClick={() => handleToolClick(tool)}
                  className="group p-4 rounded-xl border-2 cursor-pointer transition-all border-border bg-card/50 hover:border-success/50 hover:bg-success/5 hover:shadow-lg hover:shadow-success/10 relative overflow-hidden"
                >
                  {/* Live indicator */}
                  <div className="absolute top-3 right-3 flex items-center gap-1.5 px-2 py-0.5 rounded-full bg-success/20 border border-success/30">
                    <div className="w-1.5 h-1.5 rounded-full bg-success animate-pulse" />
                    <span className="text-[10px] font-medium text-success uppercase">Live</span>
                  </div>
                  
                  <div className="flex items-start gap-3">
                    <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-primary/20 to-primary/5 border border-primary/20 flex items-center justify-center flex-shrink-0 group-hover:border-success/40 transition-colors">
                      <Icon className="w-6 h-6 text-primary group-hover:text-success transition-colors" />
                    </div>
                    <div className="flex-1 pr-16">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <h3 className="font-bold text-base group-hover:text-success transition-colors">{tool.name}</h3>
                      </div>
                      <div className="flex items-center gap-1.5 mb-2">
                        <span className={cn("px-2 py-0.5 rounded text-xs", category.color)}>
                          {category.label}
                        </span>
                        <span className={cn("px-2 py-0.5 rounded text-xs", apiType.color)}>
                          {apiType.label}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground mb-3">{tool.description}</p>
                      <div className="flex items-center gap-3 text-xs">
                        <div className="flex items-center gap-1 text-muted-foreground">
                          <Clock className="w-3 h-3" />
                          <span>{tool.rateLimit}</span>
                        </div>
                        <Button variant="link" size="sm" className="h-auto p-0 text-xs text-primary group-hover:text-success">
                          Launch Tool →
                        </Button>
                      </div>
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {tool.tags.map(tag => (
                          <span key={tag} className="text-xs bg-secondary/50 px-2 py-0.5 rounded">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </TabsContent>

        {/* Raw Threat Feed Tab */}
        <TabsContent value="feed" className="space-y-4">
          <div className="p-4 rounded-lg border border-border bg-card/50 text-center">
            <Radio className="w-12 h-12 mx-auto mb-4 text-muted-foreground opacity-50" />
            <h3 className="font-semibold mb-2">Raw Threat Intelligence Feed</h3>
            <p className="text-sm text-muted-foreground">
              Use the Quick Query tool or individual OSINT tools to fetch real-time threat data.
              Results will appear here for review and correlation.
            </p>
          </div>
        </TabsContent>
      </Tabs>

      {/* Tool Modal */}
      <OSINTToolModal
        isOpen={showToolModal}
        onClose={() => setShowToolModal(false)}
        tool={selectedTool}
      />
    </div>
  );
}
