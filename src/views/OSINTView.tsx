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
  Cloud
} from 'lucide-react';
import { format } from 'date-fns';

// OSINT Tool definitions
interface OSINTTool {
  id: string;
  name: string;
  description: string;
  category: 'discovery' | 'enumeration' | 'analysis' | 'monitoring';
  icon: React.ComponentType<{ className?: string }>;
  usage: string;
  example: string;
  tags: string[];
}

const osintTools: OSINTTool[] = [
  {
    id: 'shodan',
    name: 'Shodan',
    description: 'Search engine for internet-connected devices. Discovers exposed servers, IoT devices, webcams, industrial control systems, and misconfigured services.',
    category: 'discovery',
    icon: Server,
    usage: 'Search by IP, hostname, organization, port, or service banner. Filter by country, OS, or vulnerability.',
    example: 'shodan search "port:22 country:US org:Amazon"',
    tags: ['IoT', 'Servers', 'Ports', 'Vulnerabilities'],
  },
  {
    id: 'theharvester',
    name: 'theHarvester',
    description: 'Gathers email addresses, subdomains, hosts, employee names, open ports, and banners from public sources like search engines and PGP key servers.',
    category: 'enumeration',
    icon: Mail,
    usage: 'Enumerate emails and subdomains for target domain. Sources include Google, Bing, LinkedIn, Twitter.',
    example: 'theHarvester -d example.com -b google,linkedin -l 500',
    tags: ['Emails', 'Subdomains', 'DNS', 'Social'],
  },
  {
    id: 'maltego',
    name: 'Maltego',
    description: 'Visual link analysis tool that maps relationships between people, companies, domains, and infrastructure. Creates intelligence graphs from OSINT data.',
    category: 'analysis',
    icon: Share2,
    usage: 'Build entity graphs showing connections between targets. Use transforms to discover related infrastructure.',
    example: 'Transform: Domain → DNS Names → IP Addresses → Geolocation',
    tags: ['Graphs', 'Relationships', 'Infrastructure', 'Visual'],
  },
  {
    id: 'google-dorking',
    name: 'Google Dorking',
    description: 'Advanced Google search operators to find sensitive information, exposed files, login pages, and vulnerable systems indexed by Google.',
    category: 'discovery',
    icon: FileSearch,
    usage: 'Use operators like site:, filetype:, inurl:, intitle: to narrow searches.',
    example: 'site:example.com filetype:pdf "confidential" OR "internal use only"',
    tags: ['Search', 'Files', 'Exposed Data', 'Indexing'],
  },
  {
    id: 'whois',
    name: 'WHOIS Lookup',
    description: 'Query domain registration databases to find owner information, registrar details, nameservers, creation/expiration dates, and contact information.',
    category: 'enumeration',
    icon: Database,
    usage: 'Lookup domain or IP to find registration details and ownership history.',
    example: 'whois example.com | grep -E "Registrant|Admin|Tech"',
    tags: ['Domains', 'Registration', 'Ownership', 'History'],
  },
  {
    id: 'dns-recon',
    name: 'DNS Reconnaissance',
    description: 'Enumerate DNS records including A, AAAA, MX, TXT, NS, SOA, and PTR records. Discover subdomains through zone transfers, brute force, or certificate transparency.',
    category: 'enumeration',
    icon: Network,
    usage: 'Query DNS records, attempt zone transfers, enumerate subdomains, check for dangling DNS.',
    example: 'dnsrecon -d example.com -t std,brt,crt',
    tags: ['DNS', 'Subdomains', 'Zone Transfer', 'Records'],
  },
  {
    id: 'reverse-image',
    name: 'Reverse Image Search',
    description: 'Find other instances of images online, track image origins, identify people or locations, and verify authenticity of photos.',
    category: 'analysis',
    icon: Image,
    usage: 'Upload image to Google Images, TinEye, or Yandex to find matches and metadata.',
    example: 'Upload profile photo → Find social media accounts, original sources',
    tags: ['Images', 'Verification', 'SOCMINT', 'Metadata'],
  },
  {
    id: 'censys',
    name: 'Censys',
    description: 'Search engine that scans the entire IPv4 address space for hosts and websites. Provides SSL certificate and service analysis.',
    category: 'discovery',
    icon: Eye,
    usage: 'Search by IP, domain, certificate, or autonomous system. Analyze SSL/TLS configurations.',
    example: 'parsed.subject_dn:"O=Example Inc" AND protocols:443/https',
    tags: ['SSL', 'Certificates', 'Hosts', 'Services'],
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

// Standard Threat Intelligence Feed
interface ThreatIntel {
  id: string;
  source: string;
  type: 'malware' | 'botnet' | 'phishing' | 'darkweb' | 'exploit' | 'apt';
  indicator: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  timestamp: Date;
  matchScore: number;
  tags: string[];
}

const mockThreatFeed: ThreatIntel[] = [
  {
    id: 'ti-1',
    source: 'AlienVault OTX',
    type: 'botnet',
    indicator: 'Mirai variant C2: 185.220.101.xxx',
    description: 'New Mirai botnet variant with enhanced DDoS capabilities targeting IoT devices.',
    severity: 'critical',
    timestamp: new Date(Date.now() - 3600000),
    matchScore: 92,
    tags: ['DDoS', 'IoT', 'Botnet'],
  },
  {
    id: 'ti-2',
    source: 'Recorded Future',
    type: 'darkweb',
    indicator: 'RaaS listing - "NightCrypt"',
    description: 'New Ransomware-as-a-Service targeting financial sector detected on underground forum.',
    severity: 'high',
    timestamp: new Date(Date.now() - 7200000),
    matchScore: 78,
    tags: ['Ransomware', 'RaaS', 'Financial'],
  },
  {
    id: 'ti-3',
    source: 'VirusTotal',
    type: 'malware',
    indicator: 'SHA256: a3f4b8c2d1e6...',
    description: 'LockBit 3.0 variant with new anti-analysis and sandbox evasion techniques.',
    severity: 'critical',
    timestamp: new Date(Date.now() - 10800000),
    matchScore: 85,
    tags: ['Ransomware', 'LockBit', 'Evasion'],
  },
  {
    id: 'ti-4',
    source: 'CISA Advisory',
    type: 'apt',
    indicator: 'APT29 - SolarWinds TTPs',
    description: 'State-sponsored actor targeting government and diplomatic entities with supply chain attacks.',
    severity: 'critical',
    timestamp: new Date(Date.now() - 14400000),
    matchScore: 70,
    tags: ['APT', 'Government', 'Supply Chain'],
  },
  {
    id: 'ti-5',
    source: 'Exploit-DB',
    type: 'exploit',
    indicator: 'CVE-2024-XXXX: RCE in CMS',
    description: 'Critical remote code execution with public PoC exploit available.',
    severity: 'high',
    timestamp: new Date(Date.now() - 18000000),
    matchScore: 82,
    tags: ['RCE', 'CMS', 'PoC Available'],
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

export function OSINTView() {
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedTool, setSelectedTool] = useState<OSINTTool | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [activeTab, setActiveTab] = useState('fusion');
  const [showOnlyActionable, setShowOnlyActionable] = useState(false);
  const [relevanceThreshold, setRelevanceThreshold] = useState(50);

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

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Globe className="w-7 h-7 text-primary" />
            OSINT Reconnaissance Center
          </h1>
          <p className="text-muted-foreground mt-1">
            Threat Intelligence Fusion, Enrichment & Contextual Correlation
          </p>
        </div>
        <Button variant="cyber" onClick={handleRefresh} disabled={isRefreshing}>
          <RefreshCw className={cn("w-4 h-4 mr-2", isRefreshing && "animate-spin")} />
          {isRefreshing ? 'Syncing...' : 'Sync Feeds'}
        </Button>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
        <TabsList className="bg-secondary/50 p-1">
          <TabsTrigger value="fusion" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Target className="w-4 h-4 mr-2" />
            Threat Fusion
          </TabsTrigger>
          <TabsTrigger value="tools" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Terminal className="w-4 h-4 mr-2" />
            Recon Tools
          </TabsTrigger>
          <TabsTrigger value="feed" className="data-[state=active]:bg-primary data-[state=active]:text-primary-foreground">
            <Radio className="w-4 h-4 mr-2" />
            Raw Feed
          </TabsTrigger>
        </TabsList>

        {/* Threat Intelligence Fusion Tab */}
        <TabsContent value="fusion" className="space-y-6">
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

          {/* Category Legend */}
          <div className="flex gap-2 flex-wrap">
            {Object.entries(categoryConfig).map(([key, config]) => (
              <span key={key} className={cn("px-2 py-1 rounded text-xs font-medium", config.color)}>
                {config.label}
              </span>
            ))}
          </div>

          {/* Tools Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {filteredTools.map((tool) => {
              const Icon = tool.icon;
              const category = categoryConfig[tool.category];
              const isSelected = selectedTool?.id === tool.id;

              return (
                <div
                  key={tool.id}
                  onClick={() => setSelectedTool(isSelected ? null : tool)}
                  className={cn(
                    "p-4 rounded-lg border cursor-pointer transition-all",
                    isSelected 
                      ? "border-primary bg-primary/10 ring-2 ring-primary/50" 
                      : "border-border bg-card/50 hover:border-primary/30"
                  )}
                >
                  <div className="flex items-start gap-3">
                    <div className="w-10 h-10 rounded-lg bg-secondary flex items-center justify-center flex-shrink-0">
                      <Icon className="w-5 h-5 text-primary" />
                    </div>
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <h3 className="font-semibold">{tool.name}</h3>
                        <span className={cn("px-2 py-0.5 rounded text-xs", category.color)}>
                          {category.label}
                        </span>
                      </div>
                      <p className="text-sm text-muted-foreground line-clamp-2">
                        {tool.description}
                      </p>
                      <div className="flex gap-1 mt-2 flex-wrap">
                        {tool.tags.map((tag) => (
                          <span key={tag} className="text-xs bg-secondary/50 px-2 py-0.5 rounded">
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  {/* Expanded Details */}
                  {isSelected && (
                    <div className="mt-4 pt-4 border-t border-border space-y-3">
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Usage</h4>
                        <p className="text-sm">{tool.usage}</p>
                      </div>
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Example</h4>
                        <code className="text-xs bg-background/80 p-2 rounded block font-mono text-primary">
                          {tool.example}
                        </code>
                      </div>
                      <Button variant="cyber" size="sm" className="w-full">
                        <ExternalLink className="w-4 h-4 mr-2" />
                        Launch Tool
                      </Button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </TabsContent>

        {/* Raw Threat Feed Tab */}
        <TabsContent value="feed" className="space-y-4">
          <div className="p-4 rounded-lg border border-warning/30 bg-warning/5">
            <div className="flex gap-3">
              <Info className="w-5 h-5 text-warning flex-shrink-0" />
              <div>
                <h3 className="font-semibold text-warning">Unfiltered Raw Feed</h3>
                <p className="text-sm text-muted-foreground">
                  This is the raw OSINT feed without contextual enrichment. For prioritized, actionable intelligence, 
                  use the <span className="text-primary cursor-pointer" onClick={() => setActiveTab('fusion')}>Threat Fusion</span> tab.
                </p>
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2 text-sm text-muted-foreground">
            <Clock className="w-4 h-4" />
            <span>Live threat intelligence from multiple sources</span>
            <Badge variant="info" className="ml-auto">
              <Radio className="w-3 h-3 mr-1 animate-pulse" />
              Live
            </Badge>
          </div>

          <div className="space-y-3">
            {mockThreatFeed.map((item) => {
              const config = typeConfig[item.type];
              const Icon = config.icon;

              return (
                <div
                  key={item.id}
                  className="p-4 rounded-lg border border-border bg-card/50 hover:border-primary/30 transition-all"
                >
                  <div className="flex items-start gap-4">
                    <div className={cn(
                      "w-12 h-12 rounded-lg flex items-center justify-center flex-shrink-0",
                      config.bg
                    )}>
                      <Icon className={cn("w-6 h-6", config.color)} />
                    </div>

                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1 flex-wrap">
                        <Badge variant={item.severity}>{item.severity}</Badge>
                        <span className="text-xs text-muted-foreground bg-secondary px-2 py-0.5 rounded">
                          {item.source}
                        </span>
                        <span className="text-xs text-primary font-mono">
                          {item.matchScore}% raw score
                        </span>
                      </div>
                      <h3 className="font-medium font-mono">{item.indicator}</h3>
                      <p className="text-sm text-muted-foreground mt-1">{item.description}</p>

                      <div className="flex items-center gap-4 mt-3">
                        <div className="flex gap-1">
                          {item.tags.map((tag) => (
                            <span key={tag} className="text-xs bg-secondary/50 px-2 py-0.5 rounded">
                              {tag}
                            </span>
                          ))}
                        </div>
                        <span className="text-xs text-muted-foreground ml-auto">
                          {format(item.timestamp, 'MMM d, HH:mm')}
                        </span>
                      </div>
                    </div>

                    <Button variant="ghost" size="sm">
                      <ExternalLink className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </TabsContent>
      </Tabs>
    </div>
  );
}