export type ThreatSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type AlertStatus = 'new' | 'investigating' | 'contained' | 'remediated' | 'false_positive';

export interface SecurityLog {
  id: string;
  timestamp: string;
  sourceType: 'WinEventLog:Security' | 'Linux:Syslog' | 'AWS:CloudTrail' | 'Network:Zeek' | 'Sophos:XDR' | 'Firewall:PaloAlto';
  host: string;
  user: string;
  srcIp?: string;
  destIp?: string;
  destPort?: number;
  eventId?: string | number;
  processName?: string;
  commandLine?: string;
  parentProcess?: string;
  fileHash?: string;
  message: string;
  severity: ThreatSeverity;
  raw: string;
  entropy?: number;
  clusterId?: string;
  anomalyScore?: number; // 0 - 100 calculated by LogAI / Alkido
}

export interface SecurityAlert {
  id: string;
  title: string;
  description: string;
  severity: ThreatSeverity;
  status: AlertStatus;
  detectedAt: string;
  source: 'LogAI' | 'Alkido' | 'Sophos XDR' | 'Splunk Correlation' | 'Elastic SIEM' | 'ThreatIntel Feed';
  endpoint: string;
  user: string;
  mitreTactic: string;
  mitreTechniqueId: string;
  mitreTechniqueName: string;
  d3fendCountermeasure?: string;
  confidenceScore: number; // 0 - 100
  relatedLogIds: string[];
  iocs: {
    type: 'ip' | 'domain' | 'sha256' | 'url' | 'user';
    value: string;
    threatScore: number; // 0 - 100
  }[];
  playbookId?: string;
  aiAnalysis?: {
    summary: string;
    rootCause: string;
    recommendations: string[];
    threatActor?: string;
  };
}

export interface ThreatIntelligenceItem {
  id: string;
  indicator: string;
  type: 'ip' | 'domain' | 'sha256' | 'cve';
  threatName: string;
  feedSource: 'AlienVault OTX' | 'VirusTotal' | 'AbuseIPDB' | 'MISP' | 'CISA KEV';
  reputationScore: number; // 0 - 100 (100 is malicious)
  confidence: number;
  associatedThreatActor: string;
  geolocation?: string;
  tags: string[];
  firstSeen: string;
  lastSeen: string;
  activeCampaign?: string;
}

export interface EndpointHost {
  id: string;
  hostname: string;
  ip: string;
  os: string;
  agentVersion: string;
  status: 'online' | 'isolated' | 'compromised' | 'offline';
  lastHeartbeat: string;
  riskScore: number; // 0 - 100
  activeAlertsCount: number;
  user: string;
  installedEfs: boolean;
  tamperProtection: boolean;
}

export interface ProcessNode {
  pid: number;
  ppid: number;
  name: string;
  commandLine: string;
  user: string;
  startTime: string;
  hash: string;
  status: 'running' | 'terminated' | 'quarantined';
  suspicious: boolean;
  detectionReason?: string;
  children?: ProcessNode[];
}

export interface MitreTechnique {
  id: string;
  name: string;
  tacticId: string;
  tacticName: string;
  description: string;
  detectedCount: number;
  coveredByRules: boolean;
  d3fendTechniqueId: string;
  d3fendTechniqueName: string;
  d3fendCategory: 'Model' | 'Harden' | 'Detect' | 'Isolate' | 'Deceive' | 'Evict';
  gapStatus: 'covered' | 'active_threat_covered' | 'uncovered_gap';
}

export interface PlaybookStep {
  id: string;
  name: string;
  action: string;
  targetSystem: 'Sophos XDR' | 'Splunk SIEM' | 'Active Directory' | 'Palo Alto FW' | 'AWS IAM' | 'Slack / PagerDuty' | 'Sandbox';
  description: string;
  status: 'idle' | 'running' | 'success' | 'failed';
  output?: Record<string, any>;
}

export interface SoarPlaybook {
  id: string;
  name: string;
  description: string;
  triggerEvent: string;
  targetThreat: string;
  executionCount: number;
  avgDurationSec: number;
  steps: PlaybookStep[];
  status: 'idle' | 'running' | 'completed';
}

export interface UebaProfile {
  username: string;
  department: string;
  riskScore: number; // 0 - 100
  anomalyIndicators: string[];
  failedLoginsToday: number;
  unusualHoursActivity: boolean;
  highVolumeDataTransfer: boolean;
  lastActivity: string;
}

export interface AttackScenario {
  id: string;
  name: string;
  adversary: string;
  severity: ThreatSeverity;
  description: string;
  attackChainSteps: {
    stage: string;
    technique: string;
    action: string;
    detectionSource: string;
  }[];
  mitreCoverage: string[];
  recommendedPlaybookId: string;
}
