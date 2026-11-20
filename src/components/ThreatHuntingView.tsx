import React, { useState, useMemo, useEffect } from 'react';
import {
  Crosshair,
  Search,
  Share2,
  ShieldAlert,
  Server,
  User,
  Hash,
  Globe,
  Terminal,
  ArrowRight,
  ExternalLink,
  Flame,
  Radio,
  Sliders,
  CheckCircle2,
  Lock,
  Sparkles,
  RefreshCw,
  AlertTriangle,
  ShieldCheck,
  MapPin,
  Network,
  Layers,
  Shield,
  Clock,
  Check,
} from 'lucide-react';
import { SecurityAlert, SecurityLog, ThreatIntelligenceItem, ExternalThreatIntelOverlay } from '../types/soc.ts';
import { lookupThreatIntel, fetchLiveThreatIntelFeed } from '../services/api.ts';

interface ThreatHuntingViewProps {
  logs: SecurityLog[];
  alerts: SecurityAlert[];
  threatIntel: ThreatIntelligenceItem[];
  initialPivotQuery?: string;
  onSelectAlert: (alert: SecurityAlert) => void;
  onExecutePlaybook: (playbookId: string) => void;
  onIsolateHost: (hostname: string) => void;
}

export const ThreatHuntingView: React.FC<ThreatHuntingViewProps> = ({
  logs,
  alerts,
  threatIntel,
  initialPivotQuery = '185.220.101.5',
  onSelectAlert,
  onExecutePlaybook,
  onIsolateHost,
}) => {
  const [pivotTerm, setPivotTerm] = useState(initialPivotQuery);
  const [activeGraphNode, setActiveGraphNode] = useState<string>('c2_ip');
  const [activeViewMode, setActiveViewMode] = useState<'overlay' | 'graph' | 'live_feed'>('overlay');

  // External Threat Intel live state
  const [externalOverlay, setExternalOverlay] = useState<ExternalThreatIntelOverlay | null>(null);
  const [isLoadingOverlay, setIsLoadingOverlay] = useState<boolean>(false);
  const [overlayError, setOverlayError] = useState<string | null>(null);
  const [liveFeedItems, setLiveFeedItems] = useState<any[]>([]);
  const [feedFilter, setFeedFilter] = useState<'all' | 'ip' | 'domain' | 'sha256' | 'cve'>('all');
  const [actionNotice, setActionNotice] = useState<string | null>(null);

  // Load live external feed on mount
  useEffect(() => {
    async function loadFeed() {
      try {
        const feed = await fetchLiveThreatIntelFeed();
        setLiveFeedItems(feed);
      } catch (err) {
        console.warn('Could not load live threat feed:', err);
      }
    }
    loadFeed();
  }, []);

  // Fetch external intelligence overlay when pivotTerm changes
  useEffect(() => {
    let isCancelled = false;
    async function fetchOverlay() {
      if (!pivotTerm.trim()) {
        setExternalOverlay(null);
        return;
      }
      setIsLoadingOverlay(true);
      setOverlayError(null);
      try {
        const result = await lookupThreatIntel(pivotTerm.trim());
        if (!isCancelled) {
          setExternalOverlay(result);
        }
      } catch (err: any) {
        if (!isCancelled) {
          setOverlayError(err.message || 'Threat intelligence lookup failed');
        }
      } finally {
        if (!isCancelled) {
          setIsLoadingOverlay(false);
        }
      }
    }

    const timer = setTimeout(() => {
      fetchOverlay();
    }, 250);

    return () => {
      isCancelled = true;
      clearTimeout(timer);
    };
  }, [pivotTerm]);

  // Match logs containing the pivot term
  const matchedLogs = useMemo(() => {
    if (!pivotTerm.trim()) return logs;
    const term = pivotTerm.toLowerCase();
    return logs.filter(
      (l) =>
        l.host.toLowerCase().includes(term) ||
        (l.user && l.user.toLowerCase().includes(term)) ||
        (l.srcIp && l.srcIp.toLowerCase().includes(term)) ||
        (l.destIp && l.destIp.toLowerCase().includes(term)) ||
        (l.processName && l.processName.toLowerCase().includes(term)) ||
        l.message.toLowerCase().includes(term) ||
        l.raw.toLowerCase().includes(term)
    );
  }, [logs, pivotTerm]);

  // Match alerts containing the pivot term
  const matchedAlerts = useMemo(() => {
    if (!pivotTerm.trim()) return alerts;
    const term = pivotTerm.toLowerCase();
    return alerts.filter(
      (a) =>
        a.endpoint.toLowerCase().includes(term) ||
        (a.user && a.user.toLowerCase().includes(term)) ||
        a.title.toLowerCase().includes(term) ||
        (a.iocs && a.iocs.some((i) => i.value.toLowerCase().includes(term)))
    );
  }, [alerts, pivotTerm]);

  // Match Local Threat Intel item from initial dataset
  const matchedLocalIntel = useMemo(() => {
    const term = pivotTerm.toLowerCase();
    return threatIntel.find(
      (t) =>
        t.indicator.toLowerCase().includes(term) ||
        t.associatedThreatActor.toLowerCase().includes(term) ||
        t.threatName.toLowerCase().includes(term)
    );
  }, [threatIntel, pivotTerm]);

  // Blast Radius stats
  const blastRadius = useMemo(() => {
    const impactedHosts = [...new Set(matchedLogs.map((l) => l.host).filter(Boolean))];
    const impactedUsers = [...new Set(matchedLogs.map((l) => l.user).filter(Boolean))];
    const egressCount = matchedLogs.filter((l) => l.destIp).length;
    const criticalLogsCount = matchedLogs.filter((l) => l.severity === 'critical').length;

    return {
      hosts: impactedHosts,
      users: impactedUsers,
      egressCount,
      criticalLogsCount,
    };
  }, [matchedLogs]);

  // Pre-configured IOC pivot quick links
  const quickIocs = [
    { label: 'C2 IP: 185.220.101.5', value: '185.220.101.5', type: 'ip' },
    { label: 'DNS Tunnel: 91.215.85.17', value: '91.215.85.17', type: 'ip' },
    { label: 'ALPHV Hash: 8f4c2e6b...', value: '8f4c2e6b91a7d3f048e5b6c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2', type: 'hash' },
    { label: 'Exfil IP: 54.210.12.89', value: '54.210.12.89', type: 'ip' },
    { label: 'PAN-OS CVE: CVE-2024-3400', value: 'CVE-2024-3400', type: 'cve' },
    { label: 'Tunnel FQDN: *.tunnel.c2-darknode.net', value: 'a8f9c1b3.tunnel.c2-darknode.net', type: 'domain' },
    { label: 'Workstation: WS-FINANCE-07', value: 'WS-FINANCE-07', type: 'host' },
    { label: 'DC: DC-CORP-01', value: 'DC-CORP-01', type: 'host' },
  ];

  const filteredFeed = useMemo(() => {
    if (feedFilter === 'all') return liveFeedItems;
    return liveFeedItems.filter((item) => item.type === feedFilter);
  }, [liveFeedItems, feedFilter]);

  const triggerActionFeedback = (msg: string) => {
    setActionNotice(msg);
    setTimeout(() => setActionNotice(null), 4000);
  };

  return (
    <div className="space-y-4 font-mono">
      {/* Search & Pivot Command Bar */}
      <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 transition-colors">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <Crosshair className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-2">
                <span>IOC PIVOTING & LIVE THREAT INTELLIGENCE OVERLAY</span>
                <span className="text-[10px] px-1.5 py-0.2 rounded font-bold bg-cyan-100 dark:bg-cyan-950 text-cyan-800 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-700">
                  OTX • VIRUSTOTAL • ABUSEIPDB • CISA KEV
                </span>
              </h2>
              <p className="text-[10px] text-slate-500 dark:text-slate-400">
                Live multi-source OSINT feed fusion with local enterprise SIEM logs and blast-radius correlation
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3 text-xs">
            {/* View Mode Switcher */}
            <div className="flex rounded border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-950 p-0.5 text-xs font-semibold">
              <button
                onClick={() => setActiveViewMode('overlay')}
                className={`px-2.5 py-1 rounded transition cursor-pointer flex items-center gap-1 ${
                  activeViewMode === 'overlay'
                    ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                <ShieldCheck className="w-3.5 h-3.5" />
                <span>Intel Overlay</span>
              </button>
              <button
                onClick={() => setActiveViewMode('graph')}
                className={`px-2.5 py-1 rounded transition cursor-pointer flex items-center gap-1 ${
                  activeViewMode === 'graph'
                    ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                <Share2 className="w-3.5 h-3.5" />
                <span>Attack Graph</span>
              </button>
              <button
                onClick={() => setActiveViewMode('live_feed')}
                className={`px-2.5 py-1 rounded transition cursor-pointer flex items-center gap-1 ${
                  activeViewMode === 'live_feed'
                    ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                }`}
              >
                <Radio className="w-3.5 h-3.5 text-red-500 animate-pulse" />
                <span>Live Feed ({liveFeedItems.length})</span>
              </button>
            </div>
          </div>
        </div>

        {/* Pivot Input Bar */}
        <div className="relative">
          <Search className="w-4 h-4 text-cyan-600 dark:text-cyan-400 absolute left-3 top-3 pointer-events-none" />
          <input
            type="text"
            value={pivotTerm}
            onChange={(e) => setPivotTerm(e.target.value)}
            placeholder="Search & pivot on any IP, FQDN/Domain, SHA-256 Hash, CVE-ID, or User..."
            className="w-full pl-9 pr-32 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded text-xs text-cyan-900 dark:text-cyan-300 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500 dark:focus:border-cyan-400"
          />
          <div className="absolute right-2 top-1.5 flex items-center gap-1.5">
            {isLoadingOverlay && (
              <span className="text-[10px] text-cyan-600 dark:text-cyan-400 flex items-center gap-1">
                <RefreshCw className="w-3 h-3 animate-spin" />
                <span>Enriching...</span>
              </span>
            )}
            {pivotTerm && (
              <button
                onClick={() => setPivotTerm('')}
                className="px-2 py-1 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white text-xs cursor-pointer"
              >
                Clear
              </button>
            )}
          </div>
        </div>

        {/* Quick Pivot Chips */}
        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className="text-slate-500 dark:text-slate-400 font-bold">DISCOVERED ARTIFACTS:</span>
          {quickIocs.map((ioc) => (
            <button
              key={ioc.value}
              onClick={() => setPivotTerm(ioc.value)}
              className={`px-2 py-0.5 rounded border transition cursor-pointer flex items-center gap-1 ${
                pivotTerm.toLowerCase() === ioc.value.toLowerCase()
                  ? 'bg-cyan-500 text-slate-950 font-bold border-cyan-400 shadow-sm'
                  : 'bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-800 hover:bg-slate-200 dark:hover:bg-slate-800'
              }`}
            >
              <span>{ioc.label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Action Notice feedback banner */}
      {actionNotice && (
        <div className="p-2.5 rounded bg-cyan-100 dark:bg-cyan-950 border border-cyan-300 dark:border-cyan-800 text-cyan-900 dark:text-cyan-200 text-xs flex items-center justify-between">
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
            <span>{actionNotice}</span>
          </div>
          <button onClick={() => setActionNotice(null)} className="text-xs text-slate-400">
            ✕
          </button>
        </div>
      )}

      {/* VIEW 1: External Threat Intel Overlay with Local SIEM Correlation */}
      {activeViewMode === 'overlay' && (
        <div className="space-y-4">
          {/* Main Overlay Comparison Grid */}
          {externalOverlay ? (
            <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4 transition-colors">
              {/* Header Badge & Reputation Bar */}
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
                <div className="space-y-0.5">
                  <div className="flex items-center gap-2">
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase border ${
                        externalOverlay.reputationScore >= 80
                          ? 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 border-red-300 dark:border-red-800'
                          : externalOverlay.reputationScore >= 50
                          ? 'bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-800'
                          : 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border-emerald-300 dark:border-emerald-800'
                      }`}
                    >
                      {externalOverlay.reputationScore >= 80
                        ? 'MALICIOUS THREAT'
                        : externalOverlay.reputationScore >= 50
                        ? 'SUSPICIOUS ENTITY'
                        : 'BENIGN / UNCLASSIFIED'}
                    </span>
                    <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                      {externalOverlay.indicator}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 uppercase">
                      {externalOverlay.type}
                    </span>
                  </div>
                  <div className="text-xs font-semibold text-slate-700 dark:text-slate-300">
                    {externalOverlay.threatName}
                  </div>
                </div>

                <div className="flex items-center gap-3">
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400 uppercase">Global Reputation Score</div>
                    <div className="text-lg font-bold font-mono text-red-600 dark:text-red-400">
                      {externalOverlay.reputationScore} / 100
                    </div>
                  </div>
                  <div className="text-right border-l border-slate-200 dark:border-slate-800 pl-3">
                    <div className="text-[10px] text-slate-400 uppercase">External Confidence</div>
                    <div className="text-lg font-bold font-mono text-cyan-600 dark:text-cyan-400">
                      {externalOverlay.confidence}%
                    </div>
                  </div>
                </div>
              </div>

              {/* Threat Gap & Correlation Analysis Banner */}
              {externalOverlay.localCorrelation && (
                <div
                  className={`p-3 rounded-lg border text-xs flex items-start gap-3 ${
                    externalOverlay.localCorrelation.severityVariance === 'higher_than_external'
                      ? 'bg-amber-50 dark:bg-amber-950/40 border-amber-300 dark:border-amber-800/80 text-amber-900 dark:text-amber-200'
                      : externalOverlay.localCorrelation.internalSightingsCount > 0
                      ? 'bg-red-50 dark:bg-red-950/40 border-red-300 dark:border-red-800/80 text-red-900 dark:text-red-200'
                      : 'bg-blue-50 dark:bg-blue-950/40 border-blue-300 dark:border-blue-800/80 text-blue-900 dark:text-blue-200'
                  }`}
                >
                  <AlertTriangle className="w-5 h-5 flex-shrink-0 mt-0.5" />
                  <div className="space-y-1">
                    <div className="font-bold flex items-center gap-2">
                      <span>INTELLIGENCE FUSION & THREAT GAP ANALYSIS</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded font-bold uppercase bg-white dark:bg-slate-900 border">
                        {externalOverlay.localCorrelation.internalSightingsCount > 0
                          ? 'ACTIVE INTERNAL SIGHTINGS'
                          : 'PERIMETER RECONNAISSANCE ONLY'}
                      </span>
                    </div>
                    <p className="text-[11px] leading-relaxed">
                      {externalOverlay.localCorrelation.threatGapAnalysis}
                    </p>
                  </div>
                </div>
              )}

              {/* Side-by-Side: Global Threat Intel vs. Local Enterprise Telemetry */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Panel A: External Multi-Feed Intelligence */}
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <Globe className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
                      EXTERNAL OSINT THREAT INTELLIGENCE
                    </span>
                    <span className="text-[10px] text-slate-400">AlienVault • VirusTotal • AbuseIPDB</span>
                  </div>

                  {/* Threat Actor & Malware Family */}
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Attributed Threat Actor</div>
                      <div className="font-bold text-red-600 dark:text-red-400 mt-0.5">
                        {externalOverlay.associatedThreatActor || 'Unassigned APT'}
                      </div>
                    </div>
                    <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Geolocation & Hosting</div>
                      <div className="font-bold text-slate-800 dark:text-slate-200 mt-0.5 truncate">
                        {externalOverlay.country || 'Global'} ({externalOverlay.countryCode || 'NET'})
                      </div>
                    </div>
                  </div>

                  {/* Multi-Vendor Scores Breakdown */}
                  <div className="space-y-1.5">
                    <div className="text-[10px] font-bold text-slate-500 uppercase">Feed Engine Detection Breakdown</div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                      {externalOverlay.sources.map((src) => (
                        <div
                          key={src.sourceName}
                          className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-0.5"
                        >
                          <div className="flex items-center justify-between font-bold">
                            <span>{src.sourceName}</span>
                            <span
                              className={`text-[10px] ${
                                src.score >= 80 ? 'text-red-600 dark:text-red-400' : 'text-amber-600 dark:text-amber-400'
                              }`}
                            >
                              {src.positives && src.totalEngines
                                ? `${src.positives}/${src.totalEngines}`
                                : `${src.score}%`}
                            </span>
                          </div>
                          <div className="text-[10px] text-slate-500 truncate">{src.details}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Passive DNS & Tags */}
                  {externalOverlay.passiveDns && externalOverlay.passiveDns.length > 0 && (
                    <div className="p-2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px] space-y-1">
                      <div className="text-[10px] font-bold text-slate-400 uppercase">Passive DNS Resolutions</div>
                      <div className="flex flex-wrap gap-1">
                        {externalOverlay.passiveDns.map((domain) => (
                          <span
                            key={domain}
                            onClick={() => setPivotTerm(domain)}
                            className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 text-cyan-700 dark:text-cyan-300 cursor-pointer hover:underline text-[10px]"
                            title="Click to pivot on this resolved domain"
                          >
                            {domain}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* MITRE ATT&CK Techniques Mapped */}
                  <div className="space-y-1">
                    <div className="text-[10px] font-bold text-slate-500 uppercase">Associated MITRE ATT&CK Techniques</div>
                    <div className="flex flex-wrap gap-1 text-[10px]">
                      {externalOverlay.mitreTechniques.map((tech) => (
                        <span
                          key={tech.id}
                          className="px-2 py-0.5 rounded bg-purple-100 dark:bg-purple-950/80 text-purple-800 dark:text-purple-300 border border-purple-300 dark:border-purple-800"
                        >
                          {tech.id}: {tech.name}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Panel B: Local Enterprise Telemetry Correlation */}
                <div className="p-3.5 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
                    <span className="text-xs font-bold text-slate-800 dark:text-slate-200 flex items-center gap-1.5">
                      <Server className="w-4 h-4 text-purple-600 dark:text-purple-400" />
                      LOCAL ENTERPRISE CORRELATION (POSTGRESQL SIEM)
                    </span>
                    <span className="text-[10px] text-slate-400">Internal Sightings Overlay</span>
                  </div>

                  {/* Local Metrics Grid */}
                  <div className="grid grid-cols-2 gap-2 text-[11px]">
                    <div className="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Internal SIEM Sightings</div>
                      <div className="text-lg font-bold text-cyan-600 dark:text-cyan-400">
                        {externalOverlay.localCorrelation?.internalSightingsCount || 0} Events
                      </div>
                      <div className="text-[10px] text-slate-500">
                        Observed in PostgreSQL logs
                      </div>
                    </div>

                    <div className="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800">
                      <div className="text-[10px] text-slate-400 uppercase">Correlated Incidents</div>
                      <div className="text-lg font-bold text-red-600 dark:text-red-400">
                        {externalOverlay.localCorrelation?.associatedAlertsCount || 0} Alerts
                      </div>
                      <div className="text-[10px] text-slate-500">Active triage items</div>
                    </div>
                  </div>

                  {/* Impacted Hosts & Users */}
                  <div className="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px] space-y-1.5">
                    <div className="text-[10px] font-bold text-slate-400 uppercase">Impacted Corporate Endpoints</div>
                    {externalOverlay.localCorrelation?.impactedHosts &&
                    externalOverlay.localCorrelation.impactedHosts.length > 0 ? (
                      <div className="flex flex-wrap gap-1.5">
                        {externalOverlay.localCorrelation.impactedHosts.map((host) => (
                          <div
                            key={host}
                            className="px-2 py-1 rounded bg-slate-100 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 flex items-center justify-between gap-2"
                          >
                            <span className="font-bold text-slate-800 dark:text-slate-200">{host}</span>
                            <button
                              onClick={() => {
                                onIsolateHost(host);
                                triggerActionFeedback(`Dispatched Sophos isolation command for ${host}.`);
                              }}
                              className="text-[9px] px-1.5 py-0.2 rounded bg-red-600 text-white font-bold hover:bg-red-500 transition"
                            >
                              Isolate Host
                            </button>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-slate-400 italic text-[10px]">
                        No internal endpoints have communicated with this indicator yet.
                      </div>
                    )}
                  </div>

                  {/* First Seen vs Last Seen Delta */}
                  <div className="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-[11px] space-y-1">
                    <div className="text-[10px] font-bold text-slate-400 uppercase">Temporal Delta Analysis</div>
                    <div className="grid grid-cols-2 gap-2 text-[10px]">
                      <div>
                        <span className="text-slate-400">Global First Seen:</span>
                        <div className="font-mono text-slate-700 dark:text-slate-300">
                          {new Date(externalOverlay.firstSeenGlobal).toLocaleDateString()}
                        </div>
                      </div>
                      <div>
                        <span className="text-slate-400">Internal First Seen:</span>
                        <div className="font-mono text-cyan-600 dark:text-cyan-400">
                          {externalOverlay.localCorrelation?.firstSeenLocal
                            ? new Date(externalOverlay.localCorrelation.firstSeenLocal).toLocaleTimeString()
                            : 'Never observed locally'}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Immediate Response Actions */}
                  <div className="p-2.5 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 space-y-2">
                    <div className="text-[10px] font-bold text-slate-400 uppercase">
                      Recommended Defensive Responses
                    </div>
                    <div className="text-[11px] text-slate-600 dark:text-slate-400 italic">
                      {externalOverlay.recommendedAction}
                    </div>
                    <div className="grid grid-cols-2 gap-1.5 pt-1">
                      <button
                        onClick={() => {
                          triggerActionFeedback(`IOC ${externalOverlay.indicator} pushed to Perimeter Firewall Dynamic Address Group (DAG).`);
                        }}
                        className="py-1.5 px-2 rounded bg-red-600 hover:bg-red-500 text-white font-bold text-[10px] flex items-center justify-center gap-1 shadow cursor-pointer transition"
                      >
                        <ShieldAlert className="w-3 h-3" />
                        <span>Block on Firewalls</span>
                      </button>
                      <button
                        onClick={() => {
                          onExecutePlaybook('PB-RANSOMWARE-01');
                          triggerActionFeedback(`Triggered Shuffle SOAR automated mitigation workflow.`);
                        }}
                        className="py-1.5 px-2 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-[10px] flex items-center justify-center gap-1 shadow cursor-pointer transition"
                      >
                        <Terminal className="w-3 h-3" />
                        <span>Trigger SOAR Playbook</span>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          ) : (
            <div className="p-8 text-center text-slate-500 bg-white dark:bg-slate-900 rounded-lg border border-slate-200 dark:border-slate-800">
              {isLoadingOverlay ? (
                <div className="flex items-center justify-center gap-2">
                  <RefreshCw className="w-4 h-4 animate-spin text-cyan-500" />
                  <span>Querying external threat intelligence feeds for "{pivotTerm}"...</span>
                </div>
              ) : (
                <span>No threat intelligence match for "{pivotTerm}". Select an artifact above or enter an indicator.</span>
              )}
            </div>
          )}

          {/* Bottom Correlated Log Stream */}
          <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 transition-colors">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
              <span className="text-xs font-bold text-slate-900 dark:text-slate-200">
                CORRELATED TELEMETRY & LOG EVIDENCE ({matchedLogs.length})
              </span>
              <span className="text-[10px] text-slate-500 dark:text-slate-400">Chronological attack sequence</span>
            </div>

            <div className="space-y-2 max-h-[380px] overflow-y-auto scrollbar-thin text-xs">
              {matchedLogs.map((log) => (
                <div
                  key={log.id}
                  className="p-3 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700 transition space-y-1.5"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] text-slate-500">{log.timestamp}</span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-200 dark:bg-slate-800 text-cyan-800 dark:text-cyan-300 font-bold">
                        {log.sourceType}
                      </span>
                      {log.eventId && (
                        <span className="text-[10px] px-1 rounded bg-slate-100 dark:bg-slate-900 text-amber-600 dark:text-amber-400">
                          EID: {log.eventId}
                        </span>
                      )}
                    </div>
                    <span
                      className={`text-[10px] font-bold px-1.5 rounded ${
                        log.severity === 'critical'
                          ? 'text-red-700 dark:text-red-300 bg-red-100 dark:bg-red-950 border border-red-300 dark:border-red-800'
                          : log.severity === 'high'
                          ? 'text-amber-700 dark:text-amber-300 bg-amber-100 dark:bg-amber-950 border border-amber-300 dark:border-amber-800'
                          : 'text-slate-700 dark:text-slate-300 bg-slate-200 dark:bg-slate-900'
                      }`}
                    >
                      {log.severity.toUpperCase()}
                    </span>
                  </div>

                  <div className="text-slate-900 dark:text-slate-100 font-semibold">{log.message}</div>

                  {log.commandLine && (
                    <div className="p-1.5 rounded bg-slate-100 dark:bg-slate-900 text-[11px] text-amber-800 dark:text-amber-300 break-all font-mono">
                      cmd: {log.commandLine}
                    </div>
                  )}

                  <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                    <span>
                      Host: <span className="text-slate-800 dark:text-slate-200 font-bold">{log.host}</span> | User:{' '}
                      <span className="text-slate-800 dark:text-slate-200 font-bold">{log.user}</span>
                    </span>
                    {log.destIp && (
                      <span>
                        Dest: <span className="text-red-600 dark:text-red-400 font-bold">{log.destIp}:{log.destPort}</span>
                      </span>
                    )}
                  </div>
                </div>
              ))}

              {matchedLogs.length === 0 && (
                <div className="py-10 text-center text-slate-400 font-mono text-xs">
                  No internal telemetry artifacts found matching "{pivotTerm}". Select a different artifact or clear search.
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* VIEW 2: Attack Chain Topology Graph */}
      {activeViewMode === 'graph' && (
        <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 transition-colors">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Share2 className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
              <span className="text-xs font-bold text-slate-900 dark:text-slate-200">
                CORRELATED ATTACK CHAIN TOPOLOGY GRAPH
              </span>
            </div>
            <span className="text-[10px] text-slate-500 dark:text-slate-400">Click any node to pivot investigation</span>
          </div>

          <div className="p-6 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 overflow-x-auto transition-colors">
            <div className="min-w-[800px] flex items-center justify-between relative py-6">
              {/* Connecting Track Line */}
              <div className="absolute left-8 right-8 top-1/2 -translate-y-1/2 h-0.5 bg-gradient-to-r from-red-500/50 via-amber-500/50 to-purple-500/50 z-0 pointer-events-none" />

              {/* Node 1: External C2 */}
              <div
                onClick={() => {
                  setActiveGraphNode('c2_ip');
                  setPivotTerm('185.220.101.5');
                }}
                className={`relative z-10 p-3 rounded-lg border cursor-pointer transition flex flex-col items-center gap-1 text-center w-36 ${
                  activeGraphNode === 'c2_ip'
                    ? 'bg-red-100 dark:bg-red-950/80 border-red-500 ring-2 ring-red-500/40 shadow-md'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400'
                }`}
              >
                <div className="w-8 h-8 rounded-full bg-red-100 dark:bg-red-950 border border-red-300 dark:border-red-700 flex items-center justify-center text-red-600 dark:text-red-400 font-bold">
                  <Globe className="w-4 h-4" />
                </div>
                <div className="text-[11px] font-bold text-red-700 dark:text-red-300">Cobalt C2 IP</div>
                <div className="text-[10px] text-slate-600 dark:text-slate-400 break-all">185.220.101.5</div>
                <span className="text-[9px] px-1 rounded bg-red-200 dark:bg-red-900/60 text-red-800 dark:text-red-300 mt-1">Stage 1 Stager</span>
              </div>

              {/* Node 2: Weaponized Dropper */}
              <div
                onClick={() => {
                  setActiveGraphNode('dropper');
                  setPivotTerm('8f4c2e6b91a7d3f048e5b6c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2');
                }}
                className={`relative z-10 p-3 rounded-lg border cursor-pointer transition flex flex-col items-center gap-1 text-center w-36 ${
                  activeGraphNode === 'dropper'
                    ? 'bg-amber-100 dark:bg-amber-950/80 border-amber-500 ring-2 ring-amber-500/40 shadow-md'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400'
                }`}
              >
                <div className="w-8 h-8 rounded-full bg-amber-100 dark:bg-amber-950 border border-amber-300 dark:border-amber-700 flex items-center justify-center text-amber-600 dark:text-amber-400 font-bold">
                  <Hash className="w-4 h-4" />
                </div>
                <div className="text-[11px] font-bold text-amber-700 dark:text-amber-300">certutil Payload</div>
                <div className="text-[10px] text-slate-600 dark:text-slate-400">update.exe (Go)</div>
                <span className="text-[9px] px-1 rounded bg-amber-200 dark:bg-amber-900/60 text-amber-800 dark:text-amber-300 mt-1">LOLBin Exec</span>
              </div>

              {/* Node 3: Patient Zero Workstation */}
              <div
                onClick={() => {
                  setActiveGraphNode('endpoint');
                  setPivotTerm('WS-FINANCE-07');
                }}
                className={`relative z-10 p-3 rounded-lg border cursor-pointer transition flex flex-col items-center gap-1 text-center w-36 ${
                  activeGraphNode === 'endpoint'
                    ? 'bg-red-100 dark:bg-red-950/80 border-red-500 ring-2 ring-red-500/40 shadow-md'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400'
                }`}
              >
                <div className="w-8 h-8 rounded-full bg-red-100 dark:bg-red-950 border border-red-300 dark:border-red-700 flex items-center justify-center text-red-600 dark:text-red-400 font-bold">
                  <Server className="w-4 h-4" />
                </div>
                <div className="text-[11px] font-bold text-red-700 dark:text-red-300">WS-FINANCE-07</div>
                <div className="text-[10px] text-slate-600 dark:text-slate-400">CORP\m.jenkins</div>
                <span className="text-[9px] px-1 rounded bg-red-200 dark:bg-red-900/60 text-red-800 dark:text-red-300 mt-1">Compromised</span>
              </div>

              {/* Node 4: Lateral Movement to DC */}
              <div
                onClick={() => {
                  setActiveGraphNode('dc');
                  setPivotTerm('DC-CORP-01');
                }}
                className={`relative z-10 p-3 rounded-lg border cursor-pointer transition flex flex-col items-center gap-1 text-center w-36 ${
                  activeGraphNode === 'dc'
                    ? 'bg-purple-100 dark:bg-purple-950/80 border-purple-500 ring-2 ring-purple-500/40 shadow-md'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400'
                }`}
              >
                <div className="w-8 h-8 rounded-full bg-purple-100 dark:bg-purple-950 border border-purple-300 dark:border-purple-700 flex items-center justify-center text-purple-600 dark:text-purple-400 font-bold">
                  <Server className="w-4 h-4" />
                </div>
                <div className="text-[11px] font-bold text-purple-700 dark:text-purple-300">DC-CORP-01</div>
                <div className="text-[10px] text-slate-600 dark:text-slate-400">PSEXESVC Admin</div>
                <span className="text-[9px] px-1 rounded bg-purple-200 dark:bg-purple-900/60 text-purple-800 dark:text-purple-300 mt-1">PsExec Service</span>
              </div>

              {/* Node 5: Cloud Vault Target */}
              <div
                onClick={() => {
                  setActiveGraphNode('cloud');
                  setPivotTerm('corp-finance-vault-2026');
                }}
                className={`relative z-10 p-3 rounded-lg border cursor-pointer transition flex flex-col items-center gap-1 text-center w-36 ${
                  activeGraphNode === 'cloud'
                    ? 'bg-blue-100 dark:bg-blue-950/80 border-blue-500 ring-2 ring-blue-500/40 shadow-md'
                    : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400'
                }`}
              >
                <div className="w-8 h-8 rounded-full bg-blue-100 dark:bg-blue-950 border border-blue-300 dark:border-blue-700 flex items-center justify-center text-blue-600 dark:text-blue-400 font-bold">
                  <Globe className="w-4 h-4" />
                </div>
                <div className="text-[11px] font-bold text-blue-700 dark:text-blue-300">S3 Finance Vault</div>
                <div className="text-[10px] text-slate-600 dark:text-slate-400">AWS CloudTrail</div>
                <span className="text-[9px] px-1 rounded bg-blue-200 dark:bg-blue-900/60 text-blue-800 dark:text-blue-300 mt-1">Data Exfiltration</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* VIEW 3: Live Incoming External Threat Feed Browser */}
      {activeViewMode === 'live_feed' && (
        <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 transition-colors">
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <Radio className="w-4 h-4 text-red-500 animate-pulse" />
              <span className="text-xs font-bold text-slate-900 dark:text-slate-100">
                LIVE EXTERNAL THREAT FEEDS (ALIENVAULT OTX • VIRUSTOTAL • ABUSEIPDB • CISA KEV)
              </span>
            </div>

            {/* Feed Filter Chips */}
            <div className="flex gap-1 text-xs">
              {(['all', 'ip', 'domain', 'sha256', 'cve'] as const).map((filter) => (
                <button
                  key={filter}
                  onClick={() => setFeedFilter(filter)}
                  className={`px-2 py-0.5 rounded uppercase font-semibold text-[10px] cursor-pointer transition ${
                    feedFilter === filter
                      ? 'bg-cyan-500 text-slate-950 font-bold'
                      : 'bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white'
                  }`}
                >
                  {filter}
                </button>
              ))}
            </div>
          </div>

          <div className="border border-slate-200 dark:border-slate-800 rounded overflow-hidden">
            <table className="w-full text-[11px] text-left">
              <thead className="bg-slate-100 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 text-slate-500">
                <tr>
                  <th className="p-2.5">Indicator</th>
                  <th className="p-2.5">Type</th>
                  <th className="p-2.5">Threat Name & Attribution</th>
                  <th className="p-2.5">Primary Feed Source</th>
                  <th className="p-2.5">Reputation</th>
                  <th className="p-2.5">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800 bg-white dark:bg-slate-900">
                {filteredFeed.map((item) => (
                  <tr key={item.indicator} className="hover:bg-slate-50 dark:hover:bg-slate-800/60 transition">
                    <td className="p-2.5 font-bold font-mono text-cyan-800 dark:text-cyan-300 break-all max-w-[200px]">
                      {item.indicator}
                    </td>
                    <td className="p-2.5">
                      <span className="px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-800 font-bold uppercase text-[9px]">
                        {item.type}
                      </span>
                    </td>
                    <td className="p-2.5">
                      <div className="font-semibold text-slate-800 dark:text-slate-200">{item.threatName}</div>
                      <div className="text-[10px] text-slate-400">
                        Actor: <span className="text-red-600 dark:text-red-400">{item.associatedThreatActor}</span>
                      </div>
                    </td>
                    <td className="p-2.5">
                      <span className="px-1.5 py-0.5 rounded bg-purple-100 dark:bg-purple-950 text-purple-800 dark:text-purple-300 font-semibold text-[10px]">
                        {item.feedSource}
                      </span>
                    </td>
                    <td className="p-2.5 font-bold font-mono text-red-600 dark:text-red-400">
                      {item.reputationScore} / 100
                    </td>
                    <td className="p-2.5">
                      <button
                        onClick={() => {
                          setPivotTerm(item.indicator);
                          setActiveViewMode('overlay');
                        }}
                        className="px-2.5 py-1 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-[10px] flex items-center gap-1 shadow cursor-pointer transition"
                      >
                        <Crosshair className="w-3 h-3" />
                        <span>Pivot & Overlay</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
};
