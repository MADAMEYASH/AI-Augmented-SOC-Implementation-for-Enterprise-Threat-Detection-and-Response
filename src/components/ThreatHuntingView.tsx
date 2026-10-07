import React, { useState, useMemo } from 'react';
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
} from 'lucide-react';
import { SecurityAlert, SecurityLog, ThreatIntelligenceItem } from '../types/soc.ts';

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
  const [selectedIocType, setSelectedIocType] = useState<string>('all');
  const [activeGraphNode, setActiveGraphNode] = useState<string>('c2_ip');

  // Match logs containing the pivot term
  const matchedLogs = useMemo(() => {
    if (!pivotTerm.trim()) return logs;
    const term = pivotTerm.toLowerCase();
    return logs.filter(
      (l) =>
        l.host.toLowerCase().includes(term) ||
        l.user.toLowerCase().includes(term) ||
        (l.srcIp && l.srcIp.toLowerCase().includes(term)) ||
        (l.destIp && l.destIp.toLowerCase().includes(term)) ||
        (l.fileHash && l.fileHash.toLowerCase().includes(term)) ||
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
        a.user.toLowerCase().includes(term) ||
        a.title.toLowerCase().includes(term) ||
        a.iocs.some((i) => i.value.toLowerCase().includes(term))
    );
  }, [alerts, pivotTerm]);

  // Match Threat Intel item
  const matchedIntel = useMemo(() => {
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
    const impactedHosts = [...new Set(matchedLogs.map((l) => l.host))];
    const impactedUsers = [...new Set(matchedLogs.map((l) => l.user))];
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
    { label: 'Workstation: WS-FINANCE-07', value: 'WS-FINANCE-07', type: 'host' },
    { label: 'User: CORP\\m.jenkins', value: 'CORP\\m.jenkins', type: 'user' },
    { label: 'BlackCat Hash: 8f4c2e6b...', value: '8f4c2e6b91a7d3f048e5b6c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2', type: 'hash' },
    { label: 'Tunnel IP: 91.215.85.17', value: '91.215.85.17', type: 'ip' },
    { label: 'Domain Controller: DC-CORP-01', value: 'DC-CORP-01', type: 'host' },
  ];

  return (
    <div className="space-y-4 font-mono">
      {/* Search & Pivot Command Bar */}
      <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 transition-colors">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <Crosshair className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100">
                IOC PIVOTING & THREAT HUNTING WORKBENCH
              </h2>
              <p className="text-[10px] text-slate-500 dark:text-slate-400">
                Multi-dimensional correlation across endpoints, network telemetry, and identity directories
              </p>
            </div>
          </div>

          <div className="text-xs text-slate-500 dark:text-slate-400 flex items-center gap-2">
            <span>PIVOT CORRELATION:</span>
            <span className="text-cyan-700 dark:text-cyan-400 font-bold">{matchedLogs.length} Events</span>
            <span className="text-red-600 dark:text-red-400 font-bold">({matchedAlerts.length} Alerts)</span>
          </div>
        </div>

        {/* Pivot Input Bar */}
        <div className="relative">
          <Search className="w-4 h-4 text-cyan-600 dark:text-cyan-400 absolute left-3 top-3 pointer-events-none" />
          <input
            type="text"
            value={pivotTerm}
            onChange={(e) => setPivotTerm(e.target.value)}
            placeholder="Pivot on any IP, Domain, Hash, Hostname, or User Account..."
            className="w-full pl-9 pr-24 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-300 dark:border-slate-700 rounded text-xs text-cyan-900 dark:text-cyan-300 placeholder-slate-400 dark:placeholder-slate-500 focus:outline-none focus:border-cyan-500 dark:focus:border-cyan-400"
          />
          {pivotTerm && (
            <button
              onClick={() => setPivotTerm('')}
              className="absolute right-3 top-2.5 text-slate-400 hover:text-slate-200 text-xs"
            >
              Clear
            </button>
          )}
        </div>

        {/* Quick Pivot Chips */}
        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className="text-slate-500 dark:text-slate-500">HOT ARTIFACTS:</span>
          {quickIocs.map((ioc) => (
            <button
              key={ioc.value}
              onClick={() => setPivotTerm(ioc.value)}
              className={`px-2 py-0.5 rounded border transition cursor-pointer ${
                pivotTerm.toLowerCase() === ioc.value.toLowerCase()
                  ? 'bg-cyan-500 text-slate-950 font-bold border-cyan-400 shadow-sm'
                  : 'bg-slate-100 dark:bg-slate-950 text-slate-700 dark:text-slate-300 border-slate-200 dark:border-slate-800 hover:bg-slate-200 dark:hover:bg-slate-800'
              }`}
            >
              {ioc.label}
            </button>
          ))}
        </div>
      </div>

      {/* Visual Attack Chain Topology Graph */}
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

        {/* Interactive Node Graph Visualizer */}
        <div className="p-6 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-850 overflow-x-auto transition-colors">
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
                  ? 'bg-red-100 dark:bg-red-950/80 border-red-500 ring-2 ring-red-500/40 shadow-[0_0_15px_rgba(239,68,68,0.3)]'
                  : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700'
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
                  ? 'bg-amber-100 dark:bg-amber-950/80 border-amber-500 ring-2 ring-amber-500/40 shadow-[0_0_15px_rgba(245,158,11,0.3)]'
                  : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700'
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
                  ? 'bg-red-100 dark:bg-red-950/80 border-red-500 ring-2 ring-red-500/40 shadow-[0_0_15px_rgba(239,68,68,0.3)]'
                  : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700'
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
                  ? 'bg-purple-100 dark:bg-purple-950/80 border-purple-500 ring-2 ring-purple-500/40 shadow-[0_0_15px_rgba(168,85,247,0.3)]'
                  : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700'
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
                  ? 'bg-blue-100 dark:bg-blue-950/80 border-blue-500 ring-2 ring-blue-500/40 shadow-[0_0_15px_rgba(59,130,246,0.3)]'
                  : 'bg-white dark:bg-slate-900 border-slate-200 dark:border-slate-800 hover:border-slate-400 dark:hover:border-slate-700'
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

      {/* Blast Radius & Investigation Cards */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left Column: Blast Radius Telemetry (1 Col) */}
        <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4 transition-colors">
          <div className="border-b border-slate-200 dark:border-slate-800 pb-2">
            <span className="text-xs font-bold text-slate-900 dark:text-slate-200">BLAST RADIUS & IMPACT SUMMARY</span>
            <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">Calculated for "{pivotTerm}"</p>
          </div>

          <div className="grid grid-cols-2 gap-2 text-xs">
            <div className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-[10px] text-slate-500 dark:text-slate-400">IMPACTED HOSTS</div>
              <div className="text-lg font-bold text-cyan-700 dark:text-cyan-300">{blastRadius.hosts.length}</div>
              <div className="text-[10px] text-slate-500 truncate">{blastRadius.hosts.join(', ') || 'None'}</div>
            </div>

            <div className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-[10px] text-slate-500 dark:text-slate-400">COMPROMISED IDENTITIES</div>
              <div className="text-lg font-bold text-purple-700 dark:text-purple-300">{blastRadius.users.length}</div>
              <div className="text-[10px] text-slate-500 truncate">{blastRadius.users.join(', ') || 'None'}</div>
            </div>

            <div className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-[10px] text-slate-500 dark:text-slate-400">CRITICAL DETECTIONS</div>
              <div className="text-lg font-bold text-red-600 dark:text-red-400">{blastRadius.criticalLogsCount}</div>
              <div className="text-[10px] text-slate-500">LogAI / Sophos alerts</div>
            </div>

            <div className="p-2.5 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
              <div className="text-[10px] text-slate-500 dark:text-slate-400">EGRESS SESSIONS</div>
              <div className="text-lg font-bold text-amber-600 dark:text-amber-400">{blastRadius.egressCount}</div>
              <div className="text-[10px] text-slate-500">Outbound flow traces</div>
            </div>
          </div>

          {/* Threat Intel Match Card */}
          {matchedIntel && (
            <div className="p-3 rounded bg-red-950/30 border border-red-800/60 space-y-2 text-xs">
              <div className="flex items-center justify-between">
                <span className="font-bold text-red-300 flex items-center gap-1">
                  <Flame className="w-3.5 h-3.5 text-red-400" />
                  THREAT INTEL MATCH
                </span>
                <span className="text-[10px] px-1.5 py-0.2 rounded bg-red-900 text-red-200 font-bold">
                  VT: {matchedIntel.reputationScore}/100
                </span>
              </div>
              <div className="text-[11px] text-slate-200 font-semibold">{matchedIntel.threatName}</div>
              <div className="text-[10px] text-slate-400">
                Actor: <span className="text-red-400 font-semibold">{matchedIntel.associatedThreatActor}</span>
              </div>
              <div className="flex flex-wrap gap-1 text-[9px]">
                {matchedIntel.tags.map((t) => (
                  <span key={t} className="px-1 rounded bg-slate-900 text-slate-300">
                    #{t}
                  </span>
                ))}
              </div>
            </div>
          )}

          {/* Direct Incident Response Containment Buttons */}
          <div className="pt-2 border-t border-slate-800 space-y-2">
            <div className="text-[10px] text-slate-400 uppercase">RAPID CONTAINMENT ACTIONS</div>
            <button
              onClick={() => onIsolateHost('WS-FINANCE-07')}
              className="w-full py-1.5 px-2.5 rounded bg-red-950 hover:bg-red-900 text-red-200 border border-red-800/80 text-xs font-bold flex items-center justify-center gap-1.5 transition cursor-pointer"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Isolate WS-FINANCE-07 in Sophos XDR</span>
            </button>
            <button
              onClick={() => onExecutePlaybook('PB-RANSOMWARE-01')}
              className="w-full py-1.5 px-2.5 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-200 border border-cyan-800/80 text-xs font-bold flex items-center justify-center gap-1.5 transition cursor-pointer"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Launch Ransomware SOAR Playbook</span>
            </button>
          </div>
        </div>

        {/* Right Column: Correlated Evidence Stream (2 Cols) */}
        <div className="lg:col-span-2 p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-xs font-bold text-slate-200">
              CORRELATED TELEMETRY & LOG EVIDENCE ({matchedLogs.length})
            </span>
            <span className="text-[10px] text-slate-400">Chronological attack sequence</span>
          </div>

          <div className="space-y-2.5 max-h-[440px] overflow-y-auto scrollbar-thin text-xs">
            {matchedLogs.map((log) => (
              <div
                key={log.id}
                className="p-3 rounded bg-slate-950 border border-slate-850 hover:border-slate-750 transition space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-slate-500">{log.timestamp}</span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300">
                      {log.sourceType}
                    </span>
                    {log.eventId && (
                      <span className="text-[10px] px-1 rounded bg-slate-900 text-amber-400">
                        EID: {log.eventId}
                      </span>
                    )}
                  </div>
                  <span
                    className={`text-[10px] font-bold px-1.5 rounded ${
                      log.severity === 'critical'
                        ? 'text-red-400 bg-red-950'
                        : log.severity === 'high'
                        ? 'text-amber-400 bg-amber-950'
                        : 'text-slate-400 bg-slate-900'
                    }`}
                  >
                    {log.severity.toUpperCase()}
                  </span>
                </div>

                <div className="text-slate-200 font-semibold">{log.message}</div>

                {log.commandLine && (
                  <div className="p-1.5 rounded bg-slate-900 text-[11px] text-yellow-300 break-all">
                    cmd: {log.commandLine}
                  </div>
                )}

                <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1">
                  <span>
                    Host: <span className="text-slate-300">{log.host}</span> | User:{' '}
                    <span className="text-slate-300">{log.user}</span>
                  </span>
                  {log.destIp && (
                    <span>
                      Dest: <span className="text-red-400">{log.destIp}:{log.destPort}</span>
                    </span>
                  )}
                </div>
              </div>
            ))}

            {matchedLogs.length === 0 && (
              <div className="py-12 text-center text-slate-500 font-mono text-xs">
                No telemetry artifacts found matching "{pivotTerm}". Select a different artifact or clear search.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
