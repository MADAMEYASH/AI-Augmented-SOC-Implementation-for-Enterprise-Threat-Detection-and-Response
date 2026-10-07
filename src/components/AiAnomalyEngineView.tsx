import React, { useState } from 'react';
import {
  Brain,
  Cpu,
  Fingerprint,
  Globe,
  ShieldAlert,
  Sliders,
  Sparkles,
  TrendingUp,
  UserCheck,
  AlertTriangle,
  Layers,
  Search,
  ExternalLink,
} from 'lucide-react';
import { SecurityLog, ThreatIntelligenceItem, UebaProfile } from '../types/soc.ts';

interface AiAnomalyEngineViewProps {
  logs: SecurityLog[];
  threatIntel: ThreatIntelligenceItem[];
  uebaProfiles: UebaProfile[];
  onPivotToHunting: (indicator: string) => void;
}

export const AiAnomalyEngineView: React.FC<AiAnomalyEngineViewProps> = ({
  logs,
  threatIntel,
  uebaProfiles,
  onPivotToHunting,
}) => {
  const [activeSubTab, setActiveSubTab] = useState<'logai' | 'alkido' | 'intel'>('logai');
  const [iocSearch, setIocSearch] = useState('');

  // Extract cluster statistics from logs
  const clusterStats = React.useMemo(() => {
    const clusters: Record<string, { count: number; maxScore: number; logs: SecurityLog[] }> = {};
    logs.forEach((log) => {
      const cid = log.clusterId || 'CLUSTER_UNKNOWN';
      if (!clusters[cid]) {
        clusters[cid] = { count: 0, maxScore: 0, logs: [] };
      }
      clusters[cid].count++;
      clusters[cid].maxScore = Math.max(clusters[cid].maxScore, log.anomalyScore || 0);
      clusters[cid].logs.push(log);
    });
    return clusters;
  }, [logs]);

  // Filtered threat intel indicators
  const filteredIntel = threatIntel.filter(
    (item) =>
      item.indicator.toLowerCase().includes(iocSearch.toLowerCase()) ||
      item.threatName.toLowerCase().includes(iocSearch.toLowerCase()) ||
      item.associatedThreatActor.toLowerCase().includes(iocSearch.toLowerCase()) ||
      item.tags.some((t) => t.toLowerCase().includes(iocSearch.toLowerCase()))
  );

  return (
    <div className="space-y-4">
      {/* Sub-navigation & Overview Banner */}
      <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-wrap items-center justify-between gap-4 transition-colors">
        <div>
          <div className="flex items-center gap-2">
            <Brain className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
            <h2 className="text-base font-bold font-mono text-slate-900 dark:text-slate-100">
              AI-DRIVEN ANOMALY DETECTION & THREAT INTELLIGENCE
            </h2>
          </div>
          <p className="text-xs text-slate-500 dark:text-slate-400 font-mono mt-0.5">
            LogAI Semantic Parsing & Drain Clustering • Alkido Behavioral Sequence & Entropy Engine • AlienVault OTX & VT Feeds
          </p>
        </div>

        {/* Tab Switcher */}
        <div className="flex rounded border border-slate-300 dark:border-slate-700 bg-slate-100 dark:bg-slate-950 p-0.5 font-mono text-xs">
          <button
            onClick={() => setActiveSubTab('logai')}
            className={`px-3 py-1.5 rounded transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTab === 'logai'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <Cpu className="w-3.5 h-3.5" />
            <span>LogAI Parser & Clusters</span>
          </button>
          <button
            onClick={() => setActiveSubTab('alkido')}
            className={`px-3 py-1.5 rounded transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTab === 'alkido'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <TrendingUp className="w-3.5 h-3.5" />
            <span>Alkido UEBA & Entropy</span>
          </button>
          <button
            onClick={() => setActiveSubTab('intel')}
            className={`px-3 py-1.5 rounded transition cursor-pointer flex items-center gap-1.5 ${
              activeSubTab === 'intel'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Threat Intel Feeds</span>
          </button>
        </div>
      </div>

      {/* Sub-Tab 1: LogAI Module */}
      {activeSubTab === 'logai' && (
        <div className="space-y-4">
          {/* Algorithm Metrics Strip */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div className="p-3.5 rounded-lg bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 shadow-sm font-mono transition-colors">
              <div className="text-[10px] text-slate-500 dark:text-slate-400">LOGAI PARSER MODEL</div>
              <div className="text-base font-bold text-cyan-700 dark:text-cyan-300">Drain-3 Deep Semantic</div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">Depth: 4 | Sim Thresh: 0.85</div>
            </div>
            <div className="p-3.5 rounded-lg bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 shadow-sm font-mono transition-colors">
              <div className="text-[10px] text-slate-500 dark:text-slate-400">UNSUPERVISED CLUSTERS</div>
              <div className="text-base font-bold text-purple-700 dark:text-purple-300">{Object.keys(clusterStats).length} Clusters</div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">DBSCAN Epsilon: 0.42</div>
            </div>
            <div className="p-3.5 rounded-lg bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 shadow-sm font-mono transition-colors">
              <div className="text-[10px] text-slate-500 dark:text-slate-400">OUTLIER DEVIATION RATE</div>
              <div className="text-base font-bold text-red-600 dark:text-red-400">3.4% Anomaly Spike</div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">Isolation Forest: 120 trees</div>
            </div>
            <div className="p-3.5 rounded-lg bg-white dark:bg-slate-900/80 border border-slate-200 dark:border-slate-800 shadow-sm font-mono transition-colors">
              <div className="text-[10px] text-slate-500 dark:text-slate-400">PARSED TEMPLATES</div>
              <div className="text-base font-bold text-emerald-600 dark:text-emerald-400">14 Unique Templates</div>
              <div className="text-[10px] text-slate-400 dark:text-slate-500 mt-1">100% Parameterized</div>
            </div>
          </div>

          {/* Cluster Visualization & Templates */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left: Clusters Breakdown (2 Cols) */}
            <div className="lg:col-span-2 p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 font-mono transition-colors">
              <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
                <span className="text-xs font-bold text-slate-900 dark:text-slate-200">
                  LOGAI SEQUENCE CLUSTERS & DEVIATION SCORING
                </span>
                <span className="text-[10px] text-slate-500 dark:text-slate-400">Dynamic Clustering Engine</span>
              </div>

              <div className="space-y-3">
                {Object.entries(clusterStats).map(([clusterId, data]) => {
                  const isHighRisk = data.maxScore > 80;
                  const isMediumRisk = data.maxScore > 50 && data.maxScore <= 80;

                  return (
                    <div
                      key={clusterId}
                      className={`p-3 rounded border transition ${
                        isHighRisk
                          ? 'bg-red-950/20 border-red-800/60'
                          : isMediumRisk
                          ? 'bg-amber-950/20 border-amber-800/60'
                          : 'bg-slate-950/60 border-slate-800'
                      }`}
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
                        <div className="flex items-center gap-2">
                          <Layers
                            className={`w-4 h-4 ${
                              isHighRisk
                                ? 'text-red-400'
                                : isMediumRisk
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          />
                          <span className="font-bold text-xs text-slate-200">{clusterId}</span>
                          <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                            {data.count} events
                          </span>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-slate-400">MAX ANOMALY:</span>
                          <span
                            className={`text-xs font-bold ${
                              isHighRisk
                                ? 'text-red-400'
                                : isMediumRisk
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {data.maxScore}/100
                          </span>
                        </div>
                      </div>

                      {/* Sample event from cluster */}
                      <div className="text-[11px] text-slate-300 bg-slate-950 p-2 rounded border border-slate-900 truncate">
                        <span className="text-cyan-400 mr-2">Sample:</span>
                        {data.logs[0]?.message}
                      </div>

                      <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500">
                        <span>Affected Hosts: {[...new Set(data.logs.map((l) => l.host))].join(', ')}</span>
                        <span>Source: {data.logs[0]?.sourceType}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Right: Drain Template Lexicon */}
            <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3 font-mono text-xs">
              <div className="border-b border-slate-800 pb-2">
                <span className="font-bold text-slate-200">DRAIN TEMPLATE MINER</span>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  Extracted invariant patterns & variable wildcards (&lt;*&gt;)
                </p>
              </div>

              <div className="space-y-2">
                {[
                  {
                    pattern: 'Process Creation: Obfuscated <*> initiated by parent process <*>',
                    count: 2,
                    risk: 'High Anomaly',
                    color: 'text-red-400',
                  },
                  {
                    pattern: 'Credential Guard violation detected: Attempted OpenProcess against LSASS with <*>',
                    count: 1,
                    risk: 'Critical Violation',
                    color: 'text-red-400',
                  },
                  {
                    pattern: 'High entropy DNS queries detected (<*> subdomains/min) indicative of tunnel',
                    count: 1,
                    risk: 'Severe Outlier',
                    color: 'text-amber-400',
                  },
                  {
                    pattern: 'Audit Failure: <*> failed Kerberos authentication attempts for <*> with invalid ticket',
                    count: 14,
                    risk: 'Brute Deviation',
                    color: 'text-amber-400',
                  },
                  {
                    pattern: 'sshd: Accepted publickey for <*> from <*> port <*> ssh2',
                    count: 48,
                    risk: 'Baseline Normal',
                    color: 'text-emerald-400',
                  },
                ].map((tmpl, idx) => (
                  <div key={idx} className="p-2 rounded bg-slate-950 border border-slate-800 space-y-1">
                    <div className="flex items-center justify-between text-[10px]">
                      <span className={tmpl.color}>{tmpl.risk}</span>
                      <span className="text-slate-500">{tmpl.count} occurrences</span>
                    </div>
                    <div className="text-[11px] text-slate-300 break-words font-mono">
                      {tmpl.pattern}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Sub-Tab 2: Alkido Behavioral Engine & UEBA */}
      {activeSubTab === 'alkido' && (
        <div className="space-y-4 font-mono">
          {/* Shannon Entropy & Behavioral Sequence Telemetry */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2 p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
              <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                <div>
                  <span className="text-xs font-bold text-slate-200">
                    ALKIDO SHANNON ENTROPY DISTRIBUTION
                  </span>
                  <p className="text-[10px] text-slate-400">
                    Detects encrypted staging, DNS tunneling, and packed LOLBin commandlines
                  </p>
                </div>
                <span className="text-xs text-cyan-400 font-bold">H(X) = -Σ P(xi) log2 P(xi)</span>
              </div>

              {/* Entropy Bar Graph Visualizer */}
              <div className="space-y-2.5">
                {logs
                  .filter((l) => l.entropy !== undefined)
                  .map((log) => {
                    const entropy = log.entropy || 0;
                    const pct = Math.min((entropy / 8) * 100, 100);
                    const isHigh = entropy > 6.0;
                    const isMedium = entropy > 4.0 && entropy <= 6.0;

                    return (
                      <div key={log.id} className="p-2.5 rounded bg-slate-950 border border-slate-850">
                        <div className="flex justify-between text-xs mb-1">
                          <span className="text-slate-300 truncate max-w-sm">
                            <span className="text-cyan-400 mr-2">[{log.host}]</span>
                            {log.processName || log.sourceType}: {log.message}
                          </span>
                          <span
                            className={`font-bold ${
                              isHigh ? 'text-red-400' : isMedium ? 'text-amber-400' : 'text-emerald-400'
                            }`}
                          >
                            {entropy.toFixed(2)} bit/char {isHigh ? '(ENCRYPTED/TUNNEL)' : ''}
                          </span>
                        </div>
                        <div className="w-full h-2 rounded bg-slate-800 overflow-hidden">
                          <div
                            className={`h-full transition-all ${
                              isHigh
                                ? 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]'
                                : isMedium
                                ? 'bg-amber-500'
                                : 'bg-emerald-500'
                            }`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                    );
                  })}
              </div>
            </div>

            {/* Sequence Perplexity & Transition Engine */}
            <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3 text-xs">
              <div className="border-b border-slate-800 pb-2">
                <span className="font-bold text-slate-200">SEQUENCE MARKOV ANOMALIES</span>
                <p className="text-[10px] text-slate-400 mt-0.5">
                  Transition probabilities P(Event_t | Event_t-1)
                </p>
              </div>

              <div className="space-y-2.5">
                <div className="p-2.5 rounded bg-red-950/30 border border-red-800/60 space-y-1">
                  <div className="flex justify-between text-[11px] text-red-300 font-bold">
                    <span>EXCEL.EXE → certutil.exe</span>
                    <span>P = 0.00004%</span>
                  </div>
                  <p className="text-[10px] text-slate-400">
                    Office macro executing living-off-the-land download utility violates normal enterprise process tree baseline.
                  </p>
                </div>

                <div className="p-2.5 rounded bg-red-950/30 border border-red-800/60 space-y-1">
                  <div className="flex justify-between text-[11px] text-red-300 font-bold">
                    <span>certutil.exe → update.exe → LSASS</span>
                    <span>P = 0.00001%</span>
                  </div>
                  <p className="text-[10px] text-slate-400">
                    Direct memory handle request to Local Security Authority Subsystem Service from untrusted binary in C:\Users\Public.
                  </p>
                </div>

                <div className="p-2.5 rounded bg-amber-950/30 border border-amber-800/60 space-y-1">
                  <div className="flex justify-between text-[11px] text-amber-300 font-bold">
                    <span>PsExec → vssadmin delete shadows</span>
                    <span>P = 0.00012%</span>
                  </div>
                  <p className="text-[10px] text-slate-400">
                    High correlation with ransomware destruction pre-encryption stage.
                  </p>
                </div>
              </div>
            </div>
          </div>

          {/* User & Entity Behavior Analytics (UEBA) Profile Cards */}
          <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <UserCheck className="w-4 h-4 text-cyan-400" />
                <span className="text-xs font-bold text-slate-200">
                  UEBA ENTERPRISE RISK SCORING (Alkido Behavioral Profiling)
                </span>
              </div>
              <span className="text-[10px] text-slate-400">Baselines: 30-Day Rolling Window</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
              {uebaProfiles.map((user) => {
                const isCritical = user.riskScore >= 85;
                const isHigh = user.riskScore >= 60 && user.riskScore < 85;

                return (
                  <div
                    key={user.username}
                    className={`p-3.5 rounded-lg border font-mono space-y-2.5 ${
                      isCritical
                        ? 'bg-red-950/20 border-red-800/80'
                        : isHigh
                        ? 'bg-amber-950/20 border-amber-800/80'
                        : 'bg-slate-950/80 border-slate-800'
                    }`}
                  >
                    <div className="flex justify-between items-start">
                      <div>
                        <div className="font-bold text-xs text-slate-200">{user.username}</div>
                        <div className="text-[10px] text-slate-400">{user.department}</div>
                      </div>
                      <div
                        className={`text-sm font-bold px-2 py-0.5 rounded border ${
                          isCritical
                            ? 'bg-red-900/80 text-red-200 border-red-700'
                            : isHigh
                            ? 'bg-amber-900/80 text-amber-200 border-amber-700'
                            : 'bg-emerald-950 text-emerald-300 border-emerald-800'
                        }`}
                      >
                        {user.riskScore}/100
                      </div>
                    </div>

                    <div className="space-y-1 text-[10px]">
                      <div className="flex justify-between text-slate-400">
                        <span>Failed Logins Today:</span>
                        <span className={user.failedLoginsToday > 5 ? 'text-red-400 font-bold' : 'text-slate-200'}>
                          {user.failedLoginsToday}
                        </span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Unusual Hours:</span>
                        <span className={user.unusualHoursActivity ? 'text-amber-400 font-bold' : 'text-emerald-400'}>
                          {user.unusualHoursActivity ? 'FLAGGED (2AM)' : 'NORMAL'}
                        </span>
                      </div>
                      <div className="flex justify-between text-slate-400">
                        <span>Mass Egress:</span>
                        <span className={user.highVolumeDataTransfer ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                          {user.highVolumeDataTransfer ? '42 GB OUT' : 'BASELINE'}
                        </span>
                      </div>
                    </div>

                    {/* Anomalies List */}
                    <div className="border-t border-slate-800/80 pt-2 text-[10px] text-slate-300 space-y-1">
                      <div className="text-slate-500 uppercase">INDICATORS:</div>
                      {user.anomalyIndicators.map((ind, i) => (
                        <div key={i} className="text-red-300 flex items-center gap-1 truncate">
                          <AlertTriangle className="w-2.5 h-2.5 flex-shrink-0 text-red-400" />
                          <span>{ind}</span>
                        </div>
                      ))}
                    </div>

                    <button
                      onClick={() => onPivotToHunting(user.username)}
                      className="w-full py-1 text-[11px] rounded bg-slate-800 hover:bg-slate-700 text-cyan-300 border border-slate-700 transition"
                    >
                      Pivot on Identity →
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* Sub-Tab 3: Threat Intelligence Feeds */}
      {activeSubTab === 'intel' && (
        <div className="space-y-4 font-mono">
          {/* Search Strip */}
          <div className="p-3.5 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-3">
            <div className="relative flex-1 min-w-[240px]">
              <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={iocSearch}
                onChange={(e) => setIocSearch(e.target.value)}
                placeholder="Search indicator IP, domain, hash, CVE, actor (e.g. 185.220.101.5, Cobalt Strike)..."
                className="w-full pl-9 pr-3 py-1.5 bg-slate-950 border border-slate-700 rounded text-xs text-cyan-300 placeholder-slate-500 focus:outline-none focus:border-cyan-400"
              />
            </div>

            <div className="flex items-center gap-2 text-xs">
              <span className="text-slate-400">ACTIVE FEEDS:</span>
              <span className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 text-[10px]">
                AlienVault OTX
              </span>
              <span className="px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800 text-[10px]">
                VirusTotal (v3)
              </span>
              <span className="px-2 py-0.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-[10px]">
                AbuseIPDB
              </span>
              <span className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 text-[10px]">
                MISP Threat Sharing
              </span>
            </div>
          </div>

          {/* Threat Intel Cards Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {filteredIntel.map((item) => (
              <div
                key={item.id}
                className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 hover:border-slate-700 transition space-y-3"
              >
                <div className="flex items-start justify-between">
                  <div>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 font-bold uppercase">
                      {item.type}
                    </span>
                    <div className="text-xs font-bold text-slate-200 mt-1 break-all">
                      {item.indicator}
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-[10px] text-slate-400">REPUTATION</div>
                    <div className="text-sm font-bold text-red-400">{item.reputationScore}/100</div>
                  </div>
                </div>

                <div className="text-xs text-slate-300">
                  <div className="font-semibold text-cyan-300">{item.threatName}</div>
                  <div className="text-[11px] text-slate-400 mt-0.5">
                    Actor: <span className="text-red-400 font-semibold">{item.associatedThreatActor}</span>
                  </div>
                  {item.geolocation && (
                    <div className="text-[10px] text-slate-500 mt-0.5">Origin: {item.geolocation}</div>
                  )}
                </div>

                <div className="flex flex-wrap gap-1">
                  {item.tags.map((tag) => (
                    <span
                      key={tag}
                      className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-300 text-[10px]"
                    >
                      #{tag}
                    </span>
                  ))}
                </div>

                <div className="border-t border-slate-800 pt-2 flex items-center justify-between text-[10px] text-slate-400">
                  <span>Feed: {item.feedSource}</span>
                  <button
                    onClick={() => onPivotToHunting(item.indicator)}
                    className="text-cyan-400 hover:text-cyan-300 flex items-center gap-0.5 font-bold"
                  >
                    Hunt in SIEM →
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
