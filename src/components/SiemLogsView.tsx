import React, { useState, useMemo } from 'react';
import {
  Terminal,
  Search,
  Filter,
  Sparkles,
  Play,
  Copy,
  Check,
  Download,
  PlusCircle,
  Database,
  Layers,
  ArrowRight,
  Shield,
  FileCode2,
} from 'lucide-react';
import { SecurityLog } from '../types/soc.ts';
import { translateQueryWithGemini } from '../services/api.ts';

interface SiemLogsViewProps {
  logs: SecurityLog[];
  onPivotToHunting: (iocValue: string) => void;
  onSelectLogForDetail?: (log: SecurityLog) => void;
  onInjectCustomLog: (newLog: SecurityLog) => void;
}

export const SiemLogsView: React.FC<SiemLogsViewProps> = ({
  logs,
  onPivotToHunting,
  onInjectCustomLog,
}) => {
  const [queryMode, setQueryMode] = useState<'SPL' | 'KQL'>('SPL');
  const [searchQuery, setSearchQuery] = useState(
    'index=security sourcetype=WinEventLog:Security (EventCode=4688 OR EventCode=4625)'
  );
  const [sourceFilter, setSourceFilter] = useState<string>('all');
  const [severityFilter, setSeverityFilter] = useState<string>('all');
  const [selectedLog, setSelectedLog] = useState<SecurityLog | null>(logs[0] || null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // AI Natural Language Query translator state
  const [showAiModal, setShowAiModal] = useState(false);
  const [nlPrompt, setNlPrompt] = useState('');
  const [isTranslating, setIsTranslating] = useState(false);
  const [aiExplanation, setAiExplanation] = useState<string | null>(null);

  // Custom log inject state
  const [showInjectModal, setShowInjectModal] = useState(false);
  const [customSource, setCustomSource] = useState<SecurityLog['sourceType']>('WinEventLog:Security');
  const [customHost, setCustomHost] = useState('WS-FINANCE-07');
  const [customUser, setCustomUser] = useState('CORP\\m.jenkins');
  const [customMsg, setCustomMsg] = useState('powershell.exe -NoP -NonI -W Hidden -Enc SQBFAFgA...');
  const [customSeverity, setCustomSeverity] = useState<SecurityLog['severity']>('high');

  // Filter logs based on search bar & dropdowns
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (sourceFilter !== 'all' && log.sourceType !== sourceFilter) return false;
      if (severityFilter !== 'all' && log.severity !== severityFilter) return false;

      if (!searchQuery.trim()) return true;

      const q = searchQuery.toLowerCase();
      // Handle simple SPL syntax matching
      if (q.includes('eventcode=')) {
        const codeMatch = q.match(/eventcode=(\d+)/);
        if (codeMatch && log.eventId?.toString() !== codeMatch[1]) {
          return false;
        }
      }
      if (q.includes('sourcetype=')) {
        const stMatch = q.match(/sourcetype=([^\s|]+)/);
        if (stMatch && !log.sourceType.toLowerCase().includes(stMatch[1].toLowerCase())) {
          return false;
        }
      }

      // General string matching on host, user, message, raw, process
      const matchString = `${log.host} ${log.user} ${log.message} ${log.processName || ''} ${log.commandLine || ''} ${log.destIp || ''} ${log.srcIp || ''} ${log.raw}`.toLowerCase();
      
      const keywords = q
        .replace(/index=\S+/g, '')
        .replace(/sourcetype=\S+/g, '')
        .replace(/eventcode=\S+/g, '')
        .replace(/\|\s*stats.*$/g, '')
        .replace(/event\.category:\s*\S+/g, '')
        .trim();

      if (!keywords) return true;
      return keywords.split(/\s+/).every((kw) => matchString.includes(kw));
    });
  }, [logs, searchQuery, sourceFilter, severityFilter]);

  const handleTranslateQuery = async () => {
    if (!nlPrompt.trim()) return;
    setIsTranslating(true);
    setAiExplanation(null);
    try {
      const res = await translateQueryWithGemini(nlPrompt, queryMode);
      setSearchQuery(res.convertedQuery);
      setAiExplanation(res.explanation);
    } finally {
      setIsTranslating(false);
    }
  };

  const handleCopyRaw = (rawText: string, id: string) => {
    navigator.clipboard.writeText(rawText);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  const handleCreateCustomLog = () => {
    const newLog: SecurityLog = {
      id: `log-cust-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 23),
      sourceType: customSource,
      host: customHost,
      user: customUser,
      message: customMsg,
      severity: customSeverity,
      raw: `Custom Ingestion [${customSource}]: ${customMsg} (User: ${customUser}, Host: ${customHost})`,
      entropy: 5.6,
      clusterId: 'CLUSTER_MANUAL_INJECT',
      anomalyScore: customSeverity === 'critical' ? 95 : customSeverity === 'high' ? 82 : 45,
    };
    onInjectCustomLog(newLog);
    setSelectedLog(newLog);
    setShowInjectModal(false);
  };

  const splPresets = [
    {
      label: 'Certutil LOLBin Executions',
      query: 'index=security sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*certutil*"',
    },
    {
      label: 'Failed Logons (4625) Spikes',
      query: 'index=security sourcetype=WinEventLog:Security EventCode=4625 | stats count by TargetUserName',
    },
    {
      label: 'Volume Shadow Copy Deletion',
      query: 'index=security CommandLine="*vssadmin*delete*shadows*"',
    },
    {
      label: 'AWS CloudTrail S3 Policy Alterations',
      query: 'sourcetype=AWS:CloudTrail eventName="PutBucketPolicy"',
    },
  ];

  const kqlPresets = [
    {
      label: 'Anomalous Process Spawns',
      query: 'process.name: ("certutil.exe" or "cmd.exe" or "powershell.exe") and event.action: "process_started"',
    },
    {
      label: 'Failed Authentication Attempts',
      query: 'event.category: "authentication" and event.outcome: "failure"',
    },
    {
      label: 'High Risk Sophos Detections',
      query: 'event.dataset: "sophos.xdr" and sophos.threat_severity: "critical"',
    },
  ];

  return (
    <div className="space-y-4">
      {/* Top SIEM Control Strip */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-3">
        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-slate-400">TOTAL INGESTED LOGS</div>
            <div className="text-xl font-bold font-mono text-slate-100">{logs.length.toLocaleString()}</div>
          </div>
          <Database className="w-6 h-6 text-cyan-400" />
        </div>
        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-slate-400">ACTIVE SOURCES</div>
            <div className="text-xl font-bold font-mono text-cyan-300">6 CONNECTORS</div>
          </div>
          <Layers className="w-6 h-6 text-blue-400" />
        </div>
        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-slate-400">CORRELATION RULES ACTIVE</div>
            <div className="text-xl font-bold font-mono text-emerald-400">42 SIGMA / SPL</div>
          </div>
          <Shield className="w-6 h-6 text-emerald-400" />
        </div>
        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800 flex items-center justify-between">
          <div>
            <div className="text-xs font-mono text-slate-400">QUERY PARSER ENGINE</div>
            <div className="text-xl font-bold font-mono text-purple-400">SPL & KQL v9.2</div>
          </div>
          <Terminal className="w-6 h-6 text-purple-400" />
        </div>
      </div>

      {/* Query Builder Console */}
      <div className="p-4 rounded-lg bg-slate-900/95 border border-slate-800 shadow-xl space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-400">QUERY DIALECT:</span>
            <div className="flex rounded border border-slate-700 bg-slate-950 p-0.5">
              <button
                onClick={() => {
                  setQueryMode('SPL');
                  setSearchQuery('index=security sourcetype=WinEventLog:Security (EventCode=4688 OR EventCode=4625)');
                }}
                className={`px-2.5 py-1 text-xs font-mono font-semibold rounded transition cursor-pointer ${
                  queryMode === 'SPL'
                    ? 'bg-cyan-500 text-slate-950 shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Splunk SPL
              </button>
              <button
                onClick={() => {
                  setQueryMode('KQL');
                  setSearchQuery('event.category: "authentication" and event.outcome: "failure"');
                }}
                className={`px-2.5 py-1 text-xs font-mono font-semibold rounded transition cursor-pointer ${
                  queryMode === 'KQL'
                    ? 'bg-cyan-500 text-slate-950 shadow'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                Elastic KQL
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={() => setShowAiModal(true)}
              className="px-2.5 py-1 text-xs font-mono rounded bg-purple-950/80 hover:bg-purple-900 text-purple-300 border border-purple-700/60 flex items-center gap-1.5 transition cursor-pointer"
            >
              <Sparkles className="w-3.5 h-3.5 text-purple-400" />
              <span>AI Query Translator</span>
            </button>

            <button
              onClick={() => setShowInjectModal(true)}
              className="px-2.5 py-1 text-xs font-mono rounded bg-emerald-950/80 hover:bg-emerald-900 text-emerald-300 border border-emerald-700/60 flex items-center gap-1.5 transition cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5 text-emerald-400" />
              <span>Ingest Raw Log</span>
            </button>
          </div>
        </div>

        {/* Input Bar */}
        <div className="relative font-mono">
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
            <Terminal className="w-4 h-4 text-cyan-400" />
          </div>
          <input
            type="text"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            placeholder={
              queryMode === 'SPL'
                ? 'index=security sourcetype=WinEventLog:Security EventCode=4688 | stats count by CommandLine'
                : 'event.category: "process" and process.name: "certutil.exe"'
            }
            className="w-full pl-9 pr-24 py-2 bg-slate-950 border border-slate-700 rounded text-xs font-mono text-cyan-300 placeholder-slate-600 focus:outline-none focus:border-cyan-400 focus:ring-1 focus:ring-cyan-400"
          />
          <div className="absolute inset-y-0 right-1 flex items-center gap-1 pr-1">
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="px-2 py-1 text-[11px] text-slate-400 hover:text-slate-200"
              >
                Clear
              </button>
            )}
            <button
              onClick={() => {}}
              className="px-3 py-1 bg-cyan-600 hover:bg-cyan-500 text-slate-950 text-xs font-bold rounded flex items-center gap-1 transition cursor-pointer"
            >
              <Search className="w-3 h-3" />
              <span>SEARCH</span>
            </button>
          </div>
        </div>

        {/* Query Presets Chips */}
        <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
          <span className="text-slate-500">QUICK INVESTIGATION PRESETS:</span>
          {(queryMode === 'SPL' ? splPresets : kqlPresets).map((preset, idx) => (
            <button
              key={idx}
              onClick={() => setSearchQuery(preset.query)}
              className="px-2 py-0.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition cursor-pointer"
            >
              {preset.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main Grid: Log Table & Field Inspector Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left Column: Log Events Table (2 Cols) */}
        <div className="lg:col-span-2 p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-slate-200">
                MATCHING EVENTS ({filteredLogs.length})
              </span>
              <span className="text-[10px] font-mono text-slate-500">
                Showing newest first
              </span>
            </div>

            {/* Quick Filters */}
            <div className="flex items-center gap-2">
              <select
                value={sourceFilter}
                onChange={(e) => setSourceFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-300 text-xs font-mono rounded px-2 py-1"
              >
                <option value="all">All Sources</option>
                <option value="WinEventLog:Security">WinEventLog:Security</option>
                <option value="Sophos:XDR">Sophos:XDR</option>
                <option value="Network:Zeek">Network:Zeek</option>
                <option value="AWS:CloudTrail">AWS:CloudTrail</option>
                <option value="Linux:Syslog">Linux:Syslog</option>
                <option value="Firewall:PaloAlto">Firewall:PaloAlto</option>
              </select>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-slate-950 border border-slate-800 text-slate-300 text-xs font-mono rounded px-2 py-1"
              >
                <option value="all">All Severities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>

          {/* Table Container */}
          <div className="overflow-x-auto max-h-[520px] scrollbar-thin">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-slate-950/80 text-slate-400 sticky top-0 border-b border-slate-800">
                <tr>
                  <th className="py-2 px-2.5">TIME</th>
                  <th className="py-2 px-2">SEV</th>
                  <th className="py-2 px-2.5">SOURCE</th>
                  <th className="py-2 px-2.5">HOST / USER</th>
                  <th className="py-2 px-2.5">EVENT / MESSAGE</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {filteredLogs.map((log) => {
                  const isSelected = selectedLog?.id === log.id;
                  const sevColor =
                    log.severity === 'critical'
                      ? 'text-red-400 bg-red-950/70 border-red-800/80'
                      : log.severity === 'high'
                      ? 'text-amber-400 bg-amber-950/70 border-amber-800/80'
                      : log.severity === 'medium'
                      ? 'text-yellow-400 bg-yellow-950/50 border-yellow-800/60'
                      : 'text-slate-400 bg-slate-800/50 border-slate-700/60';

                  return (
                    <tr
                      key={log.id}
                      onClick={() => setSelectedLog(log)}
                      className={`hover:bg-slate-800/40 cursor-pointer transition ${
                        isSelected ? 'bg-cyan-950/30 border-l-2 border-cyan-400' : ''
                      }`}
                    >
                      <td className="py-2 px-2.5 whitespace-nowrap text-slate-400 text-[11px]">
                        {log.timestamp.slice(11)}
                      </td>
                      <td className="py-2 px-2">
                        <span className={`text-[10px] px-1.5 py-0.2 rounded border font-semibold ${sevColor}`}>
                          {log.severity.toUpperCase()}
                        </span>
                      </td>
                      <td className="py-2 px-2.5 whitespace-nowrap text-cyan-300 text-[11px]">
                        {log.sourceType}
                      </td>
                      <td className="py-2 px-2.5 whitespace-nowrap">
                        <div className="font-semibold text-slate-200">{log.host}</div>
                        <div className="text-[10px] text-slate-400">{log.user}</div>
                      </td>
                      <td className="py-2 px-2.5 text-slate-300 max-w-xs truncate text-[11px]" title={log.message}>
                        {log.eventId && (
                          <span className="mr-1.5 px-1 py-0.2 rounded bg-slate-800 text-slate-300 text-[10px]">
                            EID:{log.eventId}
                          </span>
                        )}
                        {log.message}
                      </td>
                    </tr>
                  );
                })}
                {filteredLogs.length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500 font-mono text-xs">
                      No logs matched query filter: "{searchQuery}"
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right Column: Parsed Log Inspector & Raw Payload (1 Col) */}
        <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-4">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <div className="flex items-center gap-2">
              <FileCode2 className="w-4 h-4 text-cyan-400" />
              <span className="text-xs font-mono font-bold text-slate-200">
                FIELD EXTRACTION & RAW PAYLOAD
              </span>
            </div>
            {selectedLog && (
              <button
                onClick={() => handleCopyRaw(selectedLog.raw, selectedLog.id)}
                className="p-1 text-slate-400 hover:text-slate-200 text-xs flex items-center gap-1"
                title="Copy raw event"
              >
                {copiedId === selectedLog.id ? (
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                ) : (
                  <Copy className="w-3.5 h-3.5" />
                )}
              </button>
            )}
          </div>

          {selectedLog ? (
            <div className="space-y-4 font-mono text-xs">
              {/* Quick Pivoting Actions */}
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 space-y-1.5">
                <div className="text-[10px] text-slate-400 uppercase tracking-wider">
                  QUICK THREAT HUNTING PIVOTS
                </div>
                <div className="flex flex-wrap gap-1.5">
                  <button
                    onClick={() => onPivotToHunting(selectedLog.host)}
                    className="px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800 hover:bg-cyan-900 text-[11px] flex items-center gap-1"
                  >
                    Host: {selectedLog.host}
                    <ArrowRight className="w-2.5 h-2.5" />
                  </button>
                  <button
                    onClick={() => onPivotToHunting(selectedLog.user)}
                    className="px-2 py-0.5 rounded bg-blue-950 text-blue-300 border border-blue-800 hover:bg-blue-900 text-[11px] flex items-center gap-1"
                  >
                    User: {selectedLog.user}
                    <ArrowRight className="w-2.5 h-2.5" />
                  </button>
                  {selectedLog.srcIp && (
                    <button
                      onClick={() => onPivotToHunting(selectedLog.srcIp!)}
                      className="px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800 hover:bg-amber-900 text-[11px] flex items-center gap-1"
                    >
                      SrcIP: {selectedLog.srcIp}
                      <ArrowRight className="w-2.5 h-2.5" />
                    </button>
                  )}
                  {selectedLog.fileHash && (
                    <button
                      onClick={() => onPivotToHunting(selectedLog.fileHash!)}
                      className="px-2 py-0.5 rounded bg-purple-950 text-purple-300 border border-purple-800 hover:bg-purple-900 text-[11px] flex items-center gap-1"
                    >
                      Hash: {selectedLog.fileHash.slice(0, 10)}...
                      <ArrowRight className="w-2.5 h-2.5" />
                    </button>
                  )}
                </div>
              </div>

              {/* Parsed Key-Value Pairs */}
              <div className="space-y-1.5 max-h-48 overflow-y-auto scrollbar-thin">
                <div className="text-[10px] text-slate-400 uppercase">PARSED ATTRIBUTES</div>
                <div className="space-y-1 bg-slate-950 p-2.5 rounded border border-slate-800">
                  <div className="flex justify-between py-0.5 border-b border-slate-900">
                    <span className="text-slate-400">_time</span>
                    <span className="text-slate-200">{selectedLog.timestamp}</span>
                  </div>
                  <div className="flex justify-between py-0.5 border-b border-slate-900">
                    <span className="text-slate-400">sourcetype</span>
                    <span className="text-cyan-400">{selectedLog.sourceType}</span>
                  </div>
                  {selectedLog.eventId && (
                    <div className="flex justify-between py-0.5 border-b border-slate-900">
                      <span className="text-slate-400">EventCode</span>
                      <span className="text-amber-400 font-bold">{selectedLog.eventId}</span>
                    </div>
                  )}
                  {selectedLog.processName && (
                    <div className="flex justify-between py-0.5 border-b border-slate-900">
                      <span className="text-slate-400">ProcessName</span>
                      <span className="text-emerald-400">{selectedLog.processName}</span>
                    </div>
                  )}
                  {selectedLog.commandLine && (
                    <div className="py-0.5 border-b border-slate-900">
                      <span className="text-slate-400 block mb-0.5">CommandLine</span>
                      <span className="text-yellow-300 text-[11px] break-all bg-slate-900 p-1 rounded block">
                        {selectedLog.commandLine}
                      </span>
                    </div>
                  )}
                  {selectedLog.entropy && (
                    <div className="flex justify-between py-0.5 border-b border-slate-900">
                      <span className="text-slate-400">Shannon Entropy</span>
                      <span className="text-purple-300 font-bold">{selectedLog.entropy} bit/char</span>
                    </div>
                  )}
                  {selectedLog.anomalyScore && (
                    <div className="flex justify-between py-0.5">
                      <span className="text-slate-400">Alkido Anomaly Score</span>
                      <span
                        className={`font-bold ${
                          selectedLog.anomalyScore > 80
                            ? 'text-red-400'
                            : selectedLog.anomalyScore > 50
                            ? 'text-amber-400'
                            : 'text-emerald-400'
                        }`}
                      >
                        {selectedLog.anomalyScore} / 100
                      </span>
                    </div>
                  )}
                </div>
              </div>

              {/* Raw Format View */}
              <div className="space-y-1.5">
                <div className="text-[10px] text-slate-400 uppercase">RAW LOG RECORD</div>
                <div className="bg-slate-950 p-2.5 rounded border border-slate-800 text-[11px] text-slate-300 font-mono break-all max-h-40 overflow-y-auto">
                  {selectedLog.raw}
                </div>
              </div>
            </div>
          ) : (
            <div className="py-12 text-center text-slate-500 font-mono text-xs">
              Select any log event on the left to inspect extracted fields and raw payload.
            </div>
          )}
        </div>
      </div>

      {/* Modal: AI Natural Language Query Translator */}
      {showAiModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <Sparkles className="w-5 h-5 text-purple-400" />
                <h3 className="font-bold font-mono text-slate-100 text-sm">
                  AI NATURAL LANGUAGE TO {queryMode} TRANSLATOR
                </h3>
              </div>
              <button
                onClick={() => setShowAiModal(false)}
                className="text-slate-400 hover:text-slate-200 text-xs font-mono"
              >
                [ESC]
              </button>
            </div>

            <p className="text-xs text-slate-400 font-mono">
              Describe in plain English what security artifacts or anomalous behaviors you want to investigate.
              Gemini will translate it into optimized production {queryMode} syntax.
            </p>

            <textarea
              value={nlPrompt}
              onChange={(e) => setNlPrompt(e.target.value)}
              placeholder="e.g. Find all workstations where certutil or powershell ran to download executable binaries from external IP addresses..."
              className="w-full h-24 p-2.5 bg-slate-950 border border-slate-700 rounded text-xs font-mono text-slate-200 focus:outline-none focus:border-purple-400"
            />

            {aiExplanation && (
              <div className="p-3 rounded bg-purple-950/40 border border-purple-800 text-xs font-mono text-purple-200 space-y-1">
                <div className="font-bold text-[10px] text-purple-400 uppercase">TRANSLATOR RATIONALE</div>
                <p>{aiExplanation}</p>
              </div>
            )}

            <div className="flex justify-end gap-2">
              <button
                onClick={() => setShowAiModal(false)}
                className="px-3 py-1.5 rounded border border-slate-700 text-slate-400 hover:text-slate-200 text-xs font-mono"
              >
                Cancel
              </button>
              <button
                onClick={handleTranslateQuery}
                disabled={isTranslating || !nlPrompt.trim()}
                className="px-4 py-1.5 rounded bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-mono text-xs font-bold flex items-center gap-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{isTranslating ? 'Translating...' : 'Generate Query'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Modal: Custom Log Ingestion */}
      {showInjectModal && (
        <div className="fixed inset-0 bg-slate-950/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-md w-full p-5 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <h3 className="font-bold text-slate-100 text-sm flex items-center gap-2">
                <PlusCircle className="w-4 h-4 text-emerald-400" />
                INGEST CUSTOM LOG RECORD
              </h3>
              <button onClick={() => setShowInjectModal(false)} className="text-slate-400 hover:text-slate-200">
                ✕
              </button>
            </div>

            <div className="space-y-3">
              <div>
                <label className="text-slate-400 block mb-1 text-[11px]">SOURCE TYPE</label>
                <select
                  value={customSource}
                  onChange={(e) => setCustomSource(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-slate-200"
                >
                  <option value="WinEventLog:Security">WinEventLog:Security</option>
                  <option value="Sophos:XDR">Sophos:XDR</option>
                  <option value="Network:Zeek">Network:Zeek</option>
                  <option value="AWS:CloudTrail">AWS:CloudTrail</option>
                  <option value="Linux:Syslog">Linux:Syslog</option>
                  <option value="Firewall:PaloAlto">Firewall:PaloAlto</option>
                </select>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="text-slate-400 block mb-1 text-[11px]">TARGET HOST</label>
                  <input
                    type="text"
                    value={customHost}
                    onChange={(e) => setCustomHost(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-slate-200"
                  />
                </div>
                <div>
                  <label className="text-slate-400 block mb-1 text-[11px]">USER IDENTITY</label>
                  <input
                    type="text"
                    value={customUser}
                    onChange={(e) => setCustomUser(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-slate-200"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-400 block mb-1 text-[11px]">LOG MESSAGE / PAYLOAD</label>
                <textarea
                  value={customMsg}
                  onChange={(e) => setCustomMsg(e.target.value)}
                  className="w-full h-20 bg-slate-950 border border-slate-800 rounded p-1.5 text-slate-200 text-[11px]"
                />
              </div>

              <div>
                <label className="text-slate-400 block mb-1 text-[11px]">SEVERITY</label>
                <select
                  value={customSeverity}
                  onChange={(e) => setCustomSeverity(e.target.value as any)}
                  className="w-full bg-slate-950 border border-slate-800 rounded p-1.5 text-slate-200"
                >
                  <option value="critical">Critical</option>
                  <option value="high">High</option>
                  <option value="medium">Medium</option>
                  <option value="low">Low</option>
                  <option value="info">Info</option>
                </select>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setShowInjectModal(false)}
                className="px-3 py-1.5 rounded border border-slate-700 text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateCustomLog}
                className="px-3 py-1.5 rounded bg-emerald-600 hover:bg-emerald-500 text-slate-950 font-bold"
              >
                Push to SIEM Pipeline
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
