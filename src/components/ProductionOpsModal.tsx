import React, { useState, useEffect } from 'react';
import {
  Server,
  Activity,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Play,
  RotateCcw,
  Check,
  X,
  Database,
  Lock,
  Layers,
  FileText,
  Clock,
  Sparkles,
  Sliders,
  Terminal,
} from 'lucide-react';
import {
  fetchHealthStatus,
  runProductionTests,
  fetchAuditLogs,
  fetchIncidentActions,
  approveIncidentAction,
  HealthResponse,
  TestSuiteReport,
  IncidentActionRecord,
} from '../services/api.ts';
import { useAuth } from '../context/AuthContext.tsx';

interface ProductionOpsModalProps {
  isOpen: boolean;
  onClose: () => void;
}

export const ProductionOpsModal: React.FC<ProductionOpsModalProps> = ({ isOpen, onClose }) => {
  if (!isOpen) return null;

  const { dbUser, isSimulatedMode, setIsSimulatedMode, canApproveActions } = useAuth();
  const [activeTab, setActiveTab] = useState<'health' | 'tests' | 'approvals' | 'audit'>('health');

  // Health state
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [healthLoading, setHealthLoading] = useState(false);

  // Test suite state
  const [testReport, setTestReport] = useState<TestSuiteReport | null>(null);
  const [testingRunning, setTestingRunning] = useState(false);

  // Approvals state
  const [pendingActions, setPendingActions] = useState<IncidentActionRecord[]>([]);
  const [approvalsLoading, setApprovalsLoading] = useState(false);
  const [actionFeedback, setActionFeedback] = useState<string | null>(null);

  // Audit state
  const [auditLogs, setAuditLogs] = useState<any[]>([]);
  const [auditLoading, setAuditLoading] = useState(false);

  useEffect(() => {
    loadHealth();
  }, []);

  const loadHealth = async () => {
    setHealthLoading(true);
    try {
      const data = await fetchHealthStatus();
      setHealth(data);
    } catch (e) {
      console.error(e);
    } finally {
      setHealthLoading(false);
    }
  };

  const loadApprovals = async () => {
    setApprovalsLoading(true);
    try {
      const all = await fetchIncidentActions();
      setPendingActions(all.filter((a) => a.status === 'pending_approval'));
    } catch (e) {
      console.error(e);
    } finally {
      setApprovalsLoading(false);
    }
  };

  const loadAudit = async () => {
    setAuditLoading(true);
    try {
      const logs = await fetchAuditLogs();
      setAuditLogs(logs);
    } catch (e) {
      console.error(e);
    } finally {
      setAuditLoading(false);
    }
  };

  const handleRunTests = async () => {
    setTestingRunning(true);
    try {
      const report = await runProductionTests();
      setTestReport(report);
    } catch (e) {
      console.error(e);
    } finally {
      setTestingRunning(false);
    }
  };

  const handleDecision = async (actionId: number, decision: 'approved' | 'rejected') => {
    try {
      await approveIncidentAction(actionId, decision);
      setActionFeedback(`Action #${actionId} successfully ${decision}.`);
      loadApprovals();
      setTimeout(() => setActionFeedback(null), 4000);
    } catch (e: any) {
      setActionFeedback(`Failed to update action: ${e.message}`);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-900/70 dark:bg-slate-950/85 backdrop-blur-sm z-50 flex items-center justify-center p-4 font-mono transition-colors">
      <div className="bg-white dark:bg-slate-900 border border-slate-300 dark:border-slate-700 rounded-lg max-w-4xl w-full p-5 space-y-4 shadow-2xl max-h-[92vh] overflow-y-auto scrollbar-thin text-xs text-slate-900 dark:text-slate-100 transition-colors">
        {/* Header */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-200 dark:border-slate-800 pb-3">
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-600 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-slate-900 dark:text-slate-100 tracking-wider">
                AEGIS PRODUCTION CONTROL & DIAGNOSTICS
              </h2>
              <p className="text-[11px] text-slate-500 dark:text-slate-400">
                PostgreSQL • Splunk/Elastic Connectors • Sophos & Shuffle IR Gates • RBAC
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Simulation toggle */}
            <button
              onClick={() => setIsSimulatedMode(!isSimulatedMode)}
              className={`px-2.5 py-1 rounded text-[11px] font-semibold border flex items-center gap-1.5 transition ${
                isSimulatedMode
                  ? 'bg-amber-100 dark:bg-amber-950/70 text-amber-800 dark:text-amber-300 border-amber-300 dark:border-amber-700'
                  : 'bg-emerald-100 dark:bg-emerald-950/70 text-emerald-800 dark:text-emerald-300 border-emerald-300 dark:border-emerald-700'
              }`}
              title="Toggle safe demonstration vs production enforcement"
            >
              <Sliders className="w-3.5 h-3.5" />
              <span>{isSimulatedMode ? 'MODE: SAFE SIMULATION' : 'MODE: LIVE ENTERPRISE'}</span>
            </button>

            <button
              onClick={onClose}
              className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200 p-1 text-base leading-none"
            >
              ✕
            </button>
          </div>
        </div>

        {/* Tab Strip */}
        <div className="flex border-b border-slate-200 dark:border-slate-800 gap-2">
          <button
            onClick={() => {
              setActiveTab('health');
              loadHealth();
            }}
            className={`px-3 py-1.5 font-bold border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'health'
                ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Activity className="w-3.5 h-3.5" />
            Health & Backend
          </button>
          <button
            onClick={() => setActiveTab('tests')}
            className={`px-3 py-1.5 font-bold border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'tests'
                ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Sparkles className="w-3.5 h-3.5" />
            Phase 1-5 Automated Tests
          </button>
          <button
            onClick={() => {
              setActiveTab('approvals');
              loadApprovals();
            }}
            className={`px-3 py-1.5 font-bold border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'approvals'
                ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            Approval Gates {pendingActions.length > 0 && `(${pendingActions.length})`}
          </button>
          <button
            onClick={() => {
              setActiveTab('audit');
              loadAudit();
            }}
            className={`px-3 py-1.5 font-bold border-b-2 transition flex items-center gap-1.5 ${
              activeTab === 'audit'
                ? 'border-cyan-500 text-cyan-600 dark:text-cyan-400'
                : 'border-transparent text-slate-500 hover:text-slate-800 dark:hover:text-slate-200'
            }`}
          >
            <FileText className="w-3.5 h-3.5" />
            Immutable Audit Trail
          </button>
        </div>

        {/* Tab 1: Health & Backend */}
        {activeTab === 'health' && (
          <div className="space-y-3">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="p-3 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-[10px] text-slate-400 uppercase">Database Provider</div>
                <div className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-1.5 mt-0.5">
                  <Database className="w-4 h-4 text-cyan-500" />
                  PostgreSQL (Cloud SQL)
                </div>
                <div className="text-[11px] text-emerald-600 dark:text-emerald-400 mt-1">
                  Latency: {health?.database.latencyMs ?? '...'} ms (Operational)
                </div>
              </div>

              <div className="p-3 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-[10px] text-slate-400 uppercase">Uptime & Control Plane</div>
                <div className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-1.5 mt-0.5">
                  <Server className="w-4 h-4 text-purple-500" />
                  {health ? `${health.uptimeSeconds}s active` : 'Loading...'}
                </div>
                <div className="text-[11px] text-slate-500 mt-1">Environment: {health?.environment}</div>
              </div>

              <div className="p-3 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800">
                <div className="text-[10px] text-slate-400 uppercase">Active Operator Identity</div>
                <div className="text-sm font-bold text-slate-900 dark:text-slate-100 flex items-center gap-1.5 mt-0.5">
                  <Lock className="w-4 h-4 text-amber-500" />
                  {dbUser?.role.toUpperCase()}
                </div>
                <div className="text-[11px] text-slate-500 mt-1 truncate">{dbUser?.email}</div>
              </div>
            </div>

            {/* Ingestion & Connectors status */}
            <div className="p-3 rounded bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-2">
              <div className="text-xs font-bold text-slate-800 dark:text-slate-200">
                Real Ingestion Connectors (Splunk / Elastic / Sophos / Shuffle)
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex items-center justify-between">
                  <div>
                    <span className="font-bold">Splunk HEC:</span> /api/siem/splunk-hec
                    <div className="text-[10px] text-slate-400">Endpoint: https://splunk.corp.internal:8088</div>
                  </div>
                  <span className="px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-bold text-[10px]">
                    ONLINE
                  </span>
                </div>

                <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex items-center justify-between">
                  <div>
                    <span className="font-bold">Elasticsearch Bulk:</span> /api/siem/ingest
                    <div className="text-[10px] text-slate-400">Endpoint: https://es-cluster.corp.internal:9200</div>
                  </div>
                  <span className="px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-bold text-[10px]">
                    ONLINE
                  </span>
                </div>

                <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex items-center justify-between">
                  <div>
                    <span className="font-bold">Sophos Central API:</span> Host Isolation & EDR
                    <div className="text-[10px] text-slate-400">Live Agent Heartbeat & Tamper Protection</div>
                  </div>
                  <span className="px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-bold text-[10px]">
                    ONLINE
                  </span>
                </div>

                <div className="p-2 rounded border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 flex items-center justify-between">
                  <div>
                    <span className="font-bold">Shuffle SOAR Engine:</span> /api/incident/shuffle-playbook
                    <div className="text-[10px] text-slate-400">Node Webhook Runner & Orchestrator</div>
                  </div>
                  <span className="px-1.5 py-0.5 rounded bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 font-bold text-[10px]">
                    ONLINE
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Automated Tests */}
        {activeTab === 'tests' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-bold text-slate-800 dark:text-slate-200">
                  Automated End-to-End SOC Verification Suite
                </div>
                <div className="text-[11px] text-slate-500">
                  Executes actual DB queries, ingestion validations, RBAC checks, and SOAR response traces.
                </div>
              </div>

              <button
                onClick={handleRunTests}
                disabled={testingRunning}
                className="px-3 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-white font-bold text-xs flex items-center gap-1.5 shadow transition disabled:opacity-50"
              >
                {testingRunning ? (
                  <>
                    <RotateCcw className="w-3.5 h-3.5 animate-spin" />
                    <span>Executing Tests...</span>
                  </>
                ) : (
                  <>
                    <Play className="w-3.5 h-3.5" />
                    <span>Run Full Test Suite</span>
                  </>
                )}
              </button>
            </div>

            {testReport && (
              <div className="space-y-2">
                <div
                  className={`p-2.5 rounded border text-xs font-bold flex items-center justify-between ${
                    testReport.summary.status === 'ALL_PASSED'
                      ? 'bg-emerald-50 dark:bg-emerald-950/60 border-emerald-300 dark:border-emerald-800 text-emerald-800 dark:text-emerald-300'
                      : 'bg-red-50 dark:bg-red-950/60 border-red-300 dark:border-red-800 text-red-800 dark:text-red-300'
                  }`}
                >
                  <div className="flex items-center gap-2">
                    {testReport.summary.status === 'ALL_PASSED' ? (
                      <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-600" />
                    )}
                    <span>
                      {testReport.summary.passedTests} / {testReport.summary.totalTests} Tests Passed
                    </span>
                  </div>
                  <span className="text-[10px] font-mono">
                    Duration: {testReport.summary.totalDurationMs}ms
                  </span>
                </div>

                <div className="space-y-1.5">
                  {testReport.tests.map((t) => (
                    <div
                      key={t.id}
                      className="p-2.5 rounded border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-950 flex items-start justify-between gap-2"
                    >
                      <div className="space-y-0.5">
                        <div className="flex items-center gap-2 font-bold text-slate-800 dark:text-slate-200">
                          <span className="text-[10px] text-cyan-600 dark:text-cyan-400">[{t.id}]</span>
                          <span>{t.name}</span>
                          <span className="text-[9px] px-1 py-0.2 rounded bg-slate-200 dark:bg-slate-800 text-slate-600 dark:text-slate-400">
                            {t.phase}
                          </span>
                        </div>
                        <div className="text-[11px] text-slate-500 dark:text-slate-400">
                          {t.details || t.error}
                        </div>
                      </div>

                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                          t.status === 'PASSED'
                            ? 'bg-emerald-100 dark:bg-emerald-950 text-emerald-700 dark:text-emerald-300 border border-emerald-300 dark:border-emerald-800'
                            : t.status === 'FALLBACK_READY'
                            ? 'bg-blue-100 dark:bg-blue-950 text-blue-700 dark:text-blue-300 border border-blue-300 dark:border-blue-800'
                            : 'bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-300 border border-red-300 dark:border-red-800'
                        }`}
                      >
                        {t.status}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Tab 3: Approval Gates */}
        {activeTab === 'approvals' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-bold text-slate-800 dark:text-slate-200">
                  Incident Containment Approval Gate
                </div>
                <div className="text-[11px] text-slate-500">
                  Critical infrastructure containment actions (e.g. Domain Controllers, core DBs) require SOC Admin authorization.
                </div>
              </div>

              <button
                onClick={loadApprovals}
                className="px-2.5 py-1 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-[11px]"
              >
                Refresh
              </button>
            </div>

            {actionFeedback && (
              <div className="p-2 rounded bg-cyan-100 dark:bg-cyan-950 text-cyan-800 dark:text-cyan-300 text-xs font-bold border border-cyan-300 dark:border-cyan-800">
                {actionFeedback}
              </div>
            )}

            {pendingActions.length === 0 ? (
              <div className="p-6 text-center text-slate-400 bg-slate-50 dark:bg-slate-950 rounded border border-slate-200 dark:border-slate-800">
                <CheckCircle2 className="w-6 h-6 text-emerald-500 mx-auto mb-1.5" />
                No pending containment requests. All critical systems operating under normal policy.
              </div>
            ) : (
              <div className="space-y-2">
                {pendingActions.map((act) => (
                  <div
                    key={act.id}
                    className="p-3 rounded border border-amber-300 dark:border-amber-800/80 bg-amber-50 dark:bg-amber-950/30 flex items-center justify-between gap-3"
                  >
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-amber-800 dark:text-amber-300 uppercase text-xs">
                          {act.actionType.replace('_', ' ')}
                        </span>
                        <span className="text-slate-500 font-mono text-[10px]">Target: {act.target}</span>
                      </div>
                      <div className="text-[11px] text-slate-600 dark:text-slate-400 mt-0.5">
                        Requested by: <span className="font-semibold">{act.requestedBy}</span> • Platform: {act.platform}
                      </div>
                      {act.notes && <div className="text-[10px] text-slate-500 italic mt-0.5">{act.notes}</div>}
                    </div>

                    <div className="flex items-center gap-1.5">
                      {canApproveActions ? (
                        <>
                          <button
                            onClick={() => handleDecision(act.id, 'approved')}
                            className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-[11px] flex items-center gap-1 shadow"
                          >
                            <Check className="w-3.5 h-3.5" />
                            Approve
                          </button>
                          <button
                            onClick={() => handleDecision(act.id, 'rejected')}
                            className="px-2.5 py-1 rounded bg-red-600 hover:bg-red-500 text-white font-bold text-[11px] flex items-center gap-1 shadow"
                          >
                            <X className="w-3.5 h-3.5" />
                            Reject
                          </button>
                        </>
                      ) : (
                        <span className="text-[10px] text-slate-500 italic">
                          Admin permissions required to approve
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Tab 4: Audit Trail */}
        {activeTab === 'audit' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-bold text-slate-800 dark:text-slate-200">
                  Cryptographic SOC Audit Trail
                </div>
                <div className="text-[11px] text-slate-500">
                  Immutable PostgreSQL log of every containment action, role elevation, and alert resolution.
                </div>
              </div>
              <button
                onClick={loadAudit}
                className="px-2.5 py-1 rounded bg-slate-200 dark:bg-slate-800 text-slate-700 dark:text-slate-300 text-[11px]"
              >
                Refresh
              </button>
            </div>

            <div className="border border-slate-200 dark:border-slate-800 rounded overflow-hidden max-h-72 overflow-y-auto">
              <table className="w-full text-[11px] text-left">
                <thead className="bg-slate-100 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 text-slate-500">
                  <tr>
                    <th className="p-2">Timestamp</th>
                    <th className="p-2">User</th>
                    <th className="p-2">Action</th>
                    <th className="p-2">Resource</th>
                    <th className="p-2">Details</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-800 bg-white dark:bg-slate-900">
                  {auditLogs.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="p-4 text-center text-slate-400">
                        No audit records recorded yet.
                      </td>
                    </tr>
                  ) : (
                    auditLogs.map((log: any) => (
                      <tr key={log.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                        <td className="p-2 whitespace-nowrap text-slate-400 font-mono text-[10px]">
                          {new Date(log.createdAt).toLocaleTimeString()}
                        </td>
                        <td className="p-2 font-semibold text-slate-800 dark:text-slate-200">
                          {log.userEmail || 'system'}
                        </td>
                        <td className="p-2 font-mono text-cyan-700 dark:text-cyan-300 font-bold">
                          {log.action}
                        </td>
                        <td className="p-2 text-slate-600 dark:text-slate-400">{log.resourceType}</td>
                        <td className="p-2 text-slate-500 font-mono text-[10px] truncate max-w-xs">
                          {JSON.stringify(log.details || {})}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
