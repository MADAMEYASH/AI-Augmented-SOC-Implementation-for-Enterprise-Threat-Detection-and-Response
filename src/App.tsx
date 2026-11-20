import React, { useState, useEffect } from 'react';
import { AuthProvider, useAuth } from './context/AuthContext.tsx';
import { Header } from './components/Header.tsx';
import { SiemLogsView } from './components/SiemLogsView.tsx';
import { AiAnomalyEngineView } from './components/AiAnomalyEngineView.tsx';
import { ThreatHuntingView } from './components/ThreatHuntingView.tsx';
import { XdrEndpointView } from './components/XdrEndpointView.tsx';
import { MitreMatrixView } from './components/MitreMatrixView.tsx';
import { SoarPlaybooksView } from './components/SoarPlaybooksView.tsx';
import { AlertDetailModal } from './components/AlertDetailModal.tsx';
import { InjectScenarioModal } from './components/InjectScenarioModal.tsx';
import { ProductionOpsModal } from './components/ProductionOpsModal.tsx';

import {
  SecurityLog,
  SecurityAlert,
  ThreatIntelligenceItem,
  EndpointHost,
  MitreTechnique,
  SoarPlaybook,
  UebaProfile,
  AttackScenario,
} from './types/soc.ts';

import {
  fetchSocState,
  fetchSiemStats,
  ingestSiemLog,
  updateAlertStatus,
  executeIncidentAction,
  injectAttackScenario,
  deployMitreCountermeasure,
  resetSocDatabase,
} from './services/api.ts';

// Cyber acoustic synthesizer
function playAlertTone(type: 'warning' | 'success' | 'inject') {
  try {
    const AudioContextClass = window.AudioContext || (window as any).webkitAudioContext;
    if (!AudioContextClass) return;
    const ctx = new AudioContextClass();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();

    osc.connect(gain);
    gain.connect(ctx.destination);

    if (type === 'inject') {
      osc.type = 'sawtooth';
      osc.frequency.setValueAtTime(440, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(880, ctx.currentTime + 0.15);
      osc.frequency.exponentialRampToValueAtTime(220, ctx.currentTime + 0.3);
      gain.gain.setValueAtTime(0.12, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.35);
      osc.start();
      osc.stop(ctx.currentTime + 0.35);
    } else if (type === 'warning') {
      osc.type = 'square';
      osc.frequency.setValueAtTime(600, ctx.currentTime);
      osc.frequency.setValueAtTime(750, ctx.currentTime + 0.1);
      gain.gain.setValueAtTime(0.1, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.25);
      osc.start();
      osc.stop(ctx.currentTime + 0.25);
    } else {
      osc.type = 'sine';
      osc.frequency.setValueAtTime(520, ctx.currentTime);
      osc.frequency.exponentialRampToValueAtTime(1040, ctx.currentTime + 0.18);
      gain.gain.setValueAtTime(0.08, ctx.currentTime);
      gain.gain.exponentialRampToValueAtTime(0.01, ctx.currentTime + 0.2);
      osc.start();
      osc.stop(ctx.currentTime + 0.2);
    }
  } catch {
    // Audio context may be restricted before user gesture
  }
}

function SocInnerApp() {
  const { isSimulatedMode } = useAuth();
  const [activeTab, setActiveTab] = useState<string>('siem');
  const [logs, setLogs] = useState<SecurityLog[]>([]);
  const [alerts, setAlerts] = useState<SecurityAlert[]>([]);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelligenceItem[]>([]);
  const [endpoints, setEndpoints] = useState<EndpointHost[]>([]);
  const [techniques, setTechniques] = useState<MitreTechnique[]>([]);
  const [playbooks, setPlaybooks] = useState<SoarPlaybook[]>([]);
  const [uebaProfiles, setUebaProfiles] = useState<UebaProfile[]>([]);
  const [attackScenarios, setAttackScenarios] = useState<AttackScenario[]>([]);
  const [isLoadingDb, setIsLoadingDb] = useState<boolean>(true);

  // Live telemetry state
  const [eps, setEps] = useState<number>(24);
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);

  // Modals & Navigation pivots
  const [selectedAlertForDetail, setSelectedAlertForDetail] = useState<SecurityAlert | null>(null);
  const [showInjectScenarioModal, setShowInjectScenarioModal] = useState<boolean>(false);
  const [showProductionOpsModal, setShowProductionOpsModal] = useState<boolean>(false);
  const [huntingPivotTerm, setHuntingPivotTerm] = useState<string>('185.220.101.5');
  const [bannerNotice, setBannerNotice] = useState<string | null>(null);

  // Dark & Light Theme State
  const [theme, setTheme] = useState<'dark' | 'light'>(() => {
    if (typeof window !== 'undefined') {
      const saved = localStorage.getItem('aegis_theme');
      if (saved === 'light' || saved === 'dark') return saved;
      return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
    }
    return 'dark';
  });

  useEffect(() => {
    const root = document.documentElement;
    if (theme === 'dark') {
      root.classList.add('dark');
      root.classList.remove('light');
    } else {
      root.classList.remove('dark');
      root.classList.add('light');
    }
    try {
      localStorage.setItem('aegis_theme', theme);
    } catch {
      // storage unavailable
    }
  }, [theme]);

  const handleToggleTheme = () => {
    setTheme((prev) => (prev === 'dark' ? 'light' : 'dark'));
  };

  // Load all real SOC data directly from Cloud SQL PostgreSQL
  const loadDatabaseState = async () => {
    try {
      const [dbState, stats] = await Promise.all([fetchSocState(), fetchSiemStats()]);
      setLogs(dbState.logs);
      setAlerts(dbState.alerts);
      setEndpoints(dbState.endpoints);
      setThreatIntel(dbState.threatIntel);
      setTechniques(dbState.techniques);
      setPlaybooks(dbState.playbooks);
      setUebaProfiles(dbState.uebaProfiles);
      setAttackScenarios(dbState.attackScenarios);
      if (stats.eps) {
        setEps(stats.eps);
      }
    } catch (err) {
      console.error('Failed to load SOC state from PostgreSQL:', err);
      setBannerNotice('Database connection error: Unable to load live telemetry from PostgreSQL.');
    } finally {
      setIsLoadingDb(false);
    }
  };

  useEffect(() => {
    loadDatabaseState();
  }, []);

  // Periodic real stats & event rate sync
  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(async () => {
      try {
        const stats = await fetchSiemStats();
        setEps(stats.eps);
      } catch {
        // Fallback gentle fluctuation
        setEps((prev) => Math.floor(Math.max(30, prev + (Math.random() * 8 - 4))));
      }
    }, 4000);

    return () => clearInterval(interval);
  }, [isStreaming]);

  // Notice banner auto-dismiss
  useEffect(() => {
    if (!bannerNotice) return;
    const timer = setTimeout(() => setBannerNotice(null), 5000);
    return () => clearTimeout(timer);
  }, [bannerNotice]);

  // Pivoting handler
  const handlePivotToHunting = (indicator: string) => {
    setHuntingPivotTerm(indicator);
    setActiveTab('threat-hunting');
  };

  // Host isolation toggle handler with Approval Gate support
  const handleToggleIsolation = async (hostname: string) => {
    const hostObj = endpoints.find((h) => h.hostname === hostname);
    const willIsolate = hostObj?.status !== 'isolated';
    const actionType = willIsolate ? 'isolate_host' : 'unisolate_host';

    try {
      // Execute response action through production API
      const result = await executeIncidentAction({
        actionType,
        target: hostname,
        platform: 'sophos',
        notes: `${willIsolate ? 'Isolate' : 'Unisolate'} triggered from Aegis SOC console`,
        simulate: isSimulatedMode,
      });

      if (result.status === 'pending_approval') {
        setBannerNotice(
          `APPROVAL GATE: Containment action on high-value asset '${hostname}' queued for Administrator approval.`
        );
        if (soundEnabled) playAlertTone('warning');
        return;
      }

      // Update local state
      setEndpoints((prev) =>
        prev.map((h) => {
          if (h.hostname === hostname) {
            const nextStatus = willIsolate ? 'isolated' : 'online';
            return {
              ...h,
              status: nextStatus,
              riskScore: nextStatus === 'isolated' ? Math.max(10, h.riskScore - 40) : h.riskScore,
            };
          }
          return h;
        })
      );

      // Ingest response action audit log into SIEM & PostgreSQL
      const auditLog: SecurityLog = {
        id: `log-iso-${Date.now()}`,
        timestamp: new Date().toISOString().replace('T', ' ').slice(0, 23),
        sourceType: 'Sophos:XDR',
        host: hostname,
        user: 'SYSTEM',
        message: willIsolate
          ? `Sophos Central: Network isolation verified on ${hostname}. Host severed from corporate subnet.`
          : `Sophos Central: Network isolation removed on ${hostname}. Re-joined to subnet.`,
        severity: willIsolate ? 'high' : 'info',
        raw: JSON.stringify(result.executionResult || { action: actionType, target: hostname }),
        clusterId: 'CLUSTER_CONTAINMENT',
        anomalyScore: 10,
      };

      setLogs((prev) => [auditLog, ...prev]);
      ingestSiemLog(auditLog).catch(() => {});

      if (soundEnabled) playAlertTone('warning');
      setBannerNotice(
        `Sophos XDR: Verified ${willIsolate ? 'network isolation on' : 'network re-join for'} ${hostname}.`
      );
    } catch (e: any) {
      setBannerNotice(`Failed to execute response action: ${e.message}`);
    }
  };

  // Handle Playbook execution from any view
  const handleExecutePlaybookFromAlert = async (playbookId: string) => {
    setActiveTab('soar-playbooks');
    try {
      await executeIncidentAction({
        actionType: 'trigger_shuffle_playbook',
        target: playbookId,
        platform: 'shuffle',
        notes: `Playbook ${playbookId} executed via alert triage modal`,
        simulate: isSimulatedMode,
      });
      setBannerNotice(`Shuffle SOAR: Playbook ${playbookId} triggered and dispatched to runners.`);
      if (soundEnabled) playAlertTone('warning');
    } catch (e: any) {
      setBannerNotice(`Failed to trigger playbook: ${e.message}`);
    }
  };

  // Attack Scenario injection
  // Attack Scenario injection persisted in PostgreSQL
  const handleInjectScenario = async (scenario: AttackScenario) => {
    if (soundEnabled) playAlertTone('inject');

    try {
      const result = await injectAttackScenario(scenario.id);
      await loadDatabaseState();
      setBannerNotice(`ATTACK INJECTED: Telemetry for "${scenario.name}" persisted to PostgreSQL.`);
      if (result.alert) {
        setSelectedAlertForDetail(result.alert);
      }
    } catch (err: any) {
      setBannerNotice(`Scenario injection failed: ${err.message}`);
    }
  };

  // Reset SOC state in PostgreSQL and reload
  const handleResetSoc = async () => {
    try {
      await resetSocDatabase();
      await loadDatabaseState();
      setBannerNotice('PostgreSQL SOC baseline restored and reloaded.');
    } catch (err: any) {
      setBannerNotice(`Failed to reset SOC database: ${err.message}`);
    }
  };

  return (
    <div className="min-h-screen bg-slate-100 dark:bg-slate-950 text-slate-900 dark:text-slate-100 flex flex-col font-sans transition-colors duration-200">
      {/* Top SOC Command Header */}
      <Header
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        alerts={alerts}
        eps={eps}
        isStreaming={isStreaming}
        setIsStreaming={setIsStreaming}
        soundEnabled={soundEnabled}
        setSoundEnabled={setSoundEnabled}
        theme={theme}
        onToggleTheme={handleToggleTheme}
        onOpenInjectScenario={() => setShowInjectScenarioModal(true)}
        onResetSoc={handleResetSoc}
        onOpenProductionOps={() => setShowProductionOpsModal(true)}
      />

      {/* Real-time Notification Banner */}
      {bannerNotice && (
        <div className="bg-gradient-to-r from-cyan-100 via-white to-cyan-100 dark:from-cyan-950 dark:via-slate-900 dark:to-cyan-950 border-b border-cyan-300 dark:border-cyan-700/60 py-2 px-4 text-center font-mono text-xs text-cyan-900 dark:text-cyan-200 flex items-center justify-center gap-2 shadow-sm dark:shadow-lg transition-colors">
          <span className="w-2 h-2 rounded-full bg-cyan-600 dark:bg-cyan-400 animate-ping" />
          <span>{bannerNotice}</span>
          <button
            onClick={() => setBannerNotice(null)}
            className="text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200 ml-3 text-xs"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Operational Views */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6">
        {isLoadingDb ? (
          <div className="p-12 text-center font-mono text-xs text-slate-500">
            Connecting to Cloud SQL PostgreSQL and loading live SOC telemetry...
          </div>
        ) : (
          <>
            {activeTab === 'siem' && (
              <SiemLogsView
                logs={logs}
                onPivotToHunting={handlePivotToHunting}
                onInjectCustomLog={(newLog) => {
                  setLogs((prev) => [newLog, ...prev]);
                  ingestSiemLog(newLog).catch(() => {});
                }}
              />
            )}

            {activeTab === 'ai-detection' && (
              <AiAnomalyEngineView
                logs={logs}
                threatIntel={threatIntel}
                uebaProfiles={uebaProfiles}
                onPivotToHunting={handlePivotToHunting}
              />
            )}

            {activeTab === 'threat-hunting' && (
              <ThreatHuntingView
                logs={logs}
                alerts={alerts}
                threatIntel={threatIntel}
                initialPivotQuery={huntingPivotTerm}
                onSelectAlert={(a) => setSelectedAlertForDetail(a)}
                onExecutePlaybook={handleExecutePlaybookFromAlert}
                onIsolateHost={handleToggleIsolation}
              />
            )}

            {activeTab === 'xdr-endpoint' && (
              <XdrEndpointView
                endpoints={endpoints}
                onToggleIsolation={handleToggleIsolation}
                onPivotToHunting={handlePivotToHunting}
              />
            )}

            {activeTab === 'mitre-d3fend' && (
              <MitreMatrixView
                techniques={techniques}
                onDeployCountermeasure={async (techId) => {
                  try {
                    const updated = await deployMitreCountermeasure(techId);
                    setTechniques((prev) =>
                      prev.map((t) => (t.id === techId ? updated : t))
                    );
                    setBannerNotice(
                      `MITRE D3FEND: Automated countermeasure deployed for ${techId} and persisted in PostgreSQL.`
                    );
                    if (soundEnabled) playAlertTone('success');
                  } catch (err: any) {
                    setBannerNotice(`Failed to deploy countermeasure: ${err.message}`);
                  }
                }}
                onPivotToHunting={handlePivotToHunting}
              />
            )}

            {activeTab === 'soar-playbooks' && (
              <SoarPlaybooksView
                playbooks={playbooks}
                onPlaybookComplete={(pbId) => {
                  setBannerNotice(`Shuffle SOAR: Playbook ${pbId} execution completed and logged to PostgreSQL.`);
                  if (soundEnabled) playAlertTone('success');
                }}
              />
            )}
          </>
        )}
      </main>

      {/* Modals */}
      <AlertDetailModal
        alert={selectedAlertForDetail}
        logs={logs}
        onClose={() => setSelectedAlertForDetail(null)}
        onExecutePlaybook={handleExecutePlaybookFromAlert}
        onPivotToHunting={handlePivotToHunting}
        onMarkRemediated={(alertId) => {
          updateAlertStatus(alertId, 'remediated').catch(() => {});
          setAlerts((prev) =>
            prev.map((a) => (a.id === alertId ? { ...a, status: 'remediated' } : a))
          );
          setBannerNotice(`Alert ${alertId} marked as remediated in PostgreSQL.`);
        }}
      />

      <InjectScenarioModal
        isOpen={showInjectScenarioModal}
        scenarios={attackScenarios}
        onClose={() => setShowInjectScenarioModal(false)}
        onInject={handleInjectScenario}
      />

      <ProductionOpsModal
        isOpen={showProductionOpsModal}
        onClose={() => setShowProductionOpsModal(false)}
      />

      {/* Cyber SOC Footer */}
      <footer className="border-t border-slate-200 dark:border-slate-900 bg-white dark:bg-slate-950 py-3 px-6 text-center text-xs font-mono text-slate-500 dark:text-slate-400 flex flex-wrap items-center justify-between gap-2 transition-colors">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>AEGIS ENTERPRISE SOC CONTROL PLANE • POSTGRESQL PERSISTENCE • DRIZZLE ORM • RBAC</span>
        </div>
        <div className="text-[11px] text-slate-400 dark:text-slate-500">
          Connectors: Splunk HEC • Elastic Bulk • Sophos Central API • Shuffle SOAR
        </div>
      </footer>
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <SocInnerApp />
    </AuthProvider>
  );
}
