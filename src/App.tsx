import React, { useState, useEffect, useRef } from 'react';
import { Header } from './components/Header.tsx';
import { SiemLogsView } from './components/SiemLogsView.tsx';
import { AiAnomalyEngineView } from './components/AiAnomalyEngineView.tsx';
import { ThreatHuntingView } from './components/ThreatHuntingView.tsx';
import { XdrEndpointView } from './components/XdrEndpointView.tsx';
import { MitreMatrixView } from './components/MitreMatrixView.tsx';
import { SoarPlaybooksView } from './components/SoarPlaybooksView.tsx';
import { AlertDetailModal } from './components/AlertDetailModal.tsx';
import { InjectScenarioModal } from './components/InjectScenarioModal.tsx';

import {
  INITIAL_LOGS,
  INITIAL_ALERTS,
  INITIAL_THREAT_INTEL,
  INITIAL_ENDPOINTS,
  INITIAL_MITRE_TECHNIQUES,
  INITIAL_PLAYBOOKS,
  INITIAL_UEBA_PROFILES,
} from './data/mockData.ts';

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

export default function App() {
  const [activeTab, setActiveTab] = useState<string>('siem');
  const [logs, setLogs] = useState<SecurityLog[]>(INITIAL_LOGS);
  const [alerts, setAlerts] = useState<SecurityAlert[]>(INITIAL_ALERTS);
  const [threatIntel, setThreatIntel] = useState<ThreatIntelligenceItem[]>(INITIAL_THREAT_INTEL);
  const [endpoints, setEndpoints] = useState<EndpointHost[]>(INITIAL_ENDPOINTS);
  const [techniques, setTechniques] = useState<MitreTechnique[]>(INITIAL_MITRE_TECHNIQUES);
  const [playbooks, setPlaybooks] = useState<SoarPlaybook[]>(INITIAL_PLAYBOOKS);
  const [uebaProfiles, setUebaProfiles] = useState<UebaProfile[]>(INITIAL_UEBA_PROFILES);

  // Live telemetry state
  const [eps, setEps] = useState<number>(94);
  const [isStreaming, setIsStreaming] = useState<boolean>(true);
  const [soundEnabled, setSoundEnabled] = useState<boolean>(true);

  // Modals & Navigation pivots
  const [selectedAlertForDetail, setSelectedAlertForDetail] = useState<SecurityAlert | null>(null);
  const [showInjectScenarioModal, setShowInjectScenarioModal] = useState<boolean>(false);
  const [huntingPivotTerm, setHuntingPivotTerm] = useState<string>('185.220.101.5');
  const [bannerNotice, setBannerNotice] = useState<string | null>(null);

  // Simulated live EPS fluctuation & periodic benign log arrival
  useEffect(() => {
    if (!isStreaming) return;
    const interval = setInterval(() => {
      // Randomly fluctuate EPS between 80 and 125
      const newEps = Math.floor(82 + Math.random() * 42);
      setEps(newEps);
    }, 2000);

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

  // Host isolation toggle handler
  const handleToggleIsolation = (hostname: string) => {
    setEndpoints((prev) =>
      prev.map((h) => {
        if (h.hostname === hostname) {
          const nextStatus = h.status === 'isolated' ? 'online' : 'isolated';
          return {
            ...h,
            status: nextStatus,
            riskScore: nextStatus === 'isolated' ? Math.max(10, h.riskScore - 40) : h.riskScore,
          };
        }
        return h;
      })
    );

    // Ingest isolation log into SIEM
    const hostObj = endpoints.find((h) => h.hostname === hostname);
    const isNowIsolated = hostObj?.status !== 'isolated';
    const auditLog: SecurityLog = {
      id: `log-iso-${Date.now()}`,
      timestamp: new Date().toISOString().replace('T', ' ').slice(0, 23),
      sourceType: 'Sophos:XDR',
      host: hostname,
      user: 'SYSTEM',
      message: isNowIsolated
        ? `Sophos Central: Network isolation enforced on ${hostname}. Host disconnected from LAN.`
        : `Sophos Central: Network isolation removed on ${hostname}. Host rejoined to subnet.`,
      severity: isNowIsolated ? 'high' : 'info',
      raw: `{"source":"Sophos XDR","action":"${isNowIsolated ? 'isolate_endpoint' : 'rejoin_network'}","target":"${hostname}","status":"success"}`,
      clusterId: 'CLUSTER_CONTAINMENT',
      anomalyScore: 10,
    };
    setLogs((prev) => [auditLog, ...prev]);

    if (soundEnabled) playAlertTone('warning');
    setBannerNotice(`Sophos XDR: ${isNowIsolated ? 'Isolated' : 'Rejoined'} host ${hostname} successfully.`);
  };

  // Handle Playbook execution from any view
  const handleExecutePlaybookFromAlert = (playbookId: string) => {
    setActiveTab('soar-playbooks');
    setBannerNotice(`Shuffle SOAR: Playbook ${playbookId} triggered for automated containment.`);
    if (soundEnabled) playAlertTone('warning');
  };

  // Attack Scenario injection
  const handleInjectScenario = (scenario: AttackScenario) => {
    if (soundEnabled) playAlertTone('inject');

    const now = new Date().toISOString().replace('T', ' ').slice(0, 23);

    // Build correlated log batch
    const injectedLogs: SecurityLog[] = [
      {
        id: `log-inj-${Date.now()}-1`,
        timestamp: now,
        sourceType: 'WinEventLog:Security',
        host: 'WS-FINANCE-07',
        user: 'CORP\\m.jenkins',
        eventId: 4688,
        processName: 'powershell.exe',
        commandLine: 'powershell.exe -w hidden -enc JAB3AGUAYgA9AE4AZQB3AC0ATwBiAGoAZQBjAHQA...',
        message: `[ATTACK INJECTION] ${scenario.name}: Obfuscated PowerShell stager executed`,
        severity: 'critical',
        raw: `<Event><System><EventID>4688</EventID><Computer>WS-FINANCE-07</Computer></System><EventData><Data Name="CommandLine">powershell.exe -w hidden -enc JAB3...</Data></EventData></Event>`,
        entropy: 6.95,
        clusterId: 'CLUSTER_INJECTED_ATTACK',
        anomalyScore: 99,
      },
      {
        id: `log-inj-${Date.now()}-2`,
        timestamp: now,
        sourceType: 'Sophos:XDR',
        host: 'WS-FINANCE-07',
        user: 'CORP\\m.jenkins',
        message: `[ATTACK INJECTION] Sophos Intercept X: CryptoGuard behavioral heuristic triggered. Mass file rename detected.`,
        severity: 'critical',
        raw: `{"source":"Sophos XDR","threat":"Mal/Ransom-Gen","action":"blocked","target":"WS-FINANCE-07"}`,
        entropy: 7.10,
        clusterId: 'CLUSTER_INJECTED_ATTACK',
        anomalyScore: 99,
      },
      {
        id: `log-inj-${Date.now()}-3`,
        timestamp: now,
        sourceType: 'Network:Zeek',
        host: 'GATEWAY-CORP-FW',
        user: 'CORP\\m.jenkins',
        srcIp: '192.168.10.45',
        destIp: '185.220.101.5',
        destPort: 8443,
        message: `[ATTACK INJECTION] Network Beacon: High-frequency encrypted TLS heartbeat to known adversary C2`,
        severity: 'high',
        raw: `id.orig_h=192.168.10.45 id.resp_h=185.220.101.5 dest_port=8443 ja3=CobaltStrike-Profile`,
        entropy: 6.80,
        clusterId: 'CLUSTER_INJECTED_ATTACK',
        anomalyScore: 94,
      },
    ];

    setLogs((prev) => [...injectedLogs, ...prev]);

    // Create high-severity alert
    const newAlert: SecurityAlert = {
      id: `ALT-${Date.now().toString().slice(-4)}`,
      title: `${scenario.name} Detected`,
      description: `LogAI sequence anomaly and Sophos XDR flagged full kill-chain deployment by ${scenario.adversary}. Immediate containment advised.`,
      severity: scenario.severity,
      status: 'new',
      detectedAt: now,
      source: 'LogAI',
      endpoint: 'WS-FINANCE-07',
      user: 'CORP\\m.jenkins',
      mitreTactic: 'Impact / Execution',
      mitreTechniqueId: scenario.mitreCoverage[0] || 'T1486',
      mitreTechniqueName: 'Data Encrypted for Ransom',
      d3fendCountermeasure: 'D3-FRT (File Rollback) & D3-EIA (Execution Isolation)',
      confidenceScore: 99,
      relatedLogIds: injectedLogs.map((l) => l.id),
      iocs: [
        { type: 'ip', value: '185.220.101.5', threatScore: 98 },
        { type: 'sha256', value: '8f4c2e6b91a7d3f048e5b6c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2', threatScore: 99 },
      ],
      playbookId: scenario.recommendedPlaybookId,
    };

    setAlerts((prev) => [newAlert, ...prev]);

    // Mark host as compromised
    setEndpoints((prev) =>
      prev.map((h) =>
        h.hostname === 'WS-FINANCE-07'
          ? { ...h, status: 'compromised', riskScore: 99, activeAlertsCount: h.activeAlertsCount + 1 }
          : h
      )
    );

    // Light up MITRE techniques
    setTechniques((prev) =>
      prev.map((t) => {
        if (scenario.mitreCoverage.includes(t.id)) {
          return {
            ...t,
            detectedCount: t.detectedCount + 1,
            gapStatus: t.gapStatus === 'uncovered_gap' ? 'uncovered_gap' : 'active_threat_covered',
          };
        }
        return t;
      })
    );

    setBannerNotice(`🚨 SIMULATION ACTIVE: Injected "${scenario.name}". SIEM and XDR alerts created.`);
    setSelectedAlertForDetail(newAlert);
  };

  // Reset SOC state
  const handleResetSoc = () => {
    setLogs(INITIAL_LOGS);
    setAlerts(INITIAL_ALERTS);
    setEndpoints(INITIAL_ENDPOINTS);
    setTechniques(INITIAL_MITRE_TECHNIQUES);
    setPlaybooks(INITIAL_PLAYBOOKS);
    setBannerNotice('SOC state reset to baseline enterprise environment.');
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans">
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
        onOpenInjectScenario={() => setShowInjectScenarioModal(true)}
        onResetSoc={handleResetSoc}
        onQuickHunt={() => setActiveTab('threat-hunting')}
      />

      {/* Real-time Notification Banner */}
      {bannerNotice && (
        <div className="bg-gradient-to-r from-cyan-950 via-slate-900 to-cyan-950 border-b border-cyan-700/60 py-2 px-4 text-center font-mono text-xs text-cyan-200 flex items-center justify-center gap-2 shadow-lg animate-fade-in">
          <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping" />
          <span>{bannerNotice}</span>
          <button
            onClick={() => setBannerNotice(null)}
            className="text-slate-400 hover:text-slate-200 ml-3 text-xs"
          >
            ✕
          </button>
        </div>
      )}

      {/* Main Operational Views */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6">
        {activeTab === 'siem' && (
          <SiemLogsView
            logs={logs}
            onPivotToHunting={handlePivotToHunting}
            onInjectCustomLog={(newLog) => setLogs((prev) => [newLog, ...prev])}
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
            onDeployCountermeasure={(techId) => {
              setBannerNotice(`MITRE D3FEND: Automated defensive countermeasure deployed for technique ${techId}.`);
              if (soundEnabled) playAlertTone('success');
            }}
            onPivotToHunting={handlePivotToHunting}
          />
        )}

        {activeTab === 'soar-playbooks' && (
          <SoarPlaybooksView
            playbooks={playbooks}
            onPlaybookComplete={(pbId) => {
              setBannerNotice(`Shuffle SOAR: Playbook ${pbId} execution finished with 100% success.`);
              if (soundEnabled) playAlertTone('success');
              // Mark corresponding alert as remediated
              setAlerts((prev) =>
                prev.map((a) => (a.playbookId === pbId ? { ...a, status: 'remediated' } : a))
              );
            }}
          />
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
          setAlerts((prev) =>
            prev.map((a) => (a.id === alertId ? { ...a, status: 'remediated' } : a))
          );
          setBannerNotice(`Alert ${alertId} marked as remediated.`);
        }}
      />

      <InjectScenarioModal
        isOpen={showInjectScenarioModal}
        onClose={() => setShowInjectScenarioModal(false)}
        onInject={handleInjectScenario}
      />

      {/* Cyber SOC Footer */}
      <footer className="border-t border-slate-900 bg-slate-950 py-3 px-6 text-center text-xs font-mono text-slate-500 flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
          <span>AEGIS MINI-SOC DEFENSE SYSTEM • SPLUNK • ELASTIC • LOGAI • ALKIDO • SOPHOS XDR • SHUFFLE SOAR</span>
        </div>
        <div className="text-[11px] text-slate-400">
          Framework Coverage: MITRE ATT&amp;CK Enterprise v14 &amp; MITRE D3FEND
        </div>
      </footer>
    </div>
  );
}
