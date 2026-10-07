import React from 'react';
import {
  ShieldAlert,
  Activity,
  Flame,
  Radio,
  Play,
  RotateCcw,
  Volume2,
  VolumeX,
  Crosshair,
  Server,
  Zap,
  Sun,
  Moon,
} from 'lucide-react';
import { SecurityAlert } from '../types/soc.ts';

interface HeaderProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  alerts: SecurityAlert[];
  eps: number;
  isStreaming: boolean;
  setIsStreaming: React.Dispatch<React.SetStateAction<boolean>>;
  soundEnabled: boolean;
  setSoundEnabled: React.Dispatch<React.SetStateAction<boolean>>;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
  onOpenInjectScenario: () => void;
  onResetSoc: () => void;
  onQuickHunt: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeTab,
  setActiveTab,
  alerts,
  eps,
  isStreaming,
  setIsStreaming,
  soundEnabled,
  setSoundEnabled,
  theme,
  onToggleTheme,
  onOpenInjectScenario,
  onResetSoc,
  onQuickHunt,
}) => {
  const criticalCount = alerts.filter((a) => a.severity === 'critical' && a.status !== 'remediated').length;
  const highCount = alerts.filter((a) => a.severity === 'high' && a.status !== 'remediated').length;

  const defconLevel = criticalCount > 0 ? 1 : highCount > 0 ? 2 : 3;

  return (
    <header className="border-b border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-slate-950/90 backdrop-blur sticky top-0 z-40 transition-colors duration-200">
      {/* Top Bar: Identity & Real-Time Cyber Metrics */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 py-2.5 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-cyan-500/20 via-blue-600/30 to-purple-600/30 border border-cyan-500/40 flex items-center justify-center text-cyan-600 dark:text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.25)]">
              <ShieldAlert className="w-6 h-6 animate-pulse text-cyan-600 dark:text-cyan-400" />
            </div>
            <div className="absolute -bottom-1 -right-1 w-3.5 h-3.5 rounded-full bg-emerald-500 border-2 border-white dark:border-slate-950 flex items-center justify-center">
              <span className="w-1.5 h-1.5 rounded-full bg-white animate-ping" />
            </div>
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-lg font-bold tracking-wider font-['Rajdhani'] text-slate-900 dark:text-slate-100 uppercase">
                AEGIS<span className="text-cyan-600 dark:text-cyan-400">SOC</span>
              </h1>
              <span className="text-[10px] px-1.5 py-0.5 rounded font-mono font-semibold bg-cyan-100 dark:bg-cyan-950/80 text-cyan-800 dark:text-cyan-300 border border-cyan-300 dark:border-cyan-700/50">
                v4.8 ENTERPRISE
              </span>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 font-mono flex items-center gap-2">
              <span>AI-Augmented XDR • SIEM • SOAR Defense Platform</span>
            </p>
          </div>
        </div>

        {/* Center: Live SOC Vitals */}
        <div className="hidden lg:flex items-center gap-5 text-xs font-mono">
          {/* DEFCON Status */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-100 dark:bg-slate-900/90 border border-slate-300 dark:border-slate-800">
            <Flame
              className={`w-4 h-4 ${
                defconLevel === 1
                  ? 'text-red-500 animate-bounce'
                  : defconLevel === 2
                  ? 'text-amber-500'
                  : 'text-emerald-500 dark:text-emerald-400'
              }`}
            />
            <span className="text-slate-500 dark:text-slate-400">THREAT STATE:</span>
            <span
              className={`font-bold uppercase ${
                defconLevel === 1
                  ? 'text-red-600 dark:text-red-400'
                  : defconLevel === 2
                  ? 'text-amber-600 dark:text-amber-400'
                  : 'text-emerald-600 dark:text-emerald-400'
              }`}
            >
              DEFCON {defconLevel} {defconLevel === 1 ? '(ACTIVE ATTACK)' : defconLevel === 2 ? '(ELEVATED)' : '(GUARDED)'}
            </span>
          </div>

          {/* Ingestion EPS */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-100 dark:bg-slate-900/90 border border-slate-300 dark:border-slate-800">
            <Activity className="w-4 h-4 text-cyan-600 dark:text-cyan-400" />
            <span className="text-slate-500 dark:text-slate-400">INGESTION:</span>
            <span className="text-cyan-700 dark:text-cyan-300 font-bold">{eps} EPS</span>
            <span className="text-[10px] text-slate-400 dark:text-slate-500">(Splunk/Elastic)</span>
          </div>

          {/* Open Alerts Tally */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-100 dark:bg-slate-900/90 border border-slate-300 dark:border-slate-800">
            <span className="text-slate-500 dark:text-slate-400">ACTIVE INCIDENTS:</span>
            <span className="px-1.5 py-0.2 rounded bg-red-100 dark:bg-red-950 text-red-700 dark:text-red-400 border border-red-300 dark:border-red-800/60 font-bold">
              {criticalCount} CRIT
            </span>
            <span className="px-1.5 py-0.2 rounded bg-amber-100 dark:bg-amber-950 text-amber-700 dark:text-amber-400 border border-amber-300 dark:border-amber-800/60 font-bold">
              {highCount} HIGH
            </span>
          </div>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2">
          {/* Dark / Light Theme Toggle Button */}
          <button
            onClick={onToggleTheme}
            title={theme === 'dark' ? 'Switch to Light Theme' : 'Switch to Dark Theme'}
            className="p-2 rounded border border-slate-300 dark:border-slate-800 bg-slate-100 dark:bg-slate-900 text-slate-700 dark:text-slate-300 hover:text-slate-900 dark:hover:text-slate-100 hover:bg-slate-200 dark:hover:bg-slate-800 transition cursor-pointer flex items-center gap-1.5"
            aria-label="Toggle Dark and Light theme"
          >
            {theme === 'dark' ? (
              <>
                <Sun className="w-4 h-4 text-amber-400 animate-spin-slow" />
                <span className="hidden sm:inline text-xs font-mono font-semibold text-amber-400">LIGHT</span>
              </>
            ) : (
              <>
                <Moon className="w-4 h-4 text-indigo-600" />
                <span className="hidden sm:inline text-xs font-mono font-semibold text-indigo-700">DARK</span>
              </>
            )}
          </button>

          {/* Stream pause/resume */}
          <button
            onClick={() => setIsStreaming((prev) => !prev)}
            title={isStreaming ? 'Pause live ingestion feed' : 'Resume live ingestion feed'}
            className={`p-2 rounded border text-xs font-mono flex items-center gap-1.5 transition ${
              isStreaming
                ? 'bg-slate-100 dark:bg-slate-900 text-emerald-600 dark:text-emerald-400 border-emerald-300 dark:border-emerald-500/40 hover:bg-slate-200 dark:hover:bg-slate-800'
                : 'bg-amber-100 dark:bg-amber-950/40 text-amber-700 dark:text-amber-300 border-amber-300 dark:border-amber-600/50 hover:bg-amber-200 dark:hover:bg-amber-900/40'
            }`}
          >
            <Radio className={`w-3.5 h-3.5 ${isStreaming ? 'animate-pulse text-emerald-500 dark:text-emerald-400' : 'text-amber-500 dark:text-amber-400'}`} />
            <span className="hidden sm:inline">{isStreaming ? 'LIVE FEED' : 'PAUSED'}</span>
          </button>

          {/* Audio toggle */}
          <button
            onClick={() => setSoundEnabled((prev) => !prev)}
            title={soundEnabled ? 'Mute SOC acoustic alerts' : 'Enable acoustic alerts'}
            className="p-2 rounded border border-slate-300 dark:border-slate-800 bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 transition"
          >
            {soundEnabled ? <Volume2 className="w-4 h-4 text-cyan-600 dark:text-cyan-400" /> : <VolumeX className="w-4 h-4" />}
          </button>

          {/* Attack Simulator Injection */}
          <button
            onClick={onOpenInjectScenario}
            className="px-3 py-1.5 rounded bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-mono text-xs font-semibold flex items-center gap-1.5 shadow-[0_0_12px_rgba(225,29,72,0.35)] transition cursor-pointer"
          >
            <Zap className="w-3.5 h-3.5" />
            <span>INJECT ATTACK</span>
          </button>

          {/* Reset environment */}
          <button
            onClick={onResetSoc}
            title="Reset simulated SOC state"
            className="p-2 rounded border border-slate-300 dark:border-slate-800 bg-slate-100 dark:bg-slate-900 text-slate-600 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200 hover:bg-slate-200 dark:hover:bg-slate-800 transition"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Navigation Sub-bar */}
      <div className="max-w-7xl mx-auto px-4 sm:px-6 flex overflow-x-auto gap-1 border-t border-slate-200 dark:border-slate-900 scrollbar-none">
        {[
          { id: 'siem', label: '1. SIEM & Log Ingestion', sub: 'Splunk & Elastic Pipeline' },
          { id: 'ai-detection', label: '2. AI Anomaly & Threat Intel', sub: 'LogAI • Alkido • OTX' },
          { id: 'threat-hunting', label: '3. Threat Hunting & IOCs', sub: 'Pivoting & Attack Graph' },
          { id: 'xdr-endpoint', label: 'XDR Endpoint Defense', sub: 'Sophos Behavioral EDR' },
          { id: 'mitre-d3fend', label: '4. MITRE & D3FEND Gap Analysis', sub: 'Tactical Matrix Mapping' },
          { id: 'soar-playbooks', label: '5. SOAR Playbooks', sub: 'Shuffle Automated Response' },
        ].map((tab) => {
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`py-2.5 px-3.5 border-b-2 text-left whitespace-nowrap transition cursor-pointer flex flex-col ${
                isActive
                  ? 'border-cyan-500 dark:border-cyan-400 text-cyan-700 dark:text-cyan-300 bg-cyan-50/70 dark:bg-cyan-950/20'
                  : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-800 dark:hover:text-slate-200 hover:bg-slate-100/70 dark:hover:bg-slate-900/40'
              }`}
            >
              <span className="text-xs font-semibold font-mono tracking-wide">{tab.label}</span>
              <span className="text-[10px] text-slate-400 dark:text-slate-500 font-mono tracking-tight">{tab.sub}</span>
            </button>
          );
        })}
      </div>
    </header>
  );
};

