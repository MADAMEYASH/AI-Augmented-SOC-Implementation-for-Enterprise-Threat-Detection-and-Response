import React, { useState } from 'react';
import {
  Flame,
  Zap,
  ShieldAlert,
  ArrowRight,
  Server,
  Terminal,
  Activity,
  Layers,
  Check,
} from 'lucide-react';
import { AttackScenario } from '../types/soc.ts';
import { ATTACK_SCENARIOS } from '../data/mockData.ts';

interface InjectScenarioModalProps {
  isOpen: boolean;
  onClose: () => void;
  onInject: (scenario: AttackScenario) => void;
}

export const InjectScenarioModal: React.FC<InjectScenarioModalProps> = ({
  isOpen,
  onClose,
  onInject,
}) => {
  if (!isOpen) return null;

  const [selectedScenario, setSelectedScenario] = useState<AttackScenario>(
    ATTACK_SCENARIOS[0]
  );
  const [isInjecting, setIsInjecting] = useState(false);

  const handleExecuteInjection = () => {
    setIsInjecting(true);
    setTimeout(() => {
      onInject(selectedScenario);
      setIsInjecting(false);
      onClose();
    }, 600);
  };

  return (
    <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-sm z-50 flex items-center justify-center p-4 font-mono">
      <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-3xl w-full p-5 space-y-4 shadow-2xl text-xs max-h-[90vh] overflow-y-auto scrollbar-thin">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-slate-800 pb-2">
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-red-500 animate-pulse" />
            <h3 className="font-bold text-slate-100 text-sm">
              REAL-WORLD ENTERPRISE ATTACK SCENARIO SIMULATOR
            </h3>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200">
            ✕
          </button>
        </div>

        <p className="text-slate-400 text-xs">
          Select a realistic enterprise cyber intrusion scenario to simulate. Injecting will flood the SIEM with multi-stage telemetry, trigger LogAI &amp; Alkido anomaly detection, alert Sophos XDR, and light up the MITRE ATT&amp;CK matrix.
        </p>

        {/* Scenario Selection Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {ATTACK_SCENARIOS.map((sc) => {
            const isSelected = selectedScenario.id === sc.id;

            return (
              <div
                key={sc.id}
                onClick={() => setSelectedScenario(sc)}
                className={`p-3 rounded-lg border cursor-pointer transition space-y-2 ${
                  isSelected
                    ? 'bg-red-950/40 border-red-500 ring-1 ring-red-500'
                    : 'bg-slate-950 border-slate-800 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-[10px] px-1.5 py-0.2 rounded font-bold uppercase bg-red-950 text-red-300 border border-red-800">
                    {sc.severity}
                  </span>
                  <Flame className="w-4 h-4 text-red-500" />
                </div>
                <div className="font-bold text-xs text-slate-200">{sc.name}</div>
                <div className="text-[10px] text-slate-400">Actor: {sc.adversary}</div>
              </div>
            );
          })}
        </div>

        {/* Selected Scenario Kill Chain Breakdown */}
        <div className="p-4 rounded-lg bg-slate-950 border border-slate-850 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-900 pb-2">
            <div>
              <span className="font-bold text-slate-100 text-xs">{selectedScenario.name}</span>
              <p className="text-[11px] text-slate-400 mt-0.5">{selectedScenario.description}</p>
            </div>
          </div>

          <div className="space-y-2">
            <span className="text-[10px] text-slate-400 uppercase tracking-wider">
              SIMULATED KILL CHAIN STAGES:
            </span>

            <div className="space-y-2">
              {selectedScenario.attackChainSteps.map((step, idx) => (
                <div
                  key={idx}
                  className="p-2.5 rounded bg-slate-900/80 border border-slate-800 flex items-center justify-between gap-2"
                >
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-slate-800 text-cyan-300 flex items-center justify-center font-bold text-[10px]">
                      {idx + 1}
                    </span>
                    <div>
                      <div className="text-xs font-semibold text-slate-200">
                        {step.stage} • <span className="text-cyan-400">{step.technique}</span>
                      </div>
                      <div className="text-[11px] text-slate-400">{step.action}</div>
                    </div>
                  </div>
                  <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 whitespace-nowrap">
                    {step.detectionSource}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="flex items-center justify-between pt-2 border-t border-slate-800">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded border border-slate-700 text-slate-400 hover:text-slate-200"
          >
            Cancel
          </button>

          <button
            onClick={handleExecuteInjection}
            disabled={isInjecting}
            className="px-5 py-2 rounded bg-gradient-to-r from-red-600 via-rose-600 to-red-700 hover:from-red-500 hover:to-rose-500 text-white font-bold text-xs flex items-center gap-2 shadow-[0_0_15px_rgba(225,29,72,0.4)] transition cursor-pointer"
          >
            <Zap className="w-4 h-4" />
            <span>{isInjecting ? 'Injecting Telemetry...' : 'INJECT LIVE ATTACK INTO SOC'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
