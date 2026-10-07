import React, { useState } from 'react';
import {
  Zap,
  Play,
  RotateCcw,
  Sparkles,
  CheckCircle2,
  Clock,
  Terminal,
  Activity,
  Layers,
  Server,
  ShieldAlert,
  ArrowRight,
  Plus,
} from 'lucide-react';
import { PlaybookStep, SoarPlaybook } from '../types/soc.ts';
import { generatePlaybookWithGemini } from '../services/api.ts';

interface SoarPlaybooksViewProps {
  playbooks: SoarPlaybook[];
  onPlaybookComplete?: (playbookId: string) => void;
}

export const SoarPlaybooksView: React.FC<SoarPlaybooksViewProps> = ({
  playbooks,
  onPlaybookComplete,
}) => {
  const [selectedPlaybook, setSelectedPlaybook] = useState<SoarPlaybook>(playbooks[0]);
  const [isRunning, setIsRunning] = useState(false);
  const [activeStepIndex, setActiveStepIndex] = useState<number>(-1);
  const [executionLogs, setExecutionLogs] = useState<
    { timestamp: string; stepName: string; system: string; payload: string; status: string }[]
  >([]);

  // AI Playbook Generation state
  const [showAiModal, setShowAiModal] = useState(false);
  const [customScenario, setCustomScenario] = useState('');
  const [isGenerating, setIsGenerating] = useState(false);
  const [allPlaybooks, setAllPlaybooks] = useState<SoarPlaybook[]>(playbooks);

  const handleExecutePlaybook = async () => {
    if (isRunning) return;
    setIsRunning(true);
    setActiveStepIndex(0);

    const steps = selectedPlaybook.steps;
    for (let i = 0; i < steps.length; i++) {
      setActiveStepIndex(i);
      const step = steps[i];

      // Simulated execution delay
      await new Promise((resolve) => setTimeout(resolve, 800));

      const payload = JSON.stringify(
        {
          action: step.action,
          target: step.targetSystem,
          executionId: `SHUFFLE-EXEC-${Date.now().toString().slice(-6)}`,
          status: 'SUCCESS',
          code: 200,
          response: `Policy successfully enforced on ${step.targetSystem}. Remediation verified.`,
        },
        null,
        2
      );

      setExecutionLogs((prev) => [
        {
          timestamp: new Date().toLocaleTimeString(),
          stepName: step.name,
          system: step.targetSystem,
          payload,
          status: 'SUCCESS',
        },
        ...prev,
      ]);
    }

    setIsRunning(false);
    setActiveStepIndex(steps.length);
    if (onPlaybookComplete) {
      onPlaybookComplete(selectedPlaybook.id);
    }
  };

  const handleReset = () => {
    setIsRunning(false);
    setActiveStepIndex(-1);
  };

  const handleGenerateAiPlaybook = async () => {
    if (!customScenario.trim()) return;
    setIsGenerating(true);
    try {
      const generated = await generatePlaybookWithGemini(customScenario);
      const newPb: SoarPlaybook = {
        id: `PB-AI-${Date.now()}`,
        name: generated.playbookName,
        description: generated.description,
        triggerEvent: generated.triggers.join(' | ') || 'Custom Threat Trigger',
        targetThreat: customScenario,
        executionCount: 0,
        avgDurationSec: 3.5,
        status: 'idle',
        steps: generated.steps.map((s, idx) => ({
          id: `step-${idx + 1}`,
          name: s.action,
          action: s.action.toLowerCase().replace(/\s+/g, '_'),
          targetSystem: (s.system as any) || 'Sophos XDR',
          description: s.details,
          status: 'idle',
        })),
      };

      setAllPlaybooks((prev) => [newPb, ...prev]);
      setSelectedPlaybook(newPb);
      setShowAiModal(false);
      setCustomScenario('');
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <div className="space-y-4 font-mono">
      {/* SOAR Header & Execution Strip */}
      <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              SHUFFLE SOAR AUTOMATED INCIDENT RESPONSE ENGINE
            </h2>
          </div>
          <p className="text-[10px] text-slate-400 mt-0.5">
            Cross-System Playbook Orchestration: Sophos XDR, Palo Alto Firewalls, Active Directory, AWS IAM, &amp; SIEM
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAiModal(true)}
            className="px-3 py-1.5 rounded bg-purple-950/80 hover:bg-purple-900 text-purple-300 border border-purple-700/60 text-xs font-bold flex items-center gap-1.5 transition cursor-pointer"
          >
            <Sparkles className="w-3.5 h-3.5" />
            <span>AI Playbook Architect</span>
          </button>

          <button
            onClick={handleExecutePlaybook}
            disabled={isRunning}
            className="px-4 py-1.5 rounded bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 disabled:opacity-50 text-slate-950 font-bold text-xs flex items-center gap-1.5 shadow-[0_0_12px_rgba(6,182,212,0.4)] transition cursor-pointer"
          >
            <Play className={`w-3.5 h-3.5 fill-current ${isRunning ? 'animate-spin' : ''}`} />
            <span>{isRunning ? 'EXECUTING WORKFLOW...' : 'EXECUTE PLAYBOOK'}</span>
          </button>

          <button
            onClick={handleReset}
            title="Reset execution state"
            className="p-1.5 rounded bg-slate-800 text-slate-400 hover:text-slate-200"
          >
            <RotateCcw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Grid: Playbook Selector & Interactive Visual Canvas */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left: Playbooks Catalogue (1 Col) */}
        <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
          <div className="flex items-center justify-between border-b border-slate-800 pb-2">
            <span className="text-xs font-bold text-slate-200">
              RESPONSE PLAYBOOKS ({allPlaybooks.length})
            </span>
            <span className="text-[10px] text-slate-400">Shuffle Orchestrator</span>
          </div>

          <div className="space-y-2">
            {allPlaybooks.map((pb) => {
              const isSelected = selectedPlaybook.id === pb.id;

              return (
                <div
                  key={pb.id}
                  onClick={() => {
                    setSelectedPlaybook(pb);
                    handleReset();
                  }}
                  className={`p-3 rounded border cursor-pointer transition space-y-1.5 ${
                    isSelected
                      ? 'bg-cyan-950/40 border-cyan-400 ring-1 ring-cyan-400/40'
                      : 'bg-slate-950 border-slate-850 hover:bg-slate-900'
                  }`}
                >
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="text-xs font-bold text-slate-200">{pb.name}</div>
                      <div className="text-[10px] text-cyan-400 mt-0.5">{pb.id}</div>
                    </div>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-300">
                      {pb.steps.length} Steps
                    </span>
                  </div>

                  <p className="text-[11px] text-slate-400 line-clamp-2">{pb.description}</p>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-slate-900">
                    <span>Avg Duration: {pb.avgDurationSec}s</span>
                    <span>Ran {pb.executionCount}x</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Right: Visual Node Workflow Canvas (2 Cols) */}
        <div className="lg:col-span-2 p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-4">
          {/* Header of selected playbook */}
          <div className="border-b border-slate-800 pb-3 space-y-1">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-bold text-slate-100">{selectedPlaybook.name}</h3>
              <span className="text-xs text-slate-400">Trigger: {selectedPlaybook.triggerEvent}</span>
            </div>
            <p className="text-xs text-slate-400">{selectedPlaybook.description}</p>
          </div>

          {/* Interactive Visual Node Graph */}
          <div className="p-4 rounded-lg bg-slate-950 border border-slate-850 space-y-3">
            <div className="text-[10px] text-slate-400 uppercase tracking-wider">
              SHUFFLE ORCHESTRATION PIPELINE
            </div>

            <div className="space-y-3">
              {/* Trigger Node */}
              <div className="p-2.5 rounded bg-blue-950/40 border border-blue-800/80 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-6 h-6 rounded bg-blue-900 flex items-center justify-center text-blue-300 font-bold text-xs">
                    ⚡
                  </div>
                  <div>
                    <div className="text-xs font-bold text-blue-200">TRIGGER: Webhook Event</div>
                    <div className="text-[10px] text-slate-400">{selectedPlaybook.triggerEvent}</div>
                  </div>
                </div>
                <span className="text-[10px] text-emerald-400 font-bold">ARMED</span>
              </div>

              {/* Steps Flow */}
              {selectedPlaybook.steps.map((step, idx) => {
                const isStepActive = isRunning && activeStepIndex === idx;
                const isStepFinished = activeStepIndex > idx;

                return (
                  <div key={step.id} className="relative">
                    {/* Connecting line */}
                    <div className="w-0.5 h-3 bg-slate-800 ml-4 mb-1" />

                    <div
                      className={`p-3 rounded border transition flex flex-wrap items-center justify-between gap-3 ${
                        isStepActive
                          ? 'bg-cyan-950/60 border-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.3)] ring-1 ring-cyan-400'
                          : isStepFinished
                          ? 'bg-emerald-950/30 border-emerald-800/80'
                          : 'bg-slate-900/60 border-slate-800'
                      }`}
                    >
                      <div className="flex items-center gap-3">
                        <div
                          className={`w-7 h-7 rounded flex items-center justify-center font-bold text-xs ${
                            isStepFinished
                              ? 'bg-emerald-900 text-emerald-200'
                              : isStepActive
                              ? 'bg-cyan-600 text-slate-950 animate-pulse'
                              : 'bg-slate-800 text-slate-400'
                          }`}
                        >
                          {isStepFinished ? '✓' : idx + 1}
                        </div>

                        <div>
                          <div className="text-xs font-bold text-slate-200 flex items-center gap-2">
                            <span>{step.name}</span>
                            <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-cyan-300">
                              {step.targetSystem}
                            </span>
                          </div>
                          <div className="text-[11px] text-slate-400 mt-0.5">
                            {step.description}
                          </div>
                        </div>
                      </div>

                      <div>
                        {isStepActive && (
                          <span className="text-[10px] font-bold text-cyan-400 animate-pulse">
                            EXECUTING API CALL...
                          </span>
                        )}
                        {isStepFinished && (
                          <span className="text-[10px] font-bold text-emerald-400 flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" />
                            <span>COMPLETED (200 OK)</span>
                          </span>
                        )}
                        {!isStepActive && !isStepFinished && (
                          <span className="text-[10px] text-slate-500">PENDING TRIGGER</span>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Real-Time Execution Audit Log */}
          <div className="space-y-2">
            <span className="text-xs font-bold text-slate-200">
              AUDIT TRAIL &amp; MITIGATION PAYLOAD INSPECTOR
            </span>
            <div className="p-3 rounded bg-slate-950 border border-slate-850 h-44 overflow-y-auto space-y-2 text-xs scrollbar-thin">
              {executionLogs.map((log, i) => (
                <div key={i} className="p-2 rounded bg-slate-900/80 border border-slate-800 space-y-1">
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="text-slate-500">[{log.timestamp}]</span>
                    <span className="text-cyan-300 font-bold">{log.stepName}</span>
                    <span className="text-emerald-400 font-bold">{log.status}</span>
                  </div>
                  <pre className="text-[10px] text-slate-300 font-mono overflow-x-auto whitespace-pre-wrap">
                    {log.payload}
                  </pre>
                </div>
              ))}
              {executionLogs.length === 0 && (
                <div className="py-10 text-center text-slate-600 text-xs">
                  Click "EXECUTE PLAYBOOK" above to trigger automated incident containment and view live API output payloads.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Modal: AI Playbook Architect */}
      {showAiModal && (
        <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full p-5 space-y-4 shadow-2xl text-xs">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <div className="flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-purple-400" />
                <h3 className="font-bold text-slate-100 text-sm">
                  AI SHUFFLE PLAYBOOK ARCHITECT
                </h3>
              </div>
              <button
                onClick={() => setShowAiModal(false)}
                className="text-slate-400 hover:text-slate-200"
              >
                ✕
              </button>
            </div>

            <p className="text-slate-400 text-xs">
              Provide a threat scenario (e.g. "Kerberoasting credential theft on domain controller" or "Kubernetes cluster container breakout"), and Gemini will construct a complete multi-step automated SOAR response workflow.
            </p>

            <textarea
              value={customScenario}
              onChange={(e) => setCustomScenario(e.target.value)}
              placeholder="e.g. Malicious USB device connected to industrial SCADA server dumping PLC configs..."
              className="w-full h-24 p-2.5 bg-slate-950 border border-slate-700 rounded text-slate-200 focus:outline-none focus:border-purple-400 font-mono"
            />

            <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
              <button
                onClick={() => setShowAiModal(false)}
                className="px-3 py-1.5 rounded border border-slate-700 text-slate-400 hover:text-slate-200"
              >
                Cancel
              </button>
              <button
                onClick={handleGenerateAiPlaybook}
                disabled={isGenerating || !customScenario.trim()}
                className="px-4 py-1.5 rounded bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-bold flex items-center gap-1.5"
              >
                <Sparkles className="w-3.5 h-3.5" />
                <span>{isGenerating ? 'Generating Playbook...' : 'Build Playbook'}</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
