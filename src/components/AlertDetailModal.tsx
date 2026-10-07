import React, { useState } from 'react';
import {
  ShieldAlert,
  Sparkles,
  Zap,
  Server,
  User,
  Clock,
  ExternalLink,
  Flame,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
} from 'lucide-react';
import { SecurityAlert, SecurityLog } from '../types/soc.ts';
import { analyzeThreatWithGemini, ThreatAnalysisResponse } from '../services/api.ts';

interface AlertDetailModalProps {
  alert: SecurityAlert | null;
  logs: SecurityLog[];
  onClose: () => void;
  onExecutePlaybook: (playbookId: string) => void;
  onPivotToHunting: (indicator: string) => void;
  onMarkRemediated: (alertId: string) => void;
}

export const AlertDetailModal: React.FC<AlertDetailModalProps> = ({
  alert,
  logs,
  onClose,
  onExecutePlaybook,
  onPivotToHunting,
  onMarkRemediated,
}) => {
  if (!alert) return null;

  const [aiAnalysis, setAiAnalysis] = useState<ThreatAnalysisResponse | null>(
    alert.aiAnalysis
      ? {
          executiveSummary: alert.aiAnalysis.summary,
          confidenceScore: alert.confidenceScore,
          threatActor: alert.aiAnalysis.threatActor,
          mitreTechniques: [
            { id: alert.mitreTechniqueId, name: alert.mitreTechniqueName, tactic: alert.mitreTactic },
          ],
          rootCause: alert.aiAnalysis.rootCause,
          recommendedActions: alert.aiAnalysis.recommendations,
          defenseGapNote: alert.d3fendCountermeasure || 'Review D3FEND matrix for unassigned controls.',
        }
      : null
  );

  const [isAnalyzing, setIsAnalyzing] = useState(false);

  const relatedLogs = logs.filter((l) => alert.relatedLogIds.includes(l.id));

  const handleRunAiAnalysis = async () => {
    setIsAnalyzing(true);
    try {
      const result = await analyzeThreatWithGemini(alert, relatedLogs);
      setAiAnalysis(result);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-slate-950/85 backdrop-blur-sm z-50 flex items-center justify-center p-4 font-mono">
      <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-4xl w-full p-5 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto scrollbar-thin text-xs">
        {/* Header Bar */}
        <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-800 pb-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <span
                className={`text-[10px] px-2 py-0.5 rounded font-bold uppercase ${
                  alert.severity === 'critical'
                    ? 'bg-red-950 text-red-300 border border-red-800'
                    : 'bg-amber-950 text-amber-300 border border-amber-800'
                }`}
              >
                {alert.severity} SEVERITY
              </span>
              <span className="text-slate-400 text-xs">[{alert.id}]</span>
              <span className="text-slate-500">• Detected by {alert.source}</span>
            </div>
            <h3 className="text-base font-bold text-slate-100">{alert.title}</h3>
            <p className="text-slate-300">{alert.description}</p>
          </div>

          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 text-sm px-2 py-1"
          >
            ✕
          </button>
        </div>

        {/* Metadata Strip */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 block">TARGET ENDPOINT</span>
            <span className="font-bold text-cyan-300">{alert.endpoint}</span>
          </div>
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 block">USER CONTEXT</span>
            <span className="font-bold text-slate-200">{alert.user}</span>
          </div>
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 block">MITRE TACTIC</span>
            <span className="font-bold text-purple-300">{alert.mitreTechniqueId}</span>
          </div>
          <div className="p-2.5 rounded bg-slate-950 border border-slate-800">
            <span className="text-[10px] text-slate-400 block">CONFIDENCE</span>
            <span className="font-bold text-emerald-400">{alert.confidenceScore}%</span>
          </div>
        </div>

        {/* Gemini AI Co-Pilot Investigation Section */}
        <div className="p-4 rounded-lg bg-gradient-to-br from-purple-950/30 via-slate-900 to-cyan-950/20 border border-purple-800/60 space-y-3">
          <div className="flex items-center justify-between border-b border-purple-900/50 pb-2">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-purple-400" />
              <span className="font-bold text-slate-100 text-xs">
                TIER-3 AI SOC CO-PILOT ROOT CAUSE & THREAT ANALYSIS
              </span>
            </div>

            <button
              onClick={handleRunAiAnalysis}
              disabled={isAnalyzing}
              className="px-3 py-1 rounded bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white font-bold text-xs flex items-center gap-1.5 transition cursor-pointer"
            >
              <Sparkles className="w-3 h-3" />
              <span>{isAnalyzing ? 'Analyzing Kill Chain...' : 'Re-Run AI Deep Audit'}</span>
            </button>
          </div>

          {aiAnalysis ? (
            <div className="space-y-3">
              <div className="text-slate-200 leading-relaxed bg-slate-950/70 p-3 rounded border border-slate-800">
                <span className="font-bold text-purple-300 block mb-1">EXECUTIVE SUMMARY:</span>
                {aiAnalysis.executiveSummary}
              </div>

              {aiAnalysis.threatActor && (
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-slate-400">ATTRIBUTED THREAT ACTOR:</span>
                  <span className="text-red-400 font-bold px-2 py-0.5 rounded bg-red-950 border border-red-800">
                    {aiAnalysis.threatActor}
                  </span>
                </div>
              )}

              <div className="text-slate-300 bg-slate-950/70 p-3 rounded border border-slate-800">
                <span className="font-bold text-cyan-300 block mb-1">TECHNICAL ROOT CAUSE:</span>
                {aiAnalysis.rootCause}
              </div>

              <div>
                <span className="font-bold text-amber-300 block mb-1">RECOMMENDED ACTIONS:</span>
                <div className="space-y-1">
                  {aiAnalysis.recommendedActions.map((rec, i) => (
                    <div key={i} className="flex items-start gap-1.5 text-slate-300">
                      <span className="text-amber-400 font-bold">{i + 1}.</span>
                      <span>{rec}</span>
                    </div>
                  ))}
                </div>
              </div>

              {aiAnalysis.defenseGapNote && (
                <div className="text-purple-300 text-[11px] bg-purple-950/40 p-2.5 rounded border border-purple-800/80">
                  <span className="font-bold text-purple-400 block mb-0.5">D3FEND DEFENSE NOTE:</span>
                  {aiAnalysis.defenseGapNote}
                </div>
              )}
            </div>
          ) : (
            <div className="py-6 text-center text-slate-400 space-y-2">
              <p>Click "Run AI Deep Audit" to let Gemini 3.8 Flash dissect the root cause and provide instant containment steps.</p>
            </div>
          )}
        </div>

        {/* IOCs Extracted */}
        <div className="space-y-2">
          <span className="font-bold text-slate-200 block">EXTRACTED INDICATORS OF COMPROMISE (IOCs)</span>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {alert.iocs.map((ioc, idx) => (
              <div
                key={idx}
                className="p-2.5 rounded bg-slate-950 border border-slate-850 flex items-center justify-between"
              >
                <div>
                  <span className="text-[10px] px-1 rounded bg-slate-800 text-slate-400 uppercase">
                    {ioc.type}
                  </span>
                  <div className="text-xs font-bold text-slate-200 truncate max-w-[200px] mt-0.5">
                    {ioc.value}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-bold text-red-400">{ioc.threatScore}/100</span>
                  <button
                    onClick={() => onPivotToHunting(ioc.value)}
                    className="text-[10px] px-2 py-1 rounded bg-slate-800 hover:bg-slate-700 text-cyan-300"
                  >
                    Pivot
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Action Buttons */}
        <div className="flex flex-wrap items-center justify-between gap-2 pt-3 border-t border-slate-800">
          <button
            onClick={() => {
              onMarkRemediated(alert.id);
              onClose();
            }}
            className="px-3 py-1.5 rounded border border-slate-700 text-slate-300 hover:text-slate-100"
          >
            Mark as Remediated / False Positive
          </button>

          <div className="flex items-center gap-2">
            {alert.playbookId && (
              <button
                onClick={() => {
                  onExecutePlaybook(alert.playbookId!);
                  onClose();
                }}
                className="px-4 py-1.5 rounded bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold flex items-center gap-1.5 shadow-[0_0_12px_rgba(6,182,212,0.4)]"
              >
                <Zap className="w-3.5 h-3.5 fill-current" />
                <span>Trigger Shuffle Playbook ({alert.playbookId})</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
