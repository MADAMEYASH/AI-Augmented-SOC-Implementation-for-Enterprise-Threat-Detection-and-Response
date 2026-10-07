import React, { useState } from 'react';
import {
  Shield,
  Layers,
  CheckCircle,
  AlertOctagon,
  ArrowRight,
  Sparkles,
  Zap,
  Info,
  Check,
} from 'lucide-react';
import { MitreTechnique } from '../types/soc.ts';

interface MitreMatrixViewProps {
  techniques: MitreTechnique[];
  onDeployCountermeasure: (techniqueId: string) => void;
  onPivotToHunting: (indicator: string) => void;
}

export const MitreMatrixView: React.FC<MitreMatrixViewProps> = ({
  techniques,
  onDeployCountermeasure,
  onPivotToHunting,
}) => {
  const [activeTab, setActiveTab] = useState<'attack' | 'd3fend' | 'gap'>('attack');
  const [selectedTechnique, setSelectedTechnique] = useState<MitreTechnique>(techniques[0]);
  const [deployedSet, setDeployedSet] = useState<Set<string>>(new Set());

  // Tactics list
  const tactics = [
    'Reconnaissance',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Command and Control',
    'Exfiltration',
    'Impact',
  ];

  // Group techniques by tactic
  const groupedByTactic = tactics.reduce<Record<string, MitreTechnique[]>>((acc, tac) => {
    acc[tac] = techniques.filter((t) => t.tacticName === tac);
    return acc;
  }, {});

  // D3FEND categories
  const d3fendCategories = ['Model', 'Harden', 'Detect', 'Isolate', 'Deceive', 'Evict'] as const;

  const groupedByD3fend = d3fendCategories.reduce<Record<string, MitreTechnique[]>>((acc, cat) => {
    acc[cat] = techniques.filter((t) => t.d3fendCategory === cat);
    return acc;
  }, {});

  // Gap analysis calculations
  const totalCount = techniques.length;
  const coveredCount = techniques.filter((t) => t.gapStatus === 'covered' || t.gapStatus === 'active_threat_covered').length + deployedSet.size;
  const coveragePct = Math.round((coveredCount / totalCount) * 100);

  const activeThreatGaps = techniques.filter(
    (t) => t.gapStatus === 'uncovered_gap' && !deployedSet.has(t.id)
  );

  const handleDeploy = (techId: string) => {
    setDeployedSet((prev) => new Set(prev).add(techId));
    onDeployCountermeasure(techId);
  };

  return (
    <div className="space-y-4 font-mono">
      {/* Top Navigation & Coverage Metrics */}
      <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Shield className="w-5 h-5 text-cyan-400" />
            <h2 className="text-sm font-bold text-slate-100">
              MITRE ATT&amp;CK® &amp; D3FEND™ COVERAGE &amp; GAP ANALYSIS
            </h2>
          </div>
          <p className="text-[10px] text-slate-400 mt-0.5">
            Enterprise ATT&amp;CK v14 Tactical Heatmap • NSA/MITRE D3FEND Countermeasures • Automated Defense Gap Remediation
          </p>
        </div>

        {/* Tab Selector */}
        <div className="flex rounded border border-slate-700 bg-slate-950 p-0.5 text-xs">
          <button
            onClick={() => setActiveTab('attack')}
            className={`px-3 py-1.5 rounded transition cursor-pointer ${
              activeTab === 'attack'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            ATT&amp;CK Matrix
          </button>
          <button
            onClick={() => setActiveTab('d3fend')}
            className={`px-3 py-1.5 rounded transition cursor-pointer ${
              activeTab === 'd3fend'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            D3FEND Countermeasures
          </button>
          <button
            onClick={() => setActiveTab('gap')}
            className={`px-3 py-1.5 rounded transition cursor-pointer flex items-center gap-1 ${
              activeTab === 'gap'
                ? 'bg-cyan-500 text-slate-950 font-bold shadow'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <span>Gap Analysis</span>
            {activeThreatGaps.length > 0 && (
              <span className="w-2 h-2 rounded-full bg-red-400 animate-ping" />
            )}
          </button>
        </div>
      </div>

      {/* Coverage Status Banner */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
          <div className="text-[10px] text-slate-400">DEFENSIVE COVERAGE SCORE</div>
          <div className="text-xl font-bold text-cyan-300">{coveragePct}%</div>
          <div className="w-full bg-slate-800 h-1.5 rounded mt-1.5 overflow-hidden">
            <div className="bg-cyan-400 h-full transition-all" style={{ width: `${coveragePct}%` }} />
          </div>
        </div>

        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
          <div className="text-[10px] text-slate-400">ACTIVE DETECTIONS</div>
          <div className="text-xl font-bold text-red-400">
            {techniques.filter((t) => t.detectedCount > 0).length} Techniques
          </div>
          <div className="text-[10px] text-slate-500">Observed in ingested logs</div>
        </div>

        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
          <div className="text-[10px] text-slate-400">RULE ENFORCEMENT</div>
          <div className="text-xl font-bold text-emerald-400">
            {coveredCount} of {totalCount}
          </div>
          <div className="text-[10px] text-slate-500">Sigma &amp; Sophos policies active</div>
        </div>

        <div className="p-3 rounded-lg bg-slate-900/80 border border-slate-800">
          <div className="text-[10px] text-slate-400">CRITICAL DEFENSE GAPS</div>
          <div className="text-xl font-bold text-amber-400">
            {activeThreatGaps.length} Unprotected
          </div>
          <div className="text-[10px] text-slate-500">Immediate countermeasure required</div>
        </div>
      </div>

      {/* Tab 1: ATT&CK Matrix View */}
      {activeTab === 'attack' && (
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 overflow-x-auto scrollbar-thin">
            <div className="flex gap-2.5 min-w-[1300px] pb-2">
              {tactics.map((tactic) => {
                const list = groupedByTactic[tactic] || [];

                return (
                  <div key={tactic} className="flex-1 min-w-[140px] space-y-2">
                    <div className="p-2 rounded bg-slate-950 border border-slate-800 text-center">
                      <div className="text-[11px] font-bold text-cyan-300 truncate">{tactic}</div>
                      <div className="text-[9px] text-slate-500">{list.length} Techniques</div>
                    </div>

                    <div className="space-y-1.5">
                      {list.map((tech) => {
                        const isDeployed = deployedSet.has(tech.id);
                        const isSelected = selectedTechnique.id === tech.id;
                        const hasActiveDetections = tech.detectedCount > 0;
                        const isUncovered = tech.gapStatus === 'uncovered_gap' && !isDeployed;

                        return (
                          <div
                            key={tech.id}
                            onClick={() => setSelectedTechnique(tech)}
                            className={`p-2 rounded border cursor-pointer text-left transition ${
                              isSelected
                                ? 'ring-2 ring-cyan-400 border-cyan-400'
                                : ''
                            } ${
                              isUncovered
                                ? 'bg-red-950/40 border-red-800/80 hover:bg-red-900/40'
                                : hasActiveDetections
                                ? 'bg-amber-950/40 border-amber-800/80 hover:bg-amber-900/40'
                                : 'bg-slate-950/80 border-slate-800 hover:bg-slate-800'
                            }`}
                          >
                            <div className="flex items-center justify-between text-[10px]">
                              <span className="font-bold text-slate-400">{tech.id}</span>
                              {tech.detectedCount > 0 && (
                                <span className="px-1 rounded bg-red-900 text-red-200 font-bold text-[9px]">
                                  {tech.detectedCount}x
                                </span>
                              )}
                            </div>
                            <div className="text-[11px] font-semibold text-slate-200 mt-1 line-clamp-2">
                              {tech.name}
                            </div>
                            <div className="mt-1 text-[9px] flex items-center justify-between">
                              <span className={isUncovered ? 'text-red-400 font-bold' : 'text-emerald-400'}>
                                {isUncovered ? 'GAP' : 'COVERED'}
                              </span>
                              <span className="text-slate-500">{tech.d3fendCategory}</span>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Selected Technique Detail Card */}
          {selectedTechnique && (
            <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-2">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-base font-bold text-slate-100">
                      {selectedTechnique.id}: {selectedTechnique.name}
                    </span>
                    <span className="text-xs px-2 py-0.5 rounded bg-slate-800 text-cyan-300">
                      Tactic: {selectedTechnique.tacticName}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 mt-1">{selectedTechnique.description}</p>
                </div>

                <div className="flex items-center gap-2">
                  {!deployedSet.has(selectedTechnique.id) &&
                    selectedTechnique.gapStatus === 'uncovered_gap' && (
                      <button
                        onClick={() => handleDeploy(selectedTechnique.id)}
                        className="px-3 py-1.5 rounded bg-red-600 hover:bg-red-500 text-white font-bold text-xs flex items-center gap-1.5"
                      >
                        <Zap className="w-3.5 h-3.5" />
                        <span>Deploy Countermeasure</span>
                      </button>
                    )}
                  {deployedSet.has(selectedTechnique.id) && (
                    <span className="px-3 py-1.5 rounded bg-emerald-950 text-emerald-300 border border-emerald-800 text-xs font-bold flex items-center gap-1">
                      <Check className="w-3.5 h-3.5" />
                      <span>Countermeasure Active</span>
                    </span>
                  )}
                  <button
                    onClick={() => onPivotToHunting(selectedTechnique.id)}
                    className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs"
                  >
                    Hunt Technique IOCs →
                  </button>
                </div>
              </div>

              {/* Countermeasure mapping */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
                <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase">
                    MITRE D3FEND COUNTERMEASURE
                  </span>
                  <div className="font-bold text-cyan-300 text-sm">
                    {selectedTechnique.d3fendTechniqueId}: {selectedTechnique.d3fendTechniqueName}
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Defensive Strategy: <span className="text-purple-300">{selectedTechnique.d3fendCategory}</span>
                  </div>
                </div>

                <div className="p-3 rounded bg-slate-950 border border-slate-800 space-y-1">
                  <span className="text-[10px] text-slate-400 uppercase">INGESTED INCIDENTS</span>
                  <div className="font-bold text-red-400 text-sm">
                    {selectedTechnique.detectedCount} Correlated Events
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Rule Coverage: {selectedTechnique.coveredByRules ? 'Active in SIEM' : 'Uncovered Gap'}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: D3FEND Countermeasure Matrix */}
      {activeTab === 'd3fend' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {d3fendCategories.map((cat) => {
              const list = groupedByD3fend[cat] || [];

              return (
                <div key={cat} className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
                  <div className="flex items-center justify-between border-b border-slate-800 pb-2">
                    <span className="font-bold text-cyan-300 text-sm">{cat.toUpperCase()}</span>
                    <span className="text-[10px] text-slate-400">{list.length} Mechanisms</span>
                  </div>

                  <div className="space-y-2">
                    {list.map((t) => (
                      <div key={t.id} className="p-2.5 rounded bg-slate-950 border border-slate-800 space-y-1">
                        <div className="flex items-center justify-between text-xs">
                          <span className="font-bold text-purple-300">{t.d3fendTechniqueId}</span>
                          <span className="text-[10px] text-slate-500">Defends {t.id}</span>
                        </div>
                        <div className="text-xs text-slate-200">{t.d3fendTechniqueName}</div>
                        <div className="text-[10px] text-slate-400">
                          Applied against: {t.name}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Tab 3: Gap Analysis & Remediation */}
      {activeTab === 'gap' && (
        <div className="space-y-4">
          <div className="p-4 rounded-lg bg-slate-900/90 border border-slate-800 space-y-3">
            <div className="flex items-center justify-between border-b border-slate-800 pb-2">
              <span className="text-xs font-bold text-slate-200">
                ACTIVE SECURITY GAPS REQUIRING POLICY DEPLOYMENT
              </span>
              <span className="text-[10px] text-slate-400">
                Prioritized by observed attack vectors
              </span>
            </div>

            <div className="space-y-3">
              {activeThreatGaps.map((tech) => (
                <div
                  key={tech.id}
                  className="p-3.5 rounded bg-red-950/20 border border-red-800/80 flex flex-wrap items-center justify-between gap-3"
                >
                  <div className="space-y-1 max-w-xl">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-bold text-red-300">
                        {tech.id}: {tech.name}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.2 rounded bg-red-900 text-red-200 font-bold">
                        HIGH EXPOSURE
                      </span>
                    </div>
                    <p className="text-xs text-slate-300">{tech.description}</p>
                    <div className="text-[11px] text-cyan-300">
                      Recommended D3FEND Countermeasure: <span className="font-bold">{tech.d3fendTechniqueId} - {tech.d3fendTechniqueName}</span>
                    </div>
                  </div>

                  <button
                    onClick={() => handleDeploy(tech.id)}
                    className="px-4 py-2 rounded bg-gradient-to-r from-red-600 to-rose-700 hover:from-red-500 hover:to-rose-600 text-white font-bold text-xs flex items-center gap-1.5 shadow-[0_0_12px_rgba(239,68,68,0.3)] transition cursor-pointer"
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span>Deploy D3FEND Countermeasure</span>
                  </button>
                </div>
              ))}

              {activeThreatGaps.length === 0 && (
                <div className="py-8 text-center text-emerald-400 font-bold text-xs space-y-2">
                  <CheckCircle className="w-8 h-8 mx-auto text-emerald-400" />
                  <p>All identified attack vectors currently have active D3FEND defensive countermeasures applied!</p>
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
