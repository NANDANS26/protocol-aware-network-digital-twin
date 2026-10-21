import React, { useState } from 'react';
import { RealCaptureWorkbench } from './twin/RealCaptureWorkbench';
import { BenchmarkWorkbench } from './twin/BenchmarkWorkbench';
import { SecurityTestingWorkbench } from './twin/SecurityTestingWorkbench';
import {
  FileCheck2,
  Activity,
  ShieldAlert,
  FlaskConical,
  Cpu,
  ShieldCheck,
} from 'lucide-react';

export type ProtocolResearchTab = 'captures' | 'benchmarks' | 'fuzzing';

export const ProtocolResearchLabView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ProtocolResearchTab>('captures');

  return (
    <div className="space-y-6" data-testid="protocol-research-lab">
      {/* Workstation Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 bg-gray-900 border border-gray-800 rounded-lg p-5">
        <div>
          <div className="flex items-center gap-2.5">
            <div className="p-2 bg-indigo-950/80 rounded-lg border border-indigo-700/50 text-indigo-400">
              <FlaskConical className="w-5 h-5" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white flex items-center gap-2">
                Protocol Research Lab
                <span className="text-xs px-2 py-0.5 rounded bg-indigo-950 text-indigo-300 border border-indigo-800/60 font-mono font-medium">
                  Protocol Engine Active
                </span>
              </h1>
              <p className="text-xs text-gray-400 mt-0.5">
                Protocol-aware packet inspection, differential validation against reference oracle, metamorphic invariant testing, and reproducible benchmarks.
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-gray-950 border border-gray-800 text-[11px] text-gray-300 font-mono">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            C++ Systems Engine
          </span>
          <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-gray-950 border border-gray-800 text-[11px] text-gray-300 font-mono">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
            Python Reference Oracle
          </span>
        </div>
      </div>

      {/* Primary Workstation Navigation Tabs */}
      <div className="flex border-b border-gray-800 space-x-1 overflow-x-auto">
        <button
          onClick={() => setActiveTab('captures')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition whitespace-nowrap ${
            activeTab === 'captures'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
          data-testid="tab-captures"
        >
          <FileCheck2 className="w-4 h-4 text-indigo-400" />
          <span>Real Capture &amp; Differential Lab</span>
        </button>

        <button
          onClick={() => setActiveTab('benchmarks')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition whitespace-nowrap ${
            activeTab === 'benchmarks'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
          data-testid="tab-benchmarks"
        >
          <Activity className="w-4 h-4 text-cyan-400" />
          <span>Validation Benchmarks &amp; Profiling</span>
        </button>

        <button
          onClick={() => setActiveTab('fuzzing')}
          className={`flex items-center gap-2 px-4 py-2.5 text-xs font-semibold border-b-2 transition whitespace-nowrap ${
            activeTab === 'fuzzing'
              ? 'border-indigo-500 text-white bg-indigo-950/20'
              : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-700'
          }`}
          data-testid="tab-fuzzing"
        >
          <ShieldAlert className="w-4 h-4 text-amber-400" />
          <span>Protocol Security Fuzzing &amp; Mutation</span>
        </button>
      </div>

      {/* Subtab Contents */}
      <div className="pt-2">
        {activeTab === 'captures' && <RealCaptureWorkbench />}
        {activeTab === 'benchmarks' && <BenchmarkWorkbench />}
        {activeTab === 'fuzzing' && <SecurityTestingWorkbench />}
      </div>
    </div>
  );
};
