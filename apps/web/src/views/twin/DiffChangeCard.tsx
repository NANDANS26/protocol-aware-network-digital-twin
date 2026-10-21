import React, { useState } from 'react';
import {
  ShieldAlert,
  ChevronDown,
  ChevronRight,
  ArrowRight,
  Database,
  Layers,
  Network,
  Info,
} from 'lucide-react';
import type { DiffExplanationItem } from '../../types/intelligence';

export interface DiffChangeCardProps {
  change: DiffExplanationItem | string | unknown;
  index: number;
}

export const DiffChangeCard: React.FC<DiffChangeCardProps> = ({ change, index }) => {
  const [evidenceExpanded, setEvidenceExpanded] = useState<boolean>(false);
  const [metaExpanded, setMetaExpanded] = useState<boolean>(false);

  try {
    // 1. Safe normalization of the change payload
    let type = 'change';
    let category = 'DIFFERENCE';
    let entityId: string | null = null;
    let entityType: 'node' | 'edge' | 'generic' | null = null;
    let evidenceClass: string | null = null;
    let explanation = '';
    let evidenceIds: string[] = [];
    let fieldChanges: Record<string, { from?: unknown; to?: unknown }> | null = null;
    let extraMeta: Record<string, unknown> | null = null;

    if (typeof change === 'string') {
      explanation = change;
      category = 'ANNOUNCEMENT';
      type = 'explanation';
    } else if (change && typeof change === 'object') {
      const obj = change as Record<string, unknown>;

      if (typeof obj.type === 'string') {
        type = obj.type;
      }

      if (typeof obj.explanation === 'string' && obj.explanation.trim()) {
        explanation = obj.explanation;
      }

      if (typeof obj.edge_id === 'string' && obj.edge_id) {
        entityId = obj.edge_id;
        entityType = 'edge';
        category = 'RELATIONSHIP';
      } else if (typeof obj.node_id === 'string' && obj.node_id) {
        entityId = obj.node_id;
        entityType = 'node';
        category = 'ENTITY';
      } else if (typeof obj.id === 'string' && obj.id) {
        entityId = obj.id;
        entityType = 'generic';
      }

      if (typeof obj.evidence_class === 'string' && obj.evidence_class) {
        evidenceClass = obj.evidence_class;
      }

      if (Array.isArray(obj.evidence_ids)) {
        evidenceIds = obj.evidence_ids.filter((id): id is string => typeof id === 'string' && Boolean(id));
      }

      if (obj.changes && typeof obj.changes === 'object' && !Array.isArray(obj.changes)) {
        fieldChanges = obj.changes as Record<string, { from?: unknown; to?: unknown }>;
      }

      // Check category override by type string
      const typeLower = type.toLowerCase();
      if (typeLower.includes('relationship') || typeLower.includes('edge')) {
        category = 'RELATIONSHIP';
      } else if (typeLower.includes('entity') || typeLower.includes('node')) {
        category = 'ENTITY';
      } else if (typeLower.includes('structural')) {
        category = 'STRUCTURAL';
      } else if (!entityType) {
        category = type.toUpperCase().replace(/_/g, ' ');
      }

      // Any remaining metadata keys
      const handledKeys = new Set([
        'type',
        'explanation',
        'edge_id',
        'node_id',
        'id',
        'evidence_class',
        'evidence_ids',
        'changes',
      ]);
      const remainingKeys = Object.keys(obj).filter(
        (k) => !handledKeys.has(k) && obj[k] !== undefined && obj[k] !== null
      );
      if (remainingKeys.length > 0) {
        extraMeta = {};
        for (const k of remainingKeys) {
          extraMeta[k] = obj[k];
        }
      }

      // Fallback explanation if empty
      if (!explanation) {
        const idLabel = entityId ? ` on ${entityType || 'target'} [${entityId}]` : '';
        explanation = `${type.replace(/_/g, ' ')}${idLabel}`;
      }
    } else {
      explanation = String(change ?? 'Unknown difference');
    }

    // Category badge color styling
    let categoryBadgeStyle = 'bg-indigo-950/40 text-indigo-300 border-indigo-800/60';
    if (category === 'RELATIONSHIP') {
      categoryBadgeStyle = 'bg-purple-950/40 text-purple-300 border-purple-800/60';
    } else if (category === 'ENTITY') {
      categoryBadgeStyle = 'bg-emerald-950/40 text-emerald-300 border-emerald-800/60';
    } else if (category === 'STRUCTURAL') {
      categoryBadgeStyle = 'bg-cyan-950/40 text-cyan-300 border-cyan-800/60';
    }

    // Evidence class badge color
    let evidenceBadgeStyle = 'bg-gray-800 text-gray-300 border-gray-700';
    if (evidenceClass === 'DIRECT_OBSERVATION') {
      evidenceBadgeStyle = 'bg-emerald-950/50 text-emerald-300 border-emerald-700/60';
    } else if (evidenceClass === 'CONFIGURED') {
      evidenceBadgeStyle = 'bg-blue-950/50 text-blue-300 border-blue-700/60';
    } else if (evidenceClass === 'INFERRED') {
      evidenceBadgeStyle = 'bg-amber-950/50 text-amber-300 border-amber-700/60';
    }

    const hasMetaDetails = Boolean(fieldChanges && Object.keys(fieldChanges).length > 0) || Boolean(extraMeta && Object.keys(extraMeta).length > 0);

    return (
      <div
        className="p-3 bg-gray-900/70 border border-gray-800 hover:border-gray-700 rounded-lg text-xs space-y-2.5 transition"
        data-testid={`diff-change-card-${index}`}
      >
        {/* Top Badges & Target ID Row */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className={`px-2 py-0.5 rounded text-[10px] font-bold tracking-wider uppercase border ${categoryBadgeStyle}`}>
              {category}
            </span>
            <span className="px-2 py-0.5 rounded text-[10px] font-mono bg-gray-800/90 text-gray-300 border border-gray-700/60">
              {type}
            </span>
            {evidenceClass && (
              <span className={`px-2 py-0.5 rounded text-[10px] font-medium border ${evidenceBadgeStyle}`}>
                {evidenceClass}
              </span>
            )}
          </div>

          {entityId && (
            <div className="flex items-center gap-1 text-[11px] font-mono text-gray-400 bg-surface/80 px-2 py-0.5 rounded border border-gray-800">
              {entityType === 'edge' ? (
                <Network className="w-3 h-3 text-purple-400 shrink-0" />
              ) : entityType === 'node' ? (
                <Layers className="w-3 h-3 text-emerald-400 shrink-0" />
              ) : (
                <Database className="w-3 h-3 text-cyan-400 shrink-0" />
              )}
              <span className="text-gray-500 uppercase text-[9px] mr-1">{entityType || 'ID'}:</span>
              <span className="text-gray-200 truncate max-w-[260px]" title={entityId}>
                {entityId}
              </span>
            </div>
          )}
        </div>

        {/* Human Readable Explanation */}
        <div className="text-gray-200 font-sans leading-relaxed text-xs">
          {explanation}
        </div>

        {/* Expandable Drawers (Evidence IDs and Field Changes) */}
        {(evidenceIds.length > 0 || hasMetaDetails) && (
          <div className="pt-2 border-t border-gray-800/80 flex flex-wrap items-center gap-2">
            {evidenceIds.length > 0 && (
              <button
                type="button"
                onClick={() => setEvidenceExpanded((prev) => !prev)}
                className="inline-flex items-center gap-1 px-2 py-1 rounded bg-gray-800/80 hover:bg-gray-700 text-gray-300 text-[11px] font-medium transition"
                aria-expanded={evidenceExpanded}
              >
                <ShieldAlert className="w-3 h-3 text-indigo-400" />
                <span>Evidence Records ({evidenceIds.length})</span>
                {evidenceExpanded ? (
                  <ChevronDown className="w-3 h-3 ml-0.5" />
                ) : (
                  <ChevronRight className="w-3 h-3 ml-0.5" />
                )}
              </button>
            )}

            {hasMetaDetails && (
              <button
                type="button"
                onClick={() => setMetaExpanded((prev) => !prev)}
                className="inline-flex items-center gap-1 px-2 py-1 rounded bg-gray-800/80 hover:bg-gray-700 text-gray-300 text-[11px] font-medium transition"
                aria-expanded={metaExpanded}
              >
                <Info className="w-3 h-3 text-cyan-400" />
                <span>Field Details & Changes</span>
                {metaExpanded ? (
                  <ChevronDown className="w-3 h-3 ml-0.5" />
                ) : (
                  <ChevronRight className="w-3 h-3 ml-0.5" />
                )}
              </button>
            )}
          </div>
        )}

        {/* Evidence IDs Drawer */}
        {evidenceExpanded && evidenceIds.length > 0 && (
          <div className="p-2.5 bg-gray-950/80 border border-gray-800 rounded space-y-1.5 animate-fadeIn">
            <div className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">
              Auditable Evidence References
            </div>
            <div className="flex flex-wrap gap-1.5">
              {evidenceIds.map((eid, eIdx) => (
                <span
                  key={eIdx}
                  className="px-2 py-0.5 rounded bg-indigo-950/50 border border-indigo-800/60 font-mono text-[10px] text-indigo-300"
                >
                  {eid}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Field Details Drawer */}
        {metaExpanded && hasMetaDetails && (
          <div className="p-2.5 bg-gray-950/80 border border-gray-800 rounded space-y-2 animate-fadeIn font-mono text-[11px]">
            {fieldChanges && Object.keys(fieldChanges).length > 0 && (
              <div className="space-y-1">
                <div className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider font-sans">
                  Field Modifications
                </div>
                {Object.entries(fieldChanges).map(([fKey, fVal]) => (
                  <div key={fKey} className="flex items-center gap-2 p-1 bg-surface/50 rounded border border-gray-800/60">
                    <span className="text-gray-400 font-semibold">{fKey}:</span>
                    <span className="text-rose-400 line-through">
                      {fVal?.from !== undefined ? String(fVal.from) : 'null'}
                    </span>
                    <ArrowRight className="w-3 h-3 text-gray-500 shrink-0" />
                    <span className="text-emerald-400 font-medium">
                      {fVal?.to !== undefined ? String(fVal.to) : 'null'}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {extraMeta && Object.keys(extraMeta).length > 0 && (
              <div className="space-y-1 pt-1">
                <div className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider font-sans">
                  Additional Metadata
                </div>
                <pre className="p-2 bg-surface/40 rounded text-[10px] text-gray-300 overflow-x-auto whitespace-pre-wrap">
                  {JSON.stringify(extraMeta, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </div>
    );
  } catch (err) {
    // Safe error boundary fallback ensuring invalid objects never crash the page
    return (
      <div className="p-2.5 bg-rose-950/30 border border-rose-900/50 rounded text-xs text-rose-300 font-mono flex items-center justify-between">
        <span>Diff Entry #{index + 1}: Unformatted change record</span>
        <span className="text-[10px] text-gray-400 truncate max-w-xs">{String(change)}</span>
      </div>
    );
  }
};
