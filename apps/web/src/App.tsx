import React, { useState, useEffect, useCallback } from 'react';
import type { HealthStatusResponse } from '@contracts/health';
import { apiClient, type ApiError } from './api/client';
import { Header } from './components/Header';
import { Sidebar } from './components/Sidebar';
import { OverviewView } from './views/OverviewView';
import { ObservatoryView } from './views/ObservatoryView';
import { NetworkTwinView } from './views/NetworkTwinView';
import { ProtocolResearchLabView } from './views/ProtocolResearchLabView';
import { InvestigationWorkbench } from './views/twin/InvestigationWorkbench';
import { ScenarioLaboratoryView } from './views/ScenarioLaboratoryView';
import { PlaceholderView } from './views/PlaceholderView';
import { NAVIGATION_TABS, type NavigationTab } from './types/navigation';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { AnalysisProvider, useAnalysisContext } from './context/AnalysisContext';

export const AppContent: React.FC = () => {
  const [currentTab, setCurrentTab] = useState<NavigationTab>('overview');
  const [isNavDrawerOpen, setIsNavDrawerOpen] = useState<boolean>(false);
  const [health, setHealth] = useState<HealthStatusResponse | null>(null);
  const [readiness, setReadiness] = useState<HealthStatusResponse | null>(null);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [error, setError] = useState<ApiError | null>(null);

  // Cross-workspace navigation states
  const [twinInitialSnapshotId, setTwinInitialSnapshotId] = useState<string | null>(null);
  const [twinInitialCaptureId, setTwinInitialCaptureId] = useState<string | null>(null);

  const { activeCaptureId, selectedSnapshotId, setActiveCaptureId, setSelectedSnapshotId } = useAnalysisContext();

  const handleNavigateToTwin = useCallback((params: { captureId?: string; snapshotId?: string; filename?: string; jobId?: string }) => {
    if (params.snapshotId) {
      setTwinInitialSnapshotId(params.snapshotId);
      setSelectedSnapshotId(params.snapshotId);
    }
    if (params.captureId) {
      setTwinInitialCaptureId(params.captureId);
      setActiveCaptureId(params.captureId);
    }
    setCurrentTab('twin');
  }, [setActiveCaptureId, setSelectedSnapshotId]);

  useEffect(() => {
    const onNavEvent = (e: Event) => {
      const custom = e as CustomEvent;
      if (custom.detail) {
        handleNavigateToTwin(custom.detail);
      }
    };
    window.addEventListener('navigate-twin', onNavEvent);
    return () => window.removeEventListener('navigate-twin', onNavEvent);
  }, [handleNavigateToTwin]);

  const fetchSystemStatus = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const [h, r] = await Promise.all([
        apiClient.getHealth(),
        apiClient.getReadiness().catch((err: ApiError) => {
          // If readiness returns 503 (e.g. database not ready), it still returns HealthStatusResponse
          if (err.statusCode === 503 && err.details) {
            return err.details as HealthStatusResponse;
          }
          return null;
        }),
      ]);
      setHealth(h);
      setReadiness(r);
    } catch (err: unknown) {
      setError(err as ApiError);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchSystemStatus();
  }, [fetchSystemStatus]);

  const activeTabDefinition = NAVIGATION_TABS.find((t) => t.id === currentTab) || NAVIGATION_TABS[0]!;

  return (
    <div className="flex h-screen bg-background text-gray-100 overflow-hidden font-sans">
      <Sidebar
        currentTab={currentTab}
        onSelectTab={setCurrentTab}
        isOpen={isNavDrawerOpen}
        onClose={() => setIsNavDrawerOpen(false)}
      />

      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header
          health={health}
          isLoading={isLoading}
          error={error}
          onRefresh={fetchSystemStatus}
          onToggleNavDrawer={() => setIsNavDrawerOpen((prev) => !prev)}
          isNavDrawerOpen={isNavDrawerOpen}
        />

        <main className="flex-1 overflow-y-auto p-6 focus:outline-none" tabIndex={-1}>
          {error && (
            <div
              className="mb-6 p-4 rounded-lg bg-rose-950/40 border border-rose-800/50 flex items-start justify-between gap-4"
              role="alert"
              data-testid="error-banner"
            >
              <div className="flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                <div>
                  <h3 className="text-sm font-semibold text-rose-200">
                    Backend Connection Failure: {error.error}
                  </h3>
                  <p className="text-xs text-rose-300/90 mt-0.5">
                    {error.message}
                  </p>
                  {error.requestId && (
                    <div className="text-[10px] font-mono text-rose-400/80 mt-1">
                      Request ID: {error.requestId}
                    </div>
                  )}
                </div>
              </div>

              <button
                onClick={fetchSystemStatus}
                className="px-3 py-1.5 rounded bg-rose-900/60 hover:bg-rose-800 text-rose-200 text-xs font-medium border border-rose-700 transition flex items-center gap-1.5 shrink-0"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                <span>Retry Connection</span>
              </button>
            </div>
          )}

          {currentTab === 'overview' ? (
            <OverviewView
              health={health}
              readiness={readiness}
              onRefresh={fetchSystemStatus}
            />
          ) : currentTab === 'observatory' ? (
            <ObservatoryView onNavigateToTwin={handleNavigateToTwin} />
          ) : currentTab === 'twin' ? (
            <NetworkTwinView
              initialSnapshotId={twinInitialSnapshotId || selectedSnapshotId}
              initialCaptureId={twinInitialCaptureId || activeCaptureId}
              onNavigateToObservatory={() => {
                setCurrentTab('observatory');
              }}
            />
          ) : currentTab === 'laboratory' ? (
            <ScenarioLaboratoryView />
          ) : currentTab === 'research' ? (
            <ProtocolResearchLabView />
          ) : currentTab === 'investigation' ? (
            <InvestigationWorkbench />
          ) : (
            <PlaceholderView tab={activeTabDefinition} />
          )}
        </main>
      </div>
    </div>
  );
};

export const App: React.FC = () => {
  return (
    <AnalysisProvider>
      <AppContent />
    </AnalysisProvider>
  );
};

export default App;
