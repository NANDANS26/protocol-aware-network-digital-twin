import React, { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import { apiClient } from '../api/client';
import type { CaptureMetadata, ActiveCaptureContext } from '../types/intelligence';

export interface AnalysisContextType {
  activeCaptureId: string | null;
  activeCaptureName: string | null;
  activeCapture: CaptureMetadata | null;
  activeSnapshotId: string | null;
  setActiveSnapshotId: (snapshotId: string | null) => void;
  activeJobId: string | null;
  activeStatus: string | null;
  packetCount: number;
  eventCount: number;
  acceptedCount: number;
  rejectedCount: number;
  selectedSnapshotId: string | null;
  selectedModelFingerprint: string | null;
  capturesList: CaptureMetadata[];
  isLoading: boolean;
  requestGeneration: number;
  setActiveCaptureId: (captureId: string | null) => Promise<void>;
  setSelectedSnapshotId: (snapshotId: string | null) => void;
  refreshCaptures: () => Promise<CaptureMetadata[]>;
  loadActiveContext: (captureId: string) => Promise<void>;
  notifyCaptureUploaded: (captureId: string, jobId?: string, filename?: string) => Promise<void>;
}

const STORAGE_KEY = 'protocoldigitaltwin_active_capture_id';

const AnalysisContext = createContext<AnalysisContextType | undefined>(undefined);

export const AnalysisProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activeCaptureId, setActiveCaptureIdState] = useState<string | null>(() => {
    try {
      return localStorage.getItem(STORAGE_KEY);
    } catch {
      return null;
    }
  });

  const [activeCaptureName, setActiveCaptureName] = useState<string | null>(null);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [activeStatus, setActiveStatus] = useState<string | null>(null);
  const [packetCount, setPacketCount] = useState<number>(0);
  const [eventCount, setEventCount] = useState<number>(0);
  const [acceptedCount, setAcceptedCount] = useState<number>(0);
  const [rejectedCount, setRejectedCount] = useState<number>(0);
  const [selectedSnapshotId, setSelectedSnapshotId] = useState<string | null>(null);
  const [selectedModelFingerprint, setSelectedModelFingerprint] = useState<string | null>(null);
  const [capturesList, setCapturesList] = useState<CaptureMetadata[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(true);
  const [requestGeneration, setRequestGeneration] = useState<number>(1);

  const generationRef = useRef<number>(1);

  const loadActiveContext = useCallback(async (captureId: string) => {
    try {
      const ctx: ActiveCaptureContext = await apiClient.getCaptureActiveContext(captureId);
      setActiveCaptureName(ctx.filename);
      setActiveJobId(ctx.active_analysis_run_id || null);
      setActiveStatus(ctx.lifecycle_status);
      setPacketCount(ctx.packet_count || 0);
      setEventCount(ctx.event_count || 0);
      setAcceptedCount(ctx.accepted_count || 0);
      setRejectedCount(ctx.rejected_count || 0);
      if (ctx.latest_snapshot_id) {
        setSelectedSnapshotId(ctx.latest_snapshot_id);
      }
    } catch (err) {
      console.warn(`Failed to load active context for capture '${captureId}':`, err);
    }
  }, []);

  const refreshCaptures = useCallback(async (): Promise<CaptureMetadata[]> => {
    try {
      const list = await apiClient.listCaptures();
      setCapturesList(list);
      return list;
    } catch (err) {
      console.error('Failed to list captures:', err);
      return [];
    }
  }, []);

  const setActiveCaptureId = useCallback(
    async (captureId: string | null) => {
      generationRef.current += 1;
      setRequestGeneration(generationRef.current);

      setActiveCaptureIdState(captureId);

      if (captureId) {
        try {
          localStorage.setItem(STORAGE_KEY, captureId);
        } catch {
          // ignore
        }
        await loadActiveContext(captureId);
      } else {
        try {
          localStorage.removeItem(STORAGE_KEY);
        } catch {
          // ignore
        }
        setActiveCaptureName(null);
        setActiveJobId(null);
        setActiveStatus(null);
        setPacketCount(0);
        setEventCount(0);
        setAcceptedCount(0);
        setRejectedCount(0);
        setSelectedSnapshotId(null);
        setSelectedModelFingerprint(null);
      }
    },
    [loadActiveContext]
  );

  const notifyCaptureUploaded = useCallback(
    async (captureId: string, jobId?: string, filename?: string) => {
      await refreshCaptures();
      await setActiveCaptureId(captureId);
      if (filename) setActiveCaptureName(filename);
      if (jobId) setActiveJobId(jobId);
    },
    [refreshCaptures, setActiveCaptureId]
  );

  // Initial load
  useEffect(() => {
    let isMounted = true;
    (async () => {
      setIsLoading(true);
      try {
        const list = await apiClient.listCaptures();
        if (!isMounted) return;
        setCapturesList(list);

        const storedId = localStorage.getItem(STORAGE_KEY);
        const validStored = storedId ? list.find((c) => c.capture_id === storedId) : null;

        if (validStored) {
          await setActiveCaptureId(validStored.capture_id);
        } else if (list.length > 0 && list[0]) {
          // Default to latest capture
          await setActiveCaptureId(list[0].capture_id);
        } else {
          await setActiveCaptureId(null);
        }
      } catch (err) {
        console.error('Initial analysis context initialization error:', err);
      } finally {
        if (isMounted) setIsLoading(false);
      }
    })();

    return () => {
      isMounted = false;
    };
  }, []);

  const activeCapture = capturesList.find((c) => c.capture_id === activeCaptureId) || (activeCaptureId ? ({
    capture_id: activeCaptureId,
    filename: activeCaptureName || activeCaptureId,
    format: 'PCAP',
  } as CaptureMetadata) : null);

  return (
    <AnalysisContext.Provider
      value={{
        activeCaptureId,
        activeCaptureName,
        activeCapture,
        activeSnapshotId: selectedSnapshotId,
        setActiveSnapshotId: setSelectedSnapshotId,
        activeJobId,
        activeStatus,
        packetCount,
        eventCount,
        acceptedCount,
        rejectedCount,
        selectedSnapshotId,
        selectedModelFingerprint,
        capturesList,
        isLoading,
        requestGeneration,
        setActiveCaptureId,
        setSelectedSnapshotId,
        refreshCaptures,
        loadActiveContext,
        notifyCaptureUploaded,
      }}
    >
      {children}
    </AnalysisContext.Provider>
  );
};

const defaultContextValue: AnalysisContextType = {
  activeCaptureId: null,
  activeCaptureName: null,
  activeCapture: null,
  activeSnapshotId: null,
  setActiveSnapshotId: () => {},
  activeJobId: null,
  activeStatus: null,
  packetCount: 0,
  eventCount: 0,
  acceptedCount: 0,
  rejectedCount: 0,
  selectedSnapshotId: null,
  selectedModelFingerprint: null,
  capturesList: [],
  isLoading: false,
  requestGeneration: 1,
  setActiveCaptureId: async () => {},
  setSelectedSnapshotId: () => {},
  refreshCaptures: async () => [],
  loadActiveContext: async () => {},
  notifyCaptureUploaded: async () => {},
};

export const useAnalysisContext = (): AnalysisContextType => {
  const context = useContext(AnalysisContext);
  return context || defaultContextValue;
};
