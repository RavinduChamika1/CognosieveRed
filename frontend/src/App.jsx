import React, { useState, useEffect, useRef } from 'react';
import Header from './components/Header';
import DisclaimerBanner from './components/DisclaimerBanner';
import ScanForm from './components/ScanForm';
import ActiveScanConfirmModal from './components/ActiveScanConfirmModal';
import ScopeRulesGuideModal from './components/ScopeRulesGuideModal';
import ScanProgress from './components/ScanProgress';
import SummaryCards from './components/SummaryCards';
import FindingsTable from './components/FindingsTable';
import FindingDetailModal from './components/FindingDetailModal';
import RemediationMatrix from './components/RemediationMatrix';
import ScanHistory from './components/ScanHistory';
import AttackSurfaceMap from './components/AttackSurfaceMap';
import AttckHeatmap from './components/AttckHeatmap';
import { ShieldAlert, Network, Crosshair } from 'lucide-react';

import { checkHealth, submitScan, getScan, getScans } from './api/client';

export default function App() {
  const [health, setHealth] = useState(null);
  const [scans, setScans] = useState([]);
  const [currentScan, setCurrentScan] = useState(null);
  const [findings, setFindings] = useState([]);
  const [loading, setLoading] = useState(false);
  const [activeTab, setActiveTab] = useState('vulnerabilities');

  // Modals state
  const [pendingActivePayload, setPendingActivePayload] = useState(null);
  const [showGuide, setShowGuide] = useState(false);
  const [showHistory, setShowHistory] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Poll timer reference
  const pollTimerRef = useRef(null);

  // Initial health and scan load
  const loadInitialData = async () => {
    try {
      const h = await checkHealth();
      setHealth(h);
    } catch (e) {
      console.warn('Backend offline or healthcheck failed:', e);
    }

    try {
      const pastScans = await getScans();
      setScans(pastScans);
      if (pastScans.length > 0 && !currentScan) {
        // Load latest scan
        loadScanDetails(pastScans[0].id);
      }
    } catch (e) {
      console.warn('Could not load past scans:', e);
    }
  };

  useEffect(() => {
    loadInitialData();
    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, []);

  // Poll current scan if active
  useEffect(() => {
    if (!currentScan || ['completed', 'failed'].includes(currentScan.status)) {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
      return;
    }

    pollTimerRef.current = setInterval(async () => {
      try {
        const updated = await getScan(currentScan.id);
        setCurrentScan(updated);
        if (updated.findings) {
          setFindings(updated.findings);
        }
        if (['completed', 'failed'].includes(updated.status)) {
          clearInterval(pollTimerRef.current);
          setLoading(false);
          // Refresh past scans list
          const pastScans = await getScans();
          setScans(pastScans);
        }
      } catch (e) {
        console.error('Error polling scan status:', e);
      }
    }, 2500);

    return () => {
      if (pollTimerRef.current) clearInterval(pollTimerRef.current);
    };
  }, [currentScan?.id, currentScan?.status]);

  const loadScanDetails = async (scanId) => {
    try {
      const s = await getScan(scanId);
      setCurrentScan(s);
      setFindings(s.findings || []);
      if (s.redteam_operation && (!s.findings || s.findings.length === 0)) {
        setActiveTab('attack_surface');
      } else {
        setActiveTab('vulnerabilities');
      }
    } catch (e) {
      alert(`Failed to load scan: ${e.message}`);
    }
  };

  const handleFormSubmit = async (formData) => {
    if (formData.scan_mode === 'active' && !formData.active_scan_confirmed) {
      setPendingActivePayload(formData);
      return;
    }

    await launchScan(formData);
  };

  const launchScan = async (payload) => {
    setLoading(true);
    try {
      const created = await submitScan(payload);
      setCurrentScan(created);
      setFindings([]);
      // Scroll to progress
      window.scrollTo({ top: 300, behavior: 'smooth' });
    } catch (e) {
      alert(`Scan failed to start: ${e.message}`);
      setLoading(false);
    }
  };

  const handleActiveConfirmed = async () => {
    if (!pendingActivePayload) return;
    const finalPayload = {
      ...pendingActivePayload,
      active_scan_confirmed: true
    };
    setPendingActivePayload(null);
    await launchScan(finalPayload);
  };

  return (
    <div className="app-container">
      <Header
        health={health}
        currentScan={currentScan}
        onNewScan={() => {
          setCurrentScan(null);
          setFindings([]);
          window.scrollTo({ top: 0, behavior: 'smooth' });
        }}
        onOpenHistory={() => setShowHistory(true)}
        onOpenGuide={() => setShowGuide(true)}
      />

      <main className="main-content">
        <DisclaimerBanner />

        {/* Scan Input Form (Shown always or when launching new) */}
        <ScanForm
          onSubmit={handleFormSubmit}
          loading={loading}
        />

        {/* Live Progress Bar (when scan in progress or just finished) */}
        {currentScan && (
          <ScanProgress scan={currentScan} />
        )}

        {/* Dashboard Results (When scan is completed) */}
        {currentScan?.status === 'completed' && (
          <>
            <SummaryCards
              scan={currentScan}
              findings={findings}
            />

            {/* Results Navigation Tabs */}
            <div className="tabs" style={{ marginBottom: '20px', borderBottom: '1px solid #1e293b' }}>
              <button
                className={`tab-btn ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
                onClick={() => setActiveTab('vulnerabilities')}
                style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                <ShieldAlert size={16} />
                <span>Vulnerabilities &amp; Findings</span>
                {findings.length > 0 && (
                  <span style={{ background: '#1e293b', padding: '2px 8px', borderRadius: '10px', fontSize: '11px', color: '#94a3b8' }}>
                    {findings.length}
                  </span>
                )}
              </button>

              <button
                className={`tab-btn ${activeTab === 'attack_surface' ? 'active' : ''}`}
                onClick={() => setActiveTab('attack_surface')}
                style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                <Network size={16} />
                <span>Attack Surface Map</span>
                {currentScan?.redteam_operation && (
                  <span style={{ background: 'rgba(239, 68, 68, 0.2)', color: '#ef4444', padding: '2px 8px', borderRadius: '10px', fontSize: '11px', fontWeight: 700 }}>
                    Active
                  </span>
                )}
              </button>

              <button
                className={`tab-btn ${activeTab === 'attck_coverage' ? 'active' : ''}`}
                onClick={() => setActiveTab('attck_coverage')}
                style={{ display: 'flex', alignItems: 'center', gap: '8px' }}
              >
                <Crosshair size={16} />
                <span>ATT&amp;CK Coverage</span>
                {currentScan?.redteam_operation?.techniques_run && (
                  <span style={{ background: 'rgba(56, 189, 248, 0.2)', color: '#38bdf8', padding: '2px 8px', borderRadius: '10px', fontSize: '11px', fontWeight: 700 }}>
                    {currentScan.redteam_operation.techniques_run.length} TTPs
                  </span>
                )}
              </button>
            </div>

            {/* Tab 1: Vulnerabilities & Remediation */}
            {activeTab === 'vulnerabilities' && (
              <>
                <FindingsTable
                  findings={findings}
                  onSelectFinding={(f) => setSelectedFinding(f)}
                />

                <RemediationMatrix
                  findings={findings}
                />
              </>
            )}

            {/* Tab 2: Attack Surface Map (React Flow) */}
            {activeTab === 'attack_surface' && (
              currentScan?.redteam_operation ? (
                <AttackSurfaceMap redteamOperation={currentScan.redteam_operation} />
              ) : (
                <div className="glass-panel" style={{ padding: '40px 20px', textAlign: 'center', color: '#94a3b8', marginBottom: '24px' }}>
                  <Network size={44} color="#64748b" style={{ margin: '0 auto 12px' }} />
                  <h3 style={{ color: '#f8fafc', fontSize: '16px', fontWeight: 600 }}>No Attack Surface Graph Available</h3>
                  <p style={{ fontSize: '13px', maxWidth: '480px', margin: '8px auto 0', lineHeight: 1.6 }}>
                    Adversary Emulation was not enabled for this scan. Run a scan with Red Team enabled and a verified Caldera agent group to visualize compromised lab nodes, credentials, and pivot paths.
                  </p>
                </div>
              )
            )}

            {/* Tab 3: ATT&CK Coverage Heatmap */}
            {activeTab === 'attck_coverage' && (
              currentScan?.redteam_operation ? (
                <AttckHeatmap redteamOperation={currentScan.redteam_operation} />
              ) : (
                <div className="glass-panel" style={{ padding: '40px 20px', textAlign: 'center', color: '#94a3b8', marginBottom: '24px' }}>
                  <Crosshair size={44} color="#64748b" style={{ margin: '0 auto 12px' }} />
                  <h3 style={{ color: '#f8fafc', fontSize: '16px', fontWeight: 600 }}>No ATT&amp;CK Coverage Heatmap Available</h3>
                  <p style={{ fontSize: '13px', maxWidth: '480px', margin: '8px auto 0', lineHeight: 1.6 }}>
                    Adversary Emulation was not enabled for this scan. Enable Red Team mode with Caldera to map executed techniques against the MITRE ATT&amp;CK Enterprise matrix.
                  </p>
                </div>
              )
            )}
          </>
        )}
      </main>

      {/* Active Scan Double Confirmation Modal */}
      {pendingActivePayload && (
        <ActiveScanConfirmModal
          targetUrl={pendingActivePayload.target_url}
          onConfirm={handleActiveConfirmed}
          onCancel={() => setPendingActivePayload(null)}
        />
      )}

      {/* Scope Rules Guide Modal */}
      {showGuide && (
        <ScopeRulesGuideModal
          onClose={() => setShowGuide(false)}
        />
      )}

      {/* Historical Scans Drawer */}
      {showHistory && (
        <ScanHistory
          scans={scans}
          onSelectScan={loadScanDetails}
          onClose={() => setShowHistory(false)}
        />
      )}

      {/* Finding Detail Inspection Modal */}
      {selectedFinding && (
        <FindingDetailModal
          finding={selectedFinding}
          onClose={() => setSelectedFinding(null)}
        />
      )}
    </div>
  );
}
