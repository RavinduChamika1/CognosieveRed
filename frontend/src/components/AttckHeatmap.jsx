import React, { useState } from 'react';
import { Shield, ShieldAlert, CheckCircle2, XCircle, Info, Filter } from 'lucide-react';

const ALL_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact'
];

export default function AttckHeatmap({ redteamOperation }) {
  const [selectedTech, setSelectedTech] = useState(null);
  const [filterOutcome, setFilterOutcome] = useState('all');

  const techniques = redteamOperation?.techniques_run || [];
  const heatmap = redteamOperation?.attck_heatmap || [];

  // Group tested techniques by tactic
  const tacticMap = {};
  ALL_TACTICS.forEach(tactic => {
    tacticMap[tactic] = [];
  });

  techniques.forEach(t => {
    const tactic = t.tactic || 'Discovery';
    if (!tacticMap[tactic]) {
      tacticMap[tactic] = [];
    }
    tacticMap[tactic].push(t);
  });

  const totalTested = techniques.length;
  const successfulCount = techniques.filter(t => t.outcome === 'success').length;
  const blockedCount = techniques.filter(t => t.outcome === 'blocked').length;
  const failedCount = techniques.filter(t => t.outcome === 'failed').length;

  return (
    <div className="glass-panel" style={{ padding: '24px', borderRadius: '12px', marginBottom: '24px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '18px', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h2 style={{ fontSize: '18px', fontWeight: 700, color: '#f8fafc', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <Shield size={20} color="#ef4444" />
            MITRE ATT&amp;CK Coverage Heatmap
          </h2>
          <p style={{ fontSize: '13px', color: '#94a3b8', margin: '4px 0 0 0' }}>
            Technique x Outcome coverage matrix modeled after the MITRE ATT&amp;CK Navigator.
          </p>
        </div>

        {/* Coverage Metrics Pills */}
        <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
          <div style={{ background: '#0f172a', border: '1px solid #1e293b', padding: '6px 12px', borderRadius: '8px', fontSize: '12px' }}>
            <span style={{ color: '#94a3b8' }}>Tested: </span>
            <strong style={{ color: '#f8fafc' }}>{totalTested}</strong>
          </div>
          <div style={{ background: 'rgba(16, 185, 129, 0.1)', border: '1px solid #10b981', padding: '6px 12px', borderRadius: '8px', fontSize: '12px', color: '#10b981' }}>
            <span>Success: </span>
            <strong>{successfulCount}</strong>
          </div>
          <div style={{ background: 'rgba(239, 68, 68, 0.1)', border: '1px solid #ef4444', padding: '6px 12px', borderRadius: '8px', fontSize: '12px', color: '#ef4444' }}>
            <span>Blocked: </span>
            <strong>{blockedCount}</strong>
          </div>
          {failedCount > 0 && (
            <div style={{ background: 'rgba(100, 116, 139, 0.1)', border: '1px solid #64748b', padding: '6px 12px', borderRadius: '8px', fontSize: '12px', color: '#cbd5e1' }}>
              <span>Failed: </span>
              <strong>{failedCount}</strong>
            </div>
          )}
        </div>
      </div>

      {/* Heatmap Matrix Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '10px', overflowX: 'auto', paddingBottom: '10px' }}>
        {ALL_TACTICS.map(tactic => {
          const items = tacticMap[tactic] || [];
          const hasTested = items.length > 0;

          return (
            <div
              key={tactic}
              style={{
                background: '#090d16',
                border: `1px solid ${hasTested ? '#334155' : '#1e293b'}`,
                borderRadius: '8px',
                padding: '10px',
                display: 'flex',
                flexDirection: 'column',
                minHeight: '220px'
              }}
            >
              <div
                style={{
                  fontSize: '11px',
                  fontWeight: 700,
                  textTransform: 'uppercase',
                  color: hasTested ? '#38bdf8' : '#64748b',
                  borderBottom: '1px solid #1e293b',
                  paddingBottom: '6px',
                  marginBottom: '8px'
                }}
              >
                {tactic} ({items.length})
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', flexGrow: 1 }}>
                {items.length > 0 ? (
                  items.map((tech, idx) => {
                    const isSuccess = tech.outcome === 'success';
                    const isBlocked = tech.outcome === 'blocked';
                    const bg = isSuccess ? 'rgba(16, 185, 129, 0.15)' : (isBlocked ? 'rgba(239, 68, 68, 0.15)' : 'rgba(100, 116, 139, 0.15)');
                    const border = isSuccess ? '#10b981' : (isBlocked ? '#ef4444' : '#64748b');

                    return (
                      <div
                        key={idx}
                        onClick={() => setSelectedTech(tech)}
                        style={{
                          background: bg,
                          border: `1px solid ${border}`,
                          borderRadius: '6px',
                          padding: '8px',
                          cursor: 'pointer',
                          transition: 'transform 0.15s ease',
                          fontSize: '12px'
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                          <strong style={{ color: '#f8fafc' }}>{tech.technique_id}</strong>
                          <span
                            style={{
                              fontSize: '9px',
                              fontWeight: 700,
                              textTransform: 'uppercase',
                              padding: '1px 5px',
                              borderRadius: '3px',
                              background: isSuccess ? '#10b981' : (isBlocked ? '#ef4444' : '#64748b'),
                              color: '#ffffff'
                            }}
                          >
                            {tech.outcome}
                          </span>
                        </div>
                        <div style={{ color: '#cbd5e1', fontSize: '11px', marginTop: '3px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {tech.technique_name || tech.technique_id}
                        </div>
                      </div>
                    );
                  })
                ) : (
                  <div style={{ fontSize: '11px', color: '#475569', fontStyle: 'italic', textAlign: 'center', marginTop: '20px' }}>
                    Untested
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Selected Technique Detail Modal / Drawer */}
      {selectedTech && (
        <div className="modal-backdrop" onClick={() => setSelectedTech(null)}>
          <div className="glass-panel modal-card" style={{ maxWidth: '520px' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3 className="modal-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <ShieldAlert size={20} color="#ef4444" />
                MITRE Technique: {selectedTech.technique_id}
              </h3>
              <button className="btn-close" onClick={() => setSelectedTech(null)}>&times;</button>
            </div>

            <div style={{ padding: '20px' }}>
              <div style={{ background: '#090d16', padding: '14px', borderRadius: '8px', border: '1px solid #1e293b', marginBottom: '16px', fontSize: '13px' }}>
                <div><span style={{ color: '#94a3b8' }}>Name:</span> <strong>{selectedTech.technique_name}</strong></div>
                <div style={{ marginTop: '4px' }}><span style={{ color: '#94a3b8' }}>Tactic:</span> <strong>{selectedTech.tactic}</strong></div>
                <div style={{ marginTop: '4px' }}><span style={{ color: '#94a3b8' }}>Host Executed:</span> <code>{selectedTech.agent_hostname}</code></div>
                <div style={{ marginTop: '4px' }}>
                  <span style={{ color: '#94a3b8' }}>Outcome:</span>{' '}
                  <span
                    style={{
                      padding: '2px 8px',
                      borderRadius: '4px',
                      fontWeight: 700,
                      fontSize: '11px',
                      background: selectedTech.outcome === 'success' ? '#10b981' : '#ef4444',
                      color: 'white'
                    }}
                  >
                    {selectedTech.outcome.toUpperCase()}
                  </span>
                </div>
              </div>

              <h4 style={{ fontSize: '13px', color: '#cbd5e1', marginBottom: '6px' }}>Gemini AI Analysis &amp; Explanation</h4>
              <div style={{ background: 'rgba(14, 165, 233, 0.08)', border: '1px solid rgba(14, 165, 233, 0.3)', padding: '14px', borderRadius: '8px', fontSize: '13px', color: '#e2e8f0', lineHeight: 1.5 }}>
                {selectedTech.gemini_explanation || 'Technique was executed against target host.'}
              </div>

              <div style={{ marginTop: '16px', textAlign: 'right' }}>
                <a
                  href={`https://attack.mitre.org/techniques/${selectedTech.technique_id.split('.')[0]}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-secondary"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}
                >
                  <span>View on MITRE ATT&amp;CK</span>
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

