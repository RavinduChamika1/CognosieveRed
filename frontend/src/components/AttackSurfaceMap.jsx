import React, { useState, useMemo } from 'react';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  MarkerType
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Server, ShieldAlert, Key, Globe, X, Eye, EyeOff, AlertTriangle, Terminal, Network, ArrowRight } from 'lucide-react';

// Custom Node Component for Lab Agents/Hosts
function HostNode({ data, selected }) {
  const isCompromised = (data.status || '').toLowerCase() === 'compromised';
  const isControlled = (data.status || '').toLowerCase() === 'controlled';

  const borderColor = isControlled ? '#ef4444' : (isCompromised ? '#f59e0b' : '#3b82f6');
  const bgGlow = isControlled
    ? 'rgba(239, 68, 68, 0.25)'
    : (isCompromised ? 'rgba(245, 158, 11, 0.2)' : 'rgba(59, 130, 246, 0.15)');

  return (
    <div
      style={{
        padding: '14px 18px',
        borderRadius: '10px',
        background: '#0f172a',
        border: `2px solid ${borderColor}`,
        boxShadow: selected ? `0 0 20px ${borderColor}` : `0 4px 14px ${bgGlow}`,
        color: '#f8fafc',
        minWidth: 220,
        fontFamily: 'inherit',
        cursor: 'pointer',
        transition: 'all 0.2s ease',
        position: 'relative'
      }}
    >
      {/* Handles on all 4 sides for clean routing from any position */}
      <Handle type="target" position={Position.Top} id="top" style={{ background: borderColor, width: 8, height: 8 }} />
      <Handle type="source" position={Position.Bottom} id="bottom" style={{ background: borderColor, width: 8, height: 8 }} />
      <Handle type="target" position={Position.Left} id="left" style={{ background: borderColor, width: 8, height: 8 }} />
      <Handle type="source" position={Position.Right} id="right" style={{ background: borderColor, width: 8, height: 8 }} />

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Server size={18} color={borderColor} />
          <span style={{ fontWeight: 700, fontSize: '13px' }}>{data.hostname || data.id}</span>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px', marginTop: '6px' }}>
        <span style={{ color: '#94a3b8', textTransform: 'uppercase', fontWeight: 600 }}>{data.platform || 'Host'}</span>
        <span
          style={{
            padding: '2px 8px',
            borderRadius: '4px',
            fontSize: '10px',
            fontWeight: 800,
            textTransform: 'uppercase',
            background: isControlled ? 'rgba(239, 68, 68, 0.2)' : (isCompromised ? 'rgba(245, 158, 11, 0.2)' : 'rgba(59, 130, 246, 0.2)'),
            color: borderColor
          }}
        >
          {data.status || 'untouched'}
        </span>
      </div>

      {data.facts && data.facts.length > 0 && (
        <div style={{ marginTop: '10px', paddingTop: '8px', borderTop: '1px solid #1e293b', fontSize: '11px', color: '#38bdf8', display: 'flex', alignItems: 'center', gap: '4px' }}>
          <Terminal size={12} />
          <span>{data.facts.length} harvested fact(s)</span>
        </div>
      )}
    </div>
  );
}

const nodeTypes = {
  hostNode: HostNode
};

export default function AttackSurfaceMap({ redteamOperation }) {
  const [selectedNode, setSelectedNode] = useState(null);
  const [selectedEdge, setSelectedEdge] = useState(null);
  const [revealMasked, setRevealMasked] = useState(false);

  const graphData = redteamOperation?.attack_surface_graph || { nodes: [], edges: [] };
  const rawNodes = graphData.nodes || [];
  const rawEdges = graphData.edges || [];

  // Convert raw graph nodes to React Flow format with hierarchical tree layout
  const rfNodes = useMemo(() => {
    const total = rawNodes.length;
    return rawNodes.map((node, index) => {
      let x = 200;
      let y = 80;

      if (total === 1) {
        x = 340;
        y = 160;
      } else if (total === 2) {
        x = 300;
        y = index === 0 ? 70 : 280;
      } else if (index === 0) {
        x = 160 + Math.floor((total - 1) / 2) * 160;
        y = 70;
      } else {
        x = 100 + (index - 1) * 300;
        y = 280;
      }

      return {
        id: node.id,
        type: 'hostNode',
        position: { x, y },
        data: node
      };
    });
  }, [rawNodes]);

  // Convert raw graph edges to React Flow format
  const rfEdges = useMemo(() => {
    return rawEdges.map((edge, index) => {
      const sourceId = edge.from || edge.from_node || edge.source;
      const targetId = edge.to || edge.to_node || edge.target;
      const isSuccess = (edge.outcome || '').toLowerCase() === 'success';
      const isBlocked = (edge.outcome || '').toLowerCase() === 'blocked';
      const edgeColor = isSuccess ? '#10b981' : (isBlocked ? '#ef4444' : '#64748b');

      return {
        id: edge.id || `edge-${index}`,
        source: sourceId,
        target: targetId,
        sourceHandle: 'bottom',
        targetHandle: 'top',
        label: `${edge.technique_id} • ${edge.technique_name || edge.tactic || 'Lateral'}`,
        type: 'smoothstep',
        animated: isSuccess,
        interactionWidth: 24,
        style: { stroke: edgeColor, strokeWidth: 2.5 },
        labelStyle: { fill: '#f8fafc', fontWeight: 600, fontSize: 11 },
        labelBgStyle: { fill: '#0f172a', fillOpacity: 0.9, stroke: edgeColor, strokeWidth: 1 },
        labelBgPadding: [6, 4],
        labelBgBorderRadius: 4,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: edgeColor
        },
        data: edge
      };
    });
  }, [rawEdges]);

  const onNodeClick = (_, node) => {
    setSelectedEdge(null);
    setSelectedNode(node.data);
  };

  const onEdgeClick = (_, edge) => {
    setSelectedNode(null);
    setSelectedEdge(edge.data);
  };

  // Node telemetry facts partitioning
  const nodeFacts = selectedNode?.facts || [];
  const sensitiveFacts = nodeFacts.filter(f =>
    (f.fact_type || '').toLowerCase().includes('password') ||
    (f.fact_type || '').toLowerCase().includes('hash') ||
    (f.fact_type || '').toLowerCase().includes('credential') ||
    (f.value || '').includes('[REDACTED')
  );
  const generalFacts = nodeFacts.filter(f => !sensitiveFacts.includes(f));

  if (!rawNodes.length) {
    return (
      <div className="glass-panel" style={{ padding: '40px 20px', textAlign: 'center', color: '#94a3b8', marginBottom: '24px' }}>
        <Network size={44} color="#64748b" style={{ margin: '0 auto 12px' }} />
        <h3 style={{ color: '#f8fafc', fontSize: '16px', fontWeight: 600 }}>No Lab Agents Checked In</h3>
        <p style={{ fontSize: '13px', maxWidth: '480px', margin: '8px auto 0', lineHeight: 1.6 }}>
          Caldera agent group '{redteamOperation?.caldera_group_name || 'default'}' had no active checked-in hosts during execution.
          Deploy Caldera agents manually on your lab endpoints to visualize the attack topology.
        </p>
      </div>
    );
  }

  return (
    <div style={{ position: 'relative', width: '100%', height: '620px', background: '#0b1120', borderRadius: '12px', border: '1px solid #1e293b', overflow: 'hidden', marginBottom: '24px' }}>
      {/* Top Banner with Objective & Legend */}
      <div style={{ position: 'absolute', top: 12, left: 16, right: 16, zIndex: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px', pointerEvents: 'none' }}>
        <div style={{ background: 'rgba(15, 23, 42, 0.95)', padding: '8px 16px', borderRadius: '8px', border: '1px solid #334155', fontSize: '12px', color: '#e2e8f0', display: 'flex', gap: '14px', pointerEvents: 'auto', flexWrap: 'wrap' }}>
          <span><strong>Objective:</strong> {redteamOperation?.objective || 'Adversary Emulation'}</span>
          <span><strong>Profile:</strong> <span style={{ color: '#38bdf8' }}>{redteamOperation?.adversary_profile_or_chain_used || 'Caldera Technique Chain'}</span></span>
          <span><strong>Group:</strong> <span style={{ color: '#a855f7' }}>{redteamOperation?.caldera_group_name || 'Lab Group'}</span></span>
        </div>

        {/* Legend */}
        <div style={{ background: 'rgba(15, 23, 42, 0.95)', padding: '6px 14px', borderRadius: '8px', border: '1px solid #334155', fontSize: '11px', display: 'flex', gap: '12px', pointerEvents: 'auto', alignItems: 'center' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#ef4444' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ef4444' }}></span> Controlled
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#f59e0b' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#f59e0b' }}></span> Compromised
          </span>
          <span style={{ display: 'flex', alignItems: 'center', gap: '4px', color: '#10b981' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#10b981' }}></span> Pivoted
          </span>
        </div>
      </div>

      {/* React Flow Canvas */}
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        onNodeClick={onNodeClick}
        onEdgeClick={onEdgeClick}
        fitView
      >
        <Background color="#1e293b" gap={18} />
        <Controls style={{ background: '#0f172a', border: '1px solid #334155', color: '#f8fafc' }} />
        <MiniMap
          nodeColor={(n) => {
            const st = (n.data?.status || '').toLowerCase();
            return st === 'controlled' ? '#ef4444' : (st === 'compromised' ? '#f59e0b' : '#3b82f6');
          }}
          style={{ background: '#0f172a', border: '1px solid #334155' }}
        />
      </ReactFlow>

      {/* Selected Node Facts Drawer */}
      {selectedNode && (
        <div
          style={{
            position: 'absolute',
            top: 0,
            right: 0,
            width: '380px',
            height: '100%',
            background: 'rgba(15, 23, 42, 0.97)',
            borderLeft: '1px solid #334155',
            backdropFilter: 'blur(10px)',
            padding: '22px',
            zIndex: 30,
            overflowY: 'auto',
            boxShadow: '-6px 0 24px rgba(0,0,0,0.5)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Server size={18} color="#38bdf8" />
              <h3 style={{ fontSize: '15px', color: '#f8fafc', margin: 0, fontWeight: 700 }}>Host Telemetry</h3>
            </div>
            <button
              onClick={() => setSelectedNode(null)}
              style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '4px' }}
            >
              <X size={18} />
            </button>
          </div>

          <div style={{ background: '#1e293b', padding: '12px 14px', borderRadius: '8px', marginBottom: '16px', fontSize: '12px' }}>
            <div><span style={{ color: '#94a3b8' }}>Hostname:</span> <strong style={{ color: '#f8fafc' }}>{selectedNode.hostname}</strong></div>
            <div style={{ marginTop: '4px' }}><span style={{ color: '#94a3b8' }}>Platform:</span> <strong style={{ color: '#38bdf8' }}>{selectedNode.platform}</strong></div>
            <div style={{ marginTop: '4px' }}>
              <span style={{ color: '#94a3b8' }}>Status:</span>{' '}
              <strong style={{ color: selectedNode.status === 'controlled' ? '#ef4444' : '#f59e0b', textTransform: 'uppercase' }}>
                {selectedNode.status}
              </strong>
            </div>
          </div>

          {/* General Telemetry Facts */}
          <h4 style={{ fontSize: '13px', color: '#cbd5e1', marginBottom: '8px', fontWeight: 600 }}>Harvested Host Telemetry ({generalFacts.length})</h4>
          {generalFacts.length > 0 ? (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginBottom: '18px' }}>
              {generalFacts.map((fact, i) => (
                <div key={i} style={{ background: '#090d16', padding: '10px 12px', borderRadius: '6px', border: '1px solid #1e293b', fontSize: '12px' }}>
                  <div style={{ color: '#94a3b8', fontSize: '10px', textTransform: 'uppercase', fontWeight: 700 }}>{fact.fact_type}</div>
                  <div style={{ color: '#38bdf8', fontFamily: 'monospace', marginTop: '4px', wordBreak: 'break-all' }}>{fact.value}</div>
                </div>
              ))}
            </div>
          ) : (
            <p style={{ fontSize: '12px', color: '#64748b', marginBottom: '16px' }}>No general host telemetry captured.</p>
          )}

          {/* Sensitive / Credentials Section with Explicit Expansion */}
          {sensitiveFacts.length > 0 && (
            <div style={{ borderTop: '1px solid #334155', paddingTop: '14px', marginTop: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <span style={{ fontSize: '12px', fontWeight: 700, color: '#f87171', display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <Key size={14} /> Sensitive Discovered Facts ({sensitiveFacts.length})
                </span>
                <button
                  onClick={() => setRevealMasked(!revealMasked)}
                  style={{
                    background: '#1e293b',
                    border: '1px solid #334155',
                    color: '#e2e8f0',
                    padding: '3px 8px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '4px'
                  }}
                >
                  {revealMasked ? <EyeOff size={12} /> : <Eye size={12} />}
                  <span>{revealMasked ? 'Mask' : 'Inspect'}</span>
                </button>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                {sensitiveFacts.map((fact, i) => (
                  <div key={i} style={{ background: 'rgba(239, 68, 68, 0.08)', padding: '10px 12px', borderRadius: '6px', border: '1px solid rgba(239, 68, 68, 0.3)', fontSize: '12px' }}>
                    <div style={{ color: '#f87171', fontSize: '10px', textTransform: 'uppercase', fontWeight: 700 }}>{fact.fact_type}</div>
                    <div style={{ color: '#fca5a5', fontFamily: 'monospace', marginTop: '4px', wordBreak: 'break-all' }}>
                      {revealMasked ? fact.value : '[REDACTED FOR SECURITY - CLICK INSPECT TO EXPAND]'}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Selected Edge Technique Detail Drawer */}
      {selectedEdge && (
        <div
          style={{
            position: 'absolute',
            top: 0,
            right: 0,
            width: '400px',
            height: '100%',
            background: 'rgba(15, 23, 42, 0.97)',
            borderLeft: '1px solid #334155',
            backdropFilter: 'blur(10px)',
            padding: '22px',
            zIndex: 30,
            overflowY: 'auto',
            boxShadow: '-6px 0 24px rgba(0,0,0,0.5)'
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <ShieldAlert size={18} color="#ef4444" />
              <h3 style={{ fontSize: '15px', color: '#f8fafc', margin: 0, fontWeight: 700 }}>ATT&amp;CK Technique Link</h3>
            </div>
            <button
              onClick={() => setSelectedEdge(null)}
              style={{ background: 'none', border: 'none', color: '#94a3b8', cursor: 'pointer', padding: '4px' }}
            >
              <X size={18} />
            </button>
          </div>

          <div style={{ background: '#1e293b', padding: '12px 14px', borderRadius: '8px', marginBottom: '16px', fontSize: '12px' }}>
            <div><span style={{ color: '#94a3b8' }}>Technique ID:</span> <strong style={{ color: '#38bdf8' }}>{selectedEdge.technique_id}</strong></div>
            <div style={{ marginTop: '4px' }}><span style={{ color: '#94a3b8' }}>Technique Name:</span> <strong style={{ color: '#f8fafc' }}>{selectedEdge.technique_name || selectedEdge.technique_id}</strong></div>
            <div style={{ marginTop: '4px' }}><span style={{ color: '#94a3b8' }}>Tactic:</span> <strong style={{ color: '#c084fc' }}>{selectedEdge.tactic || 'Lateral Movement'}</strong></div>
            <div style={{ marginTop: '4px' }}>
              <span style={{ color: '#94a3b8' }}>Outcome:</span>{' '}
              <strong style={{ color: (selectedEdge.outcome || '').toLowerCase() === 'success' ? '#10b981' : '#ef4444', textTransform: 'uppercase' }}>
                {selectedEdge.outcome || 'success'}
              </strong>
            </div>
          </div>

          <h4 style={{ fontSize: '13px', color: '#cbd5e1', marginBottom: '8px', fontWeight: 600 }}>Gemini AI Operational Narrative</h4>
          <div style={{ background: 'rgba(14, 165, 233, 0.08)', border: '1px solid rgba(14, 165, 233, 0.3)', padding: '14px', borderRadius: '8px', fontSize: '13px', color: '#e2e8f0', lineHeight: 1.6 }}>
            {selectedEdge.explanation || 'Adversary emulation technique executed across lab endpoints without detection interference.'}
          </div>
        </div>
      )}
    </div>
  );
}
