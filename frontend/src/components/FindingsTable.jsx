import React, { useState, useMemo } from 'react';
import { Search, Filter, Sparkles, ExternalLink, ShieldAlert, CheckCircle2, AlertCircle, RefreshCw } from 'lucide-react';

export default function FindingsTable({ findings = [], onSelectFinding }) {
  const [search, setSearch] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [verdictFilter, setVerdictFilter] = useState('ALL');
  const [novelOnly, setNovelOnly] = useState(false);

  const safeFindings = useMemo(() => Array.isArray(findings) ? findings : [], [findings]);

  // Aggregate counts
  const totalCount = safeFindings.length;
  const confirmedCount = safeFindings.filter(f => (f.ai_verdict || '').toLowerCase() === 'confirmed').length;
  const needsReviewCount = safeFindings.filter(f => (f.ai_verdict || '').toLowerCase() === 'needs_review').length;
  const fpCount = safeFindings.filter(f => (f.ai_verdict || '').toLowerCase() === 'false_positive').length;
  const novelCount = safeFindings.filter(f => Boolean(f.novel_pattern_flag)).length;
  const activeCount = confirmedCount + needsReviewCount;

  const filtered = useMemo(() => {
    return safeFindings.filter(f => {
      // Search
      const q = search.trim().toLowerCase();
      if (q) {
        const matchSearch =
          (f.finding_id && f.finding_id.toLowerCase().includes(q)) ||
          (f.title && f.title.toLowerCase().includes(q)) ||
          (f.cwe_id && f.cwe_id.toLowerCase().includes(q)) ||
          (f.affected_url && f.affected_url.toLowerCase().includes(q)) ||
          (f.owasp_category && f.owasp_category.toLowerCase().includes(q)) ||
          (f.severity && f.severity.toLowerCase().includes(q)) ||
          (f.ai_verdict && f.ai_verdict.toLowerCase().includes(q));

        if (!matchSearch) return false;
      }

      // Severity Filter
      if (severityFilter !== 'ALL' && f.severity !== severityFilter) {
        return false;
      }

      // Verdict Filter
      const verdict = (f.ai_verdict || '').toLowerCase();
      if (verdictFilter === 'ACTIVE') {
        if (verdict === 'false_positive') return false;
      } else if (verdictFilter !== 'ALL' && verdict !== verdictFilter.toLowerCase()) {
        return false;
      }

      // Novel pattern Filter
      if (novelOnly && !f.novel_pattern_flag) {
        return false;
      }

      return true;
    });
  }, [safeFindings, search, severityFilter, verdictFilter, novelOnly]);

  const resetFilters = () => {
    setSearch('');
    setSeverityFilter('ALL');
    setVerdictFilter('ALL');
    setNovelOnly(false);
  };

  const getSeverityClass = (sev) => {
    return (sev || 'medium').toLowerCase();
  };

  const formatCvss = (score) => {
    if (typeof score === 'number') return score.toFixed(1);
    if (!score) return '0.0';
    return String(score);
  };

  return (
    <div className="glass-panel findings-container" style={{ marginBottom: '24px' }}>
      <div className="findings-toolbar" style={{ flexWrap: 'wrap', gap: '14px' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <h3 style={{ fontSize: '18px', fontWeight: 700, margin: 0 }}>
              Triaged Vulnerability Findings ({filtered.length} of {totalCount})
            </h3>
            {totalCount > 0 && (
              <span style={{ fontSize: '12px', background: '#1e293b', padding: '2px 8px', borderRadius: '6px', color: '#94a3b8' }}>
                {activeCount} Active • {fpCount} AI Filtered
              </span>
            )}
          </div>
          <p style={{ fontSize: '12px', color: '#94a3b8', margin: '4px 0 0 0' }}>
            Audited via OWASP ZAP &amp; Google Gemini AI false-positive analysis. Click any row to inspect HTTP evidence and remediation guidance.
          </p>
        </div>

        {/* Search and Dropdown Controls */}
        <div className="filter-group" style={{ display: 'flex', gap: '8px', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ position: 'relative' }}>
            <input
              type="text"
              className="search-input"
              placeholder="Search findings, CWE, URL, verdict..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              style={{ paddingLeft: '32px', minWidth: '220px' }}
            />
            <Search size={14} color="#64748b" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
          </div>

          <select
            className="form-select"
            style={{ width: 'auto', padding: '8px 12px', fontSize: '13px' }}
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="Critical">Critical</option>
            <option value="High">High</option>
            <option value="Medium">Medium</option>
            <option value="Low">Low</option>
          </select>

          <select
            className="form-select"
            style={{ width: 'auto', padding: '8px 12px', fontSize: '13px' }}
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
          >
            <option value="ALL">All Verdicts ({totalCount})</option>
            <option value="ACTIVE">Confirmed &amp; Review ({activeCount})</option>
            <option value="confirmed">Confirmed Only ({confirmedCount})</option>
            <option value="needs_review">Needs Review Only ({needsReviewCount})</option>
            <option value="false_positive">False Positives ({fpCount})</option>
          </select>

          <button
            type="button"
            className={`btn ${novelOnly ? 'btn-primary' : 'btn-secondary'}`}
            style={{ padding: '8px 12px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '6px' }}
            onClick={() => setNovelOnly(!novelOnly)}
          >
            <Sparkles size={14} />
            <span>Novel ({novelCount})</span>
          </button>

          {(search || severityFilter !== 'ALL' || verdictFilter !== 'ALL' || novelOnly) && (
            <button
              type="button"
              className="btn btn-secondary"
              style={{ padding: '8px 10px', fontSize: '12px', display: 'flex', alignItems: 'center', gap: '4px' }}
              onClick={resetFilters}
              title="Reset all filters"
            >
              <RefreshCw size={12} />
              <span>Reset</span>
            </button>
          )}
        </div>
      </div>

      {/* Quick Filter Status Badges */}
      <div style={{ display: 'flex', gap: '8px', padding: '0 20px 14px 20px', flexWrap: 'wrap', borderBottom: '1px solid #1e293b' }}>
        <button
          onClick={() => setVerdictFilter('ALL')}
          style={{
            background: verdictFilter === 'ALL' ? 'rgba(56, 189, 248, 0.15)' : '#0f172a',
            border: `1px solid ${verdictFilter === 'ALL' ? '#38bdf8' : '#1e293b'}`,
            color: verdictFilter === 'ALL' ? '#38bdf8' : '#94a3b8',
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '11px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          All Findings: {totalCount}
        </button>

        <button
          onClick={() => setVerdictFilter('confirmed')}
          style={{
            background: verdictFilter === 'confirmed' ? 'rgba(239, 68, 68, 0.15)' : '#0f172a',
            border: `1px solid ${verdictFilter === 'confirmed' ? '#ef4444' : '#1e293b'}`,
            color: verdictFilter === 'confirmed' ? '#f87171' : '#94a3b8',
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '11px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Confirmed: {confirmedCount}
        </button>

        <button
          onClick={() => setVerdictFilter('needs_review')}
          style={{
            background: verdictFilter === 'needs_review' ? 'rgba(245, 158, 11, 0.15)' : '#0f172a',
            border: `1px solid ${verdictFilter === 'needs_review' ? '#f59e0b' : '#1e293b'}`,
            color: verdictFilter === 'needs_review' ? '#fbbf24' : '#94a3b8',
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '11px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          Needs Review: {needsReviewCount}
        </button>

        <button
          onClick={() => setVerdictFilter('false_positive')}
          style={{
            background: verdictFilter === 'false_positive' ? 'rgba(16, 185, 129, 0.15)' : '#0f172a',
            border: `1px solid ${verdictFilter === 'false_positive' ? '#10b981' : '#1e293b'}`,
            color: verdictFilter === 'false_positive' ? '#34d399' : '#94a3b8',
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '11px',
            fontWeight: 600,
            cursor: 'pointer'
          }}
        >
          False Positives: {fpCount}
        </button>
      </div>

      {/* Table Data */}
      <div style={{ overflowX: 'auto' }}>
        <table className="findings-table">
          <thead>
            <tr>
              <th style={{ width: '10%' }}>ID</th>
              <th style={{ width: '30%' }}>Vulnerability Title &amp; Target</th>
              <th style={{ width: '10%' }}>Severity</th>
              <th style={{ width: '8%' }}>CVSS</th>
              <th style={{ width: '12%' }}>CWE ID</th>
              <th style={{ width: '14%' }}>AI Verdict</th>
              <th style={{ width: '8%' }}>Novel</th>
              <th style={{ width: '8%', textAlign: 'right' }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ textAlign: 'center', padding: '40px 20px', color: '#94a3b8' }}>
                  <ShieldAlert size={36} color="#64748b" style={{ margin: '0 auto 10px', display: 'block' }} />
                  <div style={{ color: '#f8fafc', fontWeight: 600, fontSize: '14px' }}>
                    {totalCount === 0 ? 'No security findings recorded for this scan.' : 'No findings matching current filter criteria.'}
                  </div>
                  {totalCount > 0 && (
                    <button
                      className="btn btn-secondary"
                      style={{ marginTop: '12px', fontSize: '12px', padding: '6px 14px' }}
                      onClick={resetFilters}
                    >
                      Reset Filters (Show {totalCount} Findings)
                    </button>
                  )}
                </td>
              </tr>
            ) : (
              filtered.map((f) => (
                <tr
                  key={f.id || f.finding_id}
                  onClick={() => onSelectFinding(f)}
                  style={{ cursor: 'pointer' }}
                >
                  <td style={{ fontFamily: 'monospace', fontWeight: 700, color: '#38bdf8' }}>
                    {f.finding_id}
                  </td>
                  <td>
                    <div style={{ fontWeight: 600, color: '#f8fafc' }}>{f.title}</div>
                    <div style={{ fontSize: '11px', color: '#94a3b8', fontFamily: 'monospace', wordBreak: 'break-all', marginTop: '2px' }}>
                      {f.affected_url}
                    </div>
                  </td>
                  <td>
                    <span className={`severity-pill ${getSeverityClass(f.severity)}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontWeight: 700 }}>
                    {formatCvss(f.cvss_score)}
                  </td>
                  <td style={{ fontFamily: 'monospace' }}>
                    {f.cwe_id}
                  </td>
                  <td>
                    <span className={`verdict-badge ${(f.ai_verdict || 'confirmed').toLowerCase()}`}>
                      {(f.ai_verdict || '').toLowerCase() === 'confirmed'
                        ? 'Confirmed'
                        : (f.ai_verdict || '').toLowerCase() === 'needs_review'
                        ? 'Needs Review'
                        : 'False Positive'}
                    </span>
                  </td>
                  <td>
                    {f.novel_pattern_flag ? (
                      <span className="novel-tag">Novel</span>
                    ) : (
                      <span style={{ color: '#64748b', fontSize: '12px' }}>&mdash;</span>
                    )}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-secondary"
                      style={{ padding: '4px 8px', fontSize: '11px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                      onClick={(e) => {
                        e.stopPropagation();
                        onSelectFinding(f);
                      }}
                    >
                      <ExternalLink size={12} />
                      <span>Inspect</span>
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
