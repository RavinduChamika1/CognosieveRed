import pytest
from pathlib import Path
from schemas import ScanCreateRequest
from services.caldera_service import (
    CalderaService, VETTED_ABILITY_CATALOG, VETTED_ADVERSARY_PROFILES
)
from services.gemini_service import GeminiService
from services.report_service import ReportService
from database import init_db, create_scan_record, get_scan_record, save_redteam_operation


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


def test_redteam_input_validation_and_gating():
    # 1. When redteam_enabled is False, red team fields are optional
    req1 = ScanCreateRequest(
        target_url="https://example.com",
        authorization_confirmation=True,
        redteam_enabled=False
    )
    assert req1.redteam_enabled is False
    assert req1.caldera_group_name is None

    # 2. When redteam_enabled is True, lab_authorization_confirmation is REQUIRED
    with pytest.raises(ValueError, match="lab_authorization_confirmation must be True"):
        ScanCreateRequest(
            target_url="https://example.com",
            authorization_confirmation=True,
            redteam_enabled=True,
            caldera_group_name="lab-group-1",
            redteam_objective="Test lateral movement",
            lab_authorization_confirmation=False
        )

    # 3. When redteam_enabled is True, caldera_group_name is REQUIRED
    with pytest.raises(ValueError, match="caldera_group_name is required"):
        ScanCreateRequest(
            target_url="https://example.com",
            authorization_confirmation=True,
            redteam_enabled=True,
            caldera_group_name="",
            redteam_objective="Test lateral movement",
            lab_authorization_confirmation=True
        )

    # 4. When redteam_enabled is True, redteam_objective is REQUIRED
    with pytest.raises(ValueError, match="redteam_objective is required"):
        ScanCreateRequest(
            target_url="https://example.com",
            authorization_confirmation=True,
            redteam_enabled=True,
            caldera_group_name="lab-group-1",
            redteam_objective="   ",
            lab_authorization_confirmation=True
        )

    # 5. Valid request passes
    req_valid = ScanCreateRequest(
        target_url="https://example.com",
        authorization_confirmation=True,
        redteam_enabled=True,
        caldera_group_name="cyber-range-alpha",
        redteam_objective="Emulate APT29 credential access and lateral movement",
        lab_authorization_confirmation=True
    )
    assert req_valid.redteam_enabled is True
    assert req_valid.caldera_group_name == "cyber-range-alpha"


@pytest.mark.asyncio
async def test_caldera_refuses_automatic_agent_deployment():
    service = CalderaService()
    # Attempting to verify an empty group fails with an explicit error
    with pytest.raises(ValueError, match="Caldera group name cannot be empty"):
        await service.verify_agent_group("")


@pytest.mark.asyncio
async def test_caldera_operation_mapping_to_attck_techniques():
    service = CalderaService()
    agents = await service.verify_agent_group("corp-lab")
    assert len(agents) >= 1

    plan = service.select_vetted_adversary_or_chain("Emulate APT29 lateral movement")
    assert "adversary_name" in plan
    assert len(plan["abilities"]) > 0

    op_result = await service.execute_emulation_operation(
        group_name="corp-lab",
        objective="Emulate APT29 lateral movement",
        adversary_info=plan,
        active_agents=agents
    )

    # Check mapping to ATT&CK tactics & technique IDs
    assert "techniques_run" in op_result
    assert len(op_result["techniques_run"]) > 0

    for t in op_result["techniques_run"]:
        assert t["technique_id"].startswith("T1")
        assert t["tactic"] in [
            "Discovery", "Credential Access", "Privilege Escalation",
            "Lateral Movement", "Persistence", "Collection", "Exfiltration"
        ]
        assert t["outcome"] in ("success", "failed", "blocked")
        assert len(t["agent_hostname"]) > 0


def test_attack_surface_graph_and_heatmap_builder():
    agents = [
        {"paw": "agent-win-01", "host": "srv-win01.lab.local", "platform": "windows"},
        {"paw": "agent-lin-01", "host": "srv-lin01.lab.local", "platform": "linux"}
    ]
    techniques = [
        {
            "technique_id": "T1082",
            "technique_name": "System Information Discovery",
            "tactic": "Discovery",
            "agent_hostname": "srv-win01.lab.local",
            "outcome": "success"
        },
        {
            "technique_id": "T1021.002",
            "technique_name": "SMB Lateral Pivot",
            "tactic": "Lateral Movement",
            "agent_hostname": "srv-lin01.lab.local",
            "outcome": "success"
        },
        {
            "technique_id": "T1053.005",
            "technique_name": "Scheduled Task Persistence",
            "tactic": "Persistence",
            "agent_hostname": "srv-lin01.lab.local",
            "outcome": "blocked"
        }
    ]
    facts = [
        {"host": "srv-win01.lab.local", "fact_type": "user", "value": "Administrator"}
    ]

    # Test Heatmap construction
    heatmap = CalderaService.build_attck_heatmap(techniques)
    assert len(heatmap) == 3
    t1 = next(h for h in heatmap if h["technique_id"] == "T1082")
    assert t1["tactic"] == "Discovery"
    assert t1["tested"] is True
    assert t1["outcome"] == "success"

    # Test Attack Surface Graph construction
    graph = CalderaService.build_attack_surface_graph(agents, techniques, facts)
    assert "nodes" in graph
    assert "edges" in graph
    assert len(graph["nodes"]) == 2

    # Node attributes
    node_win = next(n for n in graph["nodes"] if n["id"] == "agent-win-01")
    assert node_win["hostname"] == "srv-win01.lab.local"
    assert node_win["status"] in ("compromised", "controlled", "untouched")
    assert len(node_win["facts"]) == 1

    # Edge attributes
    assert len(graph["edges"]) >= 1
    edge = graph["edges"][0]
    assert "from" in edge
    assert "to" in edge
    assert "technique_id" in edge


def test_sensitive_fact_redaction():
    service = CalderaService()
    raw_facts = [
        {"host": "srv-01", "fact_type": "open_port", "value": "445/TCP"},
        {"host": "srv-01", "fact_type": "user_password", "value": "SuperSecretPass123!"},
        {"host": "srv-02", "fact_type": "ntlm_hash", "value": "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"}
    ]
    redacted, sensitive = service._redact_discovered_facts(raw_facts)

    # Open port is non-sensitive
    assert redacted[0]["value"] == "445/TCP"

    # Password is redacted by default
    assert "REDACTED" in redacted[1]["value"]
    assert "SuperSecretPass123!" not in redacted[1]["value"]

    # Hash is redacted by default
    assert "REDACTED" in redacted[2]["value"]

    # Sensitive list retains unredacted values under explicit section
    assert len(sensitive) == 2
    assert sensitive[0]["value"] == "SuperSecretPass123!"
    assert sensitive[1]["value"] == "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"


def test_gemini_planner_selects_only_vetted_abilities():
    gemini = GeminiService()
    plan = gemini.plan_redteam_operation(
        objective="Test lateral movement and credential discovery",
        available_profiles=VETTED_ADVERSARY_PROFILES,
        ability_catalog=VETTED_ABILITY_CATALOG
    )

    assert "adversary_name" in plan
    assert len(plan["abilities"]) > 0

    # SAFETY CHECK: every ability returned MUST be in the vetted catalog
    for ab in plan["abilities"]:
        assert ab["ability_id"] in VETTED_ABILITY_CATALOG
        assert ab["technique_id"].startswith("T")


def test_redteam_report_section_presence(tmp_path):
    sample_scan = {
        "id": "scan-rt-001",
        "target_url": "https://example.com",
        "in_scope": "*.example.com",
        "out_of_scope": "",
        "scan_mode": "passive",
        "active_scan_confirmed": False,
        "authorized_at": "2026-11-04T12:00:00Z",
        "business_impact_multiplier": 1.0,
        "exposure_factor": 1.0,
        "summary": {"overall_risk_score": 7.2, "critical": 0, "high": 1, "medium": 1, "low": 0, "novel_patterns": 0}
    }

    sample_redteam_op = {
        "objective": "Emulate APT29 Lateral Movement",
        "caldera_group_name": "range-alpha",
        "adversary_profile_or_chain_used": "APT29 Emulation",
        "techniques_run": [
            {
                "technique_id": "T1082",
                "technique_name": "System Info Discovery",
                "tactic": "Discovery",
                "agent_hostname": "lab-host-01",
                "outcome": "success",
                "gemini_explanation": "Reconnaissance verified OS patch level."
            }
        ],
        "facts_discovered": [{"host": "lab-host-01", "fact_type": "user", "value": "test-admin"}],
        "sensitive_data_found": [{"host": "lab-host-01", "fact_type": "password", "value": "secret"}],
        "attck_heatmap": [{"technique_id": "T1082", "technique_name": "System Info Discovery", "tactic": "Discovery", "tested": True, "outcome": "success"}],
        "gemini_narrative": "Adversary successfully performed initial host discovery."
    }

    # 1. Without red team operation -> Section is omitted
    html_without = ReportService.generate_html_report(sample_scan, [])
    assert "Red Team Operation" not in html_without
    assert "MITRE Caldera" not in html_without

    # 2. With red team operation -> Section is present
    html_with = ReportService.generate_html_report(sample_scan, [], redteam_operation=sample_redteam_op)
    assert "Red Team Operation" in html_with
    assert "MITRE Caldera" in html_with
    assert "APT29 Lateral Movement" in html_with
    assert "T1082" in html_with
    assert "Sensitive Data Found" in html_with

    # 3. PDF generation with red team operation
    pdf_out = tmp_path / "report_with_redteam.pdf"
    ReportService.generate_pdf_report(sample_scan, [], str(pdf_out), redteam_operation=sample_redteam_op)
    assert pdf_out.exists()
    assert pdf_out.stat().st_size > 1000

