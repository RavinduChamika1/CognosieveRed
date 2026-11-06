<p align="center">
  <img src="assets/logo.svg" alt="CognoSieve" width="170">
</p>

<h1 align="center">CognoSieve</h1>
<p align="center"><b>Unified Cyber Assessment Platform: DAST, LLM Security &amp; red-teaming & Adversary Emulation</b></p>

<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/Backend-FastAPI%20(Python%203.14)-009688?logo=fastapi&logoColor=white">
  <img alt="React" src="https://img.shields.io/badge/Frontend-React%2019-61DAFB?logo=react&logoColor=white">
  <img alt="ZAP" src="https://img.shields.io/badge/Web%20Scan-OWASP%20ZAP-FF6600">
  <img alt="promptfoo" src="https://img.shields.io/badge/LLM%20Red--Team-promptfoo-6366F1">
  <img alt="Caldera" src="https://img.shields.io/badge/Adversary%20Emulation-MITRE%20Caldera-DC2626">
  <img alt="Gemini" src="https://img.shields.io/badge/AI-Gemini-8E75B2">
  <img alt="License" src="https://img.shields.io/badge/License-MIT-green">
  <img alt="Tests" src="https://img.shields.io/badge/tests-29%20passing-success">
</p>

<p align="center">
  <b>One platform, three attack surfaces: the web app, the LLM inside it, and the network behind it.</b>
</p>

<p align="center">
  <a href="#-quick-start">Quick start</a> ·
  <a href="#-why-cognosieve-exists">Why this exists</a> ·
  <a href="#-how-it-works">How it works</a> ·
  <a href="#-api-keys">API keys</a> ·
  <a href="#-security-notes-and-honest-limitations">Limitations</a>
</p>

---

## 📌 Table of contents
- [Why CognoSieve exists](#-why-cognosieve-exists)
- [Who this helps](#-who-this-helps)
- [Why this is different from running three separate tools](#-why-this-is-different-from-running-three-separate-tools)
- [Features](#-features)
- [How it works](#-how-it-works)
- [API keys](#-api-keys)
- [Quick start](#-quick-start)
- [Usage](#-usage)
- [Example output](#-example-output)
- [Project structure](#-project-structure)
- [Testing](#-testing)
- [Safety controls actually implemented](#-safety-controls-actually-implemented)
- [Security notes and honest limitations](#-security-notes-and-honest-limitations)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [Author](#-author)
- [License](#-license)

---

## 🎯 Why CognoSieve exists

A modern application's attack surface rarely stops at the web layer. There's the web app itself, there's often an LLM feature living inside it, and there's the network and hosts behind it that a real adversary would try to move through after an initial foothold. Most toolchains test these three things with three separate tools, three separate reports, and no shared risk picture.

**CognoSieve tests all three in one platform.** OWASP ZAP covers the web layer. A promptfoo-powered red-team stage covers the LLM layer against the OWASP Top 10 for LLM Applications. A MITRE Caldera-powered adversary emulation module covers post-foothold behavior, lateral movement, discovery, persistence, mapped to MITRE ATT&CK, against lab machines you control. Every finding from all three, web, LLM, and red team, is triaged by Gemini AI and lands in one report with one risk score.

CognoSieve began as **BreachSieve** (Weeks 4-6) and was upgraded in place twice: once to add Web VAPT and LLM VAPT now it has again to add red-teaming & adversary emulation.

---

## 👥 Who this helps

| Audience | What CognoSieve gives them |
|---|---|
| **AppSec / pentest teams** | One tool covering the web, LLM, and post-foothold network layers of the same engagement |
| **Red teamers** | AI-assisted technique planning against a vetted ATT&CK ability library, plus a visual attack-surface map and coverage heatmap generated automatically from the operation |
| **Purple / blue teams** | A clear, per-technique record of what was actually tested, to check against what their detection stack caught |
| **Teams shipping an AI feature** | A repeatable OWASP LLM Top 10 check before an AI feature goes live |
| **Corporate VA teams** | One risk-adjusted score and one audit trail across all three attack surfaces, for one compliance record |

---

## 🛡️ Why this is different from running three separate tools

| Three separate tools | **CognoSieve** |
|---|---|
| Three different report formats, three different places to look | One combined report: web findings, LLM findings, and the red team operation, all in one document |
| No shared risk score across tools | One overall risk score, computed from all three sources together |
| Each tool's false positives are your problem to sort out | Gemini triages findings from all three sources with the same confirmed / false_positive / needs_review logic and evidence-quoted reasoning |
| Adversary emulation tools can be pointed at anything you can reach | CognoSieve's red-team module **cannot** act on anything you haven't manually deployed its agent to yourself, no automatic remote deployment exists in the codebase, by design |
| AI red-team planners that can be asked to "just figure something out" | Gemini's technique planner is hard-restricted to a vetted MITRE ATT&CK ability catalog, it cannot generate novel attack commands |

> **Honest note:** no software can be guaranteed free of vulnerabilities, and CognoSieve doesn't claim to be. See [Security notes and honest limitations](#-security-notes-and-honest-limitations) for what that means in practice here.

---

## ✨ Features

**Web layer (OWASP ZAP)**
- Spider, passive scan, and active scan via ZAP's REST API, with a realistic offline simulator fallback
- Strict scope allow-list / deny-list: wildcards, path prefixes, CIDR ranges, and RFC-1918 private-IP gating, with out-of-scope rules always overriding in-scope ones
- Active scanning gated behind a dual-confirmation safety modal

**LLM layer (promptfoo)**
- Red-teams any `llm_endpoint_url` against all 10 OWASP LLM Top 10 (2025) categories
- Graceful skip with a clear reason if the promptfoo CLI isn't available

**Adversary emulation (MITRE Caldera, new)**
- Verifies a live, checked-in agent exists in the named lab group before doing anything, refuses to proceed otherwise
- Gemini plans the technique chain (either matching an existing adversary profile like an APT29 emulation, or reasoning a custom chain), choosing **only** from a vetted Caldera ability catalog, never inventing new attack commands
- Every technique executed is mapped to its MITRE ATT&CK tactic and technique ID directly from Caldera's own ability metadata
- **Attack Surface Map**: an interactive React Flow graph of which hosts were touched, in what order, by which technique
- **ATT&CK Coverage Heatmap**: a matrix of every technique tested and its outcome, across all 12 Enterprise tactics
- Discovered credentials, tokens, and password hashes are **redacted by default** everywhere (logs, UI, reports), shown only behind an explicit disclosure toggle

**AI triage (Gemini, shared across all three layers)**
- Evidence-quoted verdicts (confirmed / false_positive / needs_review) for web and LLM findings
- A dedicated operation narrator explaining what happened during a red-team run and what the defensive gap means
- Deterministic rule-based fallback if `GEMINI_API_KEY` is absent or unreachable

**Reporting**
- One combined HTML and PDF report; the Red Team section appears only when that module was used
- Full audit logging: every scope validation, engine execution, and AI verdict recorded in SQLite

---

## 🔬 How it works

```
 1. Submit the form: target_url (required) · llm_endpoint_url (optional)
    · scope rules · redteam_enabled + caldera_group_name + objective
    (optional) · all required authorization confirmations
         │
         ▼
 2. If redteam_enabled: verify a live agent exists in caldera_group_name,
    Gemini plans a technique chain from the vetted ability catalog, Caldera
    executes it, results map to ATT&CK, facts are redacted by default
         │
         ▼
 3. If llm_endpoint_url is set: promptfoo red-teams it against the
    OWASP LLM Top 10
         │
         ▼
 4. OWASP ZAP spiders and scans target_url (active scanning needs its
    own confirmation)
         │
         ▼
 5. Gemini triages every finding from all three sources, shared verdict logic
         │
         ▼
 6. One combined report: web findings, LLM findings (if tested), the
    Red Team Operation section (if tested) with its heatmap and attack
    surface map, one overall risk score
```

---

## 🔑 API keys

| Key | Required? | Notes |
|---|---|---|
| `GEMINI_API_KEY` | Optional. A deterministic fallback triages findings without it | Free at https://aistudio.google.com/ |
| `ZAP_API_KEY` | Optional, defaults to a built-in value | Set in ZAP's Options → API, or via docker-compose |
| `CALDERA_API_KEY` | Optional, **defaults to `ADMIN123`** | Self-generated in Caldera's `conf/local.yml` on first run, or set via docker-compose |
| `CALDERA_BASE_URL` | Optional, defaults to `http://caldera:8888` | Points at your Caldera daemon |

> ⚠️ **Change the default `ADMIN123` Caldera key before using this for anything beyond a fully isolated personal lab.** It's a well-known default credential; leaving it in place on any network-reachable Caldera instance is a real risk, not a hypothetical one.

Copy `.env.example` to `backend/.env` and fill in what you have.

---

## 🚀 Quick start

### With Docker (recommended)

```bash
git clone https://github.com/RavinduChamika1/cognosieve.git
cd cognosieve
cp .env.example backend/.env    # set GEMINI_API_KEY, ZAP_API_KEY, CALDERA_API_KEY
docker-compose up -d
```
- Frontend: **http://localhost:3000**
- Backend API & Swagger docs: **http://localhost:8000/docs**
- OWASP ZAP: **http://localhost:8080**
- MITRE Caldera: **http://localhost:8888**

### Without Docker

```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```
```bash
cd frontend
npm install
npm run dev
```

### Setting up the Red Team module specifically

The adversary emulation module needs a lab machine with a Caldera agent on it, deployed **manually, by you**, never automatically:

1. Log in to Caldera at `http://localhost:8888` (default `admin` / `ADMIN123`, **change this immediately**).
2. Go to **Agents → Deploy Agent**, copy the launch command shown.
3. Run that command **inside your own isolated lab VM**, never on a machine you don't fully control.
4. Confirm the agent checks into your chosen group (e.g. `corp-lab`), that's the `caldera_group_name` you'll use in CognoSieve's form.

---

## 💻 Usage

1. Fill in `target_url`. Add `llm_endpoint_url` only if you have permission to red-team that specific endpoint.
2. For adversary emulation: enable `redteam_enabled`, enter the `caldera_group_name` from your lab setup above, describe the `redteam_objective` in plain English (e.g. "emulate APT29 lateral movement and credential discovery"), and confirm `lab_authorization_confirmation`.
3. Confirm the main `authorization_confirmation`, covers every target you've provided.
4. Choose passive or active web scanning.
5. Watch the scan run, then read the combined report: web findings, an LLM Security section if tested, and a Red Team Operation section (with its heatmap and attack surface map) if tested.

**⚠️ `caldera_group_name` must only ever point at your own lab machines.** CognoSieve will refuse to run if no agent is checked into that group, by design, it cannot reach out and attack anything you haven't deliberately agented yourself.

**For the web side**, a safe, legal, public test target is `https://testphp.vulnweb.com`.

---

## 📺 Example output

A real adversary-emulation run against a lab group:

```json
{
  "scan_id": "07ef42a7-b12c-48f5-9261-9e217864fe00",
  "status": "completed",
  "summary": {
    "total_findings": 11, "medium": 2, "false_positives": 9,
    "overall_risk_score": 5.4
  },
  "redteam_operation": {
    "objective": "Emulate APT29 lateral movement and credential discovery",
    "caldera_group_name": "corp-lab",
    "adversary_profile_or_chain_used": "APT29 (Cozy Bear) Emulation",
    "techniques_run": [
      {
        "technique_id": "T1082",
        "technique_name": "System Information Discovery",
        "tactic": "Discovery",
        "agent_hostname": "lab-srv-win01.corp-lab.local",
        "outcome": "success",
        "gemini_explanation": "Reconnaissance queries verified operating system architecture without triggering security impedance."
      }
    ]
  }
}
```

Note how high the false-positive count is relative to total findings in this real run (9 of 11), that's the triage layer doing its job, not a flaw.

*(Add a dashboard screenshot here, `frontend/src/assets/hero.png` already exists in the repo but isn't referenced in this README yet.)*

---

## 🗂️ Project structure

```
cognosieve/
├── assets/
│   └── logo.svg, logo.png
├── backend/
│   ├── config.py, database.py, main.py, schemas.py
│   ├── requirements.txt, Dockerfile
│   ├── services/
│   │   ├── caldera_service.py      # NEW: Caldera REST client, agent verification, redaction
│   │   ├── gemini_service.py       # plan_redteam_operation, narrate_redteam_operation (NEW)
│   │   ├── llm_redteam.py
│   │   ├── mapping_engine.py
│   │   ├── remediation_engine.py
│   │   ├── report_service.py       # includes the new Red Team Operation section
│   │   ├── scan_orchestrator.py
│   │   ├── scope_manager.py
│   │   ├── scoring_engine.py
│   │   └── zap_service.py
│   └── tests/
│       ├── test_api_endpoints.py
│       ├── test_e2e_workflow.py
│       ├── test_llm_redteam.py
│       ├── test_redteam_caldera.py  # NEW: 7 tests
│       ├── test_report_service.py
│       ├── test_scope_manager.py
│       └── test_scoring_and_mapping.py
├── frontend/
│   └── src/
│       ├── App.jsx
│       ├── api/client.js
│       ├── assets/hero.png
│       └── components/
│           ├── AttackSurfaceMap.jsx   # NEW: React Flow graph
│           ├── AttckHeatmap.jsx       # NEW: ATT&CK coverage matrix
│           ├── ScanForm.jsx, FindingsTable.jsx, Header.jsx, and others
├── docker-compose.yml   # services: zap, caldera, backend, frontend
├── .env.example
├── LICENSE
└── README.md
```

---

## 🧪 Testing

```bash
cd backend
pytest tests/ -v
```

Last recorded run: **29 passed, 0 failed**, across 7 suites.

| Test file | Tests | What it covers |
|---|---|---|
| `test_redteam_caldera.py` | 7 | *(New)* input validation/gating, that automatic remote agent deployment is refused, ATT&CK technique mapping, the attack surface graph and heatmap builder, sensitive-fact redaction, that Gemini's planner only selects vetted abilities, and report section presence |
| `test_scoring_and_mapping.py` | 5 | CVSS scoring and CWE/OWASP/MITRE mapping |
| `test_api_endpoints.py` | 6 | Authorization enforcement, scope rejection, scan submission |
| `test_llm_redteam.py` | 4 | LLM endpoint validation and promptfoo results parsing |
| `test_scope_manager.py` | 4 | Wildcard, CIDR, path-prefix, out-of-scope-override logic |
| `test_report_service.py` | 2 | HTML/PDF report generation |
| `test_e2e_workflow.py` | 1 | The full pipeline end to end |

Run it yourself to confirm on your machine before relying on it.

---

## 🔒 Safety controls actually implemented

- **`lab_authorization_confirmation` gate** before any Caldera operation starts, separate from the main web/LLM authorization.
- **No automatic remote agent deployment**, confirmed absent from the codebase by design. Deployment is always a manual, out-of-band step you perform yourself.
- **Gemini's technique planner is hard-restricted** to a vetted Caldera ability catalog, it cannot generate or run arbitrary commands.
- **Sensitive data (credentials, tokens, hashes) is redacted by default** across logs, UI, and reports, visible only behind an explicit disclosure toggle.
- **Scope allow-list / deny-list** with RFC-1918 private-IP gating, and dual confirmation before active web scanning.
- **No hardcoded secrets**, all keys read from environment variables.

---

## 🛡️ Security notes and honest limitations

- **No claim of being vulnerability-free.** No software can honestly claim that. CognoSieve's own disclaimer states this plainly, and this README does the same rather than overpromising.
- **Change the default Caldera credential (`ADMIN123`) before any real use.** It ships as a default for easy local setup, not as something to leave in place.
- **Adversary emulation executes real commands on real machines.** Only ever run it against isolated, disposable lab VMs you fully control, never anything shared, production, or not entirely yours.
- **AI triage and technique planning are not infallible.** Generative models are non-deterministic; findings and plans should be validated by a qualified human, not acted on blindly.
- **This doesn't replace SAST or manual source code review.** DAST and LLM red-teaming cover dynamic behavior, not source-level issues.
- **When ZAP, Caldera, or Gemini aren't reachable, CognoSieve falls back to local simulation** rather than failing outright, know which mode you're actually testing in before trusting a result.

---

## 🗺️ Roadmap

Part of **52 Weeks of Security**: one new cybersecurity project every week.

- [x] **Week 1:** [PassVigil](https://github.com/RavinduChamika1/passvigil)
- [x] **Week 2:** [HashKiln](https://github.com/RavinduChamika1/hashkiln)
- [x] **Week 3:** [MimicLens](https://github.com/RavinduChamika1/mimiclens)
- [x] **Week 5:** [VetBinary](https://github.com/RavinduChamika1/VetBinary)
- [x] **Weeks 4-6:** CognoSieve (formerly BreachSieve): web DAST + LLM red-teaming
- [x] **Week 7:** CognoSieve: adversary emulation via MITRE Caldera, ATT&CK mapping, attack surface map
- [ ] More coming every week

Already noted in the codebase as next steps: dynamic Caldera ability profiles pulled from live MITRE ATT&CK CTI feeds, a bi-directional purple-team feedback loop correlating blue-team detection logs against Caldera technique timestamps, and automated promptfoo plugin generation derived from live web recon findings.

---

## 🤝 Contributing

1. Fork the repository
2. Create a branch: `git checkout -b feature/your-idea`
3. Make your changes and run `pytest tests/ -v`
4. Commit and push, then open a Pull Request

Found a bug or have an idea? [Open an issue](https://github.com/RavinduChamika1/cognosieve/issues).

---

## 👤 Author

**Ravindu Chamika**

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/ravindu-chamika/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?logo=github&logoColor=white)](https://github.com/RavinduChamika1)

If this helped you learn something, please ⭐ the repo and follow the series.

---

## 📄 License

Copyright © 2026 **Ravindu Chamika**. Released under the [MIT License](LICENSE).

This project orchestrates OWASP ZAP (Apache 2.0), promptfoo, MITRE Caldera, and the Google Gemini API; it does not modify or redistribute any of them, and inherits no capability beyond what those tools already provide.

<p align="center"><sub>Built for authorized, consent-aware security testing · 52 Weeks of Security · Week 7</sub></p>
