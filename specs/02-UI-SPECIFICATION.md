# ForensicOps AI — User Interface & Frontend Specification

## 1. Tech Stack
- React 18 + TypeScript + Vite + Tailwind CSS + **React Flow** (n8n-style workflow canvas) + Zustand.

## 2. Core UI Views (`frontend/src/components/`)

### A. 3-Mode Environment Wizard (`EnvironmentWizard.tsx`)
- **Step 1:** Choose **Offline Evidence**, **Online SSH/WinRM Collector**, or **Hybrid SIEM (Elastic / Wazuh / Splunk)**.
- **Step 2:** Configure upload/read-only path, SSH host + RFC 3227 volatility checkboxes, or SIEM endpoint URL/port/auth reference.
- **Step 3:** Live SHA-256/SHA-512 intake verification table and Chain of Custody initialization.

### B. n8n-Style Workflow Canvas (`WorkflowCanvas.tsx`)
- **Starter Blueprints Dropdown:** 1-click pre-wired graphs (*Windows Logon -> PowerShell -> Persistence*, *Full Windows Triage*, *Linux SSH & Rootkit Hunt*, *RAM + PCAP Malware Hunt*).
- **Node Palette:** Evidence Input, Built-in `Dissect`, Chainsaw (Sigma), Zimmerman Tools (`EvtxECmd`, `RECmd`, `PECmd`), Volatility 3, YARA, SIEM Query, AI Goal Step, Human Approval Gate, Cited Report Compiler.
- **Per-Node Goal Box:** Clicking any `AI Goal Step` node lets the analyst enter a plain-English objective (e.g., *"Look for failed logins in EVTX and pass the compromised account downstream"*).
- **Live Wire Pivot Badges:** Displays extracted `WorkflowEdgePayload` pivots (`users`, `ips`, `timestamps`, `file_paths`) moving along edges.

### C. Visual Custom Tool Onboarding Wizard (`PluginManagerModal.tsx`)
- Zero-YAML 4-step modal to add any custom forensic binary or script:
  1. Pick executable binary, select input artifact type, and click `[Input File]` / `[Output File]` command pills.
  2. Click **"Dry-Run on Sample"** to execute inside the air-gapped sandbox and preview the first 5 output rows.
  3. Confirm AI auto-mapped dropdowns (`timestamp_utc`, `summary`, `severity`, `event_id`) and checkboxes for `ai_keep_fields` (Column Projection).
  4. Saves `plugins/<tool_id>.yaml` in the background and adds the node to the sidebar.

### D. Cited Report Viewer & v2.0 Human Feedback Controls (`CitedReportViewer.tsx`)
- Renders the 6-section report: Executive Summary & Timeline, Custody & Filter Audit Table, Observed Facts, Derived Correlations, AIFT 4-Part Rubric (*Why It Matters*, *Alternative Benign Explanation*, *How to Verify*, *Explicit Data Gaps*), Multi-Host Patient Zero Assessment, and Remediation.
- **Clickable Citation Drawer:** Clicking `[Finding: fnd-xxx | SHA-256: ...]` opens the raw tool record.
- **v2.0 Learning Loop Micro-Controls:** Every finding card includes `[👍 Confirm TP]`, `[🛡️ Mark Benign Org Baseline]`, and `[✏️ Correct Query/Rule]` buttons wired to `POST /api/feedback`.
