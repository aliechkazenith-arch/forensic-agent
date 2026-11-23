# ForensicOps AI — User Interface & Frontend Specification
## 0. Multi-User RBAC Login & Session Gate (`AuthGate.tsx`)

Before accessing the 3-Mode Environment Wizard (`EnvironmentWizard.tsx`) or other operational views, unauthenticated users are routed through the session gate in `AuthGate.tsx`:

### A. First-Boot Admin Setup Form
- **Trigger:** Rendered automatically if `GET /api/auth/status` indicates the SQLite `users` table is empty (`initialized: false`).
- **Fields:**
  - `Username` (e.g. `lead_admin`)
  - `Badge ID` (e.g. `BADGE-001`, alphanumeric DFIR credential ID)
  - `Full Name` (e.g. `Chief DFIR Investigator`)
  - `Master Password` & `Confirm Password` (hashed with `bcrypt`)
- **Action:** Submits to `POST /api/auth/setup` to create the initial `lead_investigator` account, immediately issues a JWT token, and proceeds to Case Selection.

### B. Investigator Login Card
- **Trigger:** Rendered when `initialized: true` and no valid JWT access token exists in `localStorage`.
- **Fields:** `Username / Badge ID` and `Password`.
- **Case Selection Dropdown:** Upon successful authentication, prompts the investigator to select an active case (or initialize a new Case ID) before mounting the main operational shell.

### C. Top Navigation Identity Bar (`Navbar.tsx`)
- Displays the active investigator's identity in the top-right header:
  - **Badge ID Pill:** `Badge: BADGE-XXX`
  - **Role Badge Chip:**
    - `lead_investigator`: `LEAD` (purple/gold gradient badge with crown/shield icon)
    - `soc_analyst`: `SOC ANALYST` (cyan/sky blue badge with terminal/zap icon)
    - `auditor`: `AUDITOR` (amber/slate badge with balance/eye icon)
  - **Manage Users Button:** Visible only to `lead_investigator`; opens `UserManagementModal.tsx`.
  - **Lock / Sign Out Button:** Clears JWT from storage, resets active state, and redirects to `AuthGate.tsx`.

### D. Lead User Management Modal (`UserManagementModal.tsx`)
- Accessible exclusively by `lead_investigator`.
- **User List Table:** Displays `Username`, `Badge ID`, `Role`, `Full Name`, `Created UTC`, and `Status (Active / Suspended)`.
- **Create User Form:** Allows Lead to register new `soc_analyst` and `auditor` accounts with unique `badge_id` and initial passwords.
- **Account Actions:** Toggle `Active / Suspended` status via `PATCH /api/auth/users/{user_id}/status`.

### E. Role-Based Permissions Matrix

| Feature / UI Component | `lead_investigator` | `soc_analyst` | `auditor` |
| :--- | :---: | :---: | :---: |
| **First-Boot Admin Setup** | Initialized Once | N/A | N/A |
| **User Management (`UserManagementModal.tsx`)** | Full Access | Hidden / 403 | Hidden / 403 |
| **Offline Evidence Intake (`EnvironmentWizard.tsx`)** | Allowed | Allowed | Read-Only |
| **Online Collector Dispatch (`Invoke-ForensicCollector`)** | Direct Approval | Request Lead Approval | Hidden / Blocked |
| **Workflow Studio (`WorkflowCanvas.tsx`)** | Edit & Run | Edit & Run | Read-Only (Run Button Hidden) |
| **Custom Tool Onboarding (`PluginManagerModal.tsx`)** | Allowed | Allowed | Hidden |
| **Cited Report Viewer (`CitedReportViewer.tsx`)** | Full View | Full View | Full View |
| **Human Feedback Micro-Controls (`[👍 TP] / [🛡️ Benign]`)** | Enabled | Enabled | Hidden / Read-Only |
| **Cryptographic Custody Ledger (`CustodyLedgerModal.tsx`)** | Full View & Verify | Full View & Verify | Full View & Verify (Primary Role) |
| **Ledger Actor Attribution** | `actor: user (badge) [LEAD]` | `actor: user (badge) [ANALYST]` | N/A (Auditor cannot mutate) |

---

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
