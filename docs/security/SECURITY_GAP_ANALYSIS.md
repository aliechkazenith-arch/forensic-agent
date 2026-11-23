# ForensicOps AI — Security & Forensic Defensibility Gap Analysis

**Date:** 2026-11-16  
**Auditor:** Principal DFIR Security Architect & Systems Security Audit Lead  
**Scope:** Security Core Components (`custody_engine.py`, `plugin_runner.py`, `execution_policy.py`, `action_risk_policy.py`, `approval_engine.py`, `network_validator.py`, and Frontend Browser Storage in `frontend/src/`)  
**Compliance Standards:** RFC 3227, NIST SP 800-86, ISO/IEC 27037, AGENTS.md Permanent Engineering Contract  
**Document Reference:** `docs/security/SECURITY_GAP_ANALYSIS.md`  

---

## 1. Executive Summary

This security audit conducted an exhaustive source-level inspection of the critical security controls, evidence custody mechanisms, tool sandboxing pipelines, human-in-the-loop authorization gates, network validators, and frontend state storage in the ForensicOps AI platform.

While earlier audit efforts (SA-001 through SA-013) hardened initial boundaries (such as zero-copy intake confinement, report custody checking, and route authentication), this in-depth audit identified **14 security defects and architectural gaps** across five critical security domains.

### Summary of Findings by Domain & Severity

| Domain / Target Component | Critical | High | Medium | Low | Total |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Evidence Custody & Vault (`custody_engine.py`)** | 0 | 1 | 3 | 0 | **4** |
| **Tool Sandbox & Policy (`plugin_runner.py` / `execution_policy.py`)** | 1 | 2 | 1 | 0 | **4** |
| **Action Risk & Human Approvals (`approval_engine.py` / `action_risk_policy.py`)** | 2 | 1 | 1 | 0 | **4** |
| **Network & SSRF Validator (`network_validator.py`)** | 0 | 2 | 1 | 0 | **3** |
| **Frontend Storage & Session Lifecycle (`frontend/src/`)** | 0 | 1 | 2 | 0 | **3** |
| **Total** | **3** | **7** | **8** | **0** | **18** |

### Top Critical Defects Requiring Immediate Remediation

1. **SEC-APPR-001 (Critical): Unconstrained Wildcard Master Token Bypass in `HumanApprovalToken.verify`:** If an approval token omits `action_type`, `target`, or `parameter_digest` (fields default to `None`), the verification logic skips mismatch checks. A single token can authorize ANY high-risk action (remote shell, containment, deletion) against ANY host without parameter enforcement.
2. **SEC-APPR-002 (Critical): Rogue Unconstrained Approval Token Issuance Route in `workflows.py`:** `POST /api/workflows/approval-token` issues validly signed `HumanApprovalToken` instances with completely empty `action_type`, `target`, and `parameter_digest`, bypassing `ApprovalEngine` and `ActionRiskPolicy` entirely.
3. **SEC-EXEC-001 (Critical): Broken Container In-Path Translation:** Tier B tool plugins pass host filesystem paths (e.g. `C:\forensicops-ai\vault\blobs\...`) directly into container argv while mounting `/evidence:ro` and `/scratch:rw`. Containerized tools running in Linux environments fail immediately because host paths do not exist inside the container.
4. **SEC-EXEC-003 (High): Command Argument Allowlisting Ignored in `validate_tool_execution`:** `ToolExecutionPolicy` declares `allowed_arguments` and `disallowed_arguments`, but `ExecutionPolicyRegistry.validate_tool_execution` never validates argv against them, enabling arbitrary flag and option injection into forensic binaries.
5. **SEC-NET-001 (High): Dev Mode Override Bypasses Loopback SSRF Protection:** Enabling `FORENSICOPS_ALLOW_PRIVATE_TARGETS` to reach private SIEMs (RFC 1918) completely bypasses `is_ip_prohibited`, opening loopback (`127.0.0.1`, `localhost`) to probing and SSRF attacks against backend and local LLM services.

---

## 2. Comprehensive Defect Register

### 2.1 Evidence Custody, Dual Hashing & Sandbox Vault (`custody_engine.py`)

#### SEC-CUST-001: Zero-Copy Evidence Registration Lacks Write-Protection at Rest
- **Severity:** High
- **Affects:** Forensic Defensibility, Evidence Integrity (RFC 3227, AGENTS.md Principle 3)
- **Location:** `backend/app/core/custody_engine.py:658-675` (`register_zero_copy_reference`)
- **Vulnerability Description:**
  `register_zero_copy_reference` registers external disk, VM, or memory images in-place without copying them to the system drive (`blob_path = f":ro:{resolved_path}"`). While `store_in_blob_vault` applies `safe_make_readonly()` to ensure `0400` / `S_IREAD` permissions on ingested files, `register_zero_copy_reference` never applies read-only permissions to the target file. The source evidence remains completely writable on the host filesystem by any process or user.
- **Forensic Impact:**
  If an analyst, system service, or malicious script modifies or truncates the external disk image during an ongoing investigation, evidence integrity is destroyed in place without write-protection at rest, compromising legal defensibility.
- **Recommended Remediation:**
  In `register_zero_copy_reference`, invoke `safe_make_readonly(resolved_path)`. If setting read-only fails due to filesystem permissions, raise a `VaultIntegrityError` or alert the analyst that zero-copy evidence cannot be protected at rest.

---

#### SEC-CUST-002: Incomplete Dual-Hash Deduplication in `store_in_blob_vault` and `store_bytes_in_blob_vault`
- **Severity:** Medium
- **Affects:** Cryptographic Integrity (NIST SP 800-86)
- **Location:** `backend/app/core/custody_engine.py:586-599, 625-637`
- **Vulnerability Description:**
  When checking whether a blob already exists in the vault (`shard_dir / f"{sha256}.blob"`), `store_in_blob_vault` verifies:
  ```python
  ex_sha256, ex_sha512, ex_size = compute_stream_hashes(blob_path)
  if ex_sha256.lower() != sha256.lower() or ex_size != size_bytes:
      ...
  ```
  Notice that `ex_sha512` is computed but never compared against `sha512`! Similarly, in `store_bytes_in_blob_vault`:
  ```python
  ex_sha256, _, ex_size = compute_stream_hashes(blob_path)
  if ex_sha256.lower() != sha256.lower() or ex_size != size_bytes:
      ...
  ```
  `ex_sha512` is discarded (`_`).
- **Forensic Impact:**
  Dual-algorithm hashing (SHA-256 + SHA-512) is mandated to protect against theoretical single-algorithm hash collisions and bit rot. Skipping SHA-512 comparison during deduplication nullifies the second cryptographic algorithm guarantee.
- **Recommended Remediation:**
  Update the condition in both methods to explicitly verify both hashes:
  ```python
  if ex_sha256.lower() != sha256.lower() or ex_sha512.lower() != sha512.lower() or ex_size != size_bytes:
  ```

---

#### SEC-CUST-003: Executable Defanging Deferred Post-Extraction in `safe_extract_archive` & Dead Extension Table
- **Severity:** Medium
- **Affects:** Execution Sandbox Boundary
- **Location:** `backend/app/core/custody_engine.py:40-45, 367-570, 856-926`
- **Vulnerability Description:**
  `EXECUTABLE_EXTENSIONS` is defined at lines 40-45 (`.exe`, `.ps1`, `.bat`, `.vbs`, etc.) but is never used anywhere in `custody_engine.py` (dead code). When collector capsules or triage archives are unpacked into `temp_extract_dir`, members are extracted using their original names and extensions. Files remain executable on disk in the temporary directory until manifest parsing completes and individual items are copied to the `.blob` vault.
- **Forensic Impact:**
  An execution window exists between archive extraction and blob vaulting where executable files reside on the host filesystem with executable extensions, subject to accidental execution or endpoint security scanner interference.
- **Recommended Remediation:**
  Strip executable permissions (`chmod -x` / `0600` without execute) during streaming extraction in `_safe_extract_zip` and `_safe_extract_tar`, or extract directly into defanged temporary filenames.

---

#### SEC-CUST-004: Shared Custody Chain Contamination Across Multi-Case Vaults
- **Severity:** Medium
- **Affects:** Evidence Custody & Case Isolation (ISO/IEC 27037)
- **Location:** `backend/app/core/custody_engine.py:1116-1150` (`verify_chain_integrity`)
- **Vulnerability Description:**
  When `CustodyEngine` is initialized without a per-case database path (`vault_root / "custody.db"`), all cases write to a shared `custody_chain` table. Entries are linked sequentially to the immediately preceding record regardless of case ID. Calling `verify_chain_integrity(case_id="case_A")` evaluates:
  ```python
  if effective_case_id and entry.case_id != effective_case_id:
      errors.append(f"Cross-case contamination at seq_id {entry.seq_id}...")
  ```
  Any interleaved entries from Case B cause chain verification for Case A to fail with false-positive cross-case contamination errors. Furthermore, pure SHA-256 chaining without an HMAC or digital signature allows any party with local write access to recalculate the chain from any modified entry forward.
- **Forensic Impact:**
  Cross-case custody interleaving prevents automated court-ready chain verification on shared vault deployments.
- **Recommended Remediation:**
  Enforce strict per-case custody ledger isolation (`vault/<case_id>/custody.db`) or maintain per-case hash links (`prev_case_hash`) alongside global sequence hashes. Digitally sign or HMAC-authenticate ledger checkpoint hashes.

---

### 2.2 Tool Sandbox & Policy Enforcement (`plugin_runner.py` / `execution_policy.py`)

#### SEC-EXEC-001: Broken Container In-Path Translation Prevents Container Execution
- **Severity:** Critical
- **Affects:** Sandbox Isolation & Tool Execution Reliability
- **Location:** `backend/app/core/plugin_runner.py:158-163, 442-459`
- **Vulnerability Description:**
  In `PluginRunner.run_plugin`:
  ```python
  argv: List[str] = []
  for token in plugin.command_template:
      replaced = (
          token.replace("{input_path}", str(input_path))
          .replace("{output_dir}", str(scratch_dir))
          .replace("{rules_path}", str(rules_path or ""))
      )
      argv.append(replaced)
  ```
  `{input_path}` and `{output_dir}` are replaced with the **host filesystem paths** (e.g. `C:\forensicops-ai\vault\blobs\ab\ab1234.blob` on Windows or `/home/user/forensicops/...` on Linux).
  Then `build_container_argv` executes:
  ```python
  cmd.extend(["-v", f"{Path(readonly_input_dir).resolve()}:/evidence:ro"])
  cmd.extend(["-v", f"{Path(scratch_output_dir).resolve()}:/scratch:rw"])
  cmd.extend([container_image, *argv])
  ```
  The containerized binary inside Docker/Podman is executed with the HOST paths in `argv`!
- **Forensic Impact:**
  Any Tier B plugin executed in a Linux container fails immediately with "File not found" because `C:\...` or host-specific paths do not exist inside the container. If developers work around this by mounting the host root, container sandbox isolation is broken.
- **Recommended Remediation:**
  Implement explicit path translation for containerized execution:
  - Inside the container, `{input_path}` must map to `/evidence/<filename>` (or `/evidence/<relative_path>`).
  - `{output_dir}` must map to `/scratch`.
  - `{rules_path}` must map to `/rules:ro`.
  Construct container-translated `argv` before invoking `build_container_argv`.

---

#### SEC-EXEC-002: Overly Broad Container Bind-Mount Exposes Sibling Evidence Files
- **Severity:** High
- **Affects:** Confidentiality & Least Privilege Isolation
- **Location:** `backend/app/core/plugin_runner.py:456`, `build_container_argv:159`
- **Vulnerability Description:**
  `build_container_argv` mounts `readonly_input_dir=input_path.parent` to `/evidence:ro`. In the vault blob store, blobs are organized in 2-character hex shards (`vault/blobs/ab/`). Mounting `input_path.parent` exposes all other evidence files residing in that shard to the container. If an artifact is a zero-copy file located in an evidence directory (e.g., `/cases/shared_evidence/sample.raw`), mounting `input_path.parent` exposes all other evidence in that directory to the tool container.
- **Forensic Impact:**
  An untrusted third-party tool container (Tier B) can read unauthorized evidence files and cross case boundaries.
- **Recommended Remediation:**
  Mount only the specific artifact file directly:
  `-v <host_file_path>:/evidence/<filename>:ro`
  or create a temporary hermetic directory containing only a bind mount or read-only hardlink of the single target artifact.

---

#### SEC-EXEC-003: Command Argument Allowlisting Ignored in `validate_tool_execution`
- **Severity:** High
- **Affects:** Tool Worker Sandboxing (AGENTS.md Rule 6)
- **Location:** `backend/app/core/execution_policy.py:219-227` (`validate_tool_execution`)
- **Vulnerability Description:**
  `ToolExecutionPolicy` defines `allowed_arguments: List[str]` and `disallowed_arguments: List[str]`. Canonical policies (Chainsaw, Zimmerman tools, Volatility, YARA) declare strict argument lists. However, in `ExecutionPolicyRegistry.validate_tool_execution`:
  ```python
  # 5. Validate arguments against shell injection and unauthorized flags
  for arg in argv[1:]:
      for danger in DANGEROUS_ARG_PATTERNS:
          if danger in arg:
              raise ExecutionPolicyError(f"Potentially unsafe shell metacharacter '{danger}'...")
  return policy
  ```
  The method completely ignores `policy.allowed_arguments` and `policy.disallowed_arguments`!
- **Forensic Impact:**
  Any argument or flag (such as `--exec`, `--eval`, `-o /path`, `--script`, `--debug`) can be passed to forensic binaries as long as it does not contain shell metacharacters (`;`, `&`, `|`, etc.). This permits parameter injection and unauthorized feature activation.
- **Recommended Remediation:**
  In `validate_tool_execution`, iterate through `argv[1:]` and verify that all flags match `policy.allowed_arguments` (or allowed patterns) and none match `policy.disallowed_arguments`. Reject unapproved flags fail-closed.

---

#### SEC-EXEC-004: Mutable `:latest` Container Image Tags Without Digest Pinning
- **Severity:** Medium
- **Affects:** Provenance, Supply Chain Security & Defensibility (AGENTS.md Rule 6)
- **Location:** `backend/app/core/execution_policy.py:60-133` (`APPROVED_POLICIES`)
- **Vulnerability Description:**
  All canonical policies in `APPROVED_POLICIES` configure container images using mutable `:latest` tags (e.g., `ghcr.io/forensicops/chainsaw:latest`, `ghcr.io/forensicops/ez-tools:latest`), leaving `container_image_digest=None` and `binary_digest=None`. `validate_tool_execution` only validates that `image.startswith(prefix)`.
- **Forensic Impact:**
  Using mutable `:latest` tags exposes forensic investigations to upstream supply chain attacks, silent tool changes, or cache poisoning. Court challenges can contest findings if the exact binary or image digest is not pinned.
- **Recommended Remediation:**
  Pin all container images by cryptographic digest (`image@sha256:<digest>`). Enforce `container_image_digest` verification in `validate_tool_execution` and record the immutable digest in the custody ledger.

---

### 2.3 Action Risk & Human Approval Engine (`approval_engine.py` / `action_risk_policy.py`)

#### SEC-APPR-001: Unconstrained Wildcard Master Token Bypass in `HumanApprovalToken.verify`
- **Severity:** Critical
- **Affects:** Human-in-the-Loop Gate (AGENTS.md Rule 7, ISO/IEC 27037)
- **Location:** `backend/app/models/workflow.py:198-207`, `backend/app/connectors/ssh_collector.py:475-504`
- **Vulnerability Description:**
  In `HumanApprovalToken.verify`:
  ```python
  if expected_action_type and self.action_type and self.action_type != expected_action_type:
      return False
  if expected_target and self.target and self.target != expected_target:
      return False
  if expected_parameter_digest and self.parameter_digest and self.parameter_digest.lower() != expected_parameter_digest.lower():
      return False
  ```
  Notice: `if expected_action_type and self.action_type and ...`
  If `self.action_type` is `None`, the entire condition evaluates to `False`!
  If `self.target` is `None`, the check evaluates to `False`!
  If `self.parameter_digest` is `None`, the check evaluates to `False`!
- **Forensic Impact:**
  A token generated without `action_type`, `target`, or `parameter_digest` acts as an unconstrained wildcard master token. When a gate checks `expected_action_type="containment"`, `expected_target="192.168.1.50"`, the token is approved for ANY action, ANY target, and ANY parameters!
- **Recommended Remediation:**
  Fail-closed when an expected constraint is specified:
  ```python
  if expected_action_type is not None:
      if not self.action_type or self.action_type != expected_action_type:
          return False
  if expected_target is not None:
      if not self.target or self.target != expected_target:
          return False
  if expected_parameter_digest is not None:
      if not self.parameter_digest or self.parameter_digest.lower() != expected_parameter_digest.lower():
          return False
  ```

---

#### SEC-APPR-002: Rogue Unconstrained Approval Token Issuance Route in `workflows.py`
- **Severity:** Critical
- **Affects:** Access Control & Authorization Architecture
- **Location:** `backend/app/api/workflows.py:55-75` (`POST /api/workflows/approval-token`)
- **Vulnerability Description:**
  `backend/app/api/workflows.py` exposes:
  ```python
  @router.post("/approval-token", response_model=HumanApprovalToken)
  @workflow_single_router.post("/approval-token", response_model=HumanApprovalToken)
  def issue_approval_token(req: ApprovalTokenRequest, current_user: UserRead = Depends(...)):
      token = HumanApprovalToken(
          token_id=f"gate-{uuid4().hex[:12]}",
          node_id=req.node_id,
          case_id=req.case_id,
          issued_by=f"{current_user.username} ({current_user.badge_id})",
          timestamp_utc=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
          is_valid=True,
      )
      token.sign()
      return token
  ```
  This endpoint:
  1. Issues a token with `action_type=None`, `target=None`, `parameter_digest=None`, `approval_id=None`.
  2. Bypasses `ApprovalEngine.create_request` and `ActionRiskPolicy.evaluate`.
  3. Bypasses all approval status tracking (no entry in `approval_requests`).
  4. Coupled with SEC-APPR-001, any authenticated SOC analyst can call this endpoint to obtain a master token that authorizes ANY high-risk collector or action on the platform!
- **Forensic Impact:**
  Completely dismantles the operation-specific human approval architecture and enables arbitrary remote command dispatch without target or parameter binding.
- **Recommended Remediation:**
  Deprecate and remove this legacy issuance route, or redirect it to `ApprovalEngine.create_request` and `approve_request` with mandatory `action_type`, `target`, and `parameters`.

---

#### SEC-APPR-003: Self-Target Comparison Bug in `verify_approval_gate`
- **Severity:** High
- **Affects:** Online Collector Authorization
- **Location:** `backend/app/connectors/ssh_collector.py:500`
- **Vulnerability Description:**
  In `OnlineCollectorOrchestrator.verify_approval_gate`:
  Line 500:
  ```python
  if not token.verify(self.secret_key, expected_case_id=target.case_id, expected_target=token.target):
  ```
  `expected_target` is passed as `token.target` instead of `target.host`! The code verifies whether the token's target matches itself rather than verifying whether the token was issued for the endpoint currently being collected from!
- **Forensic Impact:**
  If a token was issued for Host A (`token.target = "host-a"`), but the collector request is dispatched against Host B (`target.host = "host-b"`), line 500 verifies `expected_target="host-a"`, matching `token.target`!
- **Recommended Remediation:**
  Change line 500 to pass `expected_target=target.host` and `expected_action_type="remote_collection"`.

---

#### SEC-APPR-004: Non-Atomic Token Replay Check in `ApprovalEngine.verify_and_consume_token`
- **Severity:** Medium
- **Affects:** Replay Protection & Concurrency Safety
- **Location:** `backend/app/core/approval_engine.py:513-521, 576-604`
- **Vulnerability Description:**
  `verify_and_consume_token` performs a `SELECT consumed_at_utc FROM consumed_approval_tokens WHERE token_id = ?`, runs validation logic, and then issues `INSERT INTO consumed_approval_tokens`. Under concurrent execution (e.g. parallel LangGraph branches or concurrent HTTP requests), two worker threads presenting the same token can both execute the `SELECT` query before either executes the `INSERT`, allowing duplicate execution before consumption is recorded.
- **Forensic Impact:**
  Permits concurrent token replay for sensitive actions during the race window.
- **Recommended Remediation:**
  Execute the consumption atomically at the beginning of the verification:
  Execute `INSERT INTO consumed_approval_tokens (...)` within an `IMMEDIATE` transaction or check `sqlite3.IntegrityError` on unique constraint violation as the initial atomic gate.

---

### 2.4 Network Validator & SSRF Defense (`network_validator.py`)

#### SEC-NET-001: Dev Mode Override Bypasses Loopback SSRF Protection
- **Severity:** High
- **Affects:** Server-Side Request Forgery (SSRF) Boundary
- **Location:** `backend/app/core/network_validator.py:158-166, 201-218`
- **Vulnerability Description:**
  When `FORENSICOPS_ALLOW_PRIVATE_TARGETS` or `FORENSICOPS_ALLOW_PRIVATE_SIEM` is enabled (common in corporate deployments to allow reaching private SIEM servers on 10.0.0.0/8), the code sets `env_allow_dev = True`.
  In lines 163 and 201:
  ```python
  if not env_allow_dev:
      is_bad, reason = is_ip_prohibited(...)
  else:
      for meta_net in METADATA_NETWORKS:
          if ip in meta_net:
              raise SSRFSecurityError(...)
  ```
  `is_ip_prohibited` is completely bypassed! The `else:` block only checks `METADATA_NETWORKS` (169.254.0.0/16). It NEVER checks `ip.is_loopback` (`127.0.0.1`, `::1`)!
- **Forensic Impact:**
  Enabling private SIEM access opens up loopback access (`127.0.0.1`), allowing attackers or malicious SIEM configurations to probe local backend services (Uvicorn API on port 8000, Ollama on port 11434, local databases, or other localhost services).
- **Recommended Remediation:**
  Never bypass `is_ip_prohibited`. Pass `allow_private=True` to `is_ip_prohibited` instead. `is_ip_prohibited` already permits private IP ranges when `allow_private=True` while strictly blocking `ip.is_loopback`.

---

#### SEC-NET-002: DNS Rebinding (TOCTOU) Vulnerability in `validate_url_ssrf`
- **Severity:** High
- **Affects:** SSRF Defense Under Dynamic DNS
- **Location:** `backend/app/core/network_validator.py:222-255`
- **Vulnerability Description:**
  `validate_url_ssrf` resolves and validates the destination IP during pre-flight validation. However, it returns the original URL string (`url`) with the unresolved hostname. When the HTTP client (HTTPX, SIEM connector, or web client) subsequently executes the HTTP request, it initiates a fresh DNS query. An attacker controlling a DNS server with TTL=0 can resolve to an external IP during pre-flight, and then return `127.0.0.1` or `169.254.169.254` during the actual connection.
- **Forensic Impact:**
  Permits full SSRF bypass against cloud metadata services and local microservices via DNS rebinding.
- **Recommended Remediation:**
  Pin the validated IP in the outbound HTTP client (e.g. using HTTPX custom transport, socket-level IP binding, or mounting the validated IP into the request URL while setting the `Host` header).

---

#### SEC-NET-003: Incomplete Credential Scrubbing for Private Keys and Query Parameters
- **Severity:** Medium
- **Affects:** Log & Audit Trail Confidentiality
- **Location:** `backend/app/core/network_validator.py:48-56, 257-274`
- **Vulnerability Description:**
  `sanitize_credentials` applies regex patterns for `Bearer`, `ApiKey`, `Splunk`, and simple key-value patterns. It does not redact:
  1. PEM-encoded private keys (`-----BEGIN OPENSSH PRIVATE KEY-----`, `-----BEGIN RSA PRIVATE KEY-----`).
  2. Basic authentication headers (`Authorization: Basic ...`).
  3. URL query parameters (`?key=...`, `?token=...`, `?secret=...`).
- **Forensic Impact:**
  If an exception or diagnostic output dumps an SSH private key, Basic auth string, or credentialed URL, it is written unredacted to audit logs and custody files.
- **Recommended Remediation:**
  Add regex patterns for PEM blocks (`re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----")`), Basic authentication tokens, and sensitive URL query parameter values.

---

### 2.5 Browser Storage & Frontend State (`frontend/src/`)

#### SEC-UI-001: Plaintext SIEM and SSH Credentials Persisted in `sessionStorage`
- **Severity:** High
- **Affects:** Credential Confidentiality
- **Location:** `frontend/src/context/InvestigationContext.tsx:22-52, 148`
- **Vulnerability Description:**
  `InvestigationContext` writes the entire wizard state to `sessionStorage.setItem('forensicops_wiz_${caseId}', JSON.stringify(next))`. The serialized JSON contains:
  - `siemApiKey`: Active SIEM API keys/passwords (e.g., `"es-sec-token-1234"`).
  - `onlineUser`: Remote SSH/WinRM usernames (e.g., `"root"`).
  - `onlineHost`: Remote endpoint IP addresses.
  - `approvalTokenId`: Active approval token IDs.
  - `siemUrl`: Internal SIEM infrastructure endpoints.
  - Investigation hypotheses, queries, and case scopes.
- **Forensic Impact:**
  All sensitive credentials and topology data are stored in plaintext in the browser. Any XSS vulnerability or malicious browser extension/dependency can dump `sessionStorage` and steal operational credentials.
- **Recommended Remediation:**
  Strip sensitive credentials (`siemApiKey`, passwords, approval tokens) before persisting wizard state to `sessionStorage`, or keep credentials in memory only and require re-entry if the session is refreshed.

---

#### SEC-UI-002: Incomplete Session Clearing on Logout (Session Residue)
- **Severity:** Medium
- **Affects:** Workstation Multi-User Privacy & Confidentiality
- **Location:** `frontend/src/context/AuthContext.tsx:108-113` (`logout`)
- **Vulnerability Description:**
  In `AuthContext.tsx`:
  ```typescript
  const logout = () => {
    sessionStorage.removeItem("forensicops_token");
    localStorage.removeItem("forensicops_token");
    setToken(null);
    setUser(null);
  };
  ```
  `logout()` only removes the auth token. It never purges `sessionStorage.removeItem('forensicops_wiz_${caseId}')` or clears `sessionStorage`.
- **Forensic Impact:**
  When an analyst logs out, all case wizard state, investigation hypotheses, findings summaries, and endpoint configurations remain in `sessionStorage`. A subsequent user on the same workstation tab can inspect previous case data.
- **Recommended Remediation:**
  In `logout()`, call `sessionStorage.clear()` to guarantee that all case wizard, investigation, and token keys are completely purged upon session termination.

---

#### SEC-UI-003: JWT Access Token Stored in JavaScript-Accessible `sessionStorage`
- **Severity:** Medium
- **Affects:** Authentication Token Security
- **Location:** `frontend/src/context/AuthContext.tsx:23, 79, 96`, `frontend/src/services/api.ts:44-53`
- **Vulnerability Description:**
  The JWT authentication token is persisted in `sessionStorage` and read directly by JavaScript via `sessionStorage.getItem("forensicops_token")`. Web storage (`sessionStorage` and `localStorage`) has no protection against Cross-Site Scripting (XSS).
- **Forensic Impact:**
  Any script executed in the application context can read and exfiltrate the JWT bearer token to impersonate the investigator.
- **Recommended Remediation:**
  Migrate to `HttpOnly`, `SameSite=Strict`, `Secure` cookies for token storage, or maintain the token in React memory with an `HttpOnly` refresh token endpoint.

---

## 3. Prioritized Security Remediation Plan

### Tier 1: Immediate / Blockers (Do Now)

| Finding ID | Component | Defect Summary | Est. Effort |
| :--- | :--- | :--- | :---: |
| **SEC-APPR-001** | `models/workflow.py` | Enforce fail-closed validation on `HumanApprovalToken.verify` so `None` fields do not match expected constraints | Small |
| **SEC-APPR-002** | `api/workflows.py` | Deprecate unconstrained `issue_approval_token` or bind it strictly to `ApprovalEngine` | Small |
| **SEC-EXEC-001** | `core/plugin_runner.py` | Translate host paths to in-container mount paths (`/evidence/...`, `/scratch`) for container execution | Medium |
| **SEC-EXEC-003** | `core/execution_policy.py` | Enforce `policy.allowed_arguments` and `policy.disallowed_arguments` in `validate_tool_execution` | Small |
| **SEC-NET-001** | `core/network_validator.py` | Prevent dev mode from bypassing loopback (`127.0.0.1`) checks; route through `is_ip_prohibited(allow_private=True)` | Small |
| **SEC-APPR-003** | `connectors/ssh_collector.py` | Fix self-target comparison bug: pass `expected_target=target.host` and `expected_action_type` in `verify_approval_gate` | Small |

### Tier 2: High Priority (Do Next)

| Finding ID | Component | Defect Summary | Est. Effort |
| :--- | :--- | :--- | :---: |
| **SEC-CUST-001** | `core/custody_engine.py` | Apply `safe_make_readonly()` on zero-copy referenced files to ensure write-protection at rest | Small |
| **SEC-EXEC-002** | `core/plugin_runner.py` | Restrict container mount to single artifact file instead of parent shard directory | Small |
| **SEC-NET-002** | `core/network_validator.py` | Implement IP pinning in HTTP transport to prevent DNS rebinding TOCTOU | Medium |
| **SEC-UI-001** | `frontend/InvestigationContext.tsx` | Sanitize SIEM API keys and passwords before saving wizard state to `sessionStorage` | Small |
| **SEC-UI-002** | `frontend/AuthContext.tsx` | Execute `sessionStorage.clear()` on logout to eliminate case residue | Small |
| **SEC-CUST-002** | `core/custody_engine.py` | Enforce dual-hash (SHA-256 and SHA-512) verification during blob vault deduplication | Small |

### Tier 3: Hardening & Long-Term Assurance (Later)

| Finding ID | Component | Defect Summary | Est. Effort |
| :--- | :--- | :--- | :---: |
| **SEC-EXEC-004** | `core/execution_policy.py` | Pin immutable container image digests (`@sha256:...`) in `APPROVED_POLICIES` | Medium |
| **SEC-CUST-003** | `core/custody_engine.py` | Strip executable bits during archive extraction; remove dead `EXECUTABLE_EXTENSIONS` code | Small |
| **SEC-CUST-004** | `core/custody_engine.py` | Isolate custody databases strictly per-case (`vault/<case_id>/custody.db`) | Medium |
| **SEC-APPR-004** | `core/approval_engine.py` | Make token replay checking and consumption atomic using exclusive transactions | Small |
| **SEC-NET-003** | `core/network_validator.py` | Expand credential sanitizer regexes for PEM private keys, Basic auth, and query params | Small |
| **SEC-UI-003** | `frontend/AuthContext.tsx` | Transition from `sessionStorage` JWTs to `HttpOnly`, `SameSite=Strict` cookies | Medium |

---

## 4. Defect Register Matrix

| ID | Component | Severity | Description | Remediated in Current Tree? |
| :--- | :--- | :---: | :--- | :---: |
| **SEC-CUST-001** | `custody_engine.py` | High | Zero-copy evidence registration lacks write-protection at rest | Open |
| **SEC-CUST-002** | `custody_engine.py` | Medium | Dual-hash check omits SHA-512 in blob deduplication | Open |
| **SEC-CUST-003** | `custody_engine.py` | Medium | Defanging deferred post-extraction; dead extension table | Open |
| **SEC-CUST-004** | `custody_engine.py` | Medium | Shared custody ledger cross-case contamination false alarms | Open |
| **SEC-EXEC-001** | `plugin_runner.py` | Critical | Host paths passed to container argv breaks container execution | Open |
| **SEC-EXEC-002** | `plugin_runner.py` | High | Parent shard directory mount exposes sibling evidence files | Open |
| **SEC-EXEC-003** | `execution_policy.py` | High | Command argument allowlists completely unenforced in validation | Open |
| **SEC-EXEC-004** | `execution_policy.py` | Medium | Mutable `:latest` container tags without digest pinning | Open |
| **SEC-APPR-001** | `models/workflow.py` | Critical | Wildcard token bypass when `action_type`/`target` are None | Open |
| **SEC-APPR-002** | `api/workflows.py` | Critical | Unconstrained token issuance route bypasses approval engine | Open |
| **SEC-APPR-003** | `connectors/ssh_collector.py` | High | Gate compares target against token itself instead of host | Open |
| **SEC-APPR-004** | `approval_engine.py` | Medium | Non-atomic token check and consumption window | Open |
| **SEC-NET-001** | `network_validator.py` | High | Dev mode override bypasses loopback (`127.0.0.1`) check | Open |
| **SEC-NET-002** | `network_validator.py` | High | Pre-flight URL validation vulnerable to DNS rebinding TOCTOU | Open |
| **SEC-NET-003** | `network_validator.py` | Medium | Credential scrubber misses PEM private keys and query params | Open |
| **SEC-UI-001** | `frontend/InvestigationContext.tsx` | High | Plaintext SIEM keys and SSH users in `sessionStorage` | Open |
| **SEC-UI-002** | `frontend/AuthContext.tsx` | Medium | Case wizard state persists in `sessionStorage` after logout | Open |
| **SEC-UI-003** | `frontend/AuthContext.tsx` | Medium | JWT token stored in JavaScript-accessible `sessionStorage` | Open |
