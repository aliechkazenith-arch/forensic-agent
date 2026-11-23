# Security Audit Task — ForensicOps AI (local-first DFIR platform)

You are a senior application security engineer and digital-forensics tooling reviewer. Audit this codebase. This is a **read-only audit**: do not change any source file, config, or data in this task. The only files you may create are under `audits/`.

## Why this audit is different from a normal web-app audit
This tool handles forensic evidence and feeds evidence-derived text to an LLM. Besides normal vulnerabilities, hunt for anything that would let someone:
1. **Alter or fake evidence** without detection (integrity).
2. **Read evidence or cases they should not see** (confidentiality, TLP).
3. **Make the LLM or the workflow do something the user did not authorize** (prompt injection, unsafe tool calls).
4. **Weaken the chain of custody** (mutable or forgeable audit logs).
5. **Run code on the analyst's machine** through a malicious evidence file (parsers, archives, rendering).
Treat every byte that comes from an evidence file, collector package, file name, log line, or LLM output as **hostile input**.

## Ground rules (safety)
- Work only inside this repository and its local dev environment. Do not touch real evidence, real credentials, or other projects.
- Do not send source code, data, or findings to any external service. Looking up public CVE advisories through normal package-audit tools is fine.
- You may install **dev-only audit tools** into the project's own venv / local `node_modules` (for example `pip-audit`, `bandit`, `ruff`, `semgrep`, `npm audit`). List every tool you installed in the report. No global installs, no system changes.
- Proof-of-concept tests must use temporary directories and synthetic files only. Put them in `audits/poc/`. Never run a PoC against `backend/data/` or any real evidence folder. Never write a working exploit for third-party software.
- Do not delete, move, or modify existing files. If you think something must change, say so in the report.
- Do not guess. Mark every finding **Confirmed** (you demonstrated it or traced it fully in code), **Likely** (strong code evidence, not demonstrated), or **Possible** (needs more info). Never present Possible as Confirmed.

## How to work (to avoid running out of context)
Work in passes. After finishing each pass, **append its results to `audits/SECURITY_AUDIT_REPORT.md` immediately**, then continue. If you must stop, the report must already contain everything found so far and a "Not yet covered" list.

### Pass 0 — Recon (write this first)
Produce, in the report:
- Tech stack and versions (backend, frontend, DB, LLM client, any agent framework, containers, collectors).
- **Route inventory table**: every HTTP route with method, path, auth required (yes/no/how), minimum role, what it reads or writes, and whether it accepts files, paths, or free text.
- **Trust boundaries and data-flow summary**: browser ↔ API ↔ DB ↔ evidence store ↔ parsers/subprocesses ↔ LLM (local or cloud) ↔ report output.
- Where the app listens (host and port), CORS settings, debug flags, exposed docs endpoints.
- Where secrets and config live. Where evidence, DB files, logs, and temp files are written, and with what permissions.
If a feature below does not exist yet, write "N/A, not implemented" and note if its absence is itself a risk.

### Pass 1 — Evidence storage and integrity
Check each item and cite `file:line`:
- Hashing: SHA-256 (and SHA-512 if specified) computed **while streaming**, before any processing. Hash covers the exact bytes stored. Anything that can change bytes between hashing and storing?
- Stored evidence is read-only; is that enforced by the OS, and can the app process itself modify or delete it? Is the hash **re-verified before every use** (parser run, report, download)?
- Filename and path handling: `../`, absolute paths, drive letters, UNC paths (`\\server\share`), **NTFS alternate data streams** (`name.txt:hidden`), reserved names (`CON`, `NUL`, `COM1`…), trailing dots/spaces, 8.3 short names, case-insensitive collisions, Unicode normalization and bidi/control characters, very long names, null bytes, symlinks/junctions/reparse points.
- Race conditions and TOCTOU: concurrent uploads of the same file, duplicate detection races, temp-file handling, partial uploads, cleanup on error, replace/rename atomicity.
- Limits: max upload size enforced on **actual bytes** (not only Content-Length), free-disk check, concurrent upload limits, resumable upload/chunk ordering, zero-copy/reference mode (can a user register any path the server can read? allowlist? realpath? symlink?).
- Duplicate handling: can a duplicate upload overwrite or alias existing evidence? Can two different files collide in `stored_name` or ID (short hash prefixes)?
- Verify endpoint: can it be tricked (stale cache, comparing against attacker-controlled values)?

### Pass 2 — Authentication, sessions, authorization (skip with "N/A" only if truly absent)
- Password storage (bcrypt/argon2, cost), default or seeded credentials, first-run/setup takeover, user enumeration, brute-force protection, lockout.
- Token/session design: secret strength and source, algorithm pinning, expiry, rotation/revocation, cookie flags (HttpOnly, Secure, SameSite), CSRF protection, token in `localStorage`.
- **Authorization on every route** from the inventory: missing checks, role confusion (auditor/read-only able to write), **IDOR** (can user A access case/evidence/investigation IDs of user B or of a TLP:RED case), mass assignment, client-supplied user/role fields.
- Actor identity in audit records is taken from the verified token, not from request fields.

### Pass 3 — API and web surface
- SQL: every query parameterized? Any f-string/concatenated SQL, dynamic `ORDER BY`/`LIMIT`, `LIKE` injection.
- Validation: lengths, types, enums, regexes (ReDoS), pagination caps, request body size caps, JSON depth.
- CORS (wildcards with credentials), CSRF, security headers (CSP, X-Content-Type-Options, frame protection), cache headers on sensitive responses.
- Error handling: stack traces, internal paths, secrets, or SQL in error responses; verbose logging of request bodies.
- Binding: is it reachable on `0.0.0.0`? Is the OpenAPI/Swagger UI exposed? Debug/reload flags in production paths?
- SSRF / open proxy: any user-controlled URL (LLM base URL, webhook, fetch) that the server will call. Can an analyst point the LLM client at an internal service or a cloud metadata address?
- DoS: unbounded queries, large responses, long-running synchronous work blocking the event loop, thread-pool exhaustion, unbounded SSE/WebSocket connections.

### Pass 4 — LLM and agent security
- **Prompt injection:** list every place evidence-derived or user-derived text enters a prompt. For each: is it wrapped in delimiters with a **per-request random nonce**? Is marker-like text (`===`, the nonce, role words) stripped or escaped? Are lengths capped? Could a file name, log line, command line, DNS name, or HTTP user-agent break out?
- **Output handling:** is LLM output ever used as a file path, shell argument, SQL, regex, URL, HTML/Markdown, or code? Is JSON validated against a strict schema (Pydantic) with enums and length limits? What happens on invalid output (retry bounds, no fallback to unsafe parsing)?
- **Tool/callback requests:** if the LLM can trigger tools or parsers, are `tool_id`, evidence references, and parameters validated against an allowlist and the current case? Can it reference another case's evidence? Is the loop bounded (max retries, max revisions, max tool calls, timeouts)?
- **Fact integrity:** can the LLM state facts that do not trace to deterministic findings? Are cited IDs verified to exist **and** to support the claim (entity match), or only checked for existence?
- **Data egress:** can evidence leave the machine? Are cloud providers possible, and is there a policy by classification (TLP) and a log of what was sent? Any telemetry, update checks, or analytics calling out?
- **Secrets and logging:** API keys never reach the browser, DB, logs, prompts, or error messages. Are full prompts/responses stored, and who can read them (they contain evidence)?
- **Cost/abuse:** unbounded context or token use, unauthenticated LLM endpoints, ability for a low-role user to trigger heavy LLM work.
- Local model server settings: proxy/`trust_env` behavior, TLS to remote providers, timeouts.

### Pass 5 — Parsers, subprocesses, archives, deserialization
- Any `subprocess`, `os.system`, `shell=True`, string-built commands, or user/evidence-controlled arguments (argument injection such as a file name starting with `-`).
- Timeouts, output-size caps, memory/CPU limits, working-directory and temp-file hygiene, running privileges (is the app or parser running as Administrator/root?).
- Containers (if any): privileged mode, mounted Docker socket, writable evidence mounts, network access for parser containers, base-image pinning, non-root user.
- Archives and packages (zip/tar/collector packages): **zip-slip** path traversal, symlinks inside archives, zip bombs (compressed vs uncompressed size, file count, nesting), manifest vs actual hash verification, trust in embedded metadata.
- Deserialization and parsers: `pickle`, `yaml.load`, `eval/exec`, unsafe XML (XXE), unsafe regex on untrusted data, parsing libraries with known memory-safety issues.
- Parser output is treated as untrusted when stored and displayed.

### Pass 6 — Frontend
- XSS: `dangerouslySetInnerHTML`, `innerHTML`, unsanitized Markdown rendering, `href`/`src` built from data (`javascript:` URLs), rendering of file names, log lines, and LLM text, iframes without `sandbox`, `postMessage` handlers.
- Storage: tokens, hashes, case names, or evidence metadata in `localStorage`/`sessionStorage`; sensitive data in URLs or query strings.
- Build and bundle: secrets or internal URLs in the bundle, source maps published, dev proxy settings leaking into production, outdated React/Vite/Tailwind.
- Clickjacking, open redirects, CSP compatibility.

### Pass 7 — Audit log and chain of custody (if implemented)
- Is the ledger truly append-only (DB triggers or permissions), or can any code path UPDATE/DELETE rows?
- Hash chain: canonical serialization (stable key order, encoding), genesis handling, what exactly is hashed, verification function correctness, what happens when verification fails.
- Can an attacker with DB file access rewrite the whole chain? Is there an external anchor (HMAC key outside the DB, printed head hash, signed export)?
- Time: UTC everywhere? Source of timestamps? Can a client supply the time?
- Log injection (newlines/control characters), secrets or evidence text in logs, who can read logs.
- Are all security-relevant events recorded (intake, hash failures, provider switches, LLM calls, parser runs, sign-offs, permission denials)?

### Pass 8 — Secrets, configuration, dependencies, supply chain
- Secrets scan of the working tree **and git history** (API keys, tokens, passwords, private keys, `.env` committed, example files containing real values).
- Config: insecure defaults, missing required-secret checks, permissive file permissions on data/DB/evidence directories (Windows ACLs too), secrets in the DB.
- Dependencies: run `pip-audit` (or equivalent) and `npm audit`. Report known CVEs with package, version, fixed version, and whether the vulnerable code path is actually used. Check lockfiles exist and versions are pinned. Flag unmaintained or typosquat-looking packages, `postinstall` scripts, and license issues that matter for distribution (for example AGPL components).
- Run `bandit` (Python) and `semgrep` (if installable locally) and triage the results; do not paste raw tool output without triage.
- Dockerfiles / compose / CI files: unpinned base images, secrets in build args, `latest` tags, overly broad volume mounts.

### Pass 9 — Windows host and deployment
- NTFS and path behavior (covered in Pass 1), Windows Defender interaction (quarantine of samples, exclusions suggested), service account and privileges, firewall exposure, scheduled tasks, temp-directory permissions, long-path handling, line-ending or encoding issues that could break hash comparisons.

### Pass 10 — Collectors (if present in the repo)
- Required operator/authorization inputs, output location safety (not the evidence disk), read-only behavior, manifest and per-file hashes, signing or out-of-band hash design, privilege requirements, collection of sensitive data (credentials) by default, self-integrity, platform-side verification of packages.

### Pass 11 — Targeted dynamic verification (only for Confirmed-worthy items)
For the most serious Likely issues, write a minimal automated PoC under `audits/poc/` (pytest or script), run it against a **temporary copy of the app with a temp data directory**, and record the result. Examples of acceptable PoCs: traversal filename stays inside the evidence directory or not; an ADS file name is rejected or not; a package with `../` entries is rejected or not; a low-privilege role can or cannot call a write route; evidence flipped by one byte is detected or not; a hostile file name with a fake END marker appears unescaped in a captured prompt. Record PASS/FAIL and the exact command.

## Severity guide (use these definitions)
- **Critical:** remote or malicious-evidence code execution; authentication bypass; evidence silently modifiable or forgeable; arbitrary file read/write outside intended directories.
- **High:** privilege escalation or IDOR across cases; prompt injection that can trigger unauthorized tool use or data egress; stored XSS from evidence content; secrets exposure; audit log rewritable without detection.
- **Medium:** missing rate limiting/CSRF; unbounded resource use enabling DoS; weak validation without a demonstrated exploit; information disclosure through errors/logs.
- **Low:** hardening gaps, missing headers, minor misconfigurations.
- **Info:** observations and good practices worth keeping.
For each finding also say whether it affects **integrity**, **confidentiality**, **availability**, or **forensic defensibility**.

## Report format: `audits/SECURITY_AUDIT_REPORT.md`
1. **Executive summary** (max 15 lines): overall risk rating, top 5 issues, whether evidence integrity can currently be trusted, and a one-line verdict.
2. **Scope and method**: commit hash or file listing hash, date, tools installed and versions, what was and was not examined.
3. **Recon results** (Pass 0 tables).
4. **Findings**, sorted by severity. Each finding uses exactly this template:
   - **ID** `SA-001`, **Title**
   - **Severity** / **Confidence** (Confirmed|Likely|Possible) / **Affects** (integrity|confidentiality|availability|defensibility)
   - **Location**: `path/file.py:LINE` (one or more)
   - **What is wrong** (plain language, 2 to 5 sentences)
   - **Impact in this tool's context** (concrete scenario involving evidence, cases, or the LLM)
   - **How to reproduce / proof** (steps or PoC path and its result)
   - **Recommended fix** (specific; small code sketch if helpful; mention the file to change)
   - **Regression test to add** (name and what it asserts)
5. **What is done well** (specific, with file references).
6. **Coverage table**: each pass and sub-item marked Checked / Partially / Not applicable / Not checked, with the reason.
7. **Prioritized fix plan**: ordered list of fixes grouped into "do now", "do next", "later", with rough effort (S/M/L) and any dependency between fixes.
8. **Open questions for the project owner** (decisions you could not make from code alone).
Also write `audits/findings.json` containing the findings as an array of objects with fields `id, title, severity, confidence, affects, locations, status` ("open"), for later tracking.

## Quality bar (re-read before finishing)
- Every finding has a real `file:line` and, where possible, a PoC result. No generic advice without a location.
- No duplicates; merge findings with the same root cause and list all locations.
- You looked for what is **missing** (an absent check) as well as what is wrong.
- You did not modify any file outside `audits/`.
- The summary says honestly what you could not verify.

## Finish
Stop after writing the report and `findings.json`. Then answer in chat with: the verdict line, counts of findings by severity, the top 5 fixes, and the path of the report. Do not start fixing anything.

---

# Part B — Fix phase (use ONLY after the owner reviews the report and says go)
Read `audits/SECURITY_AUDIT_REPORT.md` and `audits/findings.json`. Fix **one finding at a time**, in the order of the prioritized fix plan, starting with Critical. For each finding:
1. Write the regression test first and show it failing.
2. Make the smallest code change that fixes the root cause.
3. Run the full test suite, linters, type checks, and the frontend build. Everything that passed before must still pass.
4. Update the finding's `status` to `fixed` in `findings.json` and add a short "Resolution" note in the report with the commit/changed files.
5. Stop after each finding and give a 5-line summary. Wait for the owner to say "next".
Do not refactor unrelated code. Do not change the hashing, storage, or custody-ledger design without asking first. If a fix needs a decision (for example breaking an API), stop and ask.