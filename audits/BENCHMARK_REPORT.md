# Comprehensive DFIR Intelligence Benchmark
## DeepSeek-R1 (Distill Qwen 7B) vs. Gemma 4 (7.5B IT)

- **Date:** 2026-11-09
- **Inference Platform:** LM Studio 1.3.3.0 (Local GPU Acceleration)
- **Evaluation Scope:** 10 Hard DFIR Scenarios (NTFS internals, memory injection, Kerberos forgery, persistence, lateral movement, kernel rootkits, VSS mechanics, JVM fileless web shells, and TLS 1.3 C2 analysis).

---

## 1. Executive Summary & Final Verdict

| Metric | DeepSeek-R1 Distill Qwen 7B | Gemma 4 (7.5B IT) | Winner |
| :--- | :--- | :--- | :--- |
| **Factual Forensic Accuracy** | **28 / 100** (Severe hallucinations of Event IDs, paths, and tools) | **94 / 100** (Precise kernel structs, Win32 APIs, exact Event IDs) | 🏆 **Gemma 4** |
| **DFIR Rigor & Artifact Precision** | **35 / 100** (Superficial bullet points, mixed concepts) | **96 / 100** (Granular, multi-artifact triangulation) | 🏆 **Gemma 4** |
| **Reasoning & Method Justification** | **42 / 100** (Stated actions with little/flawed justification) | **95 / 100** (Architect-level rationale, anti-forensics caveats) | 🏆 **Gemma 4** |
| **Hallucination Resilience** | **20 / 100** (Fabricated `/proc/pslist`, Event 3094, etc.) | **98 / 100** (Virtually zero fabricated artifacts) | 🏆 **Gemma 4** |
| **Average Output Depth** | 2,165 chars final response | 7,723 chars comprehensive report | 🏆 **Gemma 4** |
| **OVERALL FORENSIC SCORE** | **31.25 / 100** | **95.75 / 100** | 🏆 **Gemma 4 (Landslide)** |

### **Recommendation for ForensicOps AI Agent:**
**Choose Gemma 4 (`gemma-4-e4b-it`) unconditionally.**
DeepSeek-R1 Distill Qwen 7B is dangerously prone to fabricating forensic artifacts, hallucinating non-existent Windows Event IDs, inventing Linux kernel paths, and misidentifying fundamental security protocols. In contrast, **Gemma 4 demonstrated extraordinary domain knowledge**, matching the precision of a Principal DFIR reverse engineer and forensic systems architect.

---

## 2. Granular Question-by-Question Breakdown

### Q1: NTFS Timestomping & $MFT Forensic Reconstruction
- **DeepSeek-R1 (2/10):** Recommended using `Regshot` to parse NTFS `$MFT` (Regshot is a registry tool, not an MFT parser). Claimed to read `$SIA` from "FAT32 headers" (FAT32 has neither $MFT nor $SIA).
- **Gemma 4 (10/10):** Correctly distinguished `$STANDARD_INFORMATION` (`$SIA`) updated by user-mode Win32 `SetFileTime` from `$FILE_NAME` (`$FNA`) managed exclusively by `ntfs.sys`. Explained 100ns precision truncation/zeroing in automated tools and how `$UsnJrnl:$J` records the actual commit time regardless of backdated metadata.

### Q2: Memory Forensics: Reflective DLL Injection vs Process Hollowing
- **DeepSeek-R1 (3/10):** Made the catastrophic claim that Reflective DLL Injection "does not add a PE header since it loads directly into kernel-mode memory" (Reflective DLL injection occurs strictly in user-mode address space).
- **Gemma 4 (9.5/10):** Explained VAD tree parsing in Volatility 3, comparing unbacked `PAGE_EXECUTE_READWRITE` memory allocations without file backing (Reflective DLL) against unmapping/remapping of the original PE image at PEB `ImageBaseAddress` with entry-point thread redirection (Process Hollowing).

### Q3: Windows Execution Artifacts Discrepancy & Triangulation
- **DeepSeek-R1 (1/10):** Pure hallucination. Invented "Event ID 3094 (PE X)" and anti-forensic tools like "PE Guard or PE X Guard".
- **Gemma 4 (9.5/10):** Accurately cited `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\AppCompatCache`. Explained why Windows 10/11 inserts binaries into ShimCache upon file system interaction (browsing/probing) without execution, why Prefetch might be absent (SSD optimizations, `EnablePrefetcher` values, or executions under 10 seconds), and how to triangulate via Amcache (`Amcache.hve`) SHA1 hashes and UserAssist (`CE...` ROT13 keys).

### Q4: Active Directory & Kerberos Attack Forensics
- **DeepSeek-R1 (3/10):** Claimed Event ID 4624 detects PTK when a "client sends an invalid ticket to the DC". Stated that Silver Tickets lack Event 4769 because "the DC fails to renew it".
- **Gemma 4 (10/10):** Masterclass explanation. Explained that a Silver Ticket generates **NO Event 4769 on the Domain Controller** because the ticket is crafted offline using the service account's secret and sent directly to the resource server (e.g. CIFS/MSSQL), completely bypassing the KDC. Correctly contrasted with Golden Tickets (compromised `krbtgt`, forged TGT, anomalous 10-year validity) and Overpass-the-Hash (Event 4768 with RC4 encryption type `0x17` instead of AES `0x12`).

### Q5: Stealthy Persistence: WMI Event Subscriptions vs COM Hijacking
- **DeepSeek-R1 (2/10):** Claimed WMI events are stored in `%ProgramFiles%\Windows\WMI\` and COM hijacking "hijacks Active Directory objects".
- **Gemma 4 (10/10):** Correctly identified CIM repository on disk (`%SystemRoot%\System32\wbem\Repository\OBJECTS.DATA`), parsed `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding`. Detailed COM registry search order (`HKCU\Software\Classes\CLSID` evaluated before `HKLM\Software\Classes\CLSID`), allowing stealth persistence without administrative privileges.

### Q6: Lateral Movement: Remote Execution Artifact Triangulation
- **DeepSeek-R1 (4/10):** Fabricated "PMEM Processes" in process memory logs for PsExec.
- **Gemma 4 (9.5/10):** Detailed exact artifacts:
  - **PsExec:** Event 7045/4697 (service install), named pipe `\pipe\psexec*`, network share `ADMIN$`.
  - **WMI:** Network logon 4624 type 3, process creation 4688 with parent `wmiprvse.exe`.
  - **WinRM:** TCP 5985/5986, `wsmprovhost.exe`, and PowerShell Script Block Logging (Event ID 4104).

### Q7: Linux Anti-Forensics & Kernel Rootkits
- **DeepSeek-R1 (2/10):** Hallucinated non-existent Linux files `/proc/check_modules` and `/proc/pslist`. Claimed `init_task` was a list in `initramfs`.
- **Gemma 4 (9.5/10):** Accurately described `struct task_struct`, the `tasks` member (`struct list_head`), and the exact pointer manipulation unlinking the node ($P_{prev} \to tasks.next = T \to tasks.next$). Triangulated memory detection via Volatility `linux.pslist` (list traversal) vs `linux.pidhashtable` (hash index) and `linux.check_modules` against sysfs kobjects.

### Q8: Volume Shadow Copy Deletion & Recovery Analysis
- **DeepSeek-R1 (4/10):** Claimed `$LogFile` has a "vss.log" entry.
- **Gemma 4 (9/10):** Explained VSS copy-on-write storage mechanics, the Catalog database in `System Volume Information`, DiffArea file chunks, and how raw carving of `VSS_SNAPSHOT_STORE` headers from unallocated space allows partial block recovery.

### Q9: Fileless & In-Memory Web Shell Forensics
- **DeepSeek-R1 (5/10):** Mischaracterized `jcmd` as "Java Class Memory Debugger" and gave vague thread inspection instructions.
- **Gemma 4 (9.5/10):** Detailed JVM SA-JDI inspection (`jhsdb hsdb` / `jhsdb clhsdb`), using `dumpclass` to extract dynamically redefined bytecode from the JVM HotSpot runtime, and inspecting Tomcat's internal `ApplicationFilterChain` and `StandardContext` Valve pipelines.

### Q10: Encrypted C2 Network Forensics: TLS 1.3 Traffic Analysis
- **DeepSeek-R1 (2/10):** Falsely claimed JA3 and JA4 are "mutual authentication certificates".
- **Gemma 4 (9.5/10):** Correctly explained JA3/JA4 as Client Hello cryptographic parameter fingerprints. Clarified why TLS 1.3 encrypts Server Certificates (and Encrypted Client Hello / ECH masks SNI), requiring network defenders to rely on client-side JA4 fingerprints, inter-arrival packet timing jitter analysis, and byte size distribution profiling.

---

## 3. Conclusion & Next Steps
`gemma-4-e4b-it` is significantly superior for DFIR and agent orchestration, exhibiting professional domain knowledge and zero dangerous hallucinations.
All raw benchmark responses have been captured in:
- `c:\forensicops-ai\audits\dfir_benchmark_results.json`
- `c:\forensicops-ai\audits\dfir_benchmark_comparison.md`
