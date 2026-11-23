import json
import os
import subprocess
import sys
import time
import requests

API_URL = "http://localhost:1234/v1/chat/completions"
MODELS_URL = "http://localhost:1234/v1/models"
OUTPUT_JSON = r"c:\forensicops-ai\audits\gemma4_vs_qwen35_benchmark.json"

# 50 Advanced, Deep Forensics & DFIR Questions
QUESTIONS = [
    # --- 1-10: Windows Core Artifacts & Filesystem Forensics ---
    {
        "id": 1,
        "topic": "NTFS Timestomping & $MFT Forensic Reconstruction",
        "question": (
            "An attacker compromised a Windows endpoint and ran a timestomping tool on a malicious payload "
            "'C:\\Windows\\System32\\svchost_update.exe' to backdate its timestamps to match 'calc.exe' (2021-05-12). "
            "Explain how you prove with 100% forensic certainty that timestomping occurred by analyzing the $MFT record, "
            "$STANDARD_INFORMATION ($SIA), $FILE_NAME ($FNA), and filesystem journals ($LogFile and $UsnJrnl:$J). "
            "Why can $FNA timestamps not be altered via standard Win32 API calls (SetFileTime), what nanosecond precision anomaly "
            "is introduced by common timestomping tools, and how does $UsnJrnl provide the actual time of modification? "
            "Explain your step-by-step reasoning and explicitly justify why you chose these specific artifacts."
        )
    },
    {
        "id": 2,
        "topic": "Windows Execution Artifacts Discrepancy & Triangulation",
        "question": (
            "A forensic analyst discovers an entry for a suspicious binary in the ShimCache (AppCompatCache), but there is no "
            "corresponding .pf file in 'C:\\Windows\\Prefetch', and no entry in 'Amcache.hve'. "
            "Does the presence in ShimCache prove the binary was executed on Windows 10/11? Under what circumstances can a binary "
            "appear in ShimCache without executing, why might Prefetch be missing despite actual execution, and how do you resolve "
            "this discrepancy to determine execution status? "
            "Provide exact registry paths, flags (such as the Executed flag in different Windows versions), and justify your investigative steps."
        )
    },
    {
        "id": 3,
        "topic": "SRUM (System Resource Usage Monitor) & Network Accounting",
        "question": (
            "During an investigation of suspected data exfiltration, the attacker deleted their staging directory and event logs. "
            "Explain how you extract and correlate evidence of execution and network exfiltration using SRUM ('SRUDB.dat' and the SOFTWARE registry hive). "
            "What specific table IDs / GUIDs in SRUDB.dat store application resource usage versus network data usage? How do you map the "
            "SRUM internal AppId to full file paths and SIDs, and what are the limitations/caching intervals of SRUM data flushing to disk?"
        )
    },
    {
        "id": 4,
        "topic": "USN Journal & $LogFile Transaction Reversal",
        "question": (
            "An adversary securely wiped files using SDelete (-p 3) and then cleared the Recycle Bin. "
            "How do you trace the existence, renaming, and overwriting history of those wiped files using the $UsnJrnl:$J and $LogFile? "
            "Explain the specific USN Reason codes (e.g., USN_REASON_FILE_CREATE, USN_REASON_DATA_OVERWRITE, USN_REASON_RENAME_NEW_NAME, "
            "USN_REASON_FILE_DELETE) that appear during SDelete execution, and why the file record MFT number and parent directory sequence numbers "
            "allow reconstructing the original directory path even after deletion."
        )
    },
    {
        "id": 5,
        "topic": "Amcache.hve Deep Dive & Unexecuted Staged Binaries",
        "question": (
            "Explain the internal architecture of 'Amcache.hve' on modern Windows 10/11 (InventoryApplicationFile vs Root\\File). "
            "If an attacker drops a compilation of tools onto an endpoint via a zip file, does Amcache record SHA-1/SHA-256 hashes for "
            "binaries that have NEVER been executed? What triggers Amcache inventory parsing, and how do you distinguish between an inventory sweep "
            "and an interactive process creation event using Amcache metadata (such as FileWatcher, ProgramId, and Linker timestamps)?"
        )
    },
    {
        "id": 6,
        "topic": "LNK Files and Shellbags Forensics",
        "question": (
            "An investigator needs to prove that an insider plugged in an unapproved USB drive and browsed folders containing confidential IP. "
            "The drive has been removed. Explain how you reconstruct the folder navigation history and USB volume serial number using "
            "Shellbags (UsrClass.dat / NTUSER.DAT) and AutomaticDestinations / CustomDestinations Jump Lists. "
            "How do Shellbags store MFT entry numbers and timestamps for deleted or detached media, and how do you correlate them with USBSTOR in the SYSTEM hive?"
        )
    },
    {
        "id": 7,
        "topic": "Volume Shadow Copies (VSC) & Differential Block Carving",
        "question": (
            "Ransomware executed on a server and attempted to run 'vssadmin delete shadows /all /quiet'. "
            "How can a digital forensics examiner verify whether any Volume Shadow Copies survived or whether Catalog blocks can be carved from unallocated clusters? "
            "Detail the structure of the VSS Differential Area (Storage Area), the significance of Volsnap.sys drivers, and how you mount or parse "
            "orphaned shadow copies to recover unencrypted pre-incident files."
        )
    },
    {
        "id": 8,
        "topic": "Registry Forensics: UserAssist, BAM, and DAM",
        "question": (
            "Compare the forensic utility of UserAssist (ROT13 encoded keys in NTUSER.DAT) with the Background Activity Moderator (BAM) "
            "and Desktop Activity Moderator (DAM) in 'SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings'. "
            "What specific timestamp does BAM record (process launch vs exit), how are user SIDs segregated in BAM, and why can BAM provide proof "
            "of execution for GUI and console binaries where UserAssist fails?"
        )
    },
    {
        "id": 9,
        "topic": "Event Log Tampering & Event ID 1102 / 104 Analysis",
        "question": (
            "An attacker executed 'wevtutil cl Security' and also terminated the Windows Event Log service by injecting into svchost.exe. "
            "Explain the exact forensic indicators left behind: Event ID 1102 in Security vs Event ID 104 in System. "
            "If the attacker suspended the event logging threads or zeroed out the evtx file header chunks on disk, how can an analyst carve "
            "and recover individual XML event chunks (Record template definitions and ElfChnk structures) from unallocated space?"
        )
    },
    {
        "id": 10,
        "topic": "PowerShell ScriptBlock Logging & Obfuscation Deobfuscation",
        "question": (
            "An adversary executes a complex multistage payload using PowerShell with backticks, variable substitution, environment variable slicing, "
            "and secure string AES decryption. "
            "How do PowerShell Script Block Logging (Event ID 4104), Transcription logs, and the PSReadLine history file (ConsoleHost_history.txt) differ? "
            "Why does Event ID 4104 capture code AFTER deobfuscation/unrolling, and what are the limitations when the script block exceeds the 32KB payload size?"
        )
    },

    # --- 11-20: Memory Forensics & Process Injection ---
    {
        "id": 11,
        "topic": "Memory Forensics: Reflective DLL Injection vs Process Hollowing",
        "question": (
            "During memory triage using Volatility 3 on a memory dump of an infected Windows workstation, you encounter "
            "suspicious VAD (Virtual Address Descriptor) nodes in 'lsass.exe' and 'svchost.exe'. "
            "Detail how you distinguish between Reflective DLL Injection and Process Hollowing (RunPE) using memory structures, "
            "VAD tags/protections (e.g. PAGE_EXECUTE_READWRITE), PE headers in memory, and the thread start address / PEB ImageBaseAddress. "
            "Explain step-by-step why an unbacked memory region with execute permissions is a high-fidelity indicator, "
            "and what artifact in the VAD tree proves a DLL was loaded without LoadLibrary. "
            "Justify why you would prioritize one analysis path over the other."
        )
    },
    {
        "id": 12,
        "topic": "Process Doppelgänging vs Process Herpaderping Forensics",
        "question": (
            "Compare Process Doppelgänging (transacted NTFS via TxF) and Process Herpaderping from a memory and disk forensic perspective. "
            "How does each technique manipulate the Kernel File Object and memory section (NtCreateSection)? "
            "Why does Process Doppelgänging leave no payload binary on disk during file scanner sweeps, and how can a memory analyst using Volatility "
            "identify discrepancies between the file-backed VAD and the actual memory bytes mapped in the hollowed process?"
        )
    },
    {
        "id": 13,
        "topic": "Direct Kernel Object Manipulation (DKOM) in Windows Memory",
        "question": (
            "An advanced rootkit hides a malicious process from task managers by unlinking its EPROCESS structure from the ActiveProcessLinks doubly-linked list. "
            "Explain how Volatility plugins (such as pslist vs psscan) discover this hidden process. "
            "What pool tags (e.g., 'Proc' / 'Proc\x00') are scanned, and how do thread scanning (ETHREAD pointing back to EPROCESS) and handle table scanning "
            "reveal the presence of unlinked processes?"
        )
    },
    {
        "id": 14,
        "topic": "Thread Execution Hijacking (SetThreadContext / QueueUserAPC)",
        "question": (
            "Explain how an attacker performs Early Bird APC injection or standard QueueUserAPC / SetThreadContext thread hijacking. "
            "In a captured physical memory dump, what specific indicators in the TEB (Thread Environment Block), the thread's call stack, "
            "and RIP/EIP pointers identify that a legitimate thread was redirected to execute shellcode in an unbacked memory allocation?"
        )
    },
    {
        "id": 15,
        "topic": "LSASS Memory Protection & Credential Dumping Defense",
        "question": (
            "An attacker attempts credential theft from LSASS. Compare the forensic memory and log footprints of: "
            "1) MiniDumpWriteDump (e.g., Mimikatz, Taskmgr), 2) PssCaptureSnapshot (Process Snapshotting), and 3) LSASS memory read via direct syscalls. "
            "What specific Sysmon Event ID 10 (ProcessAccess) granted access masks (e.g. 0x1010, 0x143a, 0x1fffff) reveal each method, and what artifacts "
            "does PssCaptureSnapshot leave in terms of cloned process handles?"
        )
    },
    {
        "id": 16,
        "topic": "Kernel Hooking: SSDT vs Inline vs IRP Hooking",
        "question": (
            "Explain how Windows x64 Kernel Patch Protection (PatchGuard) limits traditional SSDT (System Service Descriptor Table) hooking. "
            "How do modern rootkits bypass PatchGuard (e.g., hypervisor-based rootkits, DKOM, or hooking unmonitored IRP dispatch tables in third-party drivers)? "
            "Detail how an investigator analyzes driver object MajorFunction pointers to detect IRP hooking in Volatility 3."
        )
    },
    {
        "id": 17,
        "topic": "Memory Carving for Cryptographic Keys & DPAPI Master Keys",
        "question": (
            "During an investigation of an encrypted C2 channel or BitLocker volume, an analyst must extract AES or BitLocker FVEK keys from memory. "
            "How does KeyFind / AesKeyFind locate AES key schedules in physical memory based on the mathematical key expansion properties and round key entropy? "
            "How do DPAPI Master Keys in LSASS memory relate to user credential decryption (Chrome cookies, vaults, RDP passwords)?"
        )
    },
    {
        "id": 18,
        "topic": "Cobalt Strike Beacon Memory Artifacts & Configuration Extraction",
        "question": (
            "Explain the in-memory architecture of a default Cobalt Strike Beacon (Malleable C2 profile, sleep obfuscation/EKKO, heap encryption, and reflective loader). "
            "When sleep obfuscation is active (VirtualProtect/WaitOnAddress or timers), how do memory scanners like pe-sieve or Volatility detect the hidden beacon? "
            "What byte patterns and XOR decoding routines reveal the .beacon configuration block (C2 domains, port, watermark, public key)?"
        )
    },
    {
        "id": 19,
        "topic": "Named Pipe Impersonation Forensics (GetNamedPipeHandleState)",
        "question": (
            "Privilege escalation via named pipe impersonation (e.g., 'getsystem' in meterpreter/Cobalt Strike) relies on connecting to a created pipe as SYSTEM. "
            "What memory and event artifacts are generated during ImpersonateNamedPipeClient? "
            "How does the Token object of the calling thread change relative to the process token, and what Windows Security Event IDs (e.g., 4624 Type 9, 4672, 4673) "
            "record privilege escalation via token duplication?"
        )
    },
    {
        "id": 20,
        "topic": "Crash Dump Analysis & Hibernation File Reconstruction",
        "question": (
            "Explain how Windows 'hiberfil.sys' compresses and stores physical memory pages across various Windows versions (Xpress vs LZNT1 compression). "
            "How do tools like Volatility or Hibr2Bin decompress and reassemble the PO_MEMORY_IMAGE and memory runs into a flat raw memory dump? "
            "Why is hiberfil.sys often a goldmine for recovering data deleted hours before shutdown?"
        )
    },

    # --- 21-30: Active Directory, Kerberos, & Identity Forensics ---
    {
        "id": 21,
        "topic": "Active Directory & Kerberos Attack Forensics",
        "question": (
            "An attacker executed an attack against Active Directory. Security event logs on the Domain Controller and workstation "
            "show several Kerberos events. "
            "How do you forensically distinguish between: "
            "1) Overpass-the-Hash / Pass-the-Key (PTK), "
            "2) Golden Ticket (forged TGT), and "
            "3) Silver Ticket (forged TGS)? "
            "Specify the exact Event IDs (e.g., 4624, 4768, 4769), ticket encryption types (0x17 RC4-HMAC vs 0x12 AES256-CTS), "
            "ticket lifetime anomalies, and PAC validation mechanisms. "
            "Why does a Silver Ticket produce NO Event ID 4769 on the Domain Controller? Explain your forensic reasoning."
        )
    },
    {
        "id": 22,
        "topic": "Kerberoasting vs AS-REP Roasting Artifacts & Detection",
        "question": (
            "Detail the forensic differences between a Kerberoasting attack and an AS-REP Roasting attack on Domain Controllers. "
            "What specific Event IDs are generated (Event 4769 vs Event 4768), what ticket options (e.g., 0x40810000) and encryption types (0x17 RC4) "
            "indicate malicious extraction, and why do accounts with 'Do not require Kerberos preauthentication' (DONT_REQ_PREAUTH) trigger AS-REP Roasting? "
            "How can you correlate service ticket requests with unusual volume from a single IP to prove automated extraction?"
        )
    },
    {
        "id": 23,
        "topic": "DCSync & Active Directory Replication Forensics",
        "question": (
            "An adversary performed a DCSync attack using Mimikatz or Impacket to dump domain credentials. "
            "What specific directory service access events (Directory Service Access Event ID 4662) are generated on Domain Controllers? "
            "What specific extended rights GUIDs (e.g., DS-Replication-Get-Changes, DS-Replication-Get-Changes-All, DS-Replication-Get-Changes-In-Filtered-Set) "
            "are queried, and how do you distinguish between legitimate Domain Controller replication (RPC over TCP) and a DCSync from a rogue workstation IP?"
        )
    },
    {
        "id": 24,
        "topic": "Shadow Credentials (msDS-KeyCredentialLink) Forensics",
        "question": (
            "Explain the mechanics and forensic footprint of the 'Shadow Credentials' attack (Whiskey/PyWhiskey). "
            "How does an attacker write to the 'msDS-KeyCredentialLink' attribute of a computer or user object in Active Directory? "
            "What Event ID (e.g., 5136 Directory Service Changes) records this modification, what does the raw binary structure of the KeyCredentialLink contain "
            "(e.g., raw X.509 public key and flags), and how does PKINIT authentication (Event ID 4768 with pre-auth type 16/17) follow?"
        )
    },
    {
        "id": 25,
        "topic": "Active Directory Certificate Services (ADCS) ESC1 & ESC8 Forensics",
        "question": (
            "Contrast ADCS ESC1 (misconfigured certificate template with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT and Client Authentication EKU) "
            "with ESC8 (NTLM Relay to ADCS HTTP Enrollment Endpoints). "
            "What specific certificate issuance events (Certification Authority Event IDs 4886, 4887, 4888) appear in the CA event log? "
            "How do you trace the SAN (Subject Alternative Name) containing a forged Domain Admin UPN, and what IIS log artifacts on the CA server "
            "prove HTTP-based NTLM relay occurred in ESC8?"
        )
    },
    {
        "id": 26,
        "topic": "Skeleton Key Malware in Active Directory Domain Controllers",
        "question": (
            "Explain how the Skeleton Key malware patches LSASS memory on an active Domain Controller to allow any domain user to authenticate "
            "with a master password while preserving legitimate user passwords. "
            "Why does Skeleton Key degrade Kerberos downgrade negotiation to RC4-HMAC? "
            "What physical memory indicators and event log anomalies occur, and why does rebooting the DC eradicate the malware if no persistence was placed?"
        )
    },
    {
        "id": 27,
        "topic": "SAM and SYSTEM Hive Offline Decryption & Syskey/BootKey",
        "question": (
            "Explain the cryptographic process of extracting local NTLM password hashes from the offline SAM hive using the SYSTEM hive. "
            "How is the BootKey derived from the 'JD', 'GBG', 'Data', and 'Skew1' subkeys in the ControlSet? "
            "How is the F value in 'SAM\\Domains\\Account' decrypted using the BootKey to obtain the AES/DES keys that decrypt the V structure of individual user RID accounts?"
        )
    },
    {
        "id": 28,
        "topic": "DPAPI Domain Backup Key & LsaRetrievePrivateData Forensics",
        "question": (
            "How does an adversary extract the Active Directory DPAPI domain backup key (using LsaRetrievePrivateData for G$BCKUPKEY_P and G$BCKUPKEY_PREFERRED)? "
            "Once extracted, how can an analyst or attacker decrypt any user's DPAPI Master Keys offline without knowing the user's plaintext password? "
            "What specific RPC calls and Event IDs (e.g., 4662 or LSASS handle access) occur on the Domain Controller when the backup key is queried remotely?"
        )
    },
    {
        "id": 29,
        "topic": "GPO Abuse & SYSVOL Scheduled Task Deployment",
        "question": (
            "An attacker compromised a Domain Admin account and modified an existing Group Policy Object (GPO) to push a malicious scheduled task "
            "to 500 workstations across the enterprise. "
            "Where in SYSVOL is the XML task definition stored ('ScheduledTasks.xml')? How do you inspect directory replication and file modification timestamps "
            "to identify when the GPO was edited, what Event IDs (5136, 5137, 5145) record the modification, and how do client endpoints log GPO application "
            "in the 'GroupPolicy\\Operational' event log?"
        )
    },
    {
        "id": 30,
        "topic": "NTLM Relaying & SMB Signing Bypass Forensics",
        "question": (
            "An attacker placed Responder on a local subnet, coerced authentication via LLMNR/NBT-NS poisoning, and relayed the NTLMv2 hashes "
            "to an SMB server where SMB Signing was disabled. "
            "Detail the forensic evidence on: 1) The poisoned victim workstation, 2) The target server receiving the relayed authentication. "
            "Why does Event ID 4624 show Logon Type 3 with the workstation name of the relay attacker or original victim, and what network capture artifacts "
            "(MIC - Message Integrity Code, NTLMSSP challenge-response) prove relaying took place?"
        )
    },

    # --- 31-40: Lateral Movement, Persistence, & Anti-Forensics ---
    {
        "id": 31,
        "topic": "Stealthy Persistence: WMI Event Subscriptions vs COM Hijacking",
        "question": (
            "Compare WMI Event Subscriptions (__EventFilter, __EventConsumer, __FilterToConsumerBinding) and User-level COM Hijacking "
            "(e.g., HKCU CLSID / InprocServer32) as persistence mechanisms. "
            "For an offline dead-box triage: Where are these artifacts stored on disk (exact file paths and registry hives)? "
            "How do you parse OBJECTS.DATA without running WMI services, and how does COM search order hijacking allow privilege elevation "
            "or persistence without administrative privileges? "
            "Explain why an adversary would choose COM hijacking over standard Run keys and justify how an investigator should detect it."
        )
    },
    {
        "id": 32,
        "topic": "Lateral Movement: Remote Execution Artifact Triangulation",
        "question": (
            "An incident responder needs to determine whether lateral movement occurred via PsExec, WMI (Win32_Process.Create), "
            "or PowerShell Remoting (WinRM). "
            "Detail the distinctive host artifacts left on both the source and target systems for each method, including Windows Event IDs "
            "(System and Security logs), named pipes, service installations, parent-child process lineages, and network connections. "
            "Why does WinRM leave high-fidelity script block logs (Event 4104) while WMI execution historically leaves blind execution traces? "
            "Justify your triage workflow."
        )
    },
    {
        "id": 33,
        "topic": "Remote Desktop Protocol (RDP) Forensics & Bitmap Caching",
        "question": (
            "An attacker accessed a critical financial system via RDP, performed manual actions, and deleted their staging folder before logging off. "
            "Detail the full chain of RDP forensic artifacts across the system: "
            "1) Event logs (TerminalServices-LocalSessionManager Event IDs 21, 24, 25; TerminalServices-RDPClient Event 1024/1026; Security 4624 Type 10 vs Type 7). "
            "2) BMC / RDP Bitmap Caches (bcache*.bmc) on the client machine and how to reconstruct graphical screenshots of the attacker's session. "
            "How do you prove whether an RDP session was interactive console or an existing session reconnect?"
        )
    },
    {
        "id": 34,
        "topic": "BITS (Background Intelligent Transfer Service) Persistence & Jobs",
        "question": (
            "Malware used BITS to stealthily download secondary payloads and maintain persistence via the 'SetNotifyCmdLine' parameter. "
            "Where are BITS jobs stored on disk across modern Windows versions (e.g., 'qmgr.db' / 'qmgr.dat' or 'StateStore.dat' in ProgramData\\Microsoft\\Network\\Downloader)? "
            "How do you extract the remote URL, local file destination, and executing command line from the BITS database, and what Event IDs (Microsoft-Windows-Bits-Client/Operational) "
            "record job creation, transfer completion, and command execution?"
        )
    },
    {
        "id": 35,
        "topic": "Scheduled Task XML Parsing & Task Tampering",
        "question": (
            "An adversary creates a scheduled task that executes every 4 hours, but hides it by deleting the SD (Security Descriptor) registry value "
            "in 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree\\<TaskName>'. "
            "Why does this task disappear from 'schtasks /query' and Task Scheduler GUI while continuing to run via the Task Scheduler service? "
            "How does a forensic investigator locate the raw XML task definition in 'C:\\Windows\\System32\\Tasks' and correlate the Task ID GUID "
            "in 'TaskCache\\Tasks' with Event ID 106 and 200 in Microsoft-Windows-TaskScheduler/Operational?"
        )
    },
    {
        "id": 36,
        "topic": "Shim Database (SDB) Custom Application Shimming",
        "question": (
            "Explain how an attacker uses custom Application Compatibility Shims (e.g., sdbinst.exe) to achieve stealthy persistence or bypass security controls "
            "like UAC or DLL redirection. "
            "Where are custom .sdb files installed on disk ('C:\\Windows\\AppPatch\\Custom'), what registry keys in 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom' "
            "and 'InstalledSDB' track their registration, and what tools or methods exist to decompile and inspect the XML/TAG structures inside an SDB file?"
        )
    },
    {
        "id": 37,
        "topic": "Office Document Macros, VBA Stomping, & Purview Forensics",
        "question": (
            "Explain the technical difference between VBA source code and compiled P-code (Performance Code) in Microsoft Office documents (OLE/CFBF format). "
            "What is 'VBA Stomping', why does it allow malicious documents to bypass AV scanners that inspect only the compressed VBA source stream, "
            "and how do forensic tools like 'oledump' or 'pcodedmp' detect when the P-code version mismatch occurs or when source code is completely stripped?"
        )
    },
    {
        "id": 38,
        "topic": "DLL Search Order Hijacking vs DLL Side-Loading Forensics",
        "question": (
            "Distinguish between DLL Search Order Hijacking and DLL Side-Loading. "
            "What is the exact search order for 32-bit and 64-bit applications under SafeDllSearchMode? "
            "How do you prove that an application loaded a rogue DLL from a non-standard directory using ShimCache, Amcache, Prefetch, or Sysmon Event ID 7 (Image Loaded)? "
            "What specific metadata in Sysmon Event ID 7 (e.g., Signed, SignatureStatus, Hashes) alerts an investigator to an unsigned side-loaded DLL?"
        )
    },
    {
        "id": 39,
        "topic": "Log Clearing Artifacts: USN Record 0x80000000 & Chunk Deallocation",
        "question": (
            "When an attacker clears an event log (e.g., Security.evtx), what happens physically on the NTFS volume? "
            "Explain how the file size of the .evtx file shrinks back to the default header size (64KB), how the old chunks are deallocated to unallocated space, "
            "and how the USN Journal records this transaction (USN_REASON_DATA_TRUNCATION / USN_REASON_DATA_EXTEND). "
            "How can an investigator carve and match deallocated chunk headers (ElfChnk signature) to reconstruct the deleted security events?"
        )
    },
    {
        "id": 40,
        "topic": "NTFS Alternate Data Streams (ADS) & Zone.Identifier Forensics",
        "question": (
            "Explain how Alternate Data Streams (ADS) work in NTFS, and specifically detail the forensic significance of 'Zone.Identifier'. "
            "What specific fields (ZoneId, HostUrl, ReferrerUrl) are populated by modern web browsers when an executable or ISO is downloaded from the internet? "
            "How does Mark-of-the-Web (MOTW) propagation occur when an archive (zip/tar) vs a disk image (ISO/VHD) is unpacked on Windows 10/11, "
            "and why did attackers pivot to ISO/LNK containers to bypass MOTW?"
        )
    },

    # --- 41-50: Linux, Cloud, Container, & Advanced Forensics ---
    {
        "id": 41,
        "topic": "Linux Anti-Forensics & Kernel Rootkits",
        "question": (
            "A compromised Linux server is suspected of running a kernel-level LKM (Loadable Kernel Module) rootkit that hides "
            "processes from '/proc' and 'ps'. "
            "How does a DKOM (Direct Kernel Object Manipulation) rootkit unlink a process from the 'init_task' circular doubly linked list? "
            "How can you detect and dump the hidden process and kernel module using physical memory analysis (e.g., LiME and Volatility "
            "'linux.pslist' vs 'linux.pidhashtable' vs 'linux.check_modules'), and what filesystem or memory artifacts reveal the rootkit's "
            "presence if '/proc/modules' is hooked? Explain your reasoning."
        )
    },
    {
        "id": 42,
        "topic": "Linux Auditd & Syscall Auditing Bypass Forensics",
        "question": (
            "An attacker obtained root privileges on an Ubuntu server configured with 'auditd'. "
            "How could the attacker bypass or tamper with auditd without stopping the daemon (e.g., modifying audit rules via 'auditctl -D', "
            "exploiting rate limits, or using ptraced direct syscalls)? "
            "Where are auditd raw logs stored ('/var/log/audit/audit.log'), what does a syscall record look like (type=SYSCALL, type=EXECVE, type=CWD, type=PATH), "
            "and how do you correlate the auid (audit UID) to find the original logging user who sudo'ed to root?"
        )
    },
    {
        "id": 43,
        "topic": "Linux Memory Forensics: Memory Acquisition without LiME (dev/fmem / /proc/kcore)",
        "question": (
            "On modern locked-down Linux kernels (Kernel Lockdown mode with Secure Boot enabled), loading unsigned kernel modules like LiME is blocked. "
            "How can an incident responder acquire physical memory using '/proc/kcore' and tools like 'dwarfextract' or 'kcore-dump'? "
            "What limitations does /proc/kcore have regarding virtual-to-physical address translation, and how do you construct a System.map and debug vmlinux "
            "profile for Volatility 3 when debug packages are not available for the target kernel?"
        )
    },
    {
        "id": 44,
        "topic": "Docker & Container Escape Forensics",
        "question": (
            "A web application running inside a Docker container was exploited, and the attacker escaped to the host Linux operating system. "
            "Detail the forensic artifacts on both the container layer and the host system for: "
            "1) Escape via privileged container mounting '/dev/sda1', 2) Escape via exposed Docker socket ('/var/run/docker.sock'), and "
            "3) Escape via cgroup release_agent exploitation. "
            "Where are container overlay2 storage diffs and container metadata stored on the host ('/var/lib/docker/overlay2' and '/var/lib/docker/containers/<id>/config.v2.json')?"
        )
    },
    {
        "id": 45,
        "topic": "Kubernetes Audit Logs & API Server Compromise",
        "question": (
            "An attacker compromised a Kubernetes cluster through a stolen ServiceAccount token and deployed a malicious DaemonSet. "
            "Explain how to investigate this incident using Kubernetes API Server Audit Logs (Audit policy levels: Metadata, Request, RequestResponse). "
            "What specific JSON fields in the audit log (verb, requestURI, user.username, sourceIPs, responseStatus.code) "
            "confirm unauthorized resource creation, and how do you trace whether the token originated from an in-pod mount or an external IP?"
        )
    },
    {
        "id": 46,
        "topic": "AWS CloudTrail Forensics & IAM Privilege Escalation",
        "question": (
            "An attacker used a compromised AWS Access Key ID to escalate privileges via 'iam:CreatePolicyVersion' and disable CloudTrail logging. "
            "Detail the CloudTrail event records for: 1) 'StopLogging', 2) 'DeleteTrail', and 3) 'CreatePolicyVersion'. "
            "What specific fields (userIdentity.arn, userIdentity.sessionContext, eventSource, eventName, requestParameters) prove the identity and action? "
            "If CloudTrail Log File Validation is enabled, how do you mathematically verify that log digests have not been tampered with or modified in the S3 bucket?"
        )
    },
    {
        "id": 47,
        "topic": "AWS EC2 EBS Snapshot Forensic Acquisition & KMS Re-encryption",
        "question": (
            "Explain the forensically sound procedure for acquiring and analyzing an infected AWS EC2 instance without altering its state or stopping the instance. "
            "Detail the steps: taking an EBS snapshot, copying the snapshot to an isolated forensics AWS account, re-encrypting it with a forensic KMS CMK, "
            "creating an EBS volume from the snapshot, and attaching it as a secondary non-boot drive to a forensic analysis EC2 workstation. "
            "Why is this workflow forensically sound under ISO 27037 standards?"
        )
    },
    {
        "id": 48,
        "topic": "TLS Decryption & Network Session Forensics",
        "question": (
            "An investigator captured a PCAP containing malicious TLS 1.3 C2 communication. "
            "Why can TLS 1.3 traffic NOT be decrypted using the server's private RSA key (due to mandatory Ephemeral Diffie-Hellman / Perfect Forward Secrecy)? "
            "How can the investigator decrypt the traffic using the client's SSLKEYLOGFILE (CLIENT_RANDOM and CLIENT_HANDSHAKE_TRAFFIC_SECRET)? "
            "If no key log file is available, what forensic information can still be extracted from the unencrypted TLS Client Hello (SNI, JA3/JA4 fingerprint, cipher suites, ALPN)?"
        )
    },
    {
        "id": 49,
        "topic": "DNS Tunneling & C2 Data Exfiltration Detection",
        "question": (
            "An insider exfiltrated sensitive databases by encoding records into DNS query subdomains (e.g., '<base32-data>.c2.evilcorp.com') sent to an authoritative DNS server. "
            "Explain the mathematical and statistical metrics used to detect DNS tunneling in passive DNS / Zeek / Corelight logs: "
            "Shannon entropy of subdomains, query length distribution, volume of TXT/NULL record queries, percentage of unique subdomains per domain, and NXDOMAIN ratios. "
            "How do you reconstruct the exfiltrated binary payload from ordered DNS queries?"
        )
    },
    {
        "id": 50,
        "topic": "Supply Chain Compromise & CI/CD Pipeline Artifacts",
        "question": (
            "A software vendor's GitHub Actions CI/CD runner was compromised to inject a backdoor into a release binary. "
            "How do you forensically investigate a compromised CI/CD workflow? "
            "What artifacts do you analyze: GitHub Actions workflow run logs, git commit SHA vs release tag verification, runner ephemeral disk images, "
            "and OIDC (OpenID Connect) token exchange logs with cloud providers? "
            "How do SLSA (Supply-chain Levels for Software Artifacts) provenance attestations and Sigstore/Cosign cosignatures prove whether a binary was produced by a trusted pipeline?"
        )
    }
]

def query_model(model_name, question_obj, max_retries=3):
    headers = {"Content-Type": "application/json"}
    
    # Prompt forcing detailed explanation and rationale
    user_prompt = (
        f"[TOPIC: {question_obj['topic']}]\n\n"
        f"FORENSIC QUESTION:\n{question_obj['question']}\n\n"
        f"MANDATORY INSTRUCTIONS:\n"
        f"1. Provide a direct, exhaustive, technically precise answer.\n"
        f"2. Detail your step-by-step forensic reasoning and artifact reconstruction.\n"
        f"3. Explain WHY you chose these specific artifacts and evidence paths, and why competing alternative explanations/hypotheses are ruled out.\n"
        f"4. Cite exact filesystem paths, registry keys, Event IDs, structures, or API functions where applicable."
    )

    payload = {
        "model": model_name,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a World-Class Senior Principal Cyber Forensics & Incident Response (DFIR) Specialist "
                    "and Systems Architect. You provide comprehensive, technically deep, and forensically sound analyses. "
                    "Always explain the underlying OS/filesystem/memory mechanics and justify every conclusion."
                )
            },
            {"role": "user", "content": user_prompt}
        ],
        "temperature": 0.1,
        "max_tokens": 4096
    }

    for attempt in range(max_retries):
        start_time = time.time()
        try:
            r = requests.post(API_URL, json=payload, headers=headers, timeout=300)
            duration = round(time.time() - start_time, 2)
            if r.status_code != 200:
                print(f"[{model_name}] Q{question_obj['id']} (attempt {attempt+1}) HTTP {r.status_code}: {r.text[:200]}")
                time.sleep(3)
                continue
            res_data = r.json()
            msg = res_data["choices"][0]["message"]
            content = msg.get("content", "")
            reasoning = msg.get("reasoning_content", "")
            print(f"[{model_name}] Q{question_obj['id']} completed in {duration}s ({len(content)} content chars, {len(reasoning)} reasoning chars)")
            return {
                "status": "success",
                "duration_seconds": duration,
                "content": content,
                "reasoning": reasoning
            }
        except Exception as e:
            duration = round(time.time() - start_time, 2)
            print(f"[{model_name}] Q{question_obj['id']} (attempt {attempt+1}) FAILED after {duration}s: {e}")
            time.sleep(3)
            
    return {
        "status": "error",
        "duration_seconds": duration,
        "error": "Max retries exceeded",
        "content": "",
        "reasoning": ""
    }

def run_lms_cmd(args):
    print(f"Executing: lms {' '.join(args)}")
    res = subprocess.run(["lms"] + args, capture_output=True, text=True, encoding="utf-8", errors="replace")
    print("STDOUT:", (res.stdout or "").strip())
    if res.stderr:
        print("STDERR:", res.stderr.strip())
    return res

def wait_for_model(model_name, timeout=60):
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = requests.get(MODELS_URL, timeout=5)
            if r.status_code == 200:
                ps_res = subprocess.run(["lms", "ps"], capture_output=True, text=True, encoding="utf-8", errors="replace")
                if model_name in ps_res.stdout:
                    print(f"Model '{model_name}' verified loaded and ready.")
                    return True
        except Exception:
            pass
        time.sleep(2)
    return False

def main():
    os.makedirs(os.path.dirname(OUTPUT_JSON), exist_ok=True)
    
    m1 = "qwen3.5-9b"
    m2 = "gemma-4-e4b-it"

    # State file to allow resume
    state = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "models": {"model_1": m1, "model_2": m2},
        "m1_results": {},
        "m2_results": {}
    }

    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if "m1_results" in saved:
                    state["m1_results"] = saved["m1_results"]
                if "m2_results" in saved:
                    state["m2_results"] = saved["m2_results"]
                print(f"Loaded existing progress: {len(state['m1_results'])} Qwen results, {len(state['m2_results'])} Gemma results.")
        except Exception as e:
            print("Could not load existing benchmark file:", e)

    # 1. Run Qwen 3.5 (currently loaded)
    print(f"\n==========================================")
    print(f"PHASE 1: BENCHMARKING {m1} (50 QUESTIONS)")
    print(f"==========================================")
    for q in QUESTIONS:
        qid_str = str(q["id"])
        if qid_str in state["m1_results"] and state["m1_results"][qid_str].get("status") == "success":
            print(f"[{m1}] Q{q['id']} already answered. Skipping.")
            continue
        ans = query_model(m1, q)
        state["m1_results"][qid_str] = ans
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)

    # 2. Unload Qwen and load Gemma
    print(f"\n==========================================")
    print(f"PHASE 2: SWITCHING MODELS ({m1} -> {m2})")
    print(f"==========================================")
    run_lms_cmd(["unload", m1])
    time.sleep(3)
    run_lms_cmd(["load", m2, "-y", "--context-length", "8192", "--parallel", "1"])
    if not wait_for_model(m2, timeout=60):
        print(f"WARNING: Model {m2} did not verify in time! Pausing 5s...")
        time.sleep(5)

    # 3. Run Gemma 4
    print(f"\n==========================================")
    print(f"PHASE 3: BENCHMARKING {m2} (50 QUESTIONS)")
    print(f"==========================================")
    for q in QUESTIONS:
        qid_str = str(q["id"])
        if qid_str in state["m2_results"] and state["m2_results"][qid_str].get("status") == "success":
            print(f"[{m2}] Q{q['id']} already answered. Skipping.")
            continue
        ans = query_model(m2, q)
        state["m2_results"][qid_str] = ans
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, ensure_ascii=False)

    print("\n==========================================")
    print("ALL 50 QUESTIONS COMPLETED FOR BOTH MODELS!")
    print(f"Results stored in: {OUTPUT_JSON}")
    print("==========================================")

if __name__ == "__main__":
    main()
