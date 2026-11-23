import json
import os
import subprocess
import sys
import time
import requests

API_URL = "http://localhost:1234/v1/chat/completions"
MODELS_URL = "http://localhost:1234/v1/models"
OUTPUT_JSON = r"c:\forensicops-ai\audits\dfir_benchmark_results.json"
OUTPUT_MD = r"c:\forensicops-ai\audits\dfir_benchmark_comparison.md"

QUESTIONS = [
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
        "id": 3,
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
        "id": 4,
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
        "id": 5,
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
        "id": 6,
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
        "id": 7,
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
        "id": 8,
        "topic": "Volume Shadow Copy Deletion & Recovery Analysis",
        "question": (
            "Ransomware operators routinely execute commands to delete Volume Shadow Copies before encrypting data (e.g. 'vssadmin delete shadows /all /quiet', "
            "'wmic shadowcopy delete', or PowerShell CIM calls). "
            "From a dead-box forensic standpoint, how do you verify shadow copy deletion, what specific artifacts in $LogFile, $MFT, and "
            "the 'C:\\System Volume Information' folder record this activity, and is it ever possible to carve or recover data from deleted shadow copy "
            "storage chunks (Catalog and DiffArea volume stores)? Explain the physical storage mechanics and justify your conclusion."
        )
    },
    {
        "id": 9,
        "topic": "Fileless & In-Memory Web Shell Forensics",
        "question": (
            "An external attacker compromised an Apache Tomcat web server. No web shell files (.jsp, .war) exist in 'webapps' or filesystem logs. "
            "The attacker is interacting with a memory-only Java web shell (such as a malicious Java Servlet Filter, Tomcat Valve, or Java Agent). "
            "How do you forensically detect, dump, and analyze this fileless Java web shell from a live process or memory dump? "
            "What specific tools or JVM inspection techniques (e.g. jcmd, jhsdb, SA-JDI, Java Agent class dumping) allow you to recover "
            "the injected bytecode, and why do traditional disk-based YARA scans fail completely? Justify your forensic approach."
        )
    },
    {
        "id": 10,
        "topic": "Encrypted C2 Network Forensics: TLS 1.3 Traffic Analysis",
        "question": (
            "A compromised internal workstation is communicating with an external Command-and-Control (C2) server over TLS 1.3 on port 443. "
            "The enterprise does not have active TLS decryption/inspection. "
            "How can a forensic network analyst identify malicious C2 beaconing and profile the adversary tooling purely from passive PCAP analysis? "
            "Explain the forensic application of JA3/JA3S/JA4 fingerprints, SNI/SAN inspection, TLS certificate anomalies, and statistical traffic "
            "analysis (inter-arrival time jitter, packet payload size distributions, long-tail connection durations). "
            "Why does TLS 1.3 make legacy SNI and certificate inspection more complex compared to TLS 1.2, and how do you overcome this?"
        )
    }
]

def query_model(model_name, question_obj, max_tokens=2048):
    print(f"\n[{model_name}] Processing Q{question_obj['id']}: {question_obj['topic']}...")
    prompt = (
        f"You are a Senior Digital Forensics and Incident Response (DFIR) Subject Matter Expert.\n\n"
        f"TASK: Answer the following advanced technical forensic question with maximum technical rigor.\n"
        f"RULES:\n"
        f"1. Name exact forensic artifacts: file paths, registry keys/values, Event IDs, data structures, VAD flags, and tool commands.\n"
        f"2. Explain your step-by-step reasoning for how the artifact is formed and parsed.\n"
        f"3. Explicitly state WHY you chose this forensic method over alternatives, including potential false positives and anti-forensics caveats.\n\n"
        f"QUESTION:\n{question_obj['question']}"
    )
    
    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": "You are a world-class Principal DFIR Systems Architect and Digital Forensics Expert."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2,
        "max_tokens": max_tokens
    }
    
    start_time = time.time()
    try:
        resp = requests.post(API_URL, json=payload, timeout=300)
        resp.raise_for_status()
        data = resp.json()
        duration = round(time.time() - start_time, 2)
        choice = data["choices"][0]
        msg = choice.get("message", {})
        content = msg.get("content", "")
        reasoning = msg.get("reasoning_content", "")
        print(f"[{model_name}] Q{question_obj['id']} completed in {duration}s ({len(content)} chars)")
        return {
            "status": "success",
            "duration_seconds": duration,
            "content": content,
            "reasoning": reasoning
        }
    except Exception as e:
        duration = round(time.time() - start_time, 2)
        print(f"[{model_name}] Q{question_obj['id']} FAILED after {duration}s: {e}")
        return {
            "status": "error",
            "duration_seconds": duration,
            "error": str(e),
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
    
    m1 = "deepseek-r1-distill-qwen-7b"
    m2 = "gemma-4-e4b-it"

    # Check if we can resume Phase 1
    m1_results = {}
    if os.path.exists(OUTPUT_JSON):
        try:
            with open(OUTPUT_JSON, "r", encoding="utf-8") as f:
                saved = json.load(f)
                if "m1_results" in saved and len(saved["m1_results"]) == len(QUESTIONS):
                    m1_results = {int(k): v for k, v in saved["m1_results"].items()}
                    print(f"Loaded {len(m1_results)} cached results for {m1}. Skipping Phase 1!")
        except Exception as e:
            print("Could not load saved m1_results:", e)

    # 1. Run Model 1: DeepSeek (if not already done)
    if len(m1_results) < len(QUESTIONS):
        print(f"\n==========================================")
        print(f"PHASE 1: BENCHMARKING {m1}")
        print(f"==========================================")
        for q in QUESTIONS:
            ans = query_model(m1, q)
            m1_results[q["id"]] = ans
            with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
                json.dump({"phase": "m1_in_progress", "m1_results": m1_results}, f, indent=2)
                
        # 2. Unload Model 1
        print(f"\n==========================================")
        print(f"PHASE 2: UNLOADING {m1}")
        print(f"==========================================")
        run_lms_cmd(["unload", m1])
        time.sleep(3)
        
        # 3. Load Model 2: Gemma 4
        print(f"\n==========================================")
        print(f"PHASE 3: LOADING {m2}")
        print(f"==========================================")
        run_lms_cmd(["load", m2, "-y"])
        if not wait_for_model(m2, timeout=60):
            print(f"WARNING: Model {m2} did not report in lms ps within 60s")
    else:
        print(f"Checking if {m2} is loaded...")
        wait_for_model(m2, timeout=10)

    # 4. Run Model 2: Gemma 4
    print(f"\n==========================================")
    print(f"PHASE 4: BENCHMARKING {m2}")
    print(f"==========================================")
    m2_results = {}
    for q in QUESTIONS:
        ans = query_model(m2, q)
        m2_results[q["id"]] = ans
        # Save incremental
        with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
            json.dump({"phase": "m2_in_progress", "m1_results": m1_results, "m2_results": m2_results}, f, indent=2)

    # 5. Compile Final Results
    combined_results = []
    for q in QUESTIONS:
        combined_results.append({
            "id": q["id"],
            "topic": q["topic"],
            "question": q["question"],
            "deepseek": m1_results.get(q["id"], {}),
            "gemma4": m2_results.get(q["id"], {})
        })
        
    benchmark_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "models": {
            "model_1": m1,
            "model_2": m2
        },
        "results": combined_results
    }
    
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(benchmark_data, f, indent=2, ensure_ascii=False)
        
    print(f"\nBenchmark completed successfully! Results written to {OUTPUT_JSON}")

if __name__ == "__main__":
    main()
