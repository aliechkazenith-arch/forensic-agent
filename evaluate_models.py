import json

with open(r"c:\forensicops-ai\audits\dfir_benchmark_results.json", "r", encoding="utf-8") as f:
    data = json.load(f)

for q in data["results"]:
    print(f"\n=======================================================")
    print(f"QUESTION {q['id']}: {q['topic']}")
    print(f"=======================================================")
    ds = q["deepseek"]["content"]
    g4 = q["gemma4"]["content"]
    
    print(f"[DEEPSEEK - {len(ds)} chars]")
    ds_lines = [l for l in ds.split("\n") if l.strip()]
    for l in ds_lines[:8]:
        try:
            print("  DS: " + l[:100])
        except Exception:
            print("  DS: [unprintable line]")
            
    print(f"\n[GEMMA 4 - {len(g4)} chars]")
    g4_lines = [l for l in g4.split("\n") if l.strip()]
    for l in g4_lines[:8]:
        try:
            print("  G4: " + l[:100])
        except Exception:
            print("  G4: [unprintable line]")
