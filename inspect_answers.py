import json

d = json.load(open(r"c:\forensicops-ai\audits\dfir_benchmark_results.json", encoding="utf-8"))

for i in range(len(d["results"])):
    item = d["results"][i]
    print(f"\n{'='*70}\nQUESTION {item['id']}: {item['topic']}\n{'='*70}")
    print(f"--- DEEPSEEK ({item['deepseek']['duration_seconds']}s) ---")
    print(item["deepseek"]["content"][:900])
    print("\n--- GEMMA 4 (" + str(item['gemma4']['duration_seconds']) + "s) ---")
    print(item["gemma4"]["content"][:900])
