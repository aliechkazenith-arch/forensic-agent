import json

with open(r"c:\forensicops-ai\audits\dfir_benchmark_results.json", "r", encoding="utf-8") as f:
    data = json.load(f)

md_out = []
md_out.append("# DFIR Benchmark: DeepSeek-R1 (Distill Qwen 7B) vs. Gemma 4 (7.5B IT)\n")
md_out.append(f"**Date:** {data.get('timestamp')}\n")
md_out.append("**Target Environment:** LM Studio 1.3.3.0 | Windows 10/Server | Local Inference\n\n")

for q in data["results"]:
    qid = q["id"]
    topic = q["topic"]
    question = q["question"]
    ds = q["deepseek"]
    g4 = q["gemma4"]
    
    md_out.append(f"## Question {qid}: {topic}\n")
    md_out.append(f"> **Scenario Question:**\n> {question}\n\n")
    
    md_out.append(f"### 🤖 Model 1: DeepSeek-R1 Distill Qwen 7B\n")
    md_out.append(f"- **Execution Time:** {ds.get('duration_seconds')}s\n")
    md_out.append(f"- **Final Response Length:** {len(ds.get('content', ''))} chars\n")
    md_out.append(f"- **Reasoning Trace Length:** {len(ds.get('reasoning', ''))} chars\n\n")
    md_out.append("#### Response Content:\n")
    md_out.append(ds.get("content", "").strip())
    md_out.append("\n\n---\n")
    
    md_out.append(f"### 🤖 Model 2: Gemma 4 (7.5B IT)\n")
    md_out.append(f"- **Execution Time:** {g4.get('duration_seconds')}s\n")
    md_out.append(f"- **Final Response Length:** {len(g4.get('content', ''))} chars\n")
    md_out.append(f"- **Reasoning Trace Length:** {len(g4.get('reasoning', ''))} chars\n\n")
    md_out.append("#### Response Content:\n")
    md_out.append(g4.get("content", "").strip())
    md_out.append("\n\n" + "="*80 + "\n\n")

with open(r"c:\forensicops-ai\audits\dfir_benchmark_comparison.md", "w", encoding="utf-8") as f:
    f.write("\n".join(md_out))

print("Successfully written dfir_benchmark_comparison.md")
