# ForensicOps AI (`forensic-agent`)

> **Autonomous Digital Forensics & Incident Response (DFIR) Platform**  
> An autonomous forensic investigation system that independently investigates authorized evidence, executes safe deterministic forensic tools, correlates findings across multiple artifacts, tests hypotheses, and produces traceable, court-defensible forensic reports.

---

## 🏛️ Non-Negotiable Core Principles

1. **Deterministic Facts:** Deterministic forensic tools produce facts; LLMs plan, correlate, formulate hypotheses, and draft reports. An LLM is never the primary source of a forensic fact.
2. **Traceable Citations:** Every claim must trace to verified findings, source artifact hashes, and precise artifact locations via CitationGuard.
3. **Evidence Immutability:** Original evidence is strictly accessed read-only (`0400` defanged permissions) and verified before and after execution (pre/post SHA-256 integrity).
4. **Offline / Air-Gapped by Default:** Evidence data is kept local; zero unauthorized external network transmission.
5. **Controlled Autonomy:** Read-only analysis and investigative pivots are autonomous; high-risk actions (remote acquisition, remediation, report approval) require explicit human approval gates.

---

## 🏗️ Architecture & Tech Stack

```
                   ┌───────────────────────────────────┐
                   │    React / TypeScript Frontend    │
                   │      (Investigation Studio)       │
                   └─────────────────┬─────────────────┘
                                     │ REST / WebSocket
                   ┌─────────────────▼─────────────────┐
                   │        FastAPI Backend API        │
                   └───────┬───────────────────┬───────┘
                           │                   │
         ┌─────────────────▼────────┐   ┌──────▼──────────────────┐
         │ LangGraph Investigation  │   │ Dual-Store Persistence  │
         │        Controller        │   │                         │
         │ - Multi-Step Pivot Loop  │   │ - DuckDB (Case Events)  │
         │ - Competing Hypotheses   │   │ - SQLite (Vault/Ledger) │
         │ - Evidence Gap Detection │   │ - Hash-Chained Custody  │
         └─────────────┬────────────┘   └─────────────────────────┘
                       │
         ┌─────────────▼─────────────────────────┐
         │   Deterministic Capabilities Engine   │
         │ - PluginRunner (Isolated Execution)   │
         │ - Dissect Userspace Adapters          │
         │ - Registry, EVTX, PCAP, Memory Parsers│
         │ - RFC 3227 Chain-of-Custody Hashes    │
         └───────────────────────────────────────┘
```

- **Backend:** Python 3.11+, FastAPI, Pydantic v2, LangGraph, DuckDB, SQLite.
- **Forensic Tooling:** `dissect`, `python-evtx`, `scapy`, specialized registry and artifact parsers.
- **Frontend:** React 19, TypeScript, TailwindCSS, Vite, Lucide Icons.
- **Local AI Engines:** Ollama, LM Studio, or local OpenAI-compatible backends.

---

## 📁 Repository Structure

```
forensicops-ai/
├── backend/
│   ├── app/
│   │   ├── api/            # FastAPI route controllers (cases, artifacts, approvals, reports)
│   │   ├── core/           # Custody engine, storage layer, Dissect adapter, auth
│   │   ├── engine/         # InvestigationController, LangGraph workflow, analyzers
│   │   ├── models/         # Pydantic schemas and database models
│   │   └── services/       # Vault, SIEM connectors, report builder, citation guard
│   └── tests/              # Extensive test suites (Phases 1-16 verification)
├── frontend/               # React + TypeScript web application
│   ├── src/
│   │   ├── components/     # UI widgets, approval modals, timeline, artifact viewers
│   │   ├── pages/          # Dashboard, Investigation, Cases, Vault, Settings
│   │   └── api/            # Typed backend client
├── plugins/                # Forensic analyzer plugin definitions (YAML cards + Python runners)
├── specs/                  # Formal specifications & protocol contracts
├── docs/                   # Architecture, threat models, and implementation roadmaps
├── AGENTS.md               # Permanent engineering contract & forensic guidelines
├── COMPATIBILITY_MATRIX.md # Empirical forensic artifact support matrix
└── STATUS.md               # Milestone tracking and test verification logs
```

---

## 🚀 Getting Started

### Prerequisites
- Python 3.11+
- Node.js 18+ & npm
- (Optional) Local LLM provider: Ollama or LM Studio

### Backend Setup
```bash
# Clone the repository
git clone https://github.com/aliechkazenith-arch/forensic-agent.git
cd forensic-agent

# Set up Python virtual environment
python -m venv .venv
# Windows:
.venv\Scripts\Activate.ps1
# Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -e ".[dev]"

# Launch the FastAPI backend server
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```
Open [http://localhost:5173](http://localhost:5173) in your browser.

---

## 🧪 Running Tests

The test suite validates forensic integrity, RFC 3227 chain of custody, token-based approvals, and end-to-end investigation workflows:

```bash
# Run backend test suite
pytest backend/tests/ -v

# Run frontend build check
cd frontend && npm run build
```

---

## 📜 Standards & Compliance

- **RFC 3227:** Guidelines for Evidence Collection and Archiving.
- **ISO/IEC 27037 / 27041 / 27042:** Digital evidence handling and analysis reliability.
- **NIST SP 800-86:** Guide to Integrating Forensic Techniques into Incident Response.
- **Defense-in-Depth:** Non-mounting userspace parsing, tamper-evident hash chaining, and zero shell execution.
