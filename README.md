# VAPT Intelligence Agent

An AI-powered VAPT (Vulnerability Assessment and Penetration Testing) finding
analysis and report generation backend.

> **Severity is an AI-assisted / evidence-based assessment and is NOT a
> replacement for a formal CVSS assessment.**

---

## Architecture

```
                    ┌─────────────────┐
                    │    FastAPI      │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   LangGraph     │
                    │   StateGraph    │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Validate Input  │  (deterministic)
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │ Analyze Finding │  (deterministic – keyword extraction)
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │   Chroma RAG    │  (ChromaDB + text-embedding-3-small)
                    └────────┬────────┘
                             ▼
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
           OWASP            CWE          Severity
            Tool            Tool           Tool
           (det.)          (det.)         (det. / AI)
              │              │              │
              └──────────────┼──────────────┘
                             ▼
                    ┌─────────────────┐
                    │  LLM Synthesis  │  ONE call per finding
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │ Pydantic Verify │  (retry once on failure)
                    └────────┬────────┘
                             ▼
                    ┌─────────────────┐
                    │ Markdown Report │  (deterministic)
                    └────────┬────────┘
                             ▼
                            END
```

### Severity assessment modes

| Factors supplied | Mode |
|-----------------|------|
| All 6 | **Deterministic** – `assess_severity()` called with all factors |
| 0 | **AI-assisted** – LLM performs conservative assessment from evidence + RAG |
| 1–5 | **AI-assisted** – supplied factors used as additional evidence; LLM does not fabricate missing ones |

---

## Features

- **LangGraph StateGraph** agentic workflow with 8 nodes
- **ChromaDB RAG** over curated OWASP / CWE / CVSS knowledge base (uses local HuggingFace embeddings)
- **Deterministic OWASP and CWE mapping** (no LLM guessing)
- **One LLM call per finding** (synthesis only, via Groq API)
- **Pydantic structured output** with automatic retry on validation failure
- **Evidence preservation** – URL, parameter, and evidence are never altered
- **Conservative confidence levels** – `Low` when evidence is insufficient
- **Batch analysis** with configurable concurrency (`MAX_CONCURRENT_ANALYSES`)
- **Optional per-IP rate limiting** (5 req/s via `aiolimiter`)
- **Graceful startup** – app starts even without an ingested knowledge base
- **Docker** support

---

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Groq API key (free at console.groq.com)

---

## Setup

### 1. Clone and install

```bash
git clone <repo-url>
cd vapt-intelligence-agent
uv sync
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env and set GROQ_API_KEY
```

### 3. Ingest knowledge base

```bash
uv run python scripts/ingest_knowledge.py
```

This populates `./data/chroma`. The first time you run this, it will download the free HuggingFace embedding model.

### 4. Start the server

```bash
uv run uvicorn app.main:app --reload
```

API docs available at: http://localhost:8000/docs

---

## API Reference

### `GET /health`

Always returns 200. Check `rag_ready` to see if the knowledge base is ready.

```json
{
  "status": "ok",
  "rag_ready": false,
  "message": "Knowledge base not initialised. Run scripts/ingest_knowledge.py to enable RAG."
}
```

---

### `POST /api/v1/analyze`

Analyse a single VAPT finding.

**Request** (all severity factors → deterministic severity):

```json
{
  "title": "Reflected XSS in search",
  "url": "/search",
  "parameter": "q",
  "evidence": "GET /search?q=<script>alert(1)</script> — script tag reflected verbatim",
  "description": "User input is reflected in the HTML response without encoding",
  "severity_factors": {
    "exploitability": "High",
    "authentication_required": "None",
    "confidentiality_impact": "High",
    "integrity_impact": "Low",
    "availability_impact": "None",
    "user_interaction": "Required"
  }
}
```

**Request** (no severity factors → AI-assisted assessment):

```json
{
  "title": "Possible SQL Injection",
  "url": "/api/users",
  "parameter": "id",
  "evidence": "id=1 AND 1=1-- returns all users"
}
```

**Response**:

```json
{
  "success": true,
  "result": {
    "vulnerability_name": "Reflected Cross-Site Scripting (XSS)",
    "severity": "Medium",
    "owasp": "A03:2021 - Injection",
    "cwe": "CWE-79",
    "url": "/search",
    "parameter": "q",
    "description": "...",
    "impact": "...",
    "remediation": {
      "immediate_mitigation": "...",
      "root_cause_fix": "...",
      "official_references": ["..."]
    },
    "poc": "...",
    "confidence": "High",
    "reasoning_summary": "..."
  },
  "report": "# VAPT Finding Report\n..."
}
```

---

### `POST /api/v1/analyze/batch`

Analyse up to 20 findings concurrently.

```json
{
  "findings": [
    { "title": "XSS", "evidence": "..." },
    { "title": "SQLi", "evidence": "..." }
  ]
}
```

---

### `POST /api/v1/report`

Generate a Markdown report from an existing `VAPTResult`.

### `POST /api/v1/report/consolidated`

Generate a consolidated Markdown report for a list of `VAPTResult` objects.

---

## Docker

```bash
docker build -t vapt-agent .
docker run -p 8000:8000 \
  -e GROQ_API_KEY=gsk_... \
  -e GROQ_MODEL=llama-3.1-8b-instant \
  -v $(pwd)/data:/app/data \
  vapt-agent
```

> Ingest the knowledge base into `./data/chroma` before running the container,
> or mount an empty volume and exec into the container to run the ingestion script.

---

## Running Tests

```bash
uv run pytest
```

---

## Limitations

- Severity is an AI-assisted / evidence-based assessment and is **NOT** a formal CVSS assessment.
- Quality of analysis depends on the chosen LLM and the evidence provided.
- The knowledge base is curated and may not cover every vulnerability type.
- No authentication or authorisation is implemented (not in scope for this MVP).
- Manual evidence review by a qualified security professional is always recommended.
