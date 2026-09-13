# Memory Poisoning Detection Research Project

## Project Overview

Research project to build a memory poisoning detection system for AI agents. The system protects agents with persistent memory (vector DB, episodic/semantic memory) from injection attacks.

## Architecture

4-layer defense system sitting between agent and memory store:
1. **Instrumentation Layer** - provenance tracking, trust_level scoring
2. **Detection Layer** - provenance rules, semantic drift check, outlier detection, injection-pattern classifier
3. **Quarantine Layer** - verification workflows for flagged entries
4. **Audit & Rollback Layer** - event sourcing, snapshot recovery

## Key Concepts

- **Memory poisoning**: attacks targeting persistent agent memory with delayed, spreading effects
- **Lethal trifecta**: untrusted content + privileged tools + persistent writes = high risk
- **Defense in depth**: combine multiple detection methods, never rely on single approach

## Tech Stack (Planned)

- Python
- Agent framework: LangChain / LlamaIndex / CrewAI
- Vector DB: Chroma or Qdrant
- Embeddings: sentence-transformers
- NLI/contradiction: HuggingFace models (DeBERTa-based)
- Classifier: LLM-as-judge or fine-tuned small model
- Audit store: SQLite → PostgreSQL
- Dashboard: Streamlit

## Implementation Phases

0. Build instrumented testbed agent with memory
1. Instrumentation + attack dataset creation
2. Baseline detector (provenance rules + semantic drift)
3. Advanced detector (outlier + injection-pattern classifier)
4. Quarantine & rollback mechanisms
5. Red-teaming & evaluation
6. (Optional) Publish benchmark dataset

## Key Files

- `dokumenriset.md` - Full research design document, read for detailed methodology

## Design Principles

- Provenance-first: every memory entry must have traceable source and trust score
- Graceful degradation: quarantine suspicious entries, don't block-all
- Auditability: all memory changes must be reversible and traceable
- Assume external content untrusted by default
