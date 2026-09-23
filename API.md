# API Documentation - Memory Poisoning Detection System

## Overview

This library provides defense-in-depth protection against memory poisoning attacks for AI agents with persistent memory. The system sits between agent and memory store, implementing 4 layers of detection and quarantine.

## Architecture

```
[Agent] → [Instrumentation] → [Detection Pipeline] → [Quarantine] → [Audit] → [Memory Store]
```

## Quick Start

```python
from src.instrumentation import MemoryMiddleware, SourceType
from src.vectorstore.chroma_client import VectorDBClient
from src.audit.store import AuditStore

# Initialize components
vector_db = VectorDBClient()
audit_store = AuditStore()
middleware = MemoryMiddleware(vector_db_client=vector_db, audit_store=audit_store)

# Write memory with automatic detection
event = middleware.intercept_write(
    content="User prefers dark mode",
    source_type=SourceType.USER_VERIFIED,
    session_id="session-123"
)

print(f"Event ID: {event.id}, Trust: {event.trust_level}")
```

## Layer 1: Instrumentation

### MemoryMiddleware

Main entry point for intercepting memory operations.

```python
from src.instrumentation import MemoryMiddleware, SourceType

middleware = MemoryMiddleware(
    vector_db_client=vector_db,
    audit_store=audit_store
)

# Write with provenance tracking
event = middleware.intercept_write(
    content="User's favorite color is blue",
    source_type=SourceType.USER_ANONYMOUS,  # or USER_VERIFIED, TOOL_RESULT, etc.
    session_id="session-abc123"
)

# Read memory (transparent, no detection)
results = middleware.intercept_read(query="user preferences", top_k=5)
```

### Source Type Hierarchy

| Type | Trust Level | Description |
|------|-------------|-------------|
| `USER_VERIFIED` | 0.9-1.0 | Content verified by trusted user |
| `SYSTEM` | 0.8-0.9 | System-generated facts |
| `TOOL_RESULT` | 0.7-0.8 | Results from authorized tools |
| `INTER_AGENT` | 0.6-0.7 | Content from other agents |
| `WEB_DOCUMENT` | 0.3-0.5 | External web content |
| `USER_ANONYMOUS` | 0.1-0.3 | Unverified user input |

## Layer 2: Detection Pipeline

### DetectionPipeline

Runs all detection methods and returns combined suspicion score.

```python
from src.detection.pipeline import DetectionPipeline

pipeline = DetectionPipeline(audit_store=audit_store)

# Run detection
result = pipeline.run_detection(
    content="Suspicious content to analyze",
    source_type="user_anonymous",
    trust_level=0.2
)

print(f"Decision: {result.decision}")
print(f"Suspicion Score: {result.suspicion_score}")
print(f"Detectors Used: {result.detectors_used}")
```

### Detection Methods

#### 1. Provenance Rule Checker
Detects trust-level mismatches (e.g., low-trust content contradicting high-trust memory).

#### 2. Semantic Drift Detection
Uses NLI model to detect contradictions with existing memory.

```python
from src.detection.semantic_drift import SemanticDriftChecker

checker = SemanticDriftChecker()
score = checker.check_contradiction(
    new_content="User lives in Tokyo",
    existing_memories=["User resides in Paris"]
)
```

#### 3. Outlier Detection
Statistical analysis of content structure and patterns.

#### 4. Injection Pattern Classifier
Rule-based and optional LLM-as-judge classification.

## Layer 3: Quarantine

### QuarantineManager

Manages suspicious entries awaiting verification.

```python
from src.detection.models import DetectionResult, DecisionType
from src.quarantine.manager import QuarantineManager

manager = QuarantineManager()

# Create quarantine entry
result = DetectionResult(
    event_id="evt-123",
    detector_type="provenance_rules",
    suspicion_score=0.75,
    decision=DecisionType.SUSPICIOUS
)

entry = manager.create_entry(result, ttl_days=7)

# Verify later
manager.verify_entry(entry.id, verified=True)  # commit to memory
manager.verify_entry(entry.id, verified=False)  # purge entry
```

## Layer 4: Audit

### AuditStore

Event sourcing for all memory operations.

```python
from src.audit.store import AuditStore

store = AuditStore()

# Get all events
events = store.get_events(limit=1000)

# Filter by session
session_events = store.get_events(session_id="session-abc")

# Get snapshots
snapshots = store.get_snapshots()
```

## Testing

Run test suite:
```bash
pytest tests/
```

Run red-teaming:
```bash
PYTHONPATH=. python scripts/run_red_team.py
```

Generate evaluation:
```bash
PYTHONPATH=. python scripts/evaluate_detector.py
```

## Configuration

Thresholds and detector settings:
- `config/thresholds.yaml` - Detection sensitivity settings
- `config/detector_config.yaml` - Per-detector configuration

## Environment Variables

- `OPENAI_API_KEY` - Optional: Use LLM-as-judge for advanced classification
- `ANTHROPIC_API_KEY` - Optional: Use Claude for classification
- `GOOGLE_API_KEY` - Optional: Use Gemini for classification

## License

MIT