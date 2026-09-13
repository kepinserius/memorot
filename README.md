# Memory Poisoning Detection System

Research project for detecting memory poisoning attacks in AI agents with persistent memory.

## Overview

4-layer defense system:
1. **Instrumentation** - Provenance tracking with trust scores
2. **Detection** - Multi-method detection (provenance, semantic drift, outlier, classifier)
3. **Quarantine** - Verification workflow for suspicious entries
4. **Audit** - Event sourcing and rollback capability

## Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Initialize data directories (auto-created on first run)
mkdir -p data/datasets/attacks data/datasets/controls data/chroma_db

# Download embedding model (first run)
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"
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

# Write memory with provenance tracking
event = middleware.intercept_write(
    content="User prefers dark mode",
    source_type=SourceType.USER_VERIFIED,
    session_id="session-123"
)

print(f"Event ID: {event.id}, Trust: {event.trust_level}")
```

## Project Structure

```
src/
├── instrumentation/   # Provenance tracking & middleware
├── detection/         # Detection pipeline (TODO)
├── quarantine/        # Quarantine management (TODO)
├── audit/            # Event sourcing & rollback
├── vectorstore/      # Chroma vector DB client
├── dashboard/        # Streamlit dashboard (TODO)
└── agent_testbed/    # Test agent (TODO)
```

## Testing

```bash
pytest tests/
```

## Configuration

Edit `config/thresholds.yaml` and `config/detector_config.yaml` for custom settings.
