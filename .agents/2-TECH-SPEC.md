# Memory Poisoning Detection System - Tech Spec

## 📄 BAGIAN 1: Tech Stack & Arsitektur

### Tech Stack
| Layer | Technology | Version |
|-------|------------|---------|
| Language | Python | 3.10+ |
| Agent Framework | LangChain / LlamaIndex | 0.1.x |
| Vector DB | Chroma | latest |
| Embeddings | sentence-transformers | 2.2.x |
| NLI Model | transformers (DeBERTa-based) | 4.40.x |
| Dashboard | Streamlit | 1.33.x |
| Database | SQLite → PostgreSQL | 3.45.x / 16.x |
| Logging | structlog | 23.3.x |
| Testing | pytest | 7.4.x |

### Arsitektur Sistem
```
[AI Agent] → [Instrumentation Middleware] → [Detection Pipeline] → [Quarantine Manager] → [Audit Layer] → [Chroma Vector DB]
                                   ↓                ↓                    ↓                     ↓
                          [Trust Level Calc] [Model Inference] [User Verification]  [SQLite/PostgreSQL]
                                   ↓                ↓                    ↓                     ↓
                          [Detection Dashboard via Streamlit]
```

### Struktur Folder
```
memrot/
├── src/
│   ├── instrumentation/
│   │   ├── middleware.py
│   │   ├── provenance.py
│   │   └── trust_level.py
│   ├── detection/
│   │   ├── pipeline.py
│   │   ├── provenance_rules.py
│   │   ├── semantic_drift.py
│   │   ├── outlier_detection.py
│   │   └── injection_classifier.py
│   ├── quarantine/
│   │   ├── manager.py
│   │   ├── verification.py
│   │   └── time_decay.py
│   ├── audit/
│   │   ├── event_sourcing.py
│   │   ├── snapshot.py
│   │   └── rollback.py
│   ├── dashboard/
│   │   ├── app.py
│   │   └── visualizations.py
│   └── agent_testbed/
│       ├── base_agent.py
│       └── memory_instrumented.py
├── data/
│   ├── datasets/
│   │   ├── attacks/
│   │   └── controls/
│   └── models/
│       └── injection_classifier/
├── tests/
│   ├── unit/
│   └── integration/
├── scripts/
│   ├── generate_attacks.py
│   └── evaluate_detector.py
├── config/
│   ├── thresholds.yaml
│   └── detector_config.yaml
├── requirements.txt
├── pyproject.toml
└── README.md
```

### Justifikasi
- **Python 3.10+**: Standar untuk ML/AI research, library ecosystem lengkap
- **LangChain/LlamaIndex**: Agent framework yang sudah populer, mudah di-instrument
- **Chroma**: Vector DB ringan, embeddable, cocok untuk research environment
- **SQLite → PostgreSQL**: SQLite untuk development simplicity, PostgreSQL untuk scaling jika perlu
- **Streamlit**: Quick dashboard untuk research visualization tanpa frontend complexity

## 📄 BAGIAN 2: Database Design

### Ringkasan Database
| Item | Detail |
|------|--------|
| Primary DB | SQLite (file-based) |
| Future Scale | PostgreSQL dengan pgvector |
| Vector Storage | Chroma (separate) |
| Migration | Manual schema evolution untuk MVP |

### Entity Overview
| Entity | Key Fields | Purpose |
|--------|-----------|--------|
| MemoryEvent | id, content, embedding, source_type, trust_level, session_id, timestamp, parent_event_id | Audit trail setiap memory operation |
| DetectionResult | id, event_id, detector_type, suspicion_score, decision, timestamp | Hasil dari setiap detector run |
| QuarantineEntry | id, event_id, suspicion_reason, verification_status, ttl, created_at | Entri yang dikarantina |
| Snapshot | id, timestamp, memory_state (serialized), checkpoint_events | Periodic memory snapshots |
| AttackDataset | id, attack_type, content, ground_truth_label, metadata | Synthetic attack entries untuk evaluation |

### Data Flow
1. AI Agent melakukan memory operation → MemoryEvent dibuat
2. Detection pipeline proses event → DetectionResult disimpan
3. Jika suspicious → QuarantineEntry dibuat
4. Verified atau timeout → MemoryEvent commit ke Chroma
5. Periodic → Snapshot diambil untuk recovery points

## 📄 BAGIAN 3: Interface Design

### API Endpoints (Streamlit Dashboard)
| Method | Path | Description | Auth |
|--------|------|-------------|------|
| GET | `/` | Dashboard overview | No |
| GET | `/events` | List MemoryEvents dengan filters | No |
| GET | `/detections` | Detection statistics | No |
| GET | `/quarantine` | Quarantine management view | No |
| POST | `/verify/{event_id}` | User verification endpoint | No |
| GET | `/audit/timeline` | Event timeline visualization | No |
| POST | `/rollback/{snapshot_id}` | Manual rollback trigger | No |

### CLI Interface
```bash
# Training & evaluation
python scripts/generate_attacks.py --type=obvious --count=100
python scripts/evaluate_detector.py --dataset=data/datasets/attacks/

# Agent testbed
python -m src.agent_testbed.base_agent --instrumented

# Dashboard
streamlit run src/dashboard/app.py
```

## 📄 BAGIAN 4: Alur Logika & Business Rules

### Alur Memory Write:
1. **Agent Attempt**: Agent memanggil memory.write()
2. **Instrumentation**: Middleware intercept, create MemoryEvent dengan metadata
3. **Trust Calculation**: Hitung trust_level berdasarkan source_type
4. **Detection Pipeline**: 
   - Provenance rule check (jika trust differential > 0.5 → flag)
   - Semantic drift check (NLI contradiction > 0.7 → flag)
   - Outlier detection (anomaly score > 2σ → flag)
   - Jika suspicion aggregate > 0.5 → classifier inference
5. **Decision Engine**:
   - Clean → langsung commit ke Chroma
   - Suspicious → quarantine + trigger verification
   - Malicious → block + alert
6. **Audit Log**: Semua steps dicatat ke SQLite

### Alur Quarantine Verification:
1. **Entry quarantined** → masuk daftar pending verification
2. **Timeout 24h** → auto-reject jika tidak diverifikasi
3. **User verifies** → commit ke memory, update trust model
4. **User rejects** → discard, log sebagai false positive training data

### Alur Rollback:
1. **Poisoning detected** → identifikasi timestamp/event_id pertama
2. **Find nearest snapshot** → sebelum contamination point
3. **Restore memory** → ke state snapshot
4. **Replay events** → hanya events verified/clean setelah snapshot
5. **Analysis report** → detil contamination spread

### Business Rules:
- trust_level calculation: user_verified=0.9, tool_result=0.7, web_document=0.3, user_anonymous=0.5
- Quarantine threshold: suspicion_score > 0.6
- Auto-commit threshold: trust_level > 0.8 + suspicion_score < 0.3
- Snapshot frequency: setiap 100 memory events atau 24 jam

## 📄 BAGIAN 5: Keamanan, Performa, & Deployment

### Keamanan
- **Trust boundary**: Instrumentation middleware harus dijalankan dalam isolated process
- **Model security**: Download verified model checksums, cache locally
- **Audit trail**: Append-only SQLite dengan checksum verification
- **Data privacy**: Local processing only, no external API calls untuk sensitive data

### Performa
- **Vector similarity**: FAISS index untuk efficient similarity search
- **Model caching**: HuggingFace models cached locally
- **Async processing**: Heavy detectors run asynchronously
- **Batch operations**: Snapshot creation di schedule background task

### Deployment (Local Research Environment)
- **Requirements**: Python 3.10+, 8GB RAM, GPU opsional (untuk model inference)
- **Setup**: `pip install -r requirements.txt`
- **Database init**: SQLite file auto-created on first run
- **Model download**: Auto-download saat pertama kali run
- **Port**: Streamlit default 8501

### Development Setup
```bash
# 1. Clone & setup
git clone <repo>
cd memrot

# 2. Install dependencies
pip install -r requirements.txt

# 3. Initialize data directories
mkdir -p data/datasets/attacks data/datasets/controls

# 4. Download models (first time)
python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('all-MiniLM-L6-v2')"

# 5. Generate attack dataset
python scripts/generate_attacks.py --count=1000

# 6. Run test agent
python -m src.agent_testbed.base_agent

# 7. Launch dashboard
streamlit run src/dashboard/app.py
```

### Monitoring & Metrics
- **Detection metrics**: Precision/recall per attack type
- **Performance metrics**: Latency per detector component
- **Resource usage**: Memory/CPU consumption selama inference
- **False positive rate**: Legitimate entries yang salah di-quarantine

### Backup Strategy
- **SQLite backup**: Daily copy ke backup directory
- **Model weights**: Version-pinned di requirements.txt
- **Dataset versioning**: Git LFS untuk attack/control datasets

---

** Tech Spec selesai!** Simpan sebagai `.agents/2-TECH-SPEC.md`

Lanjut ke Task Generator untuk breakdown implementasi?