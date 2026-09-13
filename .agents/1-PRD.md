# Memory Poisoning Detection System - PRD

## 📄 BAGIAN 1: Visi & Tujuan Produk

### Visi Produk
Sistem pertahanan 4-layer yang duduk antara AI agent dan memory store-nya untuk mendeteksi dan mencegah memory poisoning — serangan tertunda yang menargetkan memori persisten agent dengan efek spreading dan sulit ditelusuri balik.

### Tujuan Utama (3-5)
1. **Deteksi serangan memory poisoning** - Mendeteksi 80%+ serangan jelas (obvious injection) dan 50%+ serangan halus (subtle/slow-drip)
2. **Traceability & auditability** - Setiap entri memori punya provenance lengkap dan bisa ditelusuri ke sumber asal
3. **Graceful degradation** - Agent tetap berfungsi dengan false positive rate < 5% untuk entri sah
4. **Benchmark publik** - Menyediakan dataset serangan dan evaluasi framework open-source untuk komunitas riset

### Value Proposition
- Defense in depth - kombinasikan multiple detection methods, bukan cuma satu approach
- Provenance-first - setiap fakta punya trust score dan traceable source
- Practical research tool - ready-to-use untuk evaluasi sistem agent

## 📄 BAGIAN 2: User Persona

### Persona 1: AI Security Researcher
- **Usia/Pekerjaan:** 28-40, Peneliti/PhD student keamanan AI
- **Level Teknis:** Mahir (coding, ML, security)
- **Tujuan:** Mengevaluasi keamanan sistem agent, publish paper, kontribusi ke komunitas
- **Pain Points:** Tidak ada benchmark standar, susah reproduce penelitian orang lain, evaluasi manual butuh waktu
- **Motivasi:** Membangun tool penelitian yang reusable, kontribusi dataset ke komunitas, publicasi hasil

### Persona 2: AI Agent Developer
- **Usia/Pekerjaan:** 25-35, Full-stack developer building AI agent apps
- **Level Teknis:** Menengah-Mahir
- **Tujuan:** Membangun aplikasi agent yang aman untuk production
- **Pain Points:** Tidak tahu cara protect agent memory, takut deployment ke production tanpa security layer
- **Motivasi:** Mencegah serangan di aplikasi real, mendapatkan confidence sebelum production, minimal overhead

## 📄 BAGIAN 3: User Stories

### Modul 1: Instrumentation Layer

- Sebagai AI agent developer, saya ingin men-track provenance setiap memory entry, agar bisa melacak sumber jika ada masalah
- Sebagai security researcher, saya ingin melihat trust level setiap entri, agar bisa menganalisis pola serangan
- Sebagai developer, saya ingin mencatat metadata lengkap (source_type, session_id, timestamp), agar bisa audit perubahan memory

### Modul 2: Detection Layer

- Sebagai researcher, saya ingin membandingkan multiple detection methods, agar bisa evaluasi trade-off precision/recall
- Sebagai developer, saya ingin mem-flagg entri dengan trust_level rendah yang menimpa trust_level tinggi, agar mencegah overwrite berbahaya
- Sebagai researcher, saya ingin menghitung semantic drift dari entri baru vs konsensus historis, agar deteksi kontradiksi
- Sebagai developer, saya ingin menjalankan injection-pattern classifier hanya pada entri yang mencurigakan, agar menghemat resources

### Modul 3: Quarantine & Verification

- Sebagai user, saya ingin entri mencurigakan dikarantina bukan langsung ditolak, agar agent tetap berfungsi
- Sebagai developer, saya ingin meng-konfirmasi perubahan memory ke user, agar memverifikasi perubahan sah
- Sebagai researcher, saya ingin melihat statistik quarantine rate, agar analisis false positive rate

### Modul 4: Audit & Rollback

- Sebagai security researcher, saya ingin bisa rollback ke state sebelum poisoning ditemukan, agar cleanup tanpa kehilangan data sah
- Sebagai developer, saya ingin melihat chain of events dari entri beracun, agar memahami propagation
- Sebagai researcher, saya ingin mengambil snapshot memory secara periodik, agar punya recovery point

*(Total 15 user stories)*

## 📄 BAGIAN 4: Functional Requirements

### Modul 1: Instrumentation Layer

**FR-01: Provenance Tracking**
- **Input:** Memory content, source metadata, session context
- **Proses:** Enrich dengan trust_level, source_type, parent_event_id, timestamp
- **Output:** MemoryEvent dengan metadata lengkap
- **Aturan:** trust_level dihitung dari source_type (user_verified=0.9, web_document=0.3, dll)

**FR-02: Trust Level Calculation**
- **Input:** Source_type, verification status, historical reliability
- **Proses:** Hitung trust_score 0.0-1.0 berdasarkan predefined rules
- **Output:** Numerical trust_level untuk setiap entri
- **Aturan:** Low-trust entry yang menimpa high-trust di-flag

**FR-03: Metadata Enrichment**
- **Input:** Raw memory content
- **Proses:** Tambah embedding vector, session_id, user_id (jika ada)
- **Output:** Structured MemoryEvent object
- **Aturan:** Embedding wajib untuk semantic analysis

### Modul 2: Detection Layer

**FR-04: Provenance Rule Check**
- **Input:** New MemoryEvent, existing high-trust entries
- **Proses:** Cek apakah new entry contradict existing dengan trust differential > 0.5
- **Output:** Boolean flag "suspicious_provenance"
- **Aturan:** Jalankan untuk setiap entri (cheap check)

**FR-05: Semantic Drift Detection**
- **Input:** New entry embedding, historical similar entries
- **Proses:** Cari top-k similar entries, hitung contradiction score dengan NLI model
- **Output:** Contradiction score (0-1) dan flag jika > threshold
- **Aturan:** Threshold konfigurable, default 0.7

**FR-06: Outlier Detection**
- **Input:** New entry linguistic features, historical profile
- **Proses:** Bandingkan perplexity, sentence structure, vocabulary dengan baseline
- **Output:** Anomaly score dan classification (normal/suspicious)
- **Aturan:** Baseline dibangun dari 100+ historical normal entries

**FR-07: Injection Pattern Classifier**
- **Input:** Entry content, pre-trained injection detection model
- **Proses:** Klasifikasikan ke injection patterns (direct, indirect, slow-drip)
- **Output:** Classification label dan confidence score
- **Aturan:** Jalankan hanya untuk entries dengan suspicion score > 0.5

### Modul 3: Quarantine Layer

**FR-08: Quarantine Decision Engine**
- **Input:** Aggregated suspicion scores dari semua detectors
- **Proses:** Apply weighted voting threshold untuk menentukan quarantine
- **Output:** Decision (commit/quarantine/block)
- **Aturan:** Weights konfigurable berdasarkan detector performance

**FR-09: User Verification Workflow**
- **Input:** Quarantined entry, user context
- **Proses:** Prompt user untuk konfirmasi entry sah
- **Output:** User response (confirm/reject)
- **Aturan:** Timeout 24 jam, auto-reject jika no response

**FR-10: Time-Decay Quarantine**
- **Input:** Quarantined entries dengan timestamp
- **Proses:** Auto-cleanup entries yang melewati TTL tanpa verifikasi
- **Output:** Cleaned quarantine storage
- **Aturan:** Default TTL = 7 hari

### Modul 4: Audit & Rollback Layer

**FR-11: Event Sourcing**
- **Input:** Setiap memory operation (create/update/delete)
- **Proses:** Store ke immutable event log dengan sequence number
- **Output:** Append-only audit trail
- **Aturan:** Event tidak bisa dihapus/hapus, hanya append

**FR-12: Snapshot Creation**
- **Input:** Memory state pada timestamp tertentu
- **Proses:** Create checkpoint setiap N entries atau interval waktu
- **Output:** Snapshot ID dengan full memory state
- **Aturan:** Default: snapshot tiap 100 entries atau 24 jam

**FR-13: Rollback to Snapshot**
- **Input:** Snapshot ID atau timestamp
- **Proses:** Restore memory state ke titik sebelum poisoning
- **Output:** Recovered memory state, report entries yang di-revert
- **Aturan:** Preserve event log untuk audit, jangan hapus history

**FR-14: Replay Events**
- **Input:** Start snapshot ID, end snapshot ID
- **Proses:** Replay events yang sah setelah rollback untuk recovery partial
- **Output:** Final memory state dengan entries sah dikembalikan
- **Aturan:** Manual trigger dengan confirmation

### Modul 5: Dashboard & Visualization

**FR-15: Detection Dashboard**
- **Input:** Detection metrics, quarantine status, audit logs
- **Proses:** Aggregate dan visualize via Streamlit
- **Output:** Real-time dashboard dengan charts dan tables
- **Aturan:** Filter by time range, trust_level, detection_type

**FR-16: Attack Dataset Generator**
- **Input:** Attack templates, target agent memory structure
- **Proses:** Generate synthetic attack entries (obvious/moderate/subtle)
- **Output:** Labeled dataset untuk evaluation
- **Aturan:** Include negative controls (legitimate changes)

*(Total 16 FR)*

## 📄 BAGIAN 5: Non-Functional Requirements

### Performa
- Detection latency < 200ms untuk provenance + semantic drift check
- Classifier inference < 500ms per entry
- Support 10K memory operations per hari per agent
- Quarantine query response < 100ms

### Keamanan
- Trust level calculation menggunakan predetermined rules (tidak bergantung pada model yang bisa dimanipulasi)
- Audit log immutable (append-only)
- Snapshot encryption at rest
- API rate limiting untuk external tool results

### Skalabilitas
- Horizontal scaling untuk detection pipeline
- Vector DB sharding untuk 100K+ memory entries
- Async processing untuk heavy classifiers

### Usability
- Dashboard real-time dengan auto-refresh
- Export detection reports (CSV/JSON)
- CLI interface untuk batch evaluation
- Dokumentasi API lengkap

### Maintainability
- Modular detector plugins (easy add/remove)
- Konfigurasi threshold via YAML
- Logging terstruktur (JSON)
- Unit test coverage > 80%

## 📄 BAGIAN 6: Out of Scope & Dependensi

### Out of Scope (Tidak Dikerjakan di V1)
- Multi-agent shared memory coordination - ditunda ke v2
- Real-time collaborative quarantine review - ditunda ke v2
- Automated adversarial training loop - ditunda ke v2
- GUI-based attack scenario builder - ditunda ke v2
- Integration dengan commercial agent platforms - fokus research tool dulu

### Dependensi
- **Python 3.10+** - runtime environment
- **LangChain/LlamaIndex** - agent framework testbed
- **Chroma/Qdrant** - vector database
- **sentence-transformers** - embedding generation
- **HuggingFace Transformers** - NLI model untuk contradiction detection
- **Streamlit** - dashboard visualization
- **SQLite/PostgreSQL** - audit log storage

### Asumsi
- User memiliki GPU atau akses ke cloud compute untuk model inference
- Agent framework sudah diinstrumentasi untuk intercept memory operations
- Dataset serangan manual-generated (bukan crowd-sourced)
- Evaluasi dilakukan pada single-agent scenario terlebih dahulu
