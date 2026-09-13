# Memory Poisoning pada AI Agent
## Panduan Lengkap: Masalah, Arsitektur Pertahanan, dan Rencana Pengembangan

---

## 1. Ringkasan Eksekutif

Dokumen ini adalah panduan menyeluruh untuk memahami **memory poisoning** — serangan yang menargetkan memori jangka panjang pada AI agent — sebelum kamu mulai membangun sistem deteksinya. Tujuannya bukan cuma kasih kamu resep langkah demi langkah, tapi membangun pemahaman mendalam soal *kenapa* masalah ini penting, *bagaimana* bentuknya secara teknis, dan *apa* prinsip desain yang membuat sistem pertahanan efektif.

Topik ini masuk kategori riset yang masih sangat baru. OWASP baru merilis "Top 10 for Agentic Applications" pada 2026 yang secara eksplisit memasukkan memory poisoning sebagai salah satu risiko utama, dan NIST baru membuka permintaan informasi resmi soal keamanan AI agent pada Januari 2026. Artinya kamu akan bekerja di area yang standarnya belum matang — bagus untuk portofolio/riset, tapi juga berarti kamu harus banyak mendefinisikan sendiri metodologi dan metrik keberhasilan.

---

## 2. Latar Belakang: Kenapa Ini Jadi Masalah Sekarang

Sampai beberapa tahun lalu, kebanyakan LLM bersifat *stateless* — setiap percakapan dimulai dari nol. Tapi AI agent modern (asisten coding, customer service bot, agent riset otonom) makin sering dilengkapi **memori persisten**: mereka menyimpan ringkasan interaksi, fakta tentang user, hasil tool call, atau "pelajaran" dari pengalaman lalu — biasanya di vector database — lalu mengambilnya kembali lewat retrieval untuk memengaruhi jawaban di masa depan.

Perubahan ini membuka permukaan serangan baru. Selama ini, keamanan LLM banyak fokus ke **prompt injection** — manipulasi yang efeknya langsung terasa di satu sesi lalu hilang. Memory poisoning berbeda karena:

- **Efeknya tertunda** — racun ditanam sekarang, "meledak" nanti, kadang berminggu-minggu kemudian.
- **Efeknya persisten** — sekali masuk ke memori permanen, ia akan terus memengaruhi jawaban sampai dibersihkan.
- **Efeknya bisa menyebar** — kalau memori di-*share* antar sesi, antar user, atau antar agent dalam sistem multi-agent, satu titik racun bisa mengontaminasi banyak pihak.
- **Efeknya sulit dilacak balik** — ketika agent akhirnya berperilaku aneh, sumber masalahnya bisa jadi entri memori yang ditanam berminggu-minggu sebelumnya, bukan input terakhir.

Industri keamanan mulai memperlakukan ini sebagai disiplin tersendiri. Microsoft, misalnya, mendemonstrasikan lewat dua kerentanan nyata di Semantic Kernel (CVE-2026-26030 dan CVE-2026-25592) bagaimana input yang dikendalikan model bisa memengaruhi parameter tool dan berujung eksekusi kode — menegaskan bahwa begitu model terhubung ke tool dan memori, kerentanan di lapisan AI bukan lagi sekadar masalah konten, tapi bisa jadi primitif eksekusi nyata.

---

## 3. Anatomi Masalah: Apa Sebenarnya yang "Diracuni"?

### 3.1 Komponen memori agent yang jadi target

| Komponen | Contoh isi | Kenapa rawan |
|---|---|---|
| **Episodic memory** | Ringkasan percakapan lalu | Diringkas otomatis oleh LLM — mudah "disetir" lewat framing kalimat |
| **Semantic/fact memory** | "User bekerja di perusahaan X", "User lebih suka jawaban singkat" | Dianggap kebenaran mutlak oleh agent tanpa verifikasi ulang |
| **Vector index (RAG)** | Dokumen yang di-*crawl* atau di-*upload* lalu di-embed | Bisa diracuni lewat dokumen pihak ketiga yang sengaja dibuat |
| **Tool-result cache** | Hasil pemanggilan API/tool yang disimpan untuk efisiensi | Kalau tool-nya bisa dimanipulasi, hasil racun ikut ter-cache |
| **Shared/multi-agent memory** | Memori yang diakses lebih dari satu agent | Satu titik racun menyebar ke seluruh sistem |

### 3.2 Empat vektor serangan utama

**a. Injeksi langsung (direct injection)**
Penyerang secara eksplisit meminta agent "mengingat" sesuatu yang salah — misalnya menyamar sebagai instruksi sistem di tengah percakapan biasa. Ini paling mudah dideteksi karena polanya cenderung mencolok.

**b. Injeksi tidak langsung (indirect injection)**
Racun disisipkan bukan lewat percakapan langsung, tapi lewat konten yang *diproses* agent — halaman web yang di-*fetch*, dokumen yang di-*ingest* ke RAG, email yang dibaca agent, hasil API pihak ketiga. Agent "membaca" konten ini sebagai data netral, padahal berisi instruksi tersembunyi yang lalu ikut tersimpan ke memori.

**c. Poisoning bertahap (slow-drip)**
Alih-alih satu entri mencolok, penyerang menanam potongan-potongan kecil informasi yang masing-masing terlihat wajar, tapi kalau digabung mengarahkan agent ke kesimpulan atau perilaku yang salah. Ini jenis paling sulit dideteksi karena tidak ada satu titik anomali yang jelas.

**d. Retrieval poisoning**
Bukan mengubah isi memori, tapi memanipulasi *apa yang diambil* saat retrieval — misalnya menyisipkan banyak dokumen yang secara embedding sangat mirip dengan query populer, sehingga saat agent melakukan similarity search, dokumen beracun itu yang paling sering muncul di top-k hasil.

### 3.3 Konsep "lethal trifecta"

Kerangka threat-modeling untuk sistem agentic sering menyebut kombinasi tiga faktor berikut sebagai kondisi paling berbahaya:

1. Agent memproses **konten tidak terpercaya** (dokumen luar, halaman web, input user anonim)
2. Agent punya **akses ke tool/aksi berhak istimewa** (bisa eksekusi kode, kirim email, akses data sensitif)
3. Agent bisa **berkomunikasi/menyimpan hasil ke luar** (menulis ke memori persisten, mengirim output ke pihak lain)

Kalau ketiganya ada sekaligus pada satu agent, risiko memory poisoning yang berdampak nyata jauh lebih tinggi. Ini prinsip penting yang akan dipakai lagi di bagian arsitektur.

---

## 4. Kenapa Deteksinya Sulit (dan Kenapa Itu Justru Bikin Proyek Ini Bernilai)

- **Tidak ada ground truth publik.** Tidak seperti spam/phishing detection yang sudah punya dataset besar bertahun-tahun, belum ada benchmark standar untuk memory poisoning. Kamu harus membangun dataset serangan sendiri.
- **Trade-off presisi vs recall sangat tajam.** Detector yang terlalu sensitif akan menolak update memori yang sah (agent jadi "pelupa" atau kaku), yang terlalu longgar gagal melindungi.
- **Serangan halus tidak punya "tanda tangan" jelas.** Tidak seperti malware yang punya signature biner, racun linguistik yang halus bisa terlihat seperti kalimat normal.
- **Belum ada metrik evaluasi standar.** Kamu harus mendefinisikan sendiri apa artinya "berhasil", dan itu perlu dijustifikasi dengan baik kalau proyek ini mau dipakai untuk skripsi/paper/portofolio riset.

---

## 5. Prinsip Desain Sistem Pertahanan

Sebelum masuk ke arsitektur teknis, pegang lima prinsip ini — mereka akan terus jadi acuan keputusan desain kamu:

1. **Defense in depth** — jangan andalkan satu metode deteksi. Kombinasikan provenance tracking, analisis semantik, dan pola linguistik.
2. **Provenance-first** — setiap fakta di memori harus tahu "dari mana asalnya" dan seberapa dipercaya sumber itu. Ini fondasi paling penting dan paling sering diabaikan di implementasi agent yang ada sekarang.
3. **Graceful degradation, bukan block-all** — entri mencurigakan masuk karantina/butuh verifikasi, bukan langsung ditolak. Ini menjaga agent tetap berguna sambil tetap waspada.
4. **Auditability & reversibility** — semua perubahan memori harus bisa ditelusuri balik dan di-*rollback*. Kalau racun baru terdeteksi minggu depan, kamu harus bisa tahu persis kapan ia masuk dan membersihkannya tanpa merusak data sah lainnya.
5. **Asumsikan konten eksternal tidak terpercaya secara default** — terapkan prinsip *lethal trifecta* di atas: makin banyak kombinasi (konten luar + tool berhak istimewa + penulisan memori persisten), makin ketat pengawasannya.

---

## 6. Arsitektur Sistem yang Diusulkan

Bayangkan sistem ini sebagai empat lapisan yang duduk **di antara agent dan memory store-nya** — bukan mengganti memory store, tapi membungkusnya.

```
[Agent] --tulis/baca--> [LAPISAN 1: Instrumentation]
                              |
                              v
                    [LAPISAN 2: Detection]
                              |
                 flagged? ----+---- bersih?
                    |                   |
                    v                   v
        [LAPISAN 3: Quarantine]   [commit langsung]
                    |
              terverifikasi?
                    |
                    v
          [LAPISAN 4: Audit & Rollback store]
                    |
                    v
            [Memory Store sesungguhnya
             (vector DB / KV store)]
```

### Lapisan 1 — Instrumentation Layer

Middleware yang mencegat setiap operasi baca/tulis ke memori. Untuk setiap event, catat metadata berikut (skema minimal):

```
MemoryEvent {
  id: string
  content: string
  embedding: vector
  source_type: enum [user_verified, user_anonymous, tool_result,
                      web_document, inter_agent, system]
  trust_level: float (0.0 - 1.0)
  session_id: string
  timestamp: datetime
  parent_event_id: string | null   // untuk melacak rantai turunan
}
```

`trust_level` inilah yang jadi dasar untuk semua lapisan berikutnya — misalnya input yang diverifikasi manusia dapat skor tinggi, hasil scraping web anonim dapat skor rendah.

### Lapisan 2 — Detection Layer (inti riset)

Kombinasikan beberapa metode, dari yang murah secara komputasi ke yang lebih berat:

**a. Provenance rule-check (murah, cepat)**
Aturan eksplisit: entri dengan `trust_level` rendah yang mencoba menimpa/mengontradiksi entri dengan `trust_level` tinggi yang sudah mapan → otomatis di-flag.

**b. Semantic consistency / drift check (menengah)**
Untuk setiap entri baru, cari entri lama dengan topik sama (via similarity search embedding). Hitung skor kontradiksi — bisa pakai model *natural language inference* (NLI) sederhana yang mengklasifikasikan pasangan kalimat sebagai *entailment / neutral / contradiction*. Kontradiksi tinggi terhadap konsensus historis (banyak entri lama yang sepakat) → flag.

**c. Statistical/structural outlier detection (menengah)**
Bangun profil "normal" dari entri memori historis (panjang, struktur, kosakata, *perplexity* terhadap model bahasa). Entri baru yang jauh menyimpang dari profil ini — misalnya tiba-tiba berisi kalimat imperatif seperti instruksi sistem padahal biasanya isi memori berupa fakta personal — di-flag oleh classifier ringan (bisa mulai dari model statistik sederhana, baru naik ke fine-tuned transformer kecil kalau perlu).

**d. Injection-pattern classifier (paling berat, paling presisi)**
Model klasifikasi (bisa fine-tuned DistilBERT/kecil, atau LLM-as-judge dengan prompt terstruktur) yang dilatih khusus mengenali pola linguistik instruksi tersembunyi/manipulatif dalam teks yang akan disimpan. Ini lapisan terakhir untuk kasus yang lolos dari tiga metode di atas.

> Catatan desain penting: jalankan metode (a) dan (b) untuk **setiap** entri (murah), tapi metode (d) hanya untuk entri yang sudah dapat skor kecurigaan dari lapisan sebelumnya — supaya sistem tetap efisien.

### Lapisan 3 — Quarantine & Verification Layer

Entri yang di-flag tidak langsung ditolak atau diterima. Beberapa strategi verifikasi:

- **Re-konfirmasi ke user**: "Saya mencatat bahwa preferensimu berubah jadi X — konfirmasi?"
- **Korroborasi multi-sumber**: tunggu apakah fakta yang sama muncul dari sumber independen lain sebelum di-commit permanen.
- **Time-decay quarantine**: entri karantina yang tidak terverifikasi dalam waktu tertentu otomatis dibuang, bukan dibiarkan menggantung selamanya.

### Lapisan 4 — Audit & Rollback Layer

- Snapshot memori secara periodik (atau *event-sourced*, menyimpan seluruh riwayat perubahan, bukan cuma state akhir).
- Setiap entri final harus bisa ditelusuri ke `parent_event_id`-nya sampai ke sumber asal.
- Kalau poisoning ditemukan belakangan (misalnya lewat audit manual atau laporan insiden), sistem harus bisa rollback ke state sebelum racun masuk, lalu me-*replay* entri-entri sah yang terjadi sesudahnya — bukan menghapus semuanya.

---

## 7. Metodologi Evaluasi

Karena tidak ada benchmark publik, kamu perlu membangun sendiri kerangka evaluasinya:

### 7.1 Membangun dataset serangan

Buat dataset dengan minimal 3 tingkat kehalusan serangan:

1. **Mencolok (obvious)** — instruksi eksplisit yang menyamar, mudah dideteksi. Baseline untuk memastikan detector dasar bekerja.
2. **Sedang (moderate)** — framing yang lebih halus, memanfaatkan konteks percakapan yang wajar.
3. **Halus/slow-drip (subtle)** — potongan info kecil yang disebar lintas banyak sesi, masing-masing terlihat tidak berbahaya.

Untuk tiap tingkat, buat juga **kontrol negatif** — perubahan memori yang sah dan wajar (misalnya user memang pindah kota, memang berubah preferensi) — supaya kamu bisa mengukur *false positive rate*, bukan cuma *true positive rate*.

### 7.2 Metrik

- **Precision & Recall** per tingkat kehalusan serangan (bukan digabung — recall untuk serangan halus realistisnya akan jauh lebih rendah, dan itu penting dilaporkan apa adanya, bukan disamarkan dengan angka gabungan).
- **Time-to-detection** — untuk serangan slow-drip, ukur berapa banyak "langkah" racun sampai sistem berhasil mendeteksi.
- **Utility cost** — seberapa banyak update memori *sah* yang salah ditolak/dikarantina (proxy untuk seberapa mengganggu sistem ini bagi pengguna normal).

### 7.3 Red-teaming bertahap

Setelah detector versi pertama jadi, coba serang balik sistemmu sendiri dengan skenario yang makin kreatif — ini bagian yang membuat riset ini kuat: bukan cuma membangun detector, tapi mendokumentasikan skenario apa yang berhasil menembusnya dan kenapa.

---

## 8. Rencana Implementasi Teknis

### 8.1 Tech stack yang disarankan

| Kebutuhan | Pilihan |
|---|---|
| Bahasa | Python |
| Agent framework (testbed) | LangChain / LlamaIndex / CrewAI (pilih satu) |
| Vector DB | Chroma (ringan, mudah diinstrumentasi) atau Qdrant |
| Model embedding | sentence-transformers (open-source, cukup untuk MVP) |
| NLI/contradiction check | model NLI ringan dari HuggingFace (mis. berbasis DeBERTa) |
| Classifier pola injeksi | mulai dari LLM-as-judge (prompt terstruktur), baru fine-tune model kecil kalau presisi belum cukup |
| Logging/audit | SQLite untuk MVP → PostgreSQL kalau perlu skala |
| Dashboard visualisasi | Streamlit |

### 8.2 Roadmap bertahap

**Fase 0 — Persiapan (1 minggu)**
Pahami satu agent framework secara mendalam, bangun agent sederhana dengan memori berbasis Chroma sebagai testbed.

**Fase 1 — Instrumentasi & dataset (2 minggu)**
Bangun Lapisan 1 (instrumentation). Buat skrip yang bisa "meracuni" memori testbed-mu sendiri di berbagai tingkat kehalusan — ini ground truth kamu.

**Fase 2 — Detector baseline (2 minggu)**
Implementasikan provenance rule-check + semantic drift check. Ukur precision/recall terhadap dataset buatanmu.

**Fase 3 — Detector lanjutan (2-3 minggu)**
Tambahkan statistical outlier detection dan injection-pattern classifier. Bandingkan performa inkremental — dokumentasikan seberapa besar tiap lapisan menambah recall, dan seberapa besar cost-nya ke false positive.

**Fase 4 — Quarantine & rollback (1-2 minggu)**
Bangun workflow karantina dan mekanisme snapshot/rollback berbasis event-sourcing.

**Fase 5 — Red-teaming & evaluasi akhir (1-2 minggu)**
Serang sistemmu sendiri dengan skenario kreatif, dokumentasikan hasilnya secara jujur (termasuk kegagalannya).

**Fase 6 (opsional, untuk portofolio/paper) — Publikasi**
Bersihkan dataset serangan + kode evaluasi, publikasikan sebagai benchmark open-source. Ini yang membuat proyekmu punya nilai kontribusi nyata ke komunitas riset, bukan cuma proyek pribadi.

---

## 9. Risiko & Keterbatasan yang Perlu Kamu Sadari dari Awal

- **Generalisasi terbatas**: detector yang kamu latih di satu agent framework/domain mungkin tidak langsung bekerja baik di domain lain — ini wajar, dokumentasikan sebagai batasan, bukan kegagalan.
- **Serangan adaptif**: penyerang yang tahu cara kerja detectormu bisa menyesuaikan strategi. Jangan klaim sistemmu "aman total" — klaim yang jujur adalah "meningkatkan biaya serangan" dan "mendeteksi kelas serangan tertentu".
- **Skala evaluasi kecil**: sebagai proyek solo, dataset serangan buatanmu kemungkinan kecil (puluhan-ratusan sampel). Itu cukup untuk proof-of-concept, tapi jangan overclaim hasilnya sebagai representatif skala industri.

---

## 10. Referensi & Bacaan Lanjutan

- OWASP — *Top 10 for Agentic Applications 2026* (kerangka risiko resmi, termasuk memory poisoning, goal hijacking, tool misuse)
- NIST — *Request for Information: AI Agent Security* (Januari 2026)
- Microsoft Security Research — dokumentasi CVE-2026-26030 dan CVE-2026-25592 (Semantic Kernel)
- MITRE ATLAS — kerangka threat-modeling untuk sistem AI/ML adversarial
- Konsep *"lethal trifecta"* dalam threat modeling agentic AI (kombinasi konten tidak terpercaya + tool berhak istimewa + kemampuan komunikasi/penulisan keluar)

*Catatan: karena area ini bergerak sangat cepat, sebelum mulai coding ada baiknya cari publikasi terbaru dari sumber-sumber di atas — standar dan praktik terbaik kemungkinan sudah berkembang lagi sejak dokumen ini ditulis.*

---

## 11. Langkah Selanjutnya yang Disarankan

Sebelum menulis kode pertama, coba jawab dulu (di kertas/dokumen terpisah) tiga pertanyaan ini — jawabannya akan menentukan banyak keputusan desain di atas:

1. Agent seperti apa yang mau kamu lindungi — single-agent dengan memori personal, atau multi-agent dengan memori bersama? (Kompleksitasnya beda jauh.)
2. Siapa "penyerang" dalam threat model-mu — user jahat yang sengaja menyerang, atau konten pihak ketiga (web/dokumen) yang tanpa sengaja mengandung racun? (Ini menentukan vektor mana yang jadi prioritas.)
3. Definisi "berhasil" versi kamu itu apa — recall setinggi mungkin meski banyak false positive, atau presisi tinggi meski ada racun yang lolos? (Tidak ada jawaban benar universal, tapi kamu harus pilih sadar sejak awal.)
