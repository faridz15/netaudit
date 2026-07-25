# NetAudit — Panduan Eksekusi

Semua kode sudah jadi dan sudah aku test. 24/24 test lulus. Yang kamu lakukan sekarang
bukan bikin dari nol, tapi **menjalankan, memahami, lalu mempublikasikan.**

Kalau kamu cuma upload ini ke GitHub tanpa paham isinya, kamu akan hancur di interview
saat ditanya "kenapa kamu pisahkan rules dari LLM?". Jadi tahap 2 di bawah ini bukan
opsional.

---

## TAHAP 0 — Jalankan dulu (30 menit)

### 0.1 Siapkan Python

Pastikan Python 3.10 ke atas.

```bash
python --version
```

Kalau belum ada, download dari python.org. Saat install di Windows, **centang "Add
Python to PATH"**.

### 0.2 Ekstrak dan masuk foldernya

```bash
cd netaudit
```

### 0.3 Bikin virtual environment

```bash
python -m venv .venv
```

Aktifkan:

```bash
# macOS / Linux
source .venv/bin/activate

# Windows PowerShell
.venv\Scripts\Activate.ps1

# Windows CMD
.venv\Scripts\activate.bat
```

Kalau berhasil, prompt terminal kamu diawali `(.venv)`.

### 0.4 Install dependency

```bash
pip install -r requirements.txt
```

### 0.5 Jalankan test

```bash
pytest -v
```

Harus muncul `24 passed`. Kalau ada yang gagal, berhenti di sini dan kabari aku.

### 0.6 Jalankan aplikasinya

```bash
streamlit run app.py
```

Browser terbuka di `http://localhost:8501`.

**Coba tiga hal ini secara berurutan** — ini alur demo yang nanti kamu pakai di interview:

1. Sidebar → **Use a sample** → `core-switch-01.cfg` → skor **100/100 grade A**
2. Ganti sample ke `core-switch-01-drifted.cfg` → skor **61/100 grade D**
3. Sidebar → **Compare two snapshots** → A: `core-switch-01.cfg`, B: `core-switch-01-drifted.cfg`

Yang ketiga itu inti ceritanya: perangkat yang tadinya sempurna turun 39 poin
setelah satu sesi troubleshooting. Empat perubahan, masing-masing masuk akal saat
dilakukan, gabungannya serius.

### 0.7 Coba CLI

```bash
python cli.py audit samples/
python cli.py audit samples/ --fail-under 80
echo $?          # Windows PowerShell: echo $LASTEXITCODE
python cli.py drift samples/core-switch-01.cfg samples/core-switch-01-drifted.cfg
```

Exit code `1` waktu pakai `--fail-under 80` itu **fitur**, bukan bug. Itu yang bikin
tool ini bisa dipakai sebagai gate di CI pipeline. Ingat poin ini, sering ditanya.

---

## TAHAP 1 — Bikin sample config kamu sendiri (2–3 jam)

Ini yang membedakan "aku dikasih kode" dan "aku ngerti kode".

### 1.1 Bikin config baru

Ambil `samples/branch-router-01.cfg`, copy jadi `samples/dc-firewall-01.cfg`, ubah
jadi perangkat dengan profil temuan yang berbeda. Misalnya: perangkat yang SSH-nya
sudah benar tapi logging dan NTP-nya kosong.

Jalankan:

```bash
python cli.py audit samples/dc-firewall-01.cfg
```

Cek: apakah temuannya sesuai dugaanmu? Kalau tidak, baca `netaudit/rules.py` untuk
tahu kenapa.

### 1.2 Tambah minimal satu rule sendiri

Buka `netaudit/rules.py`. Ada contoh lengkap di README bagian "Adding a rule".

Ide rule yang bagus dan belum ada:

| Rule | Cek apa |
|---|---|
| `MGMT-006` | `username X password` (bukan `secret`) — Type 7 reversible |
| `SVC-005` | `no ip bootp server` tidak ada |
| `SVC-006` | `no service config` tidak ada |
| `INT-004` | Interface trunk pakai `switchport trunk native vlan 1` (VLAN hopping) |
| `LOG-005` | `logging trap` di level debugging (terlalu berisik, bisa jadi DoS ke syslog) |
| `VTY-006` | `transport output` tidak dibatasi |

Ambil satu. Tulis rule-nya. **Lalu tulis testnya** di `tests/test_netaudit.py`,
termasuk satu test false-positive.

Jalankan `pytest -v` sampai hijau.

Setelah ini kamu bisa bilang di interview: "rule set-nya extensible, saya tambah
`INT-004` untuk native VLAN hopping dan menulis test-nya." Itu kalimat orang yang
paham kodenya.

### 1.3 Baca dan pahami tiga hal ini

Sebelum lanjut, pastikan kamu bisa menjelaskan ini tanpa lihat catatan:

1. **Kenapa parser dan rules dipisah?** Karena parser tidak menilai, hanya
   menstrukturkan. Kalau digabung, setiap rule baru akan menambah kerumitan di
   parser dan lama-lama tidak bisa dirawat.

2. **Kenapa LLM tidak boleh memutuskan lulus/tidak?** Karena keputusan compliance
   harus memberi jawaban sama setiap kali dijalankan atas input yang sama. Itu satu
   sifat yang justru tidak dimiliki model bahasa. LLM di sini hanya menerjemahkan
   temuan yang sudah diputuskan `rules.py` menjadi prosa untuk audiens tertentu.

3. **Kenapa urutan remediation penting?** Karena kalau kamu apply `access-class`
   sebelum SSH dan AAA siap, kamu memutus sesi manajemen kamu sendiri ke perangkat
   yang sedang kamu kerjakan dari jarak jauh. `report.py` mengurutkan logging dan
   autentikasi lebih dulu, baru pembatasan akses. Ini detail kecil yang langsung
   dikenali orang yang pernah kerja lapangan.

---

## TAHAP 2 — Publikasikan ke GitHub (1–2 jam)

### 2.1 Bikin repo

1. Buka github.com → **New repository**
2. Nama: `netaudit`
3. Public
4. **Jangan** centang "Add a README" (sudah ada)

### 2.2 Push

```bash
git init
git add .
git commit -m "NetAudit: Cisco IOS compliance auditor with drift detection"
git branch -M main
git remote add origin https://github.com/USERNAME/netaudit.git
git push -u origin main
```

Ganti `USERNAME`.

### 2.3 Rapikan repo

- **About** (kanan atas) → deskripsi singkat + topics:
  `network-automation` `cisco` `compliance` `security` `python` `streamlit` `cis-benchmark`
- Edit `README.md`, ganti `<your-username>` dengan username GitHub kamu
- Ganti link LinkedIn di bagian bawah README

### 2.4 Tambahkan screenshot

Screenshot yang paling menjual: **halaman drift comparison**. Yang terlihat skor
turun dari 100 ke 61 dengan daftar perubahan berkode warna.

Simpan sebagai `docs/screenshot-drift.png`, lalu tambahkan di README tepat setelah
blok kode skor di paling atas:

```markdown
![Drift detection](docs/screenshot-drift.png)
```

Commit lagi.

---

## TAHAP 3 — Deploy demo live (30 menit)

Repo yang bisa diklik dan langsung jalan jauh lebih kuat daripada repo yang harus
di-clone dulu.

1. Buka `share.streamlit.io`
2. Sign in with GitHub
3. **New app** → pilih repo `netaudit` → branch `main` → main file `app.py`
4. **Deploy**

Sekitar 2–3 menit. Kamu dapat URL seperti `https://netaudit-faridz.streamlit.app`.

Kalau mau briefing layer aktif di demo publik: **Settings → Secrets**, isi:

```toml
ANTHROPIC_API_KEY = "sk-ant-..."
```

**Pertimbangkan dulu.** Demo publik berarti siapa pun bisa memanggil API pakai
kredit kamu. Untuk portofolio, aku sarankan **biarkan mati**. Tool-nya tetap jalan
penuh tanpa itu, dan di README sudah dijelaskan kenapa layer itu opsional. Kalau
interviewer ingin lihat, kamu demo dari laptop sendiri.

Terakhir: tambahkan badge di paling atas README.

```markdown
[![Live demo](https://img.shields.io/badge/demo-live-1F6F4A)](https://netaudit-faridz.streamlit.app)
```

---

## TAHAP 4 — Post LinkedIn (1 jam)

Tunggu sampai Tahap 3 selesai. Post yang mengarah ke demo hidup jauh lebih kuat.

### Draft (edit sesuai suaramu sendiri)

> Setiap praktikum jaringan mengajari cara **mengonfigurasi** perangkat. Hampir tidak
> ada yang mengajari cara **meninjau** satu perangkat yang sudah berjalan.
>
> Padahal itu yang sebenarnya jadi pekerjaan sehari-hari setelah jaringannya berdiri.
>
> Jadi saya bangun NetAudit: tool yang membaca running-config Cisco IOS dan
> memeriksanya terhadap 25 aturan hardening yang mengacu pada CIS Cisco IOS Benchmark.
>
> Yang paling menarik justru bukan fitur auditnya, tapi deteksi drift-nya.
>
> Di repo ada satu contoh: switch yang dikonfigurasi dengan benar, skor 100/100.
> Lalu ada satu sesi troubleshooting. Telnet dihidupkan sementara. Community SNMP
> read-write ditambahkan supaya monitoring bisa jalan. Management ACL dilepas karena
> menghalangi. Tujuan syslog dikomentari.
>
> Empat perubahan. Masing-masing masuk akal pada saat dilakukan. Tidak ada yang
> dikembalikan.
>
> Skornya jadi 61/100. Dua temuan kritis.
>
> Keputusan desain yang paling lama saya pikirkan: model bahasa boleh membantu, tapi
> tidak boleh memutuskan. Keputusan lulus atau tidak harus memberi jawaban yang sama
> setiap kali dijalankan atas input yang sama, dan itu justru satu sifat yang tidak
> dimiliki LLM. Jadi semua penilaian ada di rule engine yang deterministik dan bisa
> diuji. Model hanya menerjemahkan temuan yang sudah diputuskan jadi penjelasan untuk
> engineer, manajer, atau auditor.
>
> Demo: [URL]
> Kode: [URL GitHub]
>
> Buat yang pernah pegang audit jaringan di produksi: menurut kalian, drift paling
> sering datang dari mana? Dugaan saya sesi troubleshooting yang tidak pernah
> di-rollback, tapi saya penasaran apa yang kalian temui di lapangan.

### Cara post

- **Attach 2 gambar:** screenshot drift comparison + screenshot finding card yang
  menampilkan blok remediation
- **Waktu:** Selasa–Kamis, jam 7–9 pagi WIB
- **Jangan tag siapa pun** di post pertama
- Balas setiap komentar dalam 24 jam pertama

---

## TAHAP 5 — Masukkan ke CV

Di bagian **Project Experiences**, di atas atau di bawah capstone:

> **NetAudit — Network Configuration Compliance Auditor** *(2026)*
> - Built a Python tool that audits Cisco IOS configurations against 25 hardening
>   rules modelled on the CIS Cisco IOS Benchmark, producing weighted compliance
>   scores, evidence-backed findings, and dependency-ordered remediation output.
> - Implemented configuration drift detection that classifies changes by security
>   relevance, surfacing a 39-point compliance regression across a single
>   troubleshooting session in the reference scenario.
> - Designed a hybrid architecture in which all compliance decisions remain in a
>   deterministic, unit-tested rule engine and the language model layer is confined
>   to explanation, preserving reproducibility and auditability.
> - Python, Streamlit, pytest. 24 tests. Live demo and source available.

Tambahkan juga ke bagian **Skills**:
- **Networking:** tambahkan `CIS Cisco IOS Benchmark`, `configuration compliance auditing`
- **Programming & Tools:** tambahkan `Streamlit`, `pytest`

---

## Persiapan interview

Empat pertanyaan yang hampir pasti muncul. Jawaban di bawah ini kerangkanya, isi
dengan bahasamu sendiri.

**"Kenapa bikin ini?"**
Karena hampir semua latihan jaringan mengajari cara mengonfigurasi, bukan cara
meninjau. Padahal setelah jaringan berdiri, meninjau itu yang jadi pekerjaan
harian. Saya juga ingin menguji apakah LLM benar-benar berguna di alur kerja
infrastruktur atau cuma ditempelkan.

**"Kenapa LLM tidak dipakai untuk menilai?"**
Karena verdict compliance harus reproducible. Auditor akan bertanya kenapa
perangkat ini dinyatakan gagal, dan jawabannya harus bisa ditelusuri ke satu aturan
tertulis, bukan ke keluaran model yang bisa berbeda antar-pemanggilan. Saya batasi
model ke lapisan penjelasan. Pola yang sama dipakai di praktik otomasi jaringan
secara umum: lapisan kontrol deterministik, model dibatasi pada interpretasi.

**"Apa bagian tersulitnya?"**
False positive. Versi awal menandai `line aux 0` karena tidak punya `exec-timeout`,
padahal port itu sudah dimatikan dengan `no exec` sehingga tidak ada sesi yang bisa
dibuka sama sekali. Tool audit yang sering salah alarm akan diabaikan, dan tool yang
diabaikan lebih buruk daripada tidak ada tool, karena menciptakan ilusi cakupan.
Sekarang setiap kasus semacam itu punya test-nya sendiri.

**"Apa keterbatasannya?"**
Cisco IOS saja. Analisis statis saja, tidak menyentuh perangkat dan tidak bisa
melihat runtime state atau versi software. Bukan asesmen CIS bersertifikat. Dan
skor 100 bukan jaminan aman, hanya berarti lolos 25 pemeriksaan ini. Arsitektur,
segmentasi, dan patching semuanya di luar cakupan dan semuanya lebih penting
daripada kebanyakan temuan individual di sini.

Jawaban keempat itu yang paling sering membedakan kandidat. Orang yang tahu batas
buatannya sendiri jauh lebih dipercaya daripada orang yang menjualnya berlebihan.

---

## Ringkasan jadwal

| Tahap | Durasi | Hasil |
|---|---|---|
| 0 — Jalankan | 30 menit | Tool berjalan di laptop |
| 1 — Pahami dan perluas | 2–3 jam | Satu rule buatanmu sendiri, lulus test |
| 2 — GitHub | 1–2 jam | Repo publik dengan screenshot |
| 3 — Deploy | 30 menit | Demo live yang bisa diklik |
| 4 — LinkedIn | 1 jam | Post terbit |
| 5 — CV | 30 menit | Entry masuk CV |

**Total realistis: 1 akhir pekan.**

Jangan lompati Tahap 1. Selisih antara "aku punya repo ini" dan "aku paham repo ini"
akan langsung terlihat di menit kedua interview teknis.
