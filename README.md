# AI-SAST (`aisast`)

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Architecture: 3-Layer Funnel](https://img.shields.io/badge/Architecture-3--Layer%20Funnel-success.svg)](docs/ARCHITECTURE.md)

**AI Destekli Kod Güvenliği & Sır Tarayıcı CLI (`aisast`)**; modern yazılım projelerindeki güvenlik açıklarını, sızdırılmış sırları (API anahtarları, şifreler, tokenlar) ve mantıksal kod zafiyetlerini tespit etmek, doğrulamak ve otomatik yama (diff) önermek için tasarlanmış hibrit bir SAST (Static Application Security Testing) aracıdır.

Geliştirici ve Tasarımcı: **Yiğit Ali Çolakoğlu**.

---

## 🚀 3 Katmanlı Mimari Yaklaşımı

Geleneksel SAST araçlarının en büyük sorunu yüksek **yanlış pozitif (False Positive)** oranlarıdır. `aisast`, piramit huni prensibiyle çalışarak hem hızı hem de doğruluğu maksimize eder:

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. LAYER 1: Yüksek Hızlı Regex & Sır Tarayıcısı            │
│    (API Anahtarları, AWS Keys, JWT, Shannon Entropisi)      │
├─────────────────────────────────────────────────────────────┤
│ 2. LAYER 2: AST & Sezgisel Statik Kod Analizi               │
│    (SQLi, Command Injection, Path Traversal, CWE Eşleme)   │
├─────────────────────────────────────────────────────────────┤
│ 3. LAYER 3: AI / LLM Bağlamsal Doğrulama & Otomatik Yama     │
│    (Yanlış Pozitif Eleme, Güvenlik Analizi, Kod Yaması)    │
└─────────────────────────────────────────────────────────────┘
```

Detaylı mimari şemalar ve tasarım kararları için [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) dosyasını inceleyebilirsiniz.

---

## 📦 Kurulum

`aisast`, Python 3.11 veya üzerini gerektirir.

### Geliştirici Modunda Kurulum (Editable)
```bash
git clone https://github.com/yigitalic/AI-Destekli-Kod-Guvenlik.git
cd AI-Destekli-Kod-Guvenlik

# Sanal ortam oluşturma ve etkinleştirme (İsteğe bağlı)
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Projeyi düzenlenebilir modda kurun
pip install -e .

# Geliştirme ve test bağımlılıkları ile birlikte:
pip install -e .[dev]
```

---

## 🛠️ Temel Kullanım ve Komutlar

### 1. Sürüm ve Mimari Bilgisi
```bash
aisast version
```

### 2. Proje Yapılandırmasını Başlatma (`init`)
Hedef dizinde varsayılan `.aisast.yaml` ve `.aisastignore` dosyalarını üretir:
```bash
aisast init
```

### 3. Yapılandırma Doğrulama (`check-config`)
Aktif konfigürasyonu, ihmal desenlerini ve katman ayarlarını inceler:
```bash
aisast check-config
```

### 4. Kod Güvenlik Taraması (`scan`)

Varsayılan tarama (Terminal Rich tablosu ve Diff yamaları çıktısı):
```bash
aisast scan .
```

Simülasyon / Kuru Çalıştırma (`--dry-run`):
```bash
aisast scan . --dry-run
```

Markdown Formatında Rapor Üretme (GitHub PR / Job Summary için):
```bash
aisast scan ./src -f markdown -o security-report.md
```

JSON Formatında Çıktı Alma (Otomasyon ve borulama için):
```bash
aisast scan ./src -f json -o aisast-report.json
```

GitHub Actions & SARIF v2.1.0 Uyumlu Çıktı:
```bash
aisast scan . -f sarif -o report.sarif
```

Commit Bekleyen (Staged) Değişiklikleri Tarama:
```bash
aisast scan --staged
```

Katmanları Özel Olarak Etkinleştirme/Devre Dışı Bırakma:
```bash
# Sadece Sır Taraması (Layer 1)
aisast scan . --layer1 --no-layer2 --no-layer3

# AI Katmanını Etkinleştirerek Tarama (Layer 3)
aisast scan . --ai --provider openai --model gpt-4o-mini
```

CI/CD Entegrasyonu ve Hata Eşiği (`--fail-on`):
```bash
# HIGH veya CRITICAL bulgu tespit edilirse CLI exit code 2 ile çıkar
aisast scan . --fail-on HIGH
```

### 5. Tek Tıkla Git Pre-Commit Hook Kurulumu (`init-hook`)
Her commit öncesinde `git diff --staged` taramasını otomatik çalıştıran ve güvenlik açıklarını bloklayan hook'u kurar:
```bash
aisast init-hook
# AI desteği ile kurmak için:
aisast init-hook --ai --fail-on CRITICAL
```

### 6. Docker ile Çalıştırma
```bash
# İmajı derleyin
docker build -t aisast:latest .

# Mevcut dizini tarayın
docker run --rm -v "${PWD}:/workspace" aisast:latest scan /workspace
```

Detaylı CI/CD ve dağıtım kılavuzu için [docs/DEPLOYMENT_AND_CICD.md](docs/DEPLOYMENT_AND_CICD.md) belgesini inceleyin.

---

## ⚙️ Yapılandırma (`.aisast.yaml`)

Proje kök dizininde yer alan `.aisast.yaml` dosyası üzerinden tüm katman parametreleri özelleştirilebilir:

```yaml
target_path: .
ignore_file: .aisastignore
layer1:
  enabled: true
  entropy_threshold: 4.5
  detect_common_tokens: true
  max_file_size_kb: 2048
layer2:
  enabled: true
  enable_ast: true
  enable_heuristics: true
  rule_severity_threshold: LOW
layer3:
  enabled: false
  provider: openai
  model: gpt-4o-mini
  max_candidates: 30
  temperature: 0.1
reporting:
  output_format: rich
  fail_on_severity: HIGH
  show_snippets: true
  min_severity: LOW
```

### Ortam Değişkenleri (ENV)
- `AISAST_LAYER1_ENABLED`: `true` / `false`
- `AISAST_LAYER2_ENABLED`: `true` / `false`
- `AISAST_LAYER3_ENABLED`: `true` / `false`
- `AISAST_LLM_PROVIDER`: `openai`, `anthropic`, `gemini`
- `AISAST_API_KEY`: LLM sağlayıcı API anahtarı (veya `OPENAI_API_KEY`)

---

## 🧪 Testleri Çalıştırma

Tüm birim testleri `pytest` ile koşturabilirsiniz:

```bash
python -m pytest -v
```

---

## 🗺️ Faz Durumu ve Yol Haritası

- [x] **FAZ 0:** Proje İskeleti, Pydantic v2 Veri Modelleri, Mimari Dokümantasyon (`docs/ARCHITECTURE.md`) ve Temel Typer CLI.
- [x] **FAZ 1:** **Git & Dosya Tarama Motoru**: Unified diff hunk ayrıştırıcı (`--staged`), `.gitignore` & `.aisastignore` entegrasyonu, binary dosya denetimi.
- [x] **FAZ 2:** **Layer 1 (Secrets Engine)**: 12+ Regex katalogları, Shannon Entropi tespiti, maskeleme motoru, satır içi ihmal kuralları.
- [x] **FAZ 3:** **Layer 2 (AST & Heuristics Engine)**: Python AST taint analizi (SQLi, CMD, Exec, Deserialization, Crypto), sezgisel kurallar, gizlilik korumalı context window.
- [x] **FAZ 4:** **Layer 3 (LLM Verification Engine)**: Çoklu model desteği (OpenAI, Gemini, Anthropic, Ollama), redaction shield, Pydantic v2 structured output, yanlış pozitif eleme ve otomatik patch/diff üretimi.
- [x] **FAZ 5:** **Terminal UI, Markdown/SARIF Raporlama, Pre-Commit Hooks & Docker (FİNAL)**: Rich Diff arayüzü, `MarkdownReporter`, zenginleştirilmiş SARIF v2.1.0, `aisast init-hook` pre-commit kurulumu, `Dockerfile` ve CI/CD GitHub Actions entegrasyonu.

---

## 📄 Lisans

Bu proje **MIT Lisansı** altında lisanslanmıştır.
