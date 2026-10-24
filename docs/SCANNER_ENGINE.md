# AI-SAST Git & Dosya Tarama Motoru (Scanner Engine)

**Bileşen:** AI-SAST Dosya Keşfi, Ignore Filtreleme & Git Diff Hunk Ayrıştırıcı  
**Mimari Fazı:** FAZ 1 (Git & Dosya Tarama Motoru)  
**Yazar & Geliştirici:** Yiğit Ali Çolakoğlu  
**Durum:** Tamamlandı & Doğrulandı  

---

## 1. Genel Bakış ve Amaç

Statik Kod Analizi (SAST) ve Sır Tarama (Secret Scanning) araçlarında performans ve doğruluk, tarama motoruna beslenen dosyaların kalitesine doğrudan bağlıdır. Gereksiz bağımlılık dizinlerinin (`node_modules`, `venv`), derlenmiş ikili dosyaların (`.exe`, `.dll`, `.png`, `.bin`), büyük arşivlerin veya commit edilmeyecek dosyaların taranması; gereksiz CPU tüketimine, yüksek bellek harcamasına ve sahte alarmlara (False Positive) yol açar.

Ayrıca modern CI/CD boru hatlarında ve pre-commit kancalarında (git pre-commit hook) **tüm depoyu baştan sona taramak yerine sadece değiştirilen satırların (`git diff --staged`) taranması** geliştirici deneyimini katbekat hızlandırır.

FAZ 1 kapsamında geliştirilen **AI-SAST Scanner Engine** şu temel yetenekleri sunar:
1. **Dinamik Ignore Motoru:** Varsayılan dışlama kalıplarına ek olarak disk üzerindeki `.gitignore` ve `.aisastignore` dosyalarını otomatik okur, birleştirir ve tekrarları eler.
2. **İçerik Bazlı Binary Tespiti:** Uzantıdan bağımsız olarak dosyanın ilk 8192 baytında null-byte (`\x00`) kontrolü yaparak ikili ve derlenmiş dosyaları güvenle atlar.
3. **Unified Diff Hunk Ayrıştırıcı:** `git diff --staged -U0` çıktısını ayrıştırarak dosya bazında sadece eklenen ve değiştirilen satır aralıklarını (`LineRange`) çıkarır.
4. **Kapsam Farkındalığı (`ScannableFile`):** Katmanlara (Layer 1, 2, 3) taranacak dosyanın tüm satırlarının mı yoksa sadece belirli satırlarının mı denetleneceğini bildiren bağlamsal model sağlar.
5. **Gerçek LOC (Lines of Code) Sayımı:** Taranabilir metin dosyalarının toplam satır sayısını UTF-8 uyumlu biçimde hesaplayarak `ScanMetrics.total_lines_of_code` metriğini besler.

---

## 2. Dosya Keşif ve Filtreleme Hunisi (Flowchart)

Tarama motoru, verilen hedef yolu iki farklı modda işleyebilen bir filtreleme hunisi (`discover_scannable_files`) üzerinden çalıştırır:

```mermaid
flowchart TD
    Start["Girdi: Hedef Yol (Dizin / Dosya) & ScannerConfig"] --> ModeCheck{"Tarama Modu?"}

    subgraph GitDiffBranch["Git Diff Modu (--staged)"]
        ModeCheck -->|staged_only = True| GitExec["git diff --staged -U0 --diff-filter=ACMR"]
        GitExec --> ParseDiff["parse_unified_diff: Hunk Ayrıştırma"]
        ParseDiff --> StagedMap["Staged Dosyalar & LineRange Haritası"]
    end

    subgraph FullScanBranch["Tam Tarama Modu (Full Scan)"]
        ModeCheck -->|staged_only = False| GlobFiles["Dizin İçi Dosya Gezintisi (rglob)"]
    end

    StagedMap --> MergeStream["Dosya Aday Havuzu"]
    GlobFiles --> MergeStream

    subgraph FilterFunnel["Filtreleme ve Doğrulama Hunisi"]
        MergeStream --> IgnoreCheck{".gitignore & .aisastignore<br/>Eşleşiyor mu?"}
        IgnoreCheck -->|Evet| SkipIgnore["Atlanan Dosyalar (Skipped)"]
        IgnoreCheck -->|Hayır| SizeCheck{"Dosya Boyutu ><br/>max_file_size_kb?"}
        SizeCheck -->|Evet| SkipSize["Atlanan Dosyalar (Boyut Sınırı)"]
        SizeCheck -->|Hayır| BinCheck{"Binary Kontrolü<br/>İlk 8KB içinde \\x00 var mı?"}
        BinCheck -->|Evet| SkipBin["Atlanan Dosyalar (Binary/Null-byte)"]
        BinCheck -->|Hayır| LocCount["count_file_lines: UTF-8 LOC Hesapla"]
    end

    LocCount --> CreateScannable["ScannableFile Nesnesi Oluştur"]
    CreateScannable --> ContextBuild["ScanPipeline Bağlamı (context['scannable_files'])"]
    ContextBuild --> LayersExec["Katmanlara İletim (Layer 1, 2, 3)"]
```

---

## 3. Unified Diff Hunk Ayrıştırma Akışı (Sequence Diagram)

`git diff --staged --unified=0` çıktısı, dosyada yapılan ekleme ve değişiklikleri atomik "hunk" blokları olarak verir. Diff Hunk Parser bu blokları satır aralıklarına dönüştürür.

```mermaid
sequenceDiagram
    autonumber
    actor CLI as Geliştirici / CI-CD Pre-Commit
    participant Pipe as ScanPipeline
    participant DiffMod as git_diff Modülü
    participant Git as Git CLI (Subprocess)
    participant Parser as parse_unified_diff

    CLI->>Pipe: aisast scan --staged
    Pipe->>DiffMod: get_staged_files_and_ranges(target_path)
    DiffMod->>Git: git rev-parse --show-toplevel
    Git-->>DiffMod: /path/to/repo_root
    DiffMod->>Git: git diff --staged -U0 --diff-filter=ACMR
    Git-->>DiffMod: Unified Diff Metni (stdout)
    DiffMod->>Parser: parse_unified_diff(diff_stdout, repo_root)

    rect rgb(240, 248, 255)
        Note over Parser: Satır Satır Ayrıştırma:
        Note over Parser: 1. '+++ b/src/auth.py' -> Hedef dosya tespit edilir
        Note over Parser: 2. '@@ -10,3 +10,5 @@' -> Regex eşleşmesi
        Note over Parser: 3. yeni_bas=10, yeni_say=5 -> LineRange(10, 14)
        Note over Parser: 4. '@@ -30 +32 @@' -> yeni_bas=32, yeni_say=1 -> LineRange(32, 32)
        Note over Parser: 5. '@@ -50,2 +50,0 @@' -> yeni_say=0 (Silme) -> Atla
    end

    Parser-->>DiffMod: {auth.py: [LineRange(10,14), LineRange(32,32)]}
    DiffMod-->>Pipe: Filtrelenmiş ve Doğrulanmış Staged Eşlemesi
    Pipe-->>CLI: Sadece değişen satırlara odaklı tarama ve rapor
```

### Hunk Başlığı Regex Mantığı

Unified diff hunk başlıkları standart olarak şu biçimdedir:
```text
@@ -eski_baslangic[,eski_adet] +yeni_baslangic[,yeni_adet] @@ [isteğe bağlı fonksiyon başlığı]
```

Kullanılan Regex Deseni:
```python
HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
```

Ayrıştırma Kuralları:
- `yeni_baslangic = int(match.group(1))`
- `yeni_adet = int(match.group(2)) if match.group(2) is not None else 1`
- `yeni_adet == 0`: Sadece satır silinmiştir, yeni satır eklenmemiştir. Bu hunk için `LineRange` üretilmez.
- `yeni_adet > 0`: `start_line = yeni_baslangic`, `end_line = yeni_baslangic + yeni_adet - 1` formülüyle `LineRange` oluşturulur.
- `+++ /dev/null`: Silinmiş dosyalar eşleme havuzuna dahil edilmez.

---

## 4. Çekirdek Veri Modelleri (Class Diagram)

Tarama kapsamı ve satır aralıkları, **Pydantic v2** tabanlı modellerle doğrulanır:

```mermaid
classDiagram
    class LineRange {
        +int start_line
        +int end_line
        +contains_line(line: int) bool
    }

    class ScannableFile {
        +Path path
        +str relative_path
        +int size_bytes
        +int line_count
        +bool is_staged_diff
        +List~LineRange~ changed_ranges
        +is_line_in_scope(line: int) bool
    }

    class ScanMetrics {
        +int total_files
        +int scanned_files
        +int skipped_files
        +int total_lines_of_code
        +float duration_seconds
        +int layer1_findings
        +int layer2_findings
        +int layer3_findings
    }

    ScannableFile "1" *-- "0..*" LineRange : changed_ranges
    ScanMetrics ..> ScannableFile : LOC & Dosya Sayımı
```

### `ScannableFile.is_line_in_scope(line: int) -> bool`
Katmanlar (Layer 1 sır avcısı, Layer 2 AST denetleyicisi) bir bulgu ürettiğinde, bulgunun satır numarasını bu metoda sorarak tarama kapsamı dışında kalan eski kod satırlarını sessizce filtreleyebilir:
```python
if not self.is_staged_diff or not self.changed_ranges:
    return True
return any(r.contains_line(line) for r in self.changed_ranges)
```

---

## 5. Filtreleme ve İkili (Binary) Koruma Mekanizmaları

### A. Null-Byte (`\x00`) Tespiti (`is_binary_file`)
Metin tabanlı kaynak kodlar UTF-8 / ASCII biçimindedir. Derlenmiş kütüphaneler (`.so`, `.dll`), ikili çalıştırılabilirler (`.exe`, ELF), resimler (`.png`, `.jpg`) ve sıkıştırılmış arşivler ilk baytlarında null byte (`\x00`) barındırır.
- Dosyanın ilk `8192` baytı okunur (`sample_size=8192`).
- `b"\x00" in chunk` kontrolü yapılır.
- Null-byte tespit edilirse dosya doğrudan `skipped` listesine aktarılır.
- Boş dosyalar `False` döner (hata oluşturmaz).

### B. Birleşik Ignore Motoru (`load_ignore_patterns`)
1. Varsayılan desenler (`DEFAULT_IGNORE_PATTERNS`): `.git/**`, `.venv/**`, `node_modules/**`, `__pycache__/**` vb.
2. `.gitignore` dosyasındaki kurallar (`respect_gitignore=True` olduğunda).
3. `.aisastignore` dosyasındaki projeye özel kurallar.
4. Yorum satırları (`#`) ve boşluklar temizlenir, mükerrer kurallar sırası korunarak ayıklanır.

---

## 6. CLI Kullanım Senaryoları

### 1. Tam Dizin Taraması
```bash
aisast scan ./src
```

### 2. Sadece Stage Edilen (Commit Bekleyen) Değişiklikleri Tarama
```bash
aisast scan --staged
```

### 3. Dry-Run Simülasyonu (Değişen Satır Aralıklarını Görme)
```bash
aisast scan --dry-run --staged
```
*Örnek Çıktı:*
```text
DRY-RUN (Simülasyon Modu)
Hedef Yol: .
Tarama Modu: Git Diff (--staged)
.gitignore Dikkate Al: Evet
Taranacak Dosya Sayısı: 2
Atlanacak Dosya Sayısı: 0

Taranacak Dosyalar:
  • src/auth.py -> Değişen Satırlar: 10-14, 32-32 (120 satır)
  • src/db.py -> Değişen Satırlar: 45-60 (85 satır)
```

### 4. `.gitignore` Kurallarını Yoksayarak Tarama
```bash
aisast scan --no-gitignore ./tests
```

---

## 7. Sonraki Adım Hazırlığı (Layer 1 Sır & Entropi Avcısı)

FAZ 1 ile kurulan dosya ve diff tarama omurgası sayesinde, **FAZ 2 (Layer 1: Sır & Entropi Avcısı)** geliştirilirken:
- `context["scannable_files"]` üzerinden her dosyanın `is_staged_diff` ve `changed_ranges` bilgisi hazır durumdadır.
- Regex eşleşmesi veya Shannon entropi sapması bulunduğunda, bulunan satır `sf.is_line_in_scope(line)` ile denetlenerek gereksiz geçmiş kod alarmları tek bir satır kodla engellenebilecektir.
- Binary dosyalar ve ignore edilen dosyalar zaten ayıklandığı için Layer 1 sır tarama katmanı saf kaynak kod üzerinde maksimum hızla (~10.000 satır/saniye) çalışacaktır.
