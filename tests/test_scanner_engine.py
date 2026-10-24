"""AI-SAST FAZ 1 Test Paketi: Git & Dosya Tarama Motoru.

Diff Hunk Parser, .gitignore & .aisastignore Filtreleme,
Binary Dosya Tespiti, ScannableFile / LineRange Modelleri ve CLI --staged Testleri.
"""

from __future__ import annotations

import json
from pathlib import Path
import subprocess
import pytest
from typer.testing import CliRunner

from aisast.cli import app
from aisast.config import ScannerConfig
from aisast.models import LineRange, ScannableFile
from aisast.scanner import (
    GitScanError,
    ScanPipeline,
    count_file_lines,
    discover_files,
    discover_scannable_files,
    get_staged_files_and_ranges,
    is_binary_file,
    load_ignore_patterns,
    parse_unified_diff,
)

runner = CliRunner()


# ==========================================
# 1. Unified Diff Hunk Ayrıştırıcı Testleri
# ==========================================

def test_parse_unified_diff_single_and_multi_line_hunks(tmp_path: Path):
    """Tek satırlı ve çok satırlı hunk içeren diff metnini doğru LineRange nesnelerine çevirir."""
    sample_diff = """diff --git a/src/auth.py b/src/auth.py
index 0000000..1111111 100644
--- a/src/auth.py
+++ b/src/auth.py
@@ -10,3 +10,5 @@ def login():
+    token = request.headers.get('Authorization')
+    if not token:
+        raise ValueError('Missing token')
@@ -30 +32 @@ def logout():
-    session.clear()
+    session.invalidate()
"""
    diff_map = parse_unified_diff(sample_diff, tmp_path)
    expected_path = (tmp_path / "src" / "auth.py").resolve()

    assert expected_path in diff_map
    ranges = diff_map[expected_path]
    assert len(ranges) == 2

    # Hunk 1: +10,5 -> 10'dan başlar, 10 + 5 - 1 = 14'e kadar
    assert ranges[0].start_line == 10
    assert ranges[0].end_line == 14

    # Hunk 2: +32 (tek satır, count belirtilmemişse 1) -> 32'den başlar, 32'ye kadar
    assert ranges[1].start_line == 32
    assert ranges[1].end_line == 32


def test_parse_unified_diff_deletions_and_deleted_files(tmp_path: Path):
    """Sadece silinen satırlar (+X,0) ve silinen dosyalar (+++ /dev/null) LineRange üretmemelidir."""
    sample_diff = """diff --git a/removed.py b/removed.py
deleted file mode 100644
--- a/removed.py
+++ /dev/null
@@ -1,10 +0,0 @@
-print('removed')
diff --git a/src/service.py b/src/service.py
--- a/src/service.py
+++ b/src/service.py
@@ -15,4 +15,0 @@ def old_func():
-    pass
-    pass
-    pass
-    pass
"""
    diff_map = parse_unified_diff(sample_diff, tmp_path)
    removed_path = (tmp_path / "removed.py").resolve()
    service_path = (tmp_path / "src" / "service.py").resolve()

    # /dev/null dosyası eşlemeye dahil edilmemeli
    assert removed_path not in diff_map

    # Sadece silme işlemi içeren hunk için LineRange eklenmemelidir
    assert service_path in diff_map
    assert len(diff_map[service_path]) == 0


def test_parse_unified_diff_quoted_paths(tmp_path: Path):
    """Boşluk ve özel karakter içeren tırnaklı dosya yollarını doğru ayrıştırır."""
    sample_diff = """diff --git "a/my directory/file.py" "b/my directory/file.py"
--- "a/my directory/file.py"
+++ "b/my directory/file.py"
@@ -1,2 +1,3 @@
+x = 1
"""
    diff_map = parse_unified_diff(sample_diff, tmp_path)
    expected_path = (tmp_path / "my directory" / "file.py").resolve()
    assert expected_path in diff_map
    assert len(diff_map[expected_path]) == 1
    assert diff_map[expected_path][0].start_line == 1
    assert diff_map[expected_path][0].end_line == 3


# ==========================================
# 2. LineRange ve ScannableFile Model Testleri
# ==========================================

def test_line_range_contains_line():
    """LineRange sınır ve aralık kontrolü."""
    r = LineRange(start_line=10, end_line=20)
    assert not r.contains_line(9)
    assert r.contains_line(10)
    assert r.contains_line(15)
    assert r.contains_line(20)
    assert not r.contains_line(21)

    single = LineRange(start_line=5, end_line=5)
    assert not single.contains_line(4)
    assert single.contains_line(5)
    assert not single.contains_line(6)


def test_scannable_file_is_line_in_scope(tmp_path: Path):
    """ScannableFile.is_line_in_scope tam tarama ve diff modlarında doğru sonuç üretmelidir."""
    fpath = tmp_path / "example.py"

    # 1. Tam dosya tarama modu (is_staged_diff=False): Her satır kapsamdadır
    sf_full = ScannableFile(
        path=fpath,
        relative_path="example.py",
        size_bytes=100,
        line_count=50,
        is_staged_diff=False,
    )
    assert sf_full.is_line_in_scope(1)
    assert sf_full.is_line_in_scope(25)
    assert sf_full.is_line_in_scope(999)

    # 2. Staged diff modu ama changed_ranges boş: Tüm dosya varsayılan olarak kapsamda
    sf_empty_ranges = ScannableFile(
        path=fpath,
        relative_path="example.py",
        size_bytes=100,
        line_count=50,
        is_staged_diff=True,
        changed_ranges=[],
    )
    assert sf_empty_ranges.is_line_in_scope(10)

    # 3. Staged diff modu belirli aralıklarla: Yalnızca aralık içi satırlar kapsamdadır
    sf_staged = ScannableFile(
        path=fpath,
        relative_path="example.py",
        size_bytes=200,
        line_count=100,
        is_staged_diff=True,
        changed_ranges=[
            LineRange(start_line=10, end_line=15),
            LineRange(start_line=50, end_line=55),
        ],
    )
    assert not sf_staged.is_line_in_scope(9)
    assert sf_staged.is_line_in_scope(10)
    assert sf_staged.is_line_in_scope(13)
    assert sf_staged.is_line_in_scope(15)
    assert not sf_staged.is_line_in_scope(16)
    assert not sf_staged.is_line_in_scope(49)
    assert sf_staged.is_line_in_scope(50)
    assert sf_staged.is_line_in_scope(55)
    assert not sf_staged.is_line_in_scope(56)


# ==========================================
# 3. Binary Tespiti ve Satır Sayımı Testleri
# ==========================================

def test_is_binary_file(tmp_path: Path):
    """Null-byte içeren dosyaların binary olarak tespit edildiğini doğrular."""
    # Düz metin dosya
    text_file = tmp_path / "script.py"
    text_file.write_text("print('hello world')\n", encoding="utf-8")
    assert not is_binary_file(text_file)

    # Null byte içeren dosya (örn: ikili veri, resim, derlenmiş kütüphane)
    bin_file = tmp_path / "compiled.bin"
    bin_file.write_bytes(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00")
    assert is_binary_file(bin_file)

    # Boş dosya binary sayılmamalıdır
    empty_file = tmp_path / "empty.txt"
    empty_file.write_bytes(b"")
    assert not is_binary_file(empty_file)

    # Var olmayan dosya False döner
    assert not is_binary_file(tmp_path / "non_existent.dat")


def test_count_file_lines(tmp_path: Path):
    """count_file_lines satır sayısını doğru hesaplar."""
    f = tmp_path / "multi_line.py"
    f.write_text("line1\nline2\nline3\nline4\nline5\n", encoding="utf-8")
    assert count_file_lines(f) == 5

    empty = tmp_path / "empty.py"
    empty.write_text("", encoding="utf-8")
    assert count_file_lines(empty) == 0

    assert count_file_lines(tmp_path / "does_not_exist.py") == 0


# ==========================================
# 4. Ignore Motoru (.gitignore & .aisastignore) Testleri
# ==========================================

def test_load_ignore_patterns_merging(tmp_path: Path):
    """.gitignore ve .aisastignore dosyalarının birleştirildiğini ve yorumların elendiğini doğrular."""
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text("# Git ignore dosyası\n*.log\nbuild/\ntemp/\n", encoding="utf-8")

    aisastignore = tmp_path / ".aisastignore"
    aisastignore.write_text("# SAST ignore\nsecret_mock/\ntemp/\n*.tmp\n", encoding="utf-8")

    base = [".git/**", "node_modules/**"]
    merged = load_ignore_patterns(
        target_dir=tmp_path,
        base_patterns=base,
        ignore_file_name=".aisastignore",
        respect_gitignore=True,
    )

    assert ".git/**" in merged
    assert "node_modules/**" in merged
    assert "*.log" in merged
    assert "build/" in merged
    assert "temp/" in merged
    assert "secret_mock/" in merged
    assert "*.tmp" in merged

    # "temp/" tekrar etmemeli (deduplication)
    assert merged.count("temp/") == 1

    # respect_gitignore=False iken .gitignore okunmamalı
    merged_no_git = load_ignore_patterns(
        target_dir=tmp_path,
        base_patterns=base,
        ignore_file_name=".aisastignore",
        respect_gitignore=False,
    )
    assert "*.log" not in merged_no_git
    assert "secret_mock/" in merged_no_git


def test_discover_files_with_ignore_and_binary(tmp_path: Path):
    """discover_files fonksiyonunun .gitignore, .aisastignore ve binary dosyaları atladığını doğrular."""
    (tmp_path / ".gitignore").write_text("*.log\n", encoding="utf-8")
    (tmp_path / ".aisastignore").write_text("ignored_dir/**\n", encoding="utf-8")

    # Geçerli dosyalar
    valid_file = tmp_path / "app.py"
    valid_file.write_text("print('valid')\n", encoding="utf-8")

    # Binary dosya
    bin_file = tmp_path / "image.png"
    bin_file.write_bytes(b"\x89PNG\r\n\x1a\n\x00\x00\x00")

    # İhmal edilen dosyalar
    log_file = tmp_path / "app.log"
    log_file.write_text("log info\n", encoding="utf-8")

    ignored_dir = tmp_path / "ignored_dir"
    ignored_dir.mkdir()
    ignored_subfile = ignored_dir / "secret.py"
    ignored_subfile.write_text("pass\n", encoding="utf-8")

    scanned, skipped = discover_files(
        target_path=tmp_path,
        ignore_patterns=[],
    )

    scanned_names = [f.name for f in scanned]
    skipped_names = [f.name for f in skipped]

    assert "app.py" in scanned_names
    assert "image.png" in skipped_names
    assert "app.log" in skipped_names
    assert "secret.py" in skipped_names


# ==========================================
# 5. Git Diff --staged Entegrasyon Testleri
# ==========================================

def test_get_staged_files_and_ranges_with_real_git(tmp_path: Path):
    """Geçici bir git deposunda stage edilmiş dosyayı ve değişen satır aralığını doğrular."""
    # Git deposunu başlat
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True)

    # Dosya oluştur ve stage et
    code_file = tmp_path / "main.py"
    code_file.write_text("line 1\nline 2\nline 3\nline 4\nline 5\n", encoding="utf-8")
    subprocess.run(["git", "add", "main.py"], cwd=tmp_path, check=True)

    staged_map = get_staged_files_and_ranges(tmp_path)
    expected_path = code_file.resolve()

    assert expected_path in staged_map
    ranges = staged_map[expected_path]
    assert len(ranges) == 1
    assert ranges[0].start_line == 1
    assert ranges[0].end_line == 5


def test_get_staged_files_and_ranges_not_a_git_repo(tmp_path: Path):
    """Git deposu olmayan bir dizinde GitScanError fırlatılmalıdır."""
    non_git_dir = tmp_path / "not_git"
    non_git_dir.mkdir()

    with pytest.raises(GitScanError) as exc_info:
        get_staged_files_and_ranges(non_git_dir)

    assert "Git" in str(exc_info.value)


# ==========================================
# 6. ScanPipeline ve LOC Metrik Testi
# ==========================================

def test_scan_pipeline_total_lines_of_code(tmp_path: Path):
    """ScanPipeline.run() toplam satır sayısını (LOC) doğru hesaplamalıdır."""
    f1 = tmp_path / "f1.py"
    f1.write_text("a = 1\nb = 2\nc = 3\n", encoding="utf-8")  # 3 satır

    f2 = tmp_path / "f2.py"
    f2.write_text("x = 10\ny = 20\n", encoding="utf-8")        # 2 satır

    cfg = ScannerConfig(target_path=str(tmp_path), ignore_patterns=[])
    pipeline = ScanPipeline(cfg)
    result = pipeline.run(target_override=tmp_path)

    assert result.status == "completed"
    assert result.metrics.scanned_files == 2
    assert result.metrics.total_lines_of_code == 5
    assert result.metrics.duration_seconds >= 0.0


# ==========================================
# 7. CLI --staged ve --no-gitignore Testleri
# ==========================================

def test_cli_scan_dry_run_staged(tmp_path: Path):
    """`aisast scan --staged --dry-run` komutunun stage edilen dosyaları ve satır aralıklarını listelemesi."""
    # Git deposunu başlat
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=tmp_path, check=True)

    file_a = tmp_path / "service.py"
    file_a.write_text("x = 1\ny = 2\nz = 3\n", encoding="utf-8")
    subprocess.run(["git", "add", "service.py"], cwd=tmp_path, check=True)

    res = runner.invoke(app, ["scan", "--dry-run", "--staged", str(tmp_path)])
    assert res.exit_code == 0
    assert "DRY-RUN" in res.stdout
    assert "Git Diff (--staged)" in res.stdout
    assert "service.py" in res.stdout
    assert "Değişen Satırlar: 1-3" in res.stdout


def test_cli_scan_no_gitignore_flag(tmp_path: Path):
    """`--no-gitignore` bayrağı .gitignore kuralını yoksaymalıdır."""
    (tmp_path / ".gitignore").write_text("special.py\n", encoding="utf-8")
    (tmp_path / "special.py").write_text("token = 'secret'\n", encoding="utf-8")

    # 1. Varsayılan (respect_gitignore=True): special.py atlanır (.gitignore taranır, special.py atlanır)
    res_default = runner.invoke(app, ["scan", "--dry-run", str(tmp_path)])
    assert res_default.exit_code == 0
    assert "Atlanacak Dosya Sayısı: 1" in res_default.stdout
    assert "special.py" not in res_default.stdout

    # 2. --no-gitignore aktif: special.py taranacak listesine girer (.gitignore ve special.py taranır)
    res_no_git = runner.invoke(app, ["scan", "--dry-run", "--no-gitignore", str(tmp_path)])
    assert res_no_git.exit_code == 0
    assert "special.py" in res_no_git.stdout
    assert "Taranacak Dosya Sayısı: 2" in res_no_git.stdout


def test_cli_scan_staged_in_non_git_repo_fails(tmp_path: Path):
    """Git deposu olmayan bir dizinde `aisast scan --staged` hata ile çıkmalıdır."""
    res = runner.invoke(app, ["scan", "--staged", str(tmp_path)])
    assert res.exit_code == 1
    assert "Git Hatası" in res.stdout
