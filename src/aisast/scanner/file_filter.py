"""AI-SAST Dosya Filtreleme ve İkili (Binary) Dosya Tespiti Modülü.

.gitignore ve .aisastignore dosyalarının ayrıştırılması,
ikili (binary/null-byte) dosyaların filtrelenmesi ve satır sayımı işlemlerini yürütür.
"""

from __future__ import annotations

from pathlib import Path
from typing import Sequence


def is_binary_file(file_path: Path, sample_size: int = 8192) -> bool:
    """Dosyanın binary (ikili) formatta olup olmadığını tespit eder.

    Dosyanın ilk `sample_size` baytını okur; eğer içerisinde null byte (`\\x00`)
    bulunursa True (binary) döner. Boş veya erişilemeyen dosyalar False döner.
    """
    try:
        if not file_path.is_file():
            return False
        with open(file_path, "rb") as f:
            chunk = f.read(sample_size)
            if not chunk:
                return False
            return b"\x00" in chunk
    except (OSError, PermissionError):
        return False


def load_ignore_patterns(
    target_dir: Path,
    base_patterns: Sequence[str],
    ignore_file_name: str = ".aisastignore",
    respect_gitignore: bool = True,
) -> list[str]:
    """Hedef dizindeki .gitignore ve .aisastignore dosyalarını okuyarak birleştirilmiş ihmal listesi üretir.

    Args:
        target_dir: Taranan dizin veya dosya konumu.
        base_patterns: Varsayılan konfigürasyondan gelen ihmal kalıpları.
        ignore_file_name: Özel ihmal dosyası adı (varsayılan: .aisastignore).
        respect_gitignore: .gitignore dosyasının dikkate alınıp alınmayacağı.

    Returns:
        Tekrarlayan elemanları temizlenmiş, sırası korunmuş birleşik ihmal kalıpları listesi.
    """
    patterns: list[str] = list(base_patterns)
    base_dir = target_dir if target_dir.is_dir() else target_dir.parent

    def read_patterns_from_file(path: Path) -> list[str]:
        if not path.is_file():
            return []
        loaded: list[str] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for raw_line in f:
                    line = raw_line.strip()
                    if line and not line.startswith("#"):
                        loaded.append(line)
        except (OSError, PermissionError):
            pass
        return loaded

    if respect_gitignore:
        gitignore_path = base_dir / ".gitignore"
        patterns.extend(read_patterns_from_file(gitignore_path))

    if ignore_file_name:
        custom_ignore_path = base_dir / ignore_file_name
        patterns.extend(read_patterns_from_file(custom_ignore_path))

    # Tekrarlayanları temizle (sırayı koruyarak)
    seen: set[str] = set()
    deduped: list[str] = []
    for pat in patterns:
        cleaned = pat.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            deduped.append(cleaned)

    return deduped


def count_file_lines(file_path: Path) -> int:
    """UTF-8 (errors='replace') ile dosyanın toplam satır sayısını hesaplar.

    Dosya mevcut değilse veya okunamıyorsa 0 döner.
    """
    try:
        if not file_path.is_file():
            return 0
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            count = 0
            for _ in f:
                count += 1
            return count
    except (OSError, PermissionError):
        return 0
