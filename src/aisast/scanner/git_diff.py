"""AI-SAST Git Entegrasyonu ve Unified Diff Hunk Ayrıştırıcı Modülü.

`git diff --staged` çıktısını ayrıştırarak eklenen veya değiştirilen
satır aralıklarını (LineRange) tespit eder.
"""

from __future__ import annotations

from pathlib import Path
import re
import subprocess

from aisast.models import LineRange

HUNK_PATTERN = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


class GitScanError(RuntimeError):
    """Git diff veya depo işlemleri sırasında oluşan çalışma zamanı hataları."""
    pass


def parse_unified_diff(diff_text: str, repo_root: Path) -> dict[Path, list[LineRange]]:
    """Standart unified diff çıktısını ayrıştırarak dosya bazlı değişen satır aralıklarını döner.

    Args:
        diff_text: Git diff veya unified diff metni.
        repo_root: Git deposunun kök dizini (göreceli yolları çözmek için).

    Returns:
        {dosya_yolu: [LineRange, ...]} sözlüğü.
    """
    diff_map: dict[Path, list[LineRange]] = {}
    current_file: Path | None = None

    for raw_line in diff_text.splitlines():
        line = raw_line.strip()

        # Yeni bir diff bloğu başladığında mevcut dosya bağlamını sıfırla
        if line.startswith("diff --git "):
            current_file = None
            continue

        # Hedef dosya başlığı
        if line.startswith("+++ "):
            raw_path = line[4:].strip()
            # Silinen dosya kontrolü
            if raw_path == "/dev/null":
                current_file = None
                continue

            # Olası tırnak işaretlerini temizle
            if (raw_path.startswith('"') and raw_path.endswith('"')) or (
                raw_path.startswith("'") and raw_path.endswith("'")
            ):
                raw_path = raw_path[1:-1]

            # Git varsayılan 'b/' önekini kaldır
            if raw_path.startswith("b/"):
                raw_path = raw_path[2:]

            current_file = (repo_root / raw_path).resolve()
            if current_file not in diff_map:
                diff_map[current_file] = []
            continue

        # Hunk başlığı ayrıştırma
        if current_file is not None and line.startswith("@@ "):
            m = HUNK_PATTERN.match(line)
            if m:
                start_line = int(m.group(1))
                count = int(m.group(2)) if m.group(2) is not None else 1

                # yeni_say == 0 ise (sadece silme işlemi) LineRange eklenmez
                if count > 0:
                    effective_start = max(1, start_line)
                    end_line = effective_start + count - 1
                    diff_map[current_file].append(
                        LineRange(start_line=effective_start, end_line=end_line)
                    )

    return diff_map


def get_staged_files_and_ranges(target_path: Path) -> dict[Path, list[LineRange]]:
    """Hedef yol için git diff --staged çıktısını alır ve değişen satır aralıklarını döndürür.

    Args:
        target_path: Taranacak hedef dosya veya dizin.

    Returns:
        Hedef kapsamındaki mevcut dosyaların değişen satır aralıkları eşlemesi.

    Raises:
        GitScanError: Git komutu bulunamazsa veya hedef dizin bir git deposu değilse.
    """
    target_resolved = target_path.resolve()
    cwd = target_resolved if target_resolved.is_dir() else target_resolved.parent

    # 1. Git repo kök dizinini tespit et
    try:
        rev_proc = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except FileNotFoundError as exc:
        raise GitScanError(f"'git' komutu sistemde bulunamadı: {exc}") from exc
    except Exception as exc:
        raise GitScanError(f"Git deposu denetlenirken hata oluştu: {exc}") from exc

    if rev_proc.returncode != 0:
        raise GitScanError(
            f"'{target_path}' bir Git deposu içerisinde değil veya Git hatası verdi: "
            f"{rev_proc.stderr.strip()}"
        )

    repo_root = Path(rev_proc.stdout.strip()).resolve()

    # 2. Stage edilmiş diff çıktısını al (Sadece Eklenen, Kopyalanan, Değiştirilen, Yeniden Adlandırılan)
    try:
        diff_proc = subprocess.run(
            ["git", "diff", "--staged", "--unified=0", "--diff-filter=ACMR"],
            cwd=repo_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except Exception as exc:
        raise GitScanError(f"git diff komutu çalıştırılamadı: {exc}") from exc

    if diff_proc.returncode != 0:
        raise GitScanError(f"git diff komutu başarısız oldu: {diff_proc.stderr.strip()}")

    # 3. Diff çıktısını ayrıştır
    diff_map = parse_unified_diff(diff_proc.stdout, repo_root)

    # 4. Sadece target_path kapsamındaki ve diskte var olan dosyaları filtrele
    filtered_map: dict[Path, list[LineRange]] = {}
    for file_path, ranges in diff_map.items():
        if not file_path.is_file():
            continue

        if target_resolved.is_file():
            if file_path == target_resolved:
                filtered_map[file_path] = ranges
        else:
            try:
                file_path.relative_to(target_resolved)
                filtered_map[file_path] = ranges
            except ValueError:
                # target_resolved altında değilse atla
                continue

    return filtered_map
