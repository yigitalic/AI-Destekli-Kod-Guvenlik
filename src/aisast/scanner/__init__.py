"""AI-SAST Tarayıcı ve Boru Hattı Orkestrasyon Modülü.

Dosya keşfi, ihmal desenlerinin (.gitignore ve .aisastignore) uygulanması,
binary dosyaların elenmesi, Git diff hunk ayrıştırması ve
3 katmanlı tarama boru hattının sırayla yürütülmesinden sorumludur.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
import time
from typing import Any, Sequence

from aisast.config import ScannerConfig
from aisast.layers.layer1_secrets import Layer1SecretScanner
from aisast.layers.layer2_heuristics import Layer2HeuristicScanner
from aisast.layers.layer3_llm import Layer3LLMVerifier
from aisast.models import Finding, LineRange, ScannableFile, ScanMetrics, ScanResult
from aisast.scanner.file_filter import count_file_lines, is_binary_file, load_ignore_patterns
from aisast.scanner.git_diff import GitScanError, get_staged_files_and_ranges, parse_unified_diff


def matches_any_pattern(path_str: str, patterns: Sequence[str]) -> bool:
    """Verilen dosya yolunun kalıplardan herhangi biriyle eşleşip eşleşmediğini kontrol eder."""
    normalized = path_str.replace("\\", "/")
    for pat in patterns:
        clean_pat = pat.strip()
        if not clean_pat or clean_pat.startswith("#"):
            continue
        clean_pat = clean_pat.replace("\\", "/")
        # Dizin eşleşmesi için (örn: node_modules/)
        if clean_pat.endswith("/"):
            if f"/{clean_pat}" in f"/{normalized}/" or normalized.startswith(clean_pat):
                return True
        if fnmatch.fnmatch(normalized, clean_pat) or fnmatch.fnmatch(f"/{normalized}", clean_pat):
            return True
        if any(fnmatch.fnmatch(part, clean_pat) for part in normalized.split("/")):
            return True
    return False


def discover_files(
    target_path: Path,
    ignore_patterns: Sequence[str],
    max_file_size_kb: int = 5120,
    respect_gitignore: bool = True,
    ignore_file_name: str = ".aisastignore",
) -> tuple[list[Path], list[Path]]:
    """Taranacak hedef dizindeki dosyaları filtreleyerek listeler.

    Geriye dönük uyumluluk için Path listesi döner.

    Returns:
        (taranacak_dosyalar, atlanan_dosyalar) demeti.
    """
    scanned: list[Path] = []
    skipped: list[Path] = []

    target = target_path.resolve()
    base_dir = target if target.is_dir() else target.parent

    effective_patterns = load_ignore_patterns(
        target_dir=base_dir,
        base_patterns=ignore_patterns,
        ignore_file_name=ignore_file_name,
        respect_gitignore=respect_gitignore,
    )

    if target.is_file():
        if matches_any_pattern(target.name, effective_patterns):
            skipped.append(target)
            return scanned, skipped
        try:
            if (target.stat().st_size / 1024) > max_file_size_kb:
                skipped.append(target)
                return scanned, skipped
        except OSError:
            skipped.append(target)
            return scanned, skipped
        if is_binary_file(target):
            skipped.append(target)
            return scanned, skipped

        scanned.append(target)
        return scanned, skipped

    if not target.is_dir():
        return scanned, skipped

    for p in target.rglob("*"):
        if not p.is_file():
            continue

        try:
            rel = p.relative_to(target)
            rel_str = str(rel)
        except ValueError:
            rel_str = p.name

        if matches_any_pattern(rel_str, effective_patterns):
            skipped.append(p)
            continue

        try:
            size_kb = p.stat().st_size / 1024
            if size_kb > max_file_size_kb:
                skipped.append(p)
                continue
        except OSError:
            skipped.append(p)
            continue

        if is_binary_file(p):
            skipped.append(p)
            continue

        scanned.append(p)

    return scanned, skipped


def discover_scannable_files(
    target_path: Path,
    config: ScannerConfig,
) -> tuple[list[ScannableFile], list[Path]]:
    """Taranabilir dosyaları ve atlanan dosyaları ScannableFile nesneleriyle döner.

    config.staged_only True ise sadece git diff --staged içindeki dosyalar ve
    değişen satır aralıkları taranır.

    Returns:
        (taranabilir_dosyalar, atlanan_dosyalar) demeti.
    """
    scannable_files: list[ScannableFile] = []
    skipped: list[Path] = []
    target = target_path.resolve()
    base_dir = target if target.is_dir() else target.parent

    effective_patterns = load_ignore_patterns(
        target_dir=base_dir,
        base_patterns=config.ignore_patterns,
        ignore_file_name=config.ignore_file,
        respect_gitignore=config.respect_gitignore,
    )

    max_file_size_kb = config.layer1.max_file_size_kb

    # 1. Mod: Yalnızca Git diff --staged
    if config.staged_only:
        staged_map = get_staged_files_and_ranges(target)
        for p, ranges in staged_map.items():
            try:
                rel = p.relative_to(target)
                rel_str = str(rel)
            except ValueError:
                rel_str = p.name

            if matches_any_pattern(rel_str, effective_patterns):
                skipped.append(p)
                continue

            try:
                stat = p.stat()
                if (stat.st_size / 1024) > max_file_size_kb:
                    skipped.append(p)
                    continue
                size_bytes = stat.st_size
            except OSError:
                skipped.append(p)
                continue

            if is_binary_file(p):
                skipped.append(p)
                continue

            lines = count_file_lines(p)
            scannable_files.append(
                ScannableFile(
                    path=p,
                    relative_path=rel_str,
                    size_bytes=size_bytes,
                    line_count=lines,
                    is_staged_diff=True,
                    changed_ranges=ranges,
                )
            )
        return scannable_files, skipped

    # 2. Mod: Tam Dosya Taraması
    if target.is_file():
        if matches_any_pattern(target.name, effective_patterns):
            skipped.append(target)
            return scannable_files, skipped
        try:
            stat = target.stat()
            if (stat.st_size / 1024) > max_file_size_kb:
                skipped.append(target)
                return scannable_files, skipped
            size_bytes = stat.st_size
        except OSError:
            skipped.append(target)
            return scannable_files, skipped

        if is_binary_file(target):
            skipped.append(target)
            return scannable_files, skipped

        lines = count_file_lines(target)
        scannable_files.append(
            ScannableFile(
                path=target,
                relative_path=target.name,
                size_bytes=size_bytes,
                line_count=lines,
                is_staged_diff=False,
                changed_ranges=[],
            )
        )
        return scannable_files, skipped

    if not target.is_dir():
        return scannable_files, skipped

    for p in target.rglob("*"):
        if not p.is_file():
            continue

        try:
            rel = p.relative_to(target)
            rel_str = str(rel)
        except ValueError:
            rel_str = p.name

        if matches_any_pattern(rel_str, effective_patterns):
            skipped.append(p)
            continue

        try:
            stat = p.stat()
            if (stat.st_size / 1024) > max_file_size_kb:
                skipped.append(p)
                continue
            size_bytes = stat.st_size
        except OSError:
            skipped.append(p)
            continue

        if is_binary_file(p):
            skipped.append(p)
            continue

        lines = count_file_lines(p)
        scannable_files.append(
            ScannableFile(
                path=p,
                relative_path=rel_str,
                size_bytes=size_bytes,
                line_count=lines,
                is_staged_diff=False,
                changed_ranges=[],
            )
        )

    return scannable_files, skipped


class ScanPipeline:
    """3 Katmanlı Güvenlik Tarama Boru Hattı Orkestratörü."""

    def __init__(self, config: ScannerConfig) -> None:
        self.config = config
        self.layer1 = Layer1SecretScanner(config.layer1)
        self.layer2 = Layer2HeuristicScanner(config.layer2)
        self.layer3 = Layer3LLMVerifier(config.layer3)

    def run(self, target_override: Path | None = None) -> ScanResult:
        """Yapılandırılmış hedef üzerinde boru hattını çalıştırır."""
        start_time = time.perf_counter()
        target = (target_override or Path(self.config.target_path)).resolve()

        # 1. Dosya Keşfi (ScannableFile nesneleriyle)
        scannable_files, skipped_files = discover_scannable_files(
            target_path=target,
            config=self.config,
        )
        scanned_file_paths = [sf.path for sf in scannable_files]

        all_findings: list[Finding] = []
        l1_count = 0
        l2_count = 0
        l3_count = 0

        context: dict[str, Any] = {
            "target": str(target),
            "total_files": len(scannable_files),
            "scannable_files": {str(sf.path): sf for sf in scannable_files},
            "staged_only": self.config.staged_only,
        }

        # 2. Layer 1 Yürütme (Etkinse)
        if self.config.layer1.enabled:
            l1_findings = self.layer1.scan_path(target, scanned_file_paths, context)
            all_findings.extend(l1_findings)
            l1_count = len(l1_findings)

        # 3. Layer 2 Yürütme (Etkinse)
        if self.config.layer2.enabled:
            l2_findings = self.layer2.scan_path(target, scanned_file_paths, context)
            all_findings.extend(l2_findings)
            l2_count = len(l2_findings)

        # 4. Layer 3 Yürütme (Etkinse)
        if self.config.layer3.enabled:
            # Önceki katmanlardan gelen adayları LLM ile doğrula
            verified = self.layer3.verify_candidates(all_findings, context)
            l3_count = sum(1 for f in verified if f.verified_by_llm)
            all_findings = verified

        elapsed = time.perf_counter() - start_time
        total_loc = sum(sf.line_count for sf in scannable_files)

        # Metrikler
        metrics = ScanMetrics(
            total_files=len(scannable_files) + len(skipped_files),
            scanned_files=len(scannable_files),
            skipped_files=len(skipped_files),
            total_lines_of_code=total_loc,
            duration_seconds=round(elapsed, 4),
            layer1_findings=l1_count,
            layer2_findings=l2_count,
            layer3_findings=l3_count,
        )

        result = ScanResult(
            target_path=str(target),
            findings=all_findings,
            metrics=metrics,
        )
        result.recalculate_summary()
        return result


__all__ = [
    "matches_any_pattern",
    "discover_files",
    "discover_scannable_files",
    "ScanPipeline",
    "is_binary_file",
    "load_ignore_patterns",
    "count_file_lines",
    "parse_unified_diff",
    "get_staged_files_and_ranges",
    "GitScanError",
]
