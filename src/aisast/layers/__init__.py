"""AI-SAST Tarama Katmanları Soyut Arabirimleri.

Tüm analiz katmanları (L1 Secrets, L2 Heuristics, L3 LLM)
bu temel sınıfı (`BaseScanLayer`) uygulayarak standart bir girdi-çıktı sözleşmesine uyar.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Sequence

from aisast.models import Finding, ScanLayer


class BaseScanLayer(ABC):
    """Tarama katmanları için ortak soyut temel sınıf."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Katmanın insan tarafından okunabilir adı."""
        pass

    @property
    @abstractmethod
    def layer_type(self) -> ScanLayer:
        """Katmanın ScanLayer enum karşılığı."""
        pass

    @abstractmethod
    def scan_path(
        self,
        target_path: Path,
        files: Sequence[Path],
        context: dict[str, Any] | None = None
    ) -> list[Finding]:
        """Belirtilen hedef dosyalarda güvenlik taraması gerçekleştirir.

        Args:
            target_path: Taranan kök dizin veya dosya.
            files: İhmal kuralları sonrası filtrelenmiş taranacak dosya listesi.
            context: Önceki katmanlardan aktarılan bağlamsal veriler.

        Returns:
            Tespit edilen güvenlik bulguları listesi.
        """
        pass
