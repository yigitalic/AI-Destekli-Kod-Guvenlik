"""AI-SAST Çekirdek Veri Modelleri (Pydantic v2).

Tüm tarama katmanları (Layer 1, Layer 2, Layer 3), raporlama modülleri
ve CLI arabirimi tarafından paylaşılan ortak şemalar.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class SeverityLevel(str, Enum):
    """Bulgu ciddiyet seviyesi."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        """Ciddiyet derecesi ağırlığı (karşılaştırma ve filtreleme için)."""
        weights = {
            SeverityLevel.CRITICAL: 5,
            SeverityLevel.HIGH: 4,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 2,
            SeverityLevel.INFO: 1,
        }
        return weights[self]

    def is_greater_or_equal(self, other: SeverityLevel) -> bool:
        """Bu ciddiyet seviyesinin belirtilen seviyeye eşit ya da daha yüksek olduğunu doğrular."""
        return self.weight >= other.weight


class ConfidenceLevel(str, Enum):
    """Bulgu doğruluk/güvenilirlik seviyesi."""
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ScanLayer(str, Enum):
    """Bulgunun tespit edildiği veya doğrulandığı analiz katmanı."""
    LAYER1_SECRETS = "LAYER1_SECRETS"
    LAYER2_HEURISTICS = "LAYER2_HEURISTICS"
    LAYER3_LLM = "LAYER3_LLM"


class VulnerabilityCategory(str, Enum):
    """Güvenlik zafiyeti / sır tespit kategorileri."""
    SECRET_LEAK = "SECRET_LEAK"
    SQL_INJECTION = "SQL_INJECTION"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    XSS = "XSS"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    HARDCODED_CREDENTIAL = "HARDCODED_CREDENTIAL"
    WEAK_CRYPTO = "WEAK_CRYPTO"
    SSRF = "SSRF"
    XXE = "XXE"
    AUTHENTICATION_BYPASS = "AUTHENTICATION_BYPASS"
    INSECURE_CONFIGURATION = "INSECURE_CONFIGURATION"
    OTHER = "OTHER"


class CodeLocation(BaseModel):
    """Kod içerisindeki zafiyet lokasyonu."""
    model_config = ConfigDict(frozen=True)

    file_path: str = Field(description="Kaynak dosyanın göreceli veya mutlak yolu")
    start_line: int = Field(ge=1, description="Başlangıç satır numarası (1 tabanlı)")
    end_line: int = Field(ge=1, description="Bitiş satır numarası (1 tabanlı)")
    start_column: Optional[int] = Field(default=None, ge=1, description="Başlangıç sütun numarası")
    end_column: Optional[int] = Field(default=None, ge=1, description="Bitiş sütun numarası")
    snippet: Optional[str] = Field(default=None, description="Şüpheli kod parçacığı")


class LineRange(BaseModel):
    """Git diff veya dosya içi satır aralığı modeli."""
    model_config = ConfigDict(frozen=True)

    start_line: int = Field(ge=1, description="Başlangıç satır numarası (1 tabanlı)")
    end_line: int = Field(ge=1, description="Bitiş satır numarası (1 tabanlı)")

    def contains_line(self, line: int) -> bool:
        """Verilen satır numarasının aralık içinde olup olmadığını döner."""
        return self.start_line <= line <= self.end_line


class ScannableFile(BaseModel):
    """Tarayıcı tarafından işlenebilir dosya ve diff bağlamı."""
    path: Path = Field(description="Dosyanın mutlak veya çözümlenmiş yolu")
    relative_path: str = Field(description="Dosyanın hedef veya repo köküne göre göreceli yolu")
    size_bytes: int = Field(ge=0, description="Dosya boyutu (bayt)")
    line_count: int = Field(default=0, ge=0, description="Dosyadaki toplam satır sayısı")
    is_staged_diff: bool = Field(default=False, description="Dosyanın git diff --staged filtresinden gelip gelmediği")
    changed_ranges: list[LineRange] = Field(
        default_factory=list,
        description="Sadece git diff modunda değişen satır aralıkları. Boşsa tüm dosya taranır."
    )

    def is_line_in_scope(self, line: int) -> bool:
        """Belirtilen satır numarasının tarama kapsamında olup olmadığını denetler.

        Eğer is_staged_diff False ise veya changed_ranges boş ise tüm dosya kapsamdadır (True).
        Aksi takdirde satır numarası changed_ranges içindeki herhangi bir LineRange içinde olmalıdır.
        """
        if not self.is_staged_diff or not self.changed_ranges:
            return True
        return any(r.contains_line(line) for r in self.changed_ranges)


class Remediation(BaseModel):
    """Önerilen güvenlik düzeltmesi veya iyileştirme adımları."""
    model_config = ConfigDict(frozen=True)

    description: str = Field(description="Düzeltme tavsiyesinin açık metin açıklaması")
    code_snippet: Optional[str] = Field(default=None, description="Örnek güvenli kod bloğu")
    diff: Optional[str] = Field(default=None, description="Unified diff biçiminde otomatik yama önerisi")
    references: list[str] = Field(default_factory=list, description="CWE, OWASP veya CVE referans bağlantıları")


class Finding(BaseModel):
    """Tekil güvenlik bulgusu veya sır tespiti."""
    model_config = ConfigDict(extra="ignore")

    id: str = Field(
        default_factory=lambda: str(uuid.uuid4()),
        description="Benzersiz bulgu kimliği (UUIDv4)"
    )
    rule_id: str = Field(description="Tetiklenen kuralın tanımlayıcısı (örn: SEC001, AST_SQLI_01)")
    title: str = Field(description="Kısa bulgu başlığı")
    description: str = Field(description="Detaylı zafiyet veya sır açıklaması")
    severity: SeverityLevel = Field(description="Ciddiyet seviyesi")
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM, description="Güven seviyesi")
    category: VulnerabilityCategory = Field(description="Zafiyet sınıfı")
    layer: ScanLayer = Field(description="Bulguyu üreten ilk katman")
    location: CodeLocation = Field(description="Kod içerisindeki konum bilgisi")
    cwe_id: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID (örn: CWE-798)")
    owasp_category: Optional[str] = Field(default=None, description="OWASP Top 10 kategorisi")
    verified_by_llm: bool = Field(default=False, description="Layer 3 (LLM) tarafından doğrulanıp doğrulanmadığı")
    llm_reasoning: Optional[str] = Field(default=None, description="LLM tarafından yapılan bağlamsal doğrulama açıklaması")
    is_false_positive: bool = Field(default=False, description="Yanlış pozitif olarak işaretlenip işaretlenmediği")
    remediation: Optional[Remediation] = Field(default=None, description="Çözüm ve yama önerisi")
    metadata: dict[str, Any] = Field(default_factory=dict, description="Katmana özgü ek metaveriler")


class AIVulnerabilityAssessment(BaseModel):
    """Layer 3 LLM tarafından üretilen yapılandırılmış zafiyet değerlendirmesi."""
    model_config = ConfigDict(extra="ignore")

    vulnerability_type: str = Field(description="Zafiyet türü veya standart adı (örn: SQL Injection)")
    cwe_id: str = Field(description="İlgili CWE kimliği (örn: CWE-89)")
    severity: SeverityLevel = Field(description="LLM tarafından bağlamsal olarak doğrulanan ciddiyet seviyesi")
    line_number: int = Field(ge=1, description="Zafiyetin bulunduğu kaynak satır numarası")
    explanation: str = Field(description="Zafiyetin nedeni, etki alanı ve bağlamsal doğrulama açıklaması")
    secure_code_patch: str = Field(description="Zafiyetli satırı düzelten önerilen güvenli kod parçacığı")
    false_positive_probability: float = Field(
        ge=0.0,
        le=1.0,
        description="Bulgunun yanlış pozitif olma olasılığı (0.0: kesinlikle gerçek, 1.0: kesinlikle yanlış alarm)"
    )


class ScanMetrics(BaseModel):
    """Tarama süreci performans ve kapsam metrikleri."""
    total_files: int = Field(default=0, ge=0)
    scanned_files: int = Field(default=0, ge=0)
    skipped_files: int = Field(default=0, ge=0)
    total_lines_of_code: int = Field(default=0, ge=0)
    duration_seconds: float = Field(default=0.0, ge=0.0)
    layer1_findings: int = Field(default=0, ge=0)
    layer2_findings: int = Field(default=0, ge=0)
    layer3_findings: int = Field(default=0, ge=0)


class ScanSummary(BaseModel):
    """Tarama sonucu özet tablosu."""
    total_findings: int = Field(default=0, ge=0)
    critical_count: int = Field(default=0, ge=0)
    high_count: int = Field(default=0, ge=0)
    medium_count: int = Field(default=0, ge=0)
    low_count: int = Field(default=0, ge=0)
    info_count: int = Field(default=0, ge=0)
    by_category: dict[str, int] = Field(default_factory=dict)
    by_layer: dict[str, int] = Field(default_factory=dict)


class ScanResult(BaseModel):
    """Nihai tarama raporu ve sonuç konteyneri."""
    scan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    target_path: str = Field(description="Taranan dizin veya dosya yolu")
    version: str = Field(default="0.1.0", description="aisast sürümü")
    status: str = Field(default="completed", description="Tarama durumu: completed, partial, failed")
    error_message: Optional[str] = Field(default=None, description="Olası hata mesajı")
    findings: list[Finding] = Field(default_factory=list, description="Tespit edilen tüm aktif bulgular")
    metrics: ScanMetrics = Field(default_factory=ScanMetrics, description="Tarama işlem metrikleri")
    summary: ScanSummary = Field(default_factory=ScanSummary, description="Ciddiyet ve kategori özetleri")

    def recalculate_summary(self) -> ScanSummary:
        """Mevcut bulgular üzerinden özet istatistiklerini yeniden hesaplar."""
        crit = high = med = low = info = 0
        by_cat: dict[str, int] = {}
        by_layer: dict[str, int] = {}

        for f in self.findings:
            if f.is_false_positive:
                continue

            if f.severity == SeverityLevel.CRITICAL:
                crit += 1
            elif f.severity == SeverityLevel.HIGH:
                high += 1
            elif f.severity == SeverityLevel.MEDIUM:
                med += 1
            elif f.severity == SeverityLevel.LOW:
                low += 1
            elif f.severity == SeverityLevel.INFO:
                info += 1

            cat_key = f.category.value
            by_cat[cat_key] = by_cat.get(cat_key, 0) + 1

            layer_key = f.layer.value
            by_layer[layer_key] = by_layer.get(layer_key, 0) + 1

        self.summary = ScanSummary(
            total_findings=crit + high + med + low + info,
            critical_count=crit,
            high_count=high,
            medium_count=med,
            low_count=low,
            info_count=info,
            by_category=by_cat,
            by_layer=by_layer,
        )
        return self.summary

    def filter_by_severity(self, min_severity: SeverityLevel) -> list[Finding]:
        """Belirli bir asgari ciddiyet eşiğine göre bulguları filtreler."""
        return [
            f for f in self.findings
            if not f.is_false_positive and f.severity.is_greater_or_equal(min_severity)
        ]

    def to_sarif_dict(self) -> dict[str, Any]:
        """OASIS SARIF v2.1.0 standardına uyumlu sözlük çıktısı üretir."""
        rules_map: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        level_map = {
            SeverityLevel.CRITICAL: "error",
            SeverityLevel.HIGH: "error",
            SeverityLevel.MEDIUM: "warning",
            SeverityLevel.LOW: "note",
            SeverityLevel.INFO: "none",
        }

        for finding in self.findings:
            if finding.is_false_positive:
                continue

            if finding.rule_id not in rules_map:
                help_text = (
                    finding.remediation.description
                    if finding.remediation and finding.remediation.description
                    else finding.description
                )
                help_markdown = help_text
                if finding.remediation and finding.remediation.description:
                    ref_text = ""
                    if finding.remediation.references:
                        ref_text = "\n\n**Referanslar:**\n" + "\n".join(f"- {ref}" for ref in finding.remediation.references)
                    help_markdown = f"### Çözüm & İyileştirme Önerisi\n\n{finding.remediation.description}{ref_text}"

                rules_map[finding.rule_id] = {
                    "id": finding.rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "defaultConfiguration": {"level": level_map[finding.severity]},
                    "help": {
                        "text": help_text,
                        "markdown": help_markdown,
                    },
                    "properties": {
                        "category": finding.category.value,
                        "cwe": finding.cwe_id,
                        "owasp": finding.owasp_category,
                    },
                }

            result_item: dict[str, Any] = {
                "ruleId": finding.rule_id,
                "level": level_map[finding.severity],
                "message": {"text": f"{finding.title}: {finding.description}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.location.file_path},
                            "region": {
                                "startLine": finding.location.start_line,
                                "endLine": finding.location.end_line,
                                "startColumn": finding.location.start_column or 1,
                                "endColumn": finding.location.end_column or 1,
                            },
                        }
                    }
                ],
                "properties": {
                    "confidence": finding.confidence.value,
                    "layer": finding.layer.value,
                    "verifiedByLLM": finding.verified_by_llm,
                },
            }

            if finding.remediation:
                fix_entry: dict[str, Any] = {
                    "description": {"text": finding.remediation.description},
                }
                if finding.remediation.diff:
                    fix_entry["properties"] = {"diff": finding.remediation.diff}
                result_item["fixes"] = [fix_entry]
                result_item["properties"]["remediation"] = {
                    "description": finding.remediation.description,
                    "codeSnippet": finding.remediation.code_snippet,
                    "diff": finding.remediation.diff,
                    "references": finding.remediation.references,
                }

            results.append(result_item)

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "aisast",
                            "version": self.version,
                            "informationUri": "https://github.com/yigitalic/AI-Destekli-Kod-Guvenlik",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ]
        }


__all__ = [
    "SeverityLevel",
    "ConfidenceLevel",
    "ScanLayer",
    "VulnerabilityCategory",
    "CodeLocation",
    "LineRange",
    "ScannableFile",
    "Remediation",
    "Finding",
    "AIVulnerabilityAssessment",
    "ScanMetrics",
    "ScanSummary",
    "ScanResult",
]
