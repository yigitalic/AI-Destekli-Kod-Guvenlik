"""AI-SAST Konfigürasyon Modülü.

Yapılandırma dosyası (.aisast.yaml / .aisast.yml), ortam değişkenleri (ENV)
ve CLI bayraklarını birleştiren ve doğrulayan Pydantic v2 yapılandırma sistemi.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, Field
import yaml

from aisast.models import SeverityLevel

# .env dosyasını otomatik olarak çalışma dizininden yükle
load_dotenv()


DEFAULT_IGNORE_PATTERNS = [
    ".git/**",
    ".svn/**",
    ".hg/**",
    ".venv/**",
    "venv/**",
    "env/**",
    "node_modules/**",
    "vendor/**",
    "__pycache__/**",
    "*.pyc",
    "*.pyo",
    ".pytest_cache/**",
    ".mypy_cache/**",
    ".ruff_cache/**",
    "dist/**",
    "build/**",
    "*.egg-info/**",
    "package-lock.json",
    "yarn.lock",
    "poetry.lock",
    "*.min.js",
    "*.min.css",
    "*.png",
    "*.jpg",
    "*.jpeg",
    "*.gif",
    "*.svg",
    "*.ico",
    "*.zip",
    "*.tar.gz",
    "*.exe",
    "*.dll",
    "*.so",
]


class Layer1Config(BaseModel):
    """Layer 1 (Regex & Yüksek Hızlı Sır Tarama) yapılandırması."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(default=True, description="Layer 1 sır tarayıcısını etkinleştir")
    entropy_threshold: float = Field(default=4.5, ge=1.0, le=8.0, description="Shannon entropi eşiği")
    detect_common_tokens: bool = Field(default=True, description="API anahtarları, JWT ve AWS token desenlerini ara")
    custom_rules_path: Optional[str] = Field(default=None, description="Özel regex kuralları YAML dosya yolu")
    max_file_size_kb: int = Field(default=2048, ge=1, description="Taranacak maksimum dosya boyutu (KB)")


class Layer2Config(BaseModel):
    """Layer 2 (AST & Sezgisel Statik Kod Analizi) yapılandırması."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(default=True, description="Layer 2 AST ve sezgisel analiz motorunu etkinleştir")
    enable_ast: bool = Field(default=True, description="AST ayrıştırma tabanlı zafiyet kurallarını çalıştır")
    enable_heuristics: bool = Field(default=True, description="Sezgisel desen analizini çalıştır")
    rule_severity_threshold: SeverityLevel = Field(
        default=SeverityLevel.LOW,
        description="Bu seviyenin altındaki kuralları göz ardı et"
    )


class Layer3Config(BaseModel):
    """Layer 3 (AI / LLM Bağlamsal Güvenlik Analizi ve Doğrulama) yapılandırması."""
    model_config = ConfigDict(extra="ignore")

    enabled: bool = Field(default=False, description="Layer 3 LLM doğrulama motorunu etkinleştir (API anahtarı gerekir)")
    provider: str = Field(default="openai", description="Model sağlayıcısı: openai, anthropic, gemini, local")
    model: str = Field(default="gpt-4o-mini", description="Kullanılacak model adı")
    api_key: Optional[str] = Field(default=None, description="Sağlayıcı API anahtarı (veya ortam değişkeni)")
    base_url: Optional[str] = Field(default=None, description="Özel LLM API uç noktası veya yerel Ollama URL'si")
    max_candidates: int = Field(default=30, ge=1, le=200, description="LLM'e gönderilecek azami şüpheli bulgu sayısı")
    temperature: float = Field(default=0.1, ge=0.0, le=1.0, description="Model belirleyicilik seviyesi")
    timeout_seconds: float = Field(default=30.0, ge=5.0, le=120.0, description="İstek zaman aşımı")
    fp_probability_threshold: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="Bu eşik ve üzerindeki false_positive_probability değerleri yanlış pozitif olarak işaretlenir"
    )
    verify_secrets: bool = Field(
        default=False,
        description="True ise düşük güvenilirlikli sır adaylarını da (maskelenmiş olarak) LLM ile doğrular; False ise sadece kod zafiyetlerini doğrular"
    )


class ReportingConfig(BaseModel):
    """Raporlama ve CI/CD çıktı yapılandırması."""
    model_config = ConfigDict(extra="ignore")

    output_format: str = Field(default="rich", description="Çıktı formatı: rich, json, sarif, markdown")
    output_file: Optional[str] = Field(default=None, description="Raporun kaydedileceği dosya yolu")
    fail_on_severity: Optional[SeverityLevel] = Field(
        default=SeverityLevel.HIGH,
        description="Bu ve üstü ciddiyette bulgu varsa CLI hata koduyla (exit code 2) döner"
    )
    show_snippets: bool = True
    min_severity: SeverityLevel = SeverityLevel.LOW


class ScannerConfig(BaseModel):
    """Ana aisast Tarayıcı Yapılandırması."""
    model_config = ConfigDict(extra="ignore")

    target_path: str = Field(default=".", description="Taranacak hedef dizin ya da dosya")
    ignore_file: str = Field(default=".aisastignore", description="İhmal listesi dosya yolu")
    ignore_patterns: list[str] = Field(default_factory=lambda: list(DEFAULT_IGNORE_PATTERNS))
    staged_only: bool = Field(default=False, description="Sadece git diff --staged içindeki değişiklikleri tara")
    respect_gitignore: bool = Field(default=True, description=".gitignore kurallarını dikkate al")
    layer1: Layer1Config = Field(default_factory=Layer1Config)
    layer2: Layer2Config = Field(default_factory=Layer2Config)
    layer3: Layer3Config = Field(default_factory=Layer3Config)
    reporting: ReportingConfig = Field(default_factory=ReportingConfig)

    def to_yaml_string(self) -> str:
        """Yapılandırmayı temiz açıklamalı YAML metnine dönüştürür."""
        data = self.model_dump(mode="json")
        return yaml.dump(data, sort_keys=False, default_flow_style=False, allow_unicode=True)


def find_default_config_path(start_dir: Optional[Path] = None) -> Optional[Path]:
    """Çalışma dizininde varsayılan konfigürasyon dosyasını arar."""
    base = start_dir or Path.cwd()
    for candidate in [".aisast.yaml", ".aisast.yml", "aisast.yaml", "aisast.yml"]:
        p = base / candidate
        if p.is_file():
            return p
    return None


def load_config(
    config_path: Optional[Path] = None,
    overrides: Optional[dict[str, Any]] = None
) -> ScannerConfig:
    """Konfigürasyon dosyasından, ortam değişkenlerinden ve CLI geçersiz kılmalarından yapılandırmayı yükler."""
    raw_data: dict[str, Any] = {}

    target_file = config_path or find_default_config_path()
    if target_file and target_file.is_file():
        try:
            with open(target_file, "r", encoding="utf-8") as f:
                loaded = yaml.safe_load(f)
                if isinstance(loaded, dict):
                    raw_data = loaded
        except Exception as e:
            # Hatalı dosya durumunda varsayılanlarla devam et veya hata fırlat
            pass

    # Ortam değişkenlerinden okuma
    if "AISAST_LAYER1_ENABLED" in os.environ:
        raw_data.setdefault("layer1", {})["enabled"] = os.getenv("AISAST_LAYER1_ENABLED", "").lower() in ("1", "true", "yes")
    if "AISAST_LAYER2_ENABLED" in os.environ:
        raw_data.setdefault("layer2", {})["enabled"] = os.getenv("AISAST_LAYER2_ENABLED", "").lower() in ("1", "true", "yes")
    if "AISAST_LAYER3_ENABLED" in os.environ:
        raw_data.setdefault("layer3", {})["enabled"] = os.getenv("AISAST_LAYER3_ENABLED", "").lower() in ("1", "true", "yes")
    if "AISAST_LLM_PROVIDER" in os.environ:
        raw_data.setdefault("layer3", {})["provider"] = os.environ["AISAST_LLM_PROVIDER"]
    if "AISAST_LLM_MODEL" in os.environ:
        raw_data.setdefault("layer3", {})["model"] = os.environ["AISAST_LLM_MODEL"]
    if "AISAST_LLM_BASE_URL" in os.environ:
        raw_data.setdefault("layer3", {})["base_url"] = os.environ["AISAST_LLM_BASE_URL"]
    if "AISAST_FP_THRESHOLD" in os.environ:
        try:
            raw_data.setdefault("layer3", {})["fp_probability_threshold"] = float(os.environ["AISAST_FP_THRESHOLD"])
        except ValueError:
            pass
    if "AISAST_VERIFY_SECRETS" in os.environ:
        raw_data.setdefault("layer3", {})["verify_secrets"] = os.getenv("AISAST_VERIFY_SECRETS", "").lower() in ("1", "true", "yes")
    if "AISAST_API_KEY" in os.environ:
        raw_data.setdefault("layer3", {})["api_key"] = os.environ["AISAST_API_KEY"]
    elif "OPENAI_API_KEY" in os.environ:
        raw_data.setdefault("layer3", {})["api_key"] = os.environ["OPENAI_API_KEY"]
    elif "GEMINI_API_KEY" in os.environ:
        raw_data.setdefault("layer3", {})["api_key"] = os.environ["GEMINI_API_KEY"]
    elif "ANTHROPIC_API_KEY" in os.environ:
        raw_data.setdefault("layer3", {})["api_key"] = os.environ["ANTHROPIC_API_KEY"]
    if "AISAST_STAGED_ONLY" in os.environ:
        raw_data["staged_only"] = os.getenv("AISAST_STAGED_ONLY", "").lower() in ("1", "true", "yes")
    if "AISAST_RESPECT_GITIGNORE" in os.environ:
        raw_data["respect_gitignore"] = os.getenv("AISAST_RESPECT_GITIGNORE", "").lower() in ("1", "true", "yes")

    # CLI parametreleri veya programatik overrides
    if overrides:
        for k, v in overrides.items():
            if v is None:
                continue
            if "__" in k:  # e.g., layer1__enabled
                sub_k, field_k = k.split("__", 1)
                raw_data.setdefault(sub_k, {})[field_k] = v
            else:
                raw_data[k] = v

    return ScannerConfig(**raw_data)
