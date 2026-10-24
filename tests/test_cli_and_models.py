"""AI-SAST FAZ 0 Test Paketi.

Çekirdek veri modelleri (Pydantic v2), konfigürasyon yükleyici,
katman iskeletleri ve Typer CLI komutlarını test eder.
"""

from __future__ import annotations

import json
from pathlib import Path
import pytest
from typer.testing import CliRunner

from aisast import __version__
from aisast.cli import app
from aisast.config import (
    Layer1Config,
    Layer2Config,
    Layer3Config,
    ScannerConfig,
    load_config,
)
from aisast.layers import BaseScanLayer
from aisast.layers.layer1_secrets import Layer1SecretScanner
from aisast.layers.layer2_heuristics import Layer2HeuristicScanner
from aisast.layers.layer3_llm import Layer3LLMVerifier
from aisast.models import (
    CodeLocation,
    ConfidenceLevel,
    Finding,
    Remediation,
    ScanLayer,
    ScanResult,
    SeverityLevel,
    VulnerabilityCategory,
)
from aisast.scanner import discover_files, matches_any_pattern

runner = CliRunner()


# ==========================================
# 1. Pydantic v2 Veri Modelleri Testleri
# ==========================================

def test_severity_level_weights_and_comparisons():
    """Ciddiyet seviyesi ağırlık ve büyüklük karşılaştırmalarını doğrular."""
    assert SeverityLevel.CRITICAL.weight > SeverityLevel.HIGH.weight
    assert SeverityLevel.HIGH.weight > SeverityLevel.MEDIUM.weight
    assert SeverityLevel.MEDIUM.weight > SeverityLevel.LOW.weight
    assert SeverityLevel.LOW.weight > SeverityLevel.INFO.weight

    assert SeverityLevel.CRITICAL.is_greater_or_equal(SeverityLevel.HIGH)
    assert SeverityLevel.HIGH.is_greater_or_equal(SeverityLevel.HIGH)
    assert not SeverityLevel.LOW.is_greater_or_equal(SeverityLevel.MEDIUM)


def test_code_location_model():
    """CodeLocation veri modelinin doğrulamalarını test eder."""
    loc = CodeLocation(
        file_path="src/main.py",
        start_line=10,
        end_line=12,
        start_column=5,
        end_column=20,
        snippet="api_key = 'AKIA...'",
    )
    assert loc.file_path == "src/main.py"
    assert loc.start_line == 10
    assert loc.snippet == "api_key = 'AKIA...'"

    with pytest.raises(Exception):
        # 1 tabanlı satır kuralı (start_line >= 1)
        CodeLocation(file_path="test.py", start_line=0, end_line=1)


def test_finding_and_summary_recalculation():
    """Finding oluşturma ve ScanResult özet hesaplamasını test eder."""
    loc = CodeLocation(file_path="config.py", start_line=1, end_line=1)
    f1 = Finding(
        rule_id="SEC001",
        title="AWS Access Key Exposed",
        description="Kaynak kodda açık AWS erişim anahtarı bulundu.",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        layer=ScanLayer.LAYER1_SECRETS,
        location=loc,
        cwe_id="CWE-798",
    )
    f2 = Finding(
        rule_id="AST001",
        title="Potential SQL Injection",
        description="Dinamik SQL sorgusu tespit edildi.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.MEDIUM,
        category=VulnerabilityCategory.SQL_INJECTION,
        layer=ScanLayer.LAYER2_HEURISTICS,
        location=loc,
        cwe_id="CWE-89",
    )
    f_false_positive = Finding(
        rule_id="AST002",
        title="False Positive Alarm",
        description="Yanlış pozitif testi.",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.LOW,
        category=VulnerabilityCategory.OTHER,
        layer=ScanLayer.LAYER2_HEURISTICS,
        location=loc,
        is_false_positive=True,
    )

    result = ScanResult(
        target_path=".",
        findings=[f1, f2, f_false_positive],
    )
    summary = result.recalculate_summary()

    # Yanlış pozitif özet sayımına dahil edilmemeli
    assert summary.total_findings == 2
    assert summary.critical_count == 1
    assert summary.high_count == 1
    assert summary.medium_count == 0
    assert summary.by_layer[ScanLayer.LAYER1_SECRETS.value] == 1
    assert summary.by_layer[ScanLayer.LAYER2_HEURISTICS.value] == 1

    # Filtreleme testi
    high_and_above = result.filter_by_severity(SeverityLevel.HIGH)
    assert len(high_and_above) == 2  # f1 (CRITICAL) and f2 (HIGH)

    critical_only = result.filter_by_severity(SeverityLevel.CRITICAL)
    assert len(critical_only) == 1
    assert critical_only[0].rule_id == "SEC001"


def test_sarif_export():
    """SARIF v2.1.0 sözlük yapısının doğruluğunu test eder."""
    loc = CodeLocation(file_path="app.py", start_line=5, end_line=5)
    finding = Finding(
        rule_id="SEC_TOKEN",
        title="Hardcoded Token",
        description="Sert kodlanmış token bulundu.",
        severity=SeverityLevel.HIGH,
        category=VulnerabilityCategory.HARDCODED_CREDENTIAL,
        layer=ScanLayer.LAYER1_SECRETS,
        location=loc,
    )
    result = ScanResult(target_path="src/", findings=[finding])
    sarif = result.to_sarif_dict()

    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "aisast"
    assert len(sarif["runs"][0]["results"]) == 1
    assert sarif["runs"][0]["results"][0]["ruleId"] == "SEC_TOKEN"
    assert sarif["runs"][0]["results"][0]["level"] == "error"


# ==========================================
# 2. Konfigürasyon Testleri
# ==========================================

def test_default_config():
    """Varsayılan yapılandırma değerlerini denetler."""
    cfg = ScannerConfig()
    assert cfg.target_path == "."
    assert cfg.layer1.enabled is True
    assert cfg.layer1.entropy_threshold == 4.5
    assert cfg.layer2.enabled is True
    assert cfg.layer3.enabled is False
    assert cfg.reporting.output_format == "rich"
    assert cfg.reporting.fail_on_severity == SeverityLevel.HIGH


def test_config_load_with_overrides(tmp_path: Path):
    """YAML dosyasından okuma ve override mekanizmasını test eder."""
    custom_yaml = tmp_path / "custom_config.yaml"
    custom_yaml.write_text(
        """
target_path: "./my_project"
layer1:
  enabled: false
  entropy_threshold: 5.2
layer3:
  enabled: true
  provider: "anthropic"
  model: "claude-3-haiku"
""",
        encoding="utf-8",
    )

    loaded = load_config(config_path=custom_yaml)
    assert loaded.target_path == "./my_project"
    assert loaded.layer1.enabled is False
    assert loaded.layer1.entropy_threshold == 5.2
    assert loaded.layer3.enabled is True
    assert loaded.layer3.provider == "anthropic"

    # CLI overrides
    overridden = load_config(
        config_path=custom_yaml,
        overrides={"layer1__enabled": True, "reporting__output_format": "sarif"}
    )
    assert overridden.layer1.enabled is True
    assert overridden.reporting.output_format == "sarif"


# ==========================================
# 3. Katman İskeletleri (Stubs) Testleri
# ==========================================

def test_layer_stubs_interface():
    """Tüm katmanların BaseScanLayer arayüzünü uyguladığını ve FAZ 0 sözleşmesini sağladığını doğrular."""
    l1 = Layer1SecretScanner()
    l2 = Layer2HeuristicScanner()
    l3 = Layer3LLMVerifier()

    assert isinstance(l1, BaseScanLayer)
    assert isinstance(l2, BaseScanLayer)
    assert isinstance(l3, BaseScanLayer)

    assert l1.layer_type == ScanLayer.LAYER1_SECRETS
    assert l2.layer_type == ScanLayer.LAYER2_HEURISTICS
    assert l3.layer_type == ScanLayer.LAYER3_LLM

    # FAZ 0 gereği iskelet katmanlar henüz algoritma çalıştırmaz
    assert l1.scan_path(Path("."), []) == []
    assert l2.scan_path(Path("."), []) == []
    assert l3.scan_path(Path("."), []) == []


# ==========================================
# 4. Dosya Keşfi ve İhmal Kuralları Testleri
# ==========================================

def test_matches_any_pattern():
    """İhmal deseni eşleştirmesini test eder."""
    patterns = [".git/**", "node_modules/**", "*.min.js"]
    assert matches_any_pattern(".git/config", patterns) is True
    assert matches_any_pattern("node_modules/express/index.js", patterns) is True
    assert matches_any_pattern("assets/bundle.min.js", patterns) is True
    assert matches_any_pattern("src/app.py", patterns) is False


def test_discover_files(tmp_path: Path):
    """Dosya keşif motorunun filtreleme kurallarını uyguladığını test eder."""
    (tmp_path / "valid.py").write_text("print('hello')", encoding="utf-8")
    (tmp_path / "app.js").write_text("console.log('hi');", encoding="utf-8")
    git_dir = tmp_path / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main", encoding="utf-8")

    scanned, skipped = discover_files(
        target_path=tmp_path,
        ignore_patterns=[".git/**"]
    )
    scanned_names = [f.name for f in scanned]
    skipped_names = [f.name for f in skipped]

    assert "valid.py" in scanned_names
    assert "app.js" in scanned_names
    assert "HEAD" in skipped_names


# ==========================================
# 5. CLI Komutları Testleri
# ==========================================

def test_cli_version():
    """`aisast version` komutunun versiyon ve afişi bastığını doğrular."""
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert __version__ in result.stdout
    assert "Kararlı Sürüm" in result.stdout
    assert "Yiğit Ali Çolakoğlu" in result.stdout


def test_cli_help():
    """`aisast --help` komutunu test eder."""
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.stdout
    assert "init" in result.stdout
    assert "check-config" in result.stdout


def test_cli_check_config():
    """`aisast check-config` komutunu test eder."""
    result = runner.invoke(app, ["check-config"])
    assert result.exit_code == 0
    assert "Aktif Yapılandırma Parametreleri" in result.stdout


def test_cli_init(tmp_path: Path):
    """`aisast init` komutunun yapılandırma dosyalarını oluşturduğunu test eder."""
    result = runner.invoke(app, ["init", "--dir", str(tmp_path)])
    assert result.exit_code == 0
    assert (tmp_path / ".aisast.yaml").exists()
    assert (tmp_path / ".aisastignore").exists()


def test_cli_scan_dry_run(tmp_path: Path):
    """`aisast scan --dry-run` simülasyon modunu test eder."""
    (tmp_path / "sample.py").write_text("x = 1\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", "--dry-run", str(tmp_path)])
    assert result.exit_code == 0
    assert "DRY-RUN (Simülasyon Modu)" in result.stdout
    assert "Taranacak Dosya Sayısı: 1" in result.stdout


def test_cli_scan_json_output(tmp_path: Path):
    """`aisast scan` JSON format çıktısının geçerliliğini test eder."""
    (tmp_path / "test.py").write_text("x = 42\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["target_path"] == str(tmp_path.resolve())
    assert "findings" in data
    assert "metrics" in data
    assert "summary" in data


def test_cli_scan_sarif_output(tmp_path: Path):
    """`aisast scan` SARIF format çıktısının geçerliliğini test eder."""
    (tmp_path / "test.py").write_text("x = 42\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", str(tmp_path), "--format", "sarif"])
    assert result.exit_code == 0
    sarif = json.loads(result.stdout)
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "aisast"
