"""FAZ 5 Birim ve Entegrasyon Testleri.

Rich Diff UI, Markdown & SARIF Raporlama, aisast init-hook pre-commit kurulumu
ve Docker/CI-CD paketleme doğrulama testleri.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from typer.testing import CliRunner

from aisast.cli import app
from aisast.models import (
    AIVulnerabilityAssessment,
    CodeLocation,
    ConfidenceLevel,
    Finding,
    Remediation,
    ScanLayer,
    ScanMetrics,
    ScanResult,
    ScanSummary,
    SeverityLevel,
    VulnerabilityCategory,
)
from aisast.reporting import (
    ConsoleReporter,
    JSONReporter,
    MarkdownReporter,
    SARIFReporter,
    export_report,
)
from aisast.scanner import ScanPipeline
from aisast.config import ScannerConfig

runner = CliRunner()


# ==========================================
# 1. ConsoleReporter ve Rich Diff Testleri
# ==========================================

def test_console_reporter_renders_active_and_filters_false_positive():
    """ConsoleReporter'ın aktif bulguları gösterdiğini ve LLM elenen yanlış pozitifleri ayırdığını doğrular."""
    loc = CodeLocation(file_path="src/api.py", start_line=12, end_line=12, snippet='eval("1 + 1")')
    active_finding = Finding(
        rule_id="AST_EXEC_01",
        title="Dinamik Kod Yürütme",
        description="eval kullanımı tespit edildi.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.OTHER,
        layer=ScanLayer.LAYER2_HEURISTICS,
        location=loc,
        remediation=Remediation(
            description="ast.literal_eval kullanın.",
            code_snippet="ast.literal_eval(data)",
        ),
    )
    fp_finding = Finding(
        rule_id="SEC_ENTROPY_01",
        title="Yüksek Entropi",
        description="Test amaçlı sahte veri.",
        severity=SeverityLevel.LOW,
        confidence=ConfidenceLevel.LOW,
        category=VulnerabilityCategory.SECRET_LEAK,
        layer=ScanLayer.LAYER1_SECRETS,
        location=loc,
        is_false_positive=True,
    )

    result = ScanResult(
        target_path="src/",
        findings=[active_finding, fp_finding],
        metrics=ScanMetrics(scanned_files=5, duration_seconds=0.45),
    )
    result.recalculate_summary()

    test_console = Console(record=True, width=120)
    reporter = ConsoleReporter(console=test_console)
    reporter.render(result, show_snippets=True)

    rendered_text = test_console.export_text()

    # Özet panelinde false positive sayısı görünmeli
    assert "AI Elenen Yanlış Pozitif: 1" in rendered_text
    # Aktif bulgu tabloda yer almalı
    assert "AST_EXEC_01" in rendered_text
    assert "Dinamik Kod Yürütme" in rendered_text
    # Diff ve yama detayları basılmalı
    assert "- Zafiyetli Kod:" in rendered_text
    assert "+ Güvenli Öneri:" in rendered_text
    assert "ast.literal_eval(data)" in rendered_text


def test_console_reporter_diff_panel():
    """Unified diff içeren bulguların Diff panelinde render edildiğini doğrular."""
    loc = CodeLocation(file_path="src/db.py", start_line=45, end_line=45)
    diff_patch = (
        "--- a/src/db.py\n"
        "+++ b/src/db.py\n"
        "@@ -45,1 +45,1 @@\n"
        "-query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "+cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
    )
    finding = Finding(
        rule_id="AST_SQLI_01",
        title="SQL Injection",
        description="f-string ile dinamik sorgu oluşturulmuş.",
        severity=SeverityLevel.CRITICAL,
        category=VulnerabilityCategory.SQL_INJECTION,
        layer=ScanLayer.LAYER2_HEURISTICS,
        location=loc,
        verified_by_llm=True,
        llm_reasoning="Kullanıcı girdisi doğrudan sorguya eklenmiş.",
        remediation=Remediation(
            description="Parametreli SQL sorgusu kullanın.",
            diff=diff_patch,
        ),
    )

    result = ScanResult(target_path="src/db.py", findings=[finding])
    result.recalculate_summary()

    test_console = Console(record=True, width=140)
    ConsoleReporter(console=test_console).render(result, show_snippets=True)
    out = test_console.export_text()

    assert "AST_SQLI_01" in out
    assert "CRITICAL" in out
    assert "Otomatik Yama (Unified Diff)" in out
    assert "SELECT * FROM users WHERE id = %s" in out
    assert "AI Değerlendirmesi:" in out
    assert "✓ AI" in out


def test_console_reporter_clean_scan():
    """Hiç bulgu olmadığında temiz tarama kutlamasını doğrular."""
    result = ScanResult(target_path="clean_repo/", findings=[])
    result.recalculate_summary()

    test_console = Console(record=True, width=100)
    ConsoleReporter(console=test_console).render(result)
    out = test_console.export_text()

    assert "Tebrikler" in out
    assert "0" in out


# ==========================================
# 2. MarkdownReporter Testleri
# ==========================================

def test_markdown_reporter_render():
    """MarkdownReporter'ın standart başlıkları, özet tablosunu ve bulgu detaylarını ürettiğini doğrular."""
    loc = CodeLocation(file_path="app.py", start_line=10, end_line=10, snippet="api_key = 'sk-12345'")
    finding = Finding(
        rule_id="SEC_OPENAI_KEY",
        title="OpenAI API Anahtarı İfşası",
        description="Kod içerisinde açık OpenAI anahtarı bulundu.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        layer=ScanLayer.LAYER1_SECRETS,
        location=loc,
        cwe_id="CWE-798",
        owasp_category="A07:2021-Identification and Authentication Failures",
        remediation=Remediation(
            description="Anahtarı ortam değişkeninden okuyun.",
            code_snippet="api_key = os.environ.get('OPENAI_API_KEY')",
            references=["https://cwe.mitre.org/data/definitions/798.html"],
        ),
    )

    result = ScanResult(
        target_path="./app.py",
        findings=[finding],
        metrics=ScanMetrics(scanned_files=1, total_lines_of_code=50, duration_seconds=0.12),
    )
    result.recalculate_summary()

    md_output = MarkdownReporter.render(result)

    assert "# 🛡️ AI-SAST Güvenlik Tarama Raporu" in md_output
    assert "## 📊 Ciddiyet Özeti" in md_output
    assert "| 🟠 **HIGH** | 1 |" in md_output
    assert "## 🛡️ Güvenlik Bulguları" in md_output
    assert "### 1. [HIGH] SEC_OPENAI_KEY: OpenAI API Anahtarı İfşası" in md_output
    assert "`app.py:10`" in md_output
    assert "`CWE-798`" in md_output
    assert "```python" in md_output
    assert "api_key = os.environ.get('OPENAI_API_KEY')" in md_output
    assert "<https://cwe.mitre.org/data/definitions/798.html>" in md_output


def test_markdown_reporter_diff_block():
    """MarkdownReporter'ın diff içeren bulgularda ```diff kod bloğu ürettiğini doğrular."""
    loc = CodeLocation(file_path="query.py", start_line=5, end_line=5)
    diff = "--- a/query.py\n+++ b/query.py\n@@ -5 +5 @@\n-db.execute(sql)\n+db.execute(sql, (p,))"
    finding = Finding(
        rule_id="AST_SQLI_01",
        title="SQL Injection",
        description="Dinamik sorgu.",
        severity=SeverityLevel.CRITICAL,
        category=VulnerabilityCategory.SQL_INJECTION,
        layer=ScanLayer.LAYER2_HEURISTICS,
        location=loc,
        remediation=Remediation(
            description="Parametreli sorgu.",
            diff=diff,
        ),
    )
    result = ScanResult(target_path=".", findings=[finding])
    result.recalculate_summary()

    md = MarkdownReporter.render(result)
    assert "```diff" in md
    assert "-db.execute(sql)" in md
    assert "+db.execute(sql, (p,))" in md


def test_markdown_reporter_empty_findings():
    """Bulgu olmadığında temiz rapor mesajı üretildiğini doğrular."""
    result = ScanResult(target_path=".", findings=[])
    result.recalculate_summary()

    md = MarkdownReporter.render(result)
    assert "Tebrikler!" in md
    assert "Herhangi bir aktif güvenlik açığı veya sır tespit edilmedi." in md


def test_export_report_formats(tmp_path: Path):
    """export_report fonksiyonunun json, sarif ve markdown formatlarını dosyaya kaydedebildiğini doğrular."""
    result = ScanResult(target_path="src/", findings=[])
    result.recalculate_summary()

    # JSON export
    json_path = tmp_path / "report.json"
    res_json = export_report(result, format_type="json", output_file=json_path)
    assert json_path.exists()
    assert json.loads(json_path.read_text(encoding="utf-8"))["target_path"] == "src/"
    assert res_json is not None

    # SARIF export
    sarif_path = tmp_path / "report.sarif"
    res_sarif = export_report(result, format_type="sarif", output_file=sarif_path)
    assert sarif_path.exists()
    assert json.loads(sarif_path.read_text(encoding="utf-8"))["version"] == "2.1.0"
    assert res_sarif is not None

    # Markdown export (markdown ve md takma adı)
    md_path = tmp_path / "report.md"
    res_md = export_report(result, format_type="markdown", output_file=md_path)
    assert md_path.exists()
    assert "# 🛡️ AI-SAST Güvenlik Tarama Raporu" in md_path.read_text(encoding="utf-8")
    assert res_md is not None

    md_alias_path = tmp_path / "report_alias.md"
    res_alias = export_report(result, format_type="md", output_file=md_alias_path)
    assert md_alias_path.exists()
    assert res_alias == res_md


# ==========================================
# 3. Zenginleştirilmiş SARIF v2.1.0 Testleri
# ==========================================

def test_sarif_remediation_and_help_enrichment():
    """ScanResult.to_sarif_dict çıktısında rule 'help' ve result 'fixes/remediation' alanlarının yer aldığını doğrular."""
    loc = CodeLocation(file_path="service.py", start_line=20, end_line=20)
    diff = "--- a/service.py\n+++ b/service.py\n-cmd\n+safe_cmd"
    finding = Finding(
        rule_id="AST_CMD_01",
        title="Komut Enjeksiyonu",
        description="os.system güvensiz çağrıldı.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.COMMAND_INJECTION,
        layer=ScanLayer.LAYER2_HEURISTICS,
        location=loc,
        cwe_id="CWE-78",
        verified_by_llm=True,
        remediation=Remediation(
            description="subprocess.run shlex.split ile çalıştırın.",
            code_snippet="subprocess.run(['ls', '-la'])",
            diff=diff,
            references=["https://cwe.mitre.org/data/definitions/78.html"],
        ),
    )

    result = ScanResult(target_path="service.py", findings=[finding])
    sarif = result.to_sarif_dict()

    rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["id"] == "AST_CMD_01"
    assert "help" in rule
    assert "subprocess.run" in rule["help"]["text"]
    assert "Referanslar:" in rule["help"]["markdown"]

    res = sarif["runs"][0]["results"][0]
    assert res["ruleId"] == "AST_CMD_01"
    assert res["properties"]["verifiedByLLM"] is True
    assert "fixes" in res
    assert res["fixes"][0]["description"]["text"] == "subprocess.run shlex.split ile çalıştırın."
    assert res["fixes"][0]["properties"]["diff"] == diff
    assert res["properties"]["remediation"]["codeSnippet"] == "subprocess.run(['ls', '-la'])"


# ==========================================
# 4. aisast init-hook Pre-Commit Testleri
# ==========================================

def test_init_hook_in_non_git_directory_fails(tmp_path: Path):
    """Git deposu olmayan bir dizinde init-hook komutunun hata (exit code 1) verdiğini doğrular."""
    res = runner.invoke(app, ["init-hook", "--dir", str(tmp_path)])
    assert res.exit_code == 1
    assert "bir Git deposu değil" in res.stdout


def test_init_hook_creates_pre_commit_script(tmp_path: Path):
    """init-hook komutunun geçerli bir .git/hooks/pre-commit betiği oluşturduğunu doğrular."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir(parents=True)

    res = runner.invoke(app, ["init-hook", "--dir", str(tmp_path), "--fail-on", "HIGH"])
    assert res.exit_code == 0
    assert "Pre-Commit Hook Başarıyla Kuruldu" in res.stdout

    hook_path = git_dir / "hooks" / "pre-commit"
    assert hook_path.exists()
    assert hook_path.is_file()

    # LF (\n) satır sonu kontrolü (CRLF olmamalı)
    content_bytes = hook_path.read_bytes()
    assert b"\r\n" not in content_bytes
    assert b"\n" in content_bytes

    content = content_bytes.decode("utf-8")
    assert "#!/usr/bin/env sh" in content
    assert "aisast scan --staged --fail-on HIGH" in content
    assert "python -m aisast scan --staged --fail-on HIGH" in content
    assert "Commit güvenlik politikaları nedeniyle bloklandı" in content


def test_init_hook_with_ai_flag(tmp_path: Path):
    """init-hook --ai bayrağı verildiğinde betikte AI_ARG='--ai' yer aldığını doğrular."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir(parents=True)

    res = runner.invoke(app, ["init-hook", "--dir", str(tmp_path), "--ai", "--fail-on", "CRITICAL"])
    assert res.exit_code == 0

    hook_path = git_dir / "hooks" / "pre-commit"
    content = hook_path.read_text(encoding="utf-8")
    assert 'AI_ARG="--ai"' in content
    assert "CRITICAL" in content


def test_init_hook_without_force_preserves_existing(tmp_path: Path):
    """Var olan bir pre-commit dosyası varsa --force olmadan üzerine yazılmadığını doğrular."""
    git_dir = tmp_path / ".git"
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    existing_hook = hooks_dir / "pre-commit"
    existing_hook.write_text("#!/usr/bin/env sh\necho 'custom hook'\n", encoding="utf-8")

    res = runner.invoke(app, ["init-hook", "--dir", str(tmp_path)])
    assert res.exit_code == 0
    assert "zaten mevcut" in res.stdout

    # İçerik değişmemiş olmalı
    assert "echo 'custom hook'" in existing_hook.read_text(encoding="utf-8")


def test_init_hook_with_force_overwrites(tmp_path: Path):
    """--force bayrağı verildiğinde mevcut dosyanın üzerine yazıldığını doğrular."""
    git_dir = tmp_path / ".git"
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True)
    existing_hook = hooks_dir / "pre-commit"
    existing_hook.write_text("#!/usr/bin/env sh\necho 'custom hook'\n", encoding="utf-8")

    res = runner.invoke(app, ["init-hook", "--dir", str(tmp_path), "--force"])
    assert res.exit_code == 0
    assert "Pre-Commit Hook Başarıyla Kuruldu" in res.stdout

    content = existing_hook.read_text(encoding="utf-8")
    assert "aisast scan --staged" in content
    assert "custom hook" not in content


def test_init_hook_invalid_fail_on(tmp_path: Path):
    """Geçersiz --fail-on parametresi verildiğinde hata ile çıktığını doğrular."""
    git_dir = tmp_path / ".git"
    git_dir.mkdir(parents=True)

    res = runner.invoke(app, ["init-hook", "--dir", str(tmp_path), "--fail-on", "INVALID_SEV"])
    assert res.exit_code == 1
    assert "Geçersiz --fail-on değeri" in res.stdout


# ==========================================
# 5. Dockerfile ve .dockerignore Testleri
# ==========================================

def test_dockerfile_and_dockerignore_exist_and_valid():
    """Dockerfile ve .dockerignore dosyalarının geçerli yapılandırmaya sahip olduğunu doğrular."""
    root_dir = Path(__file__).resolve().parent.parent
    dockerfile = root_dir / "Dockerfile"
    dockerignore = root_dir / ".dockerignore"

    assert dockerfile.exists(), "Dockerfile kök dizinde mevcut olmalı"
    assert dockerignore.exists(), ".dockerignore kök dizinde mevcut olmalı"

    df_content = dockerfile.read_text(encoding="utf-8")
    assert "FROM python:3.11-slim" in df_content
    assert "apt-get install -y --no-install-recommends git" in df_content
    assert 'ENTRYPOINT ["aisast"]' in df_content
    assert 'CMD ["scan", "/workspace"]' in df_content

    di_content = dockerignore.read_text(encoding="utf-8")
    assert ".git" in di_content
    assert "__pycache__" in di_content
    assert ".venv" in di_content
    assert ".pytest_cache" in di_content


# ==========================================
# 6. CLI Scan --format markdown Testi
# ==========================================

def test_cli_scan_format_markdown(tmp_path: Path):
    """CLI üzerinden --format markdown ile çalıştığında standart Markdown çıktısı alındığını doğrular."""
    sample_file = tmp_path / "sample.py"
    sample_file.write_text("x = 1\n", encoding="utf-8")

    res = runner.invoke(app, ["scan", str(tmp_path), "--format", "markdown", "--no-ai"])
    assert res.exit_code == 0
    assert "# 🛡️ AI-SAST Güvenlik Tarama Raporu" in res.stdout
    assert "## 📊 Ciddiyet Özeti" in res.stdout


# ==========================================
# 7. Uçtan Uca (E2E) Tam Boru Hattı Testi
# ==========================================

def test_e2e_full_pipeline_multi_format_export(tmp_path: Path, monkeypatch):
    """Sır (Layer 1) ve SQLi (Layer 2) içeren geçici projede Mock AI ile tam tarama ve çoklu format dışa aktarımını doğrular."""
    vulnerable_py = tmp_path / "vulnerable_app.py"
    vulnerable_py.write_text(
        "# AI-SAST Test Dosyası\n"
        "import os\n"
        "OPENAI_API_KEY = 'sk-proj-1234567890abcdef1234567890abcdef12'\n"
        "def get_user(db, user_id):\n"
        "    query = f'SELECT * FROM users WHERE id = {user_id}'\n"
        "    return db.execute(query)\n",
        encoding="utf-8",
    )

    # Layer 3 mock LLM yanıtı
    mock_json_response = json.dumps({
        "vulnerability_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "CRITICAL",
        "line_number": 5,
        "explanation": "Bağlamsal analiz: f-string ile dinamik parametre enjekte edilmiş.",
        "secure_code_patch": "query = 'SELECT * FROM users WHERE id = %s'\n    return db.execute(query, (user_id,))",
        "false_positive_probability": 0.05,
    })

    monkeypatch.setattr(
        "aisast.layers.layer3_llm.Layer3LLMVerifier._call_llm",
        lambda self, sys_p, usr_p: mock_json_response,
    )

    cfg = ScannerConfig(
        target_path=str(tmp_path),
        layer1={"enabled": True},
        layer2={"enabled": True},
        layer3={"enabled": True, "api_key": "mock-test-key"},
    )

    pipeline = ScanPipeline(cfg)
    result = pipeline.run()

    # Hem Sır hem AST bulgusu tespit edilmeli
    rule_ids = [f.rule_id for f in result.findings if not f.is_false_positive]
    assert "AST_SQLI_01" in rule_ids
    assert any(rid.startswith("SEC") for rid in rule_ids)

    # SQLi bulgusu AI tarafından doğrulanmış ve diff yamasına sahip olmalı
    sqli_finding = next(f for f in result.findings if f.rule_id == "AST_SQLI_01")
    assert sqli_finding.verified_by_llm is True
    assert sqli_finding.remediation is not None
    assert sqli_finding.remediation.diff is not None

    # Çoklu format dışa aktarım testleri
    json_path = tmp_path / "out.json"
    sarif_path = tmp_path / "out.sarif"
    md_path = tmp_path / "out.md"

    export_report(result, format_type="json", output_file=json_path)
    export_report(result, format_type="sarif", output_file=sarif_path)
    export_report(result, format_type="markdown", output_file=md_path)

    assert json_path.exists()
    assert sarif_path.exists()
    assert md_path.exists()

    md_content = md_path.read_text(encoding="utf-8")
    assert "# 🛡️ AI-SAST Güvenlik Tarama Raporu" in md_content
    assert "```diff" in md_content
    assert "AST_SQLI_01" in md_content

    sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
    assert len(sarif_data["runs"][0]["results"]) >= 2
    rule_help = sarif_data["runs"][0]["tool"]["driver"]["rules"][0]["help"]
    assert "text" in rule_help
