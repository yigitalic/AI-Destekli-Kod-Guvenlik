"""AI-SAST Layer 3 (AI / LLM Zafiyet Analizi ve Otomatik Patch Motoru) Birim Testleri.

Bu test modülü, FAZ 4 kapsamında geliştirilen tüm Layer 3 bileşenlerini test eder:
- Pydantic v2 AIVulnerabilityAssessment doğrulama ve kısıtları
- Çift katmanlı gizlilik kalkanı (Double-Redaction Guarantee)
- Markdown blok temizleme ve Structured Output JSON ayrıştırma
- difflib tabanlı standart Unified Diff üretimi
- Multi-provider HTTP çağrıları (OpenAI, Gemini, Anthropic, Ollama)
- False-positive eleme eşiği ve ScanResult.recalculate_summary entegrasyonu
- Gerçek zafiyetler için remediation ve diff üretimi
- Graceful Degradation (Timeout, 500 hataları ve eksik API anahtarı toleransı)
- CLI seçenekleri (--ai, --no-ai, --provider, --model)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
from pydantic import ValidationError
import pytest
from typer.testing import CliRunner

from aisast.cli import app
from aisast.config import Layer3Config, ScannerConfig
from aisast.layers.layer3_llm import (
    Layer3LLMVerifier,
    build_verification_prompt,
    generate_unified_diff,
    parse_llm_json_response,
)
from aisast.models import (
    AIVulnerabilityAssessment,
    CodeLocation,
    ConfidenceLevel,
    Finding,
    ScanLayer,
    ScanResult,
    SeverityLevel,
    VulnerabilityCategory,
)
from aisast.scanner import ScanPipeline

runner = CliRunner()


def make_mock_http_response(
    status_code: int = 200,
    json_data: dict[str, Any] | None = None,
    text: str = "",
) -> httpx.Response:
    """Birim testler için sahte httpx.Response nesnesi üretir."""
    req = httpx.Request("POST", "https://api.mock-ai.com/test")
    if json_data is not None:
        return httpx.Response(status_code=status_code, json=json_data, request=req)
    return httpx.Response(status_code=status_code, text=text, request=req)


def make_sample_finding(
    rule_id: str = "AST_SQLI_01",
    title: str = "SQL Injection in execute()",
    category: VulnerabilityCategory = VulnerabilityCategory.SQL_INJECTION,
    layer: ScanLayer = ScanLayer.LAYER2_HEURISTICS,
    snippet: str = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    file_path: str = "src/users.py",
    start_line: int = 42,
    context_code: str = 'def get_user(user_id):\n    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n    return cursor.fetchone()',
) -> Finding:
    """Testler için örnek bulgu nesnesi üretir."""
    return Finding(
        rule_id=rule_id,
        title=title,
        description="User input is directly interpolated into SQL query.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        category=category,
        layer=layer,
        location=CodeLocation(
            file_path=file_path,
            start_line=start_line,
            end_line=start_line,
            snippet=snippet,
        ),
        cwe_id="CWE-89",
        metadata={
            "context_window": {
                "context_start_line": start_line - 1,
                "context_end_line": start_line + 1,
                "trigger_line": start_line,
                "context_code": context_code,
            }
        },
    )


# ==============================================================================
# 1. Pydantic v2 AIVulnerabilityAssessment Şema Testleri
# ==============================================================================

def test_ai_vulnerability_assessment_valid():
    """Geçerli veriyle AIVulnerabilityAssessment modelinin hatasız oluştuğunu doğrular."""
    data = {
        "vulnerability_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "CRITICAL",
        "line_number": 42,
        "explanation": "Kullanıcı girdisi doğrudan sorgu içine gömülmüş.",
        "secure_code_patch": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "false_positive_probability": 0.05,
    }
    assessment = AIVulnerabilityAssessment.model_validate(data)
    assert assessment.vulnerability_type == "SQL Injection"
    assert assessment.cwe_id == "CWE-89"
    assert assessment.severity == SeverityLevel.CRITICAL
    assert assessment.line_number == 42
    assert assessment.false_positive_probability == 0.05


def test_ai_vulnerability_assessment_invalid_fp_probability():
    """false_positive_probability [0.0, 1.0] aralığı dışındaysa ValidationError fırlatır."""
    base_data = {
        "vulnerability_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "line_number": 10,
        "explanation": "Test",
        "secure_code_patch": "safe_code()",
    }

    # 1.0'dan büyük
    with pytest.raises(ValidationError):
        AIVulnerabilityAssessment.model_validate({**base_data, "false_positive_probability": 1.1})

    # 0.0'dan küçük
    with pytest.raises(ValidationError):
        AIVulnerabilityAssessment.model_validate({**base_data, "false_positive_probability": -0.05})


def test_ai_vulnerability_assessment_invalid_line_number():
    """line_number 1'den küçükse (0 veya negatif) ValidationError fırlatır."""
    data = {
        "vulnerability_type": "Command Injection",
        "cwe_id": "CWE-78",
        "severity": "CRITICAL",
        "line_number": 0,
        "explanation": "Test",
        "secure_code_patch": "subprocess.run(['ls'])",
        "false_positive_probability": 0.1,
    }
    with pytest.raises(ValidationError):
        AIVulnerabilityAssessment.model_validate(data)


# ==============================================================================
# 2. Çift Katmanlı Gizlilik Kalkanı (Double-Redaction Guarantee)
# ==============================================================================

def test_build_verification_prompt_redacts_secrets():
    """Snippet ve context_code içindeki hassas sırların LLM prompt'una gitmeden maskelendiğini doğrular."""
    raw_api_key = "sk-proj-abc12345def67890ghijKLMNOPQRSTUV12345678"
    aws_secret = "AKIAIOSFODNN7EXAMPLE"

    finding = make_sample_finding(
        snippet=f'api_key = "{raw_api_key}"\ncursor.execute(query)',
        context_code=(
            f'def connect():\n'
            f'    aws_key = "{aws_secret}"\n'
            f'    api_key = "{raw_api_key}"\n'
            f'    cursor.execute(query)'
        ),
    )

    sys_prompt, user_prompt = build_verification_prompt(finding)

    # Açık metin sır kesinlikle prompt içinde olmamalı
    assert raw_api_key not in user_prompt
    assert aws_secret not in user_prompt
    assert "[REDACTED_SECRET]" in user_prompt
    assert "src/users.py" in user_prompt
    assert "AST_SQLI_01" in user_prompt


def test_build_verification_prompt_context_fallback():
    """Eğer metadata'da context_window yoksa snippet'e güvenli fallback yapıldığını doğrular."""
    finding = Finding(
        rule_id="HEUR_XSS_01",
        title="Cross-Site Scripting",
        description="Unescaped HTML rendering",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.MEDIUM,
        category=VulnerabilityCategory.XSS,
        layer=ScanLayer.LAYER2_HEURISTICS,
        location=CodeLocation(
            file_path="views/index.html",
            start_line=15,
            end_line=15,
            snippet="<div>${user_input}</div>",
        ),
        metadata={},  # context_window yok
    )

    sys_prompt, user_prompt = build_verification_prompt(finding)
    assert "<div>${user_input}</div>" in user_prompt
    assert "views/index.html" in user_prompt


# ==============================================================================
# 3. JSON Ayrıştırma ve Structured Output (parse_llm_json_response)
# ==============================================================================

def test_parse_llm_json_response_clean():
    """Temiz JSON metninin AIVulnerabilityAssessment nesnesine ayrıştırıldığını doğrular."""
    raw_json = json.dumps({
        "vulnerability_type": "Path Traversal",
        "cwe_id": "CWE-22",
        "severity": "HIGH",
        "line_number": 88,
        "explanation": "filename doğrulanmadan os.path.join ile birleştirilmiş.",
        "secure_code_patch": "safe_path = secure_filename(filename)",
        "false_positive_probability": 0.08,
    })
    assessment = parse_llm_json_response(raw_json)
    assert assessment.cwe_id == "CWE-22"
    assert assessment.line_number == 88
    assert assessment.false_positive_probability == 0.08


def test_parse_llm_json_response_markdown_code_block():
    """Markdown ```json ... ``` bloğuna sarılmış LLM yanıtının başarıyla ayıklandığını doğrular."""
    wrapped_text = """İşte yaptığım AppSec güvenlik değerlendirmesi:
```json
{
  "vulnerability_type": "Command Injection",
  "cwe_id": "CWE-78",
  "severity": "CRITICAL",
  "line_number": 105,
  "explanation": "os.system kullanıcı girdisiyle çalıştırılıyor.",
  "secure_code_patch": "subprocess.run(['ls', '-la', safe_arg], check=True)",
  "false_positive_probability": 0.02
}
```
Umarım yardımcı olmuştur."""
    assessment = parse_llm_json_response(wrapped_text)
    assert assessment.vulnerability_type == "Command Injection"
    assert assessment.severity == SeverityLevel.CRITICAL
    assert assessment.false_positive_probability == 0.02


def test_parse_llm_json_response_invalid_json():
    """Geçersiz JSON durumunda ValueError fırlatıldığını doğrular."""
    with pytest.raises(ValueError, match="geçerli bir JSON formatında değil"):
        parse_llm_json_response("Bu bir JSON nesnesi değildir.")

    with pytest.raises(ValueError, match="boş"):
        parse_llm_json_response("")


# ==============================================================================
# 4. Standart Unified Diff Üretimi (generate_unified_diff)
# ==============================================================================

def test_generate_unified_diff_basic():
    """Orijinal ve yamalanmış kod arasında standart unified diff üretildiğini doğrular."""
    orig = 'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")'
    patch = 'cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))'
    diff = generate_unified_diff(orig, patch, "src/db.py", start_line=12)

    assert "--- a/src/db.py" in diff
    assert "+++ b/src/db.py" in diff
    assert f"-{orig}" in diff
    assert f"+{patch}" in diff


def test_generate_unified_diff_identical_or_empty():
    """Yama orijinal kodla aynıysa veya boşsa boş string döndüğünü doğrular."""
    code = "x = calculate_hash(data)"
    assert generate_unified_diff(code, code, "hash.py") == ""
    assert generate_unified_diff(code, "", "hash.py") == ""
    assert generate_unified_diff("", "new_code()", "hash.py") == ""


# ==============================================================================
# 5. Çoklu Sağlayıcı LLM İstemcisi Testleri (OpenAI, Gemini, Anthropic, Ollama)
# ==============================================================================

def test_call_llm_openai_mock():
    """OpenAI sağlayıcısı için HTTP isteğinin ve cevabının doğru işlendiğini doğrular."""
    config = Layer3Config(enabled=True, provider="openai", model="gpt-4o-mini", api_key="sk-test")
    verifier = Layer3LLMVerifier(config)

    mock_resp = make_mock_http_response(
        status_code=200,
        json_data={
            "choices": [
                {
                    "message": {
                        "content": '{"vulnerability_type": "SQLi", "cwe_id": "CWE-89", "severity": "HIGH", "line_number": 5, "explanation": "test", "secure_code_patch": "patch()", "false_positive_probability": 0.1}'
                    }
                }
            ]
        },
    )

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        out = verifier._call_llm("sys", "user")
        assert "vulnerability_type" in out
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert "https://api.openai.com/v1/chat/completions" in args[0]
        assert "Bearer sk-test" in kwargs["headers"]["Authorization"]


def test_call_llm_gemini_mock():
    """Gemini sağlayıcısı için HTTP isteğinin ve cevabının doğru işlendiğini doğrular."""
    config = Layer3Config(enabled=True, provider="gemini", model="gemini-1.5-flash", api_key="gem-test")
    verifier = Layer3LLMVerifier(config)

    mock_resp = make_mock_http_response(
        status_code=200,
        json_data={
            "candidates": [
                {
                    "content": {
                        "parts": [{"text": '{"vulnerability_type": "XSS", "cwe_id": "CWE-79", "severity": "MEDIUM", "line_number": 10, "explanation": "xss", "secure_code_patch": "escape()", "false_positive_probability": 0.05}'}]
                    }
                }
            ]
        },
    )

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        out = verifier._call_llm("sys", "user")
        assert "vulnerability_type" in out
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert "generativelanguage.googleapis.com" in args[0]
        assert "gem-test" in args[0]


def test_call_llm_anthropic_mock():
    """Anthropic sağlayıcısı için HTTP isteğinin ve cevabının doğru işlendiğini doğrular."""
    config = Layer3Config(enabled=True, provider="anthropic", model="claude-3-5-sonnet", api_key="ant-test")
    verifier = Layer3LLMVerifier(config)

    mock_resp = make_mock_http_response(
        status_code=200,
        json_data={
            "content": [
                {"text": '{"vulnerability_type": "SSRF", "cwe_id": "CWE-918", "severity": "HIGH", "line_number": 20, "explanation": "ssrf", "secure_code_patch": "validate_url()", "false_positive_probability": 0.0}'}
            ]
        },
    )

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        out = verifier._call_llm("sys", "user")
        assert "vulnerability_type" in out
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert "https://api.anthropic.com/v1/messages" in args[0]
        assert kwargs["headers"]["x-api-key"] == "ant-test"


def test_call_llm_ollama_mock():
    """Ollama/Local sağlayıcısı için HTTP isteğinin ve cevabının doğru işlendiğini doğrular."""
    config = Layer3Config(enabled=True, provider="ollama", model="llama3:8b", base_url="http://localhost:11434/api/chat")
    verifier = Layer3LLMVerifier(config)

    mock_resp = make_mock_http_response(
        status_code=200,
        json_data={
            "message": {
                "content": '{"vulnerability_type": "Command Injection", "cwe_id": "CWE-78", "severity": "CRITICAL", "line_number": 33, "explanation": "shell=True", "secure_code_patch": "safe()", "false_positive_probability": 0.01}'
            }
        },
    )

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        out = verifier._call_llm("sys", "user")
        assert "vulnerability_type" in out
        mock_post.assert_called_once()
        args, kwargs = mock_post.call_args
        assert "http://localhost:11434/api/chat" in args[0]
        assert kwargs["json"]["format"] == "json"


def test_call_llm_unsupported_provider():
    """Bilinmeyen/desteklenmeyen bir sağlayıcı girildiğinde ValueError fırlatıldığını doğrular."""
    config = Layer3Config(enabled=True, provider="unknown_ai", api_key="test")
    verifier = Layer3LLMVerifier(config)

    with pytest.raises(ValueError, match="Desteklenmeyen LLM sağlayıcısı"):
        verifier._call_llm("sys", "user")


# ==============================================================================
# 6. Doğrulama Motoru Akışı (verify_candidates & Graceful Degradation)
# ==============================================================================

def test_verify_candidates_disabled():
    """Layer 3 devre dışıyken (enabled=False) adayların hiç değiştirilmeden döndüğünü doğrular."""
    verifier = Layer3LLMVerifier(Layer3Config(enabled=False))
    candidates = [make_sample_finding()]
    result = verifier.verify_candidates(candidates)
    assert result == candidates
    assert result[0].verified_by_llm is False


def test_verify_candidates_bypasses_deterministic_secrets():
    """Layer 1 sır bulgularının (verify_secrets=False iken) LLM'e gitmeden korunduğunu doğrular."""
    config = Layer3Config(enabled=True, provider="openai", api_key="sk-test", verify_secrets=False)
    verifier = Layer3LLMVerifier(config)

    secret_finding = Finding(
        rule_id="SEC001",
        title="AWS Access Key ID Found",
        description="Gömülü AWS anahtarı",
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        layer=ScanLayer.LAYER1_SECRETS,
        location=CodeLocation(file_path="config.py", start_line=5, end_line=5, snippet='AKIAIOSFODNN7EXAMPLE'),
    )

    with patch.object(verifier, "_call_llm") as mock_call:
        res = verifier.verify_candidates([secret_finding])
        mock_call.assert_not_called()
        assert res[0].metadata["llm_status"] == "bypassed_deterministic_secret"
        assert res[0].verified_by_llm is False


def test_verify_candidates_high_false_positive_flagging():
    """LLM false_positive_probability >= 0.75 verdiğinde bulgunun is_false_positive olarak işaretlendiğini doğrular."""
    config = Layer3Config(enabled=True, provider="openai", api_key="sk-test", fp_probability_threshold=0.75)
    verifier = Layer3LLMVerifier(config)

    finding = make_sample_finding()
    mock_llm_reply = json.dumps({
        "vulnerability_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "LOW",
        "line_number": 42,
        "explanation": "Bu kod bir test fikstürüdür ve girdi harici kullanıcıdan gelmemektedir; sahte alarm.",
        "secure_code_patch": finding.location.snippet,
        "false_positive_probability": 0.92,
    })

    with patch.object(verifier, "_call_llm", return_value=mock_llm_reply):
        result = verifier.verify_candidates([finding])
        f = result[0]
        assert f.verified_by_llm is True
        assert f.is_false_positive is True
        assert f.metadata["false_positive_probability"] == 0.92

        # ScanResult.recalculate_summary() ile özetten düşülmeli
        scan_res = ScanResult(target_path=".", findings=[f])
        summary = scan_res.recalculate_summary()
        assert summary.total_findings == 0


def test_verify_candidates_real_vulnerability_with_diff():
    """Gerçek zafiyet tespitinde yama ve unified diff'in başarıyla üretildiğini doğrular."""
    config = Layer3Config(enabled=True, provider="openai", api_key="sk-test", fp_probability_threshold=0.75)
    verifier = Layer3LLMVerifier(config)

    finding = make_sample_finding()
    mock_llm_reply = json.dumps({
        "vulnerability_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "CRITICAL",
        "line_number": 42,
        "explanation": "f-string doğrudan sorgu içine gömülmüş, acil parametreli sorguya geçilmeli.",
        "secure_code_patch": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "false_positive_probability": 0.01,
    })

    with patch.object(verifier, "_call_llm", return_value=mock_llm_reply):
        result = verifier.verify_candidates([finding])
        f = result[0]
        assert f.verified_by_llm is True
        assert f.is_false_positive is False
        assert f.severity == SeverityLevel.CRITICAL
        assert f.remediation is not None
        assert f.remediation.diff is not None
        assert "--- a/src/users.py" in f.remediation.diff
        assert "+++ b/src/users.py" in f.remediation.diff
        assert "+cursor.execute(" in f.remediation.diff
        assert len(f.remediation.references) > 0


def test_verify_candidates_network_error_graceful_degradation():
    """Ağ hatası veya zaman aşımı durumunda taramanın çökmediğini ve bulguları koruduğunu doğrular."""
    config = Layer3Config(enabled=True, provider="openai", api_key="sk-test")
    verifier = Layer3LLMVerifier(config)
    finding = make_sample_finding()

    with patch.object(verifier, "_call_llm", side_effect=httpx.TimeoutException("İstek zaman aşımına uğradı")):
        result = verifier.verify_candidates([finding])
        assert len(result) == 1
        assert result[0].verified_by_llm is False
        assert "error" in result[0].metadata["llm_status"]


def test_verify_candidates_no_api_key():
    """API anahtarı eksikken çökmeden skipped_no_api_key durumuna geçildiğini doğrular."""
    config = Layer3Config(enabled=True, provider="openai", api_key=None)
    verifier = Layer3LLMVerifier(config)
    finding = make_sample_finding()

    result = verifier.verify_candidates([finding])
    assert result[0].metadata["llm_status"] == "skipped_no_api_key"
    assert result[0].verified_by_llm is False


def test_verify_candidates_max_limit_applied():
    """max_candidates sınırını aşan bulguların skipped_candidate_limit olarak işaretlendiğini doğrular."""
    config = Layer3Config(enabled=True, provider="ollama", max_candidates=2)
    verifier = Layer3LLMVerifier(config)

    candidates = [
        make_sample_finding(file_path=f"src/test_{i}.py", start_line=i + 1)
        for i in range(5)
    ]

    mock_reply = json.dumps({
        "vulnerability_type": "SQLi",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "line_number": 1,
        "explanation": "valid",
        "secure_code_patch": "safe()",
        "false_positive_probability": 0.1,
    })

    with patch.object(verifier, "_call_llm", return_value=mock_reply):
        res = verifier.verify_candidates(candidates)
        # İlk 2 aday doğrulanmış olmalı
        assert res[0].verified_by_llm is True
        assert res[1].verified_by_llm is True
        # Kalan 3 aday sınır sebebiyle atlanmış olmalı
        assert res[2].metadata["llm_status"] == "skipped_candidate_limit"
        assert res[3].metadata["llm_status"] == "skipped_candidate_limit"
        assert res[4].metadata["llm_status"] == "skipped_candidate_limit"


# ==============================================================================
# 7. ScanPipeline & CLI Entegrasyon Testleri
# ==============================================================================

def test_scan_pipeline_l3_count_metric(tmp_path: Path):
    """ScanPipeline çalıştırıldığında l3_count metriğinin verified_by_llm=True olanları saydığını doğrular."""
    test_file = tmp_path / "app.py"
    test_file.write_text('cursor.execute(f"SELECT * FROM items WHERE name = {name}")', encoding="utf-8")

    cfg = ScannerConfig(
        target_path=str(tmp_path),
        layer1={"enabled": False},
        layer2={"enabled": True},
        layer3={"enabled": True, "provider": "ollama"},
    )

    mock_llm_reply = json.dumps({
        "vulnerability_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "HIGH",
        "line_number": 1,
        "explanation": "Doğrulandı",
        "secure_code_patch": 'cursor.execute("SELECT * FROM items WHERE name = %s", (name,))',
        "false_positive_probability": 0.05,
    })

    pipeline = ScanPipeline(cfg)
    with patch.object(pipeline.layer3, "_call_llm", return_value=mock_llm_reply):
        result = pipeline.run()
        assert result.metrics.layer3_findings >= 1
        assert any(f.verified_by_llm for f in result.findings)


def test_cli_ai_options(tmp_path: Path):
    """CLI üzerinden --ai, --no-ai, --provider, --model parametrelerinin tanındığını doğrular."""
    test_file = tmp_path / "clean.py"
    test_file.write_text("x = 10\nprint(x)", encoding="utf-8")

    res = runner.invoke(app, [
        "scan",
        str(tmp_path),
        "--ai",
        "--provider", "ollama",
        "--model", "llama3:8b",
        "--dry-run"
    ])
    assert res.exit_code == 0
    assert "DRY-RUN" in res.stdout
