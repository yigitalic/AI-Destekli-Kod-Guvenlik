"""AI-SAST FAZ 4 Demo: Layer 3 Yapay Zeka Doğrulama ve Otomatik Unified Diff Üretimi."""

import json
import sys
from unittest.mock import patch

# Windows konsolunda UTF-8 çıktıyı garantiye al
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from aisast.config import Layer3Config
from aisast.layers.layer3_llm import Layer3LLMVerifier
from aisast.models import (
    CodeLocation,
    ConfidenceLevel,
    Finding,
    ScanLayer,
    SeverityLevel,
    VulnerabilityCategory,
)


def main():
    print("=" * 70)
    print("AI-SAST FAZ 4: Layer 3 AI Doğrulama & Otomatik Patch / Diff Demosu")
    print("=" * 70)

    # 1. Layer 2'den gelen şüpheli SQLi bulgusu
    original_code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    finding = Finding(
        rule_id="AST_SQLI_01",
        title="SQL Injection (Dynamic SQL Construction)",
        description="User input is directly interpolated into SQL query via f-string.",
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SQL_INJECTION,
        layer=ScanLayer.LAYER2_HEURISTICS,
        location=CodeLocation(
            file_path="src/api/users.py",
            start_line=42,
            end_line=42,
            snippet=original_code,
        ),
        cwe_id="CWE-89",
        metadata={
            "context_window": {
                "context_start_line": 37,
                "context_end_line": 47,
                "trigger_line": 42,
                "context_code": (
                    "def get_user_profile(user_id: str):\n"
                    "    # API anahtarı maskeleme denemesi: sk-proj-1234567890abcdef\n"
                    "    conn = db.get_connection()\n"
                    "    cursor = conn.cursor()\n"
                    f"    {original_code}\n"
                    "    return cursor.fetchone()\n"
                ),
            }
        },
    )

    print(f"\n[1] Girdi Bulgusu: {finding.rule_id} ({finding.title})")
    print(f"    Dosya: {finding.location.file_path}:{finding.location.start_line}")
    print(f"    Orijinal Kod: {finding.location.snippet}")
    print(f"    Doğrulanma Durumu (Öncesi): verified_by_llm={finding.verified_by_llm}")

    # 2. Layer 3 Yapılandırması
    config = Layer3Config(
        enabled=True,
        provider="openai",
        model="gpt-4o-mini",
        api_key="sk-demo-key",
        fp_probability_threshold=0.75,
    )
    verifier = Layer3LLMVerifier(config)

    # 3. LLM Structured Output yanıtı (Mock)
    mock_llm_assessment = {
        "vulnerability_type": "SQL Injection",
        "cwe_id": "CWE-89",
        "severity": "CRITICAL",
        "line_number": 42,
        "explanation": "f-string kullanılarak kullanıcı parametresi doğrudan sorgu içine gömülmüş. Bu durum kimlik doğrulama atlatma ve veri sızıntısına yol açabilir. Parametreli sorguya geçilmelidir.",
        "secure_code_patch": 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))',
        "false_positive_probability": 0.01,
    }

    with patch.object(verifier, "_call_llm", return_value=json.dumps(mock_llm_assessment)):
        verified_findings = verifier.verify_candidates([finding])

    res = verified_findings[0]
    print("\n[2] Layer 3 AI Analiz Sonuçları:")
    print(f"    Verified by LLM: {res.verified_by_llm}")
    print(f"    False Positive: {res.is_false_positive} (FP Olasılığı: {res.metadata.get('false_positive_probability')})")
    print(f"    Güncellenmiş Ciddiyet: {res.severity.value}")
    print(f"    LLM Açıklaması: {res.llm_reasoning}")
    print(f"    Önerilen Güvenli Yama: {res.remediation.code_snippet}")

    print("\n[3] Üretilen Standart Unified Diff:")
    print("-" * 50)
    print(res.remediation.diff)
    print("-" * 50)
    print("\n[BASARILI] FAZ 4 Layer 3 AI Dogrulama ve Patch Motoru basariyla calisti!")


if __name__ == "__main__":
    main()

