"""Layer 3: AI / LLM Bağlamsal Doğrulama, Structured Output ve Otomatik Patch Motoru.

Bu katman, Layer 1 ve Layer 2'den gelen şüpheli güvenlik bulgularını
gizlilik korumalı (Double-Redaction) promptlar ile dış veya yerel LLM modellerine
(OpenAI, Gemini, Anthropic, Ollama) gönderir. Yanıtları Pydantic v2 tabanlı
AIVulnerabilityAssessment şemasıyla doğrular, yanlış pozitifleri eler,
ve zafiyetli satırlar için difflib tabanlı standart Unified Diff yama önerileri üretir.
"""

from __future__ import annotations

import difflib
import json
import logging
from pathlib import Path
import re
from typing import Any, Sequence

import httpx
from pydantic import ValidationError

from aisast.config import Layer3Config
from aisast.layers import BaseScanLayer
from aisast.layers.layer1_secrets import redact_secrets_in_text
from aisast.models import (
    AIVulnerabilityAssessment,
    ConfidenceLevel,
    Finding,
    Remediation,
    ScanLayer,
    SeverityLevel,
)

logger = logging.getLogger(__name__)


def build_verification_prompt(finding: Finding) -> tuple[str, str]:
    """Gizlilik korumalı (Double-Redaction) LLM doğrulama prompt'u üretir.

    Bulgunun hem kod parçacığı (snippet) hem de genişletilmiş kod bağlamı (context_window)
    gönderilmeden önce redact_secrets_in_text() fonksiyonundan geçirilerek olası tüm
    API anahtarları, parolalar ve tokenlar maskelenir.

    Returns:
        (system_prompt, user_prompt) demeti.
    """
    raw_snippet = finding.location.snippet or ""
    redacted_snippet = redact_secrets_in_text(raw_snippet)

    context_dict = finding.metadata.get("context_window", {})
    if isinstance(context_dict, dict) and context_dict.get("context_code"):
        raw_context = context_dict["context_code"]
    else:
        raw_context = raw_snippet

    redacted_context = redact_secrets_in_text(raw_context)

    system_prompt = (
        "Sen kıdemli bir Uygulama Güvenliği (AppSec) ve DevSecOps uzmanısın. "
        "Görevin, statik kod analizi (SAST) araçları tarafından tespit edilen şüpheli güvenlik bulgularını "
        "bağlamsal olarak incelemek, zafiyetin gerçek bir güvenlik tehdidi mi yoksa bir yanlış pozitif "
        "(False Positive) mi olduğunu değerlendirmek ve zafiyetli kod için güvenli bir yama önermektir.\n\n"
        "KURALLAR:\n"
        "1. Yanıtını KESİNLİKLE VE YALNIZCA geçerli bir JSON nesnesi olarak ver. Markdown kod bloğu dışında hiçbir "
        "ek metin, selamlama veya açıklama yazma.\n"
        "2. JSON nesnesi aşağıdaki şemaya harfiyen uymalıdır:\n"
        "{\n"
        '  "vulnerability_type": "Zafiyetin standart adı (örn: SQL Injection, Command Injection)",\n'
        '  "cwe_id": "İlgili CWE kimliği (örn: CWE-89, CWE-78)",\n'
        '  "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",\n'
        '  "line_number": <zafiyetli satır numarası - tamsayı>,\n'
        '  "explanation": "Zafiyetin nedeni, sömürülebilirlik analizi ve bağlamsal gerekçesi",\n'
        '  "secure_code_patch": "Zafiyetli satırı düzelten güvenli kod parçacığı (yalnızca düzeltilen kod)",\n'
        '  "false_positive_probability": <0.0 ile 1.0 arasında ondalık sayı (0.0: kesinlikle gerçek, 1.0: kesinlikle yanlış alarm)>\n'
        "}\n"
        "3. Eğer kod bağlamı incelendiğinde bulgunun güvenli olduğu (örn: parametreli sorgu kullanımı, "
        "güvenli kütüphane çağrısı, sanitize edilmiş girdi veya test kodu) anlaşılırsa, "
        "false_positive_probability değerini 0.75 veya üstü (örn: 0.85, 0.95, 1.0) olarak belirle.\n"
        "4. secure_code_patch alanında yalnızca değiştirilecek kod bloğunu/satırını ver, diff başlığı ekleme."
    )

    user_prompt = (
        "Lütfen aşağıdaki güvenlik bulgusunu ve çevreleyen kod bağlamını değerlendir:\n\n"
        f"- Dosya Yolu: {finding.location.file_path}\n"
        f"- Satır Numarası: {finding.location.start_line}\n"
        f"- Tetiklenen Kural: {finding.rule_id} ({finding.title})\n"
        f"- Zafiyet Kategorisi: {finding.category.value}\n"
        f"- CWE Kimliği: {finding.cwe_id or 'Belirtilmemiş'}\n\n"
        "Şüpheli Kod Parçacığı (Maskelenmiş):\n"
        "```\n"
        f"{redacted_snippet}\n"
        "```\n\n"
        "Genişletilmiş Kod Bağlamı (±5 Satır, Maskelenmiş):\n"
        "```\n"
        f"{redacted_context}\n"
        "```\n\n"
        "Lütfen bu bulguyu analiz ederek belirtilen JSON şemasında yanıt üret."
    )

    return system_prompt, user_prompt


def generate_unified_diff(
    original_code: str,
    patched_code: str,
    file_path: str,
    start_line: int = 1,
) -> str:
    """Orijinal kod parçacığı ile önerilen yama arasında standart Unified Diff metni üretir.

    Args:
        original_code: Zafiyetli orijinal kod satırı veya bloğu.
        patched_code: LLM tarafından önerilen güvenli kod parçacığı.
        file_path: İlgili dosya yolu (diff başlığında a/... ve b/... olarak görünür).
        start_line: Kodun başladığı satır numarası (bilgilendirme amaçlı).

    Returns:
        Standart Unified Diff çıktısı (örn: '--- a/app.py\n+++ b/app.py\n@@ ... @@\n- ...\n+ ...').
        Eğer yama boşsa veya orijinal kodla aynıysa boş string döner.
    """
    if not patched_code or not original_code:
        return ""
    if original_code.strip() == patched_code.strip():
        return ""

    # Satırların sonlarında newline olduğundan emin ol
    orig_lines = [line if line.endswith("\n") else line + "\n" for line in original_code.splitlines()]
    patch_lines = [line if line.endswith("\n") else line + "\n" for line in patched_code.splitlines()]

    # Dosya yolunu normalize et (Windows ters bölü işaretlerini / yap)
    norm_path = file_path.replace("\\", "/")

    diff_generator = difflib.unified_diff(
        orig_lines,
        patch_lines,
        fromfile=f"a/{norm_path}",
        tofile=f"b/{norm_path}",
        lineterm="\n",
    )
    diff_text = "".join(diff_generator)
    return diff_text


def parse_llm_json_response(raw_text: str) -> AIVulnerabilityAssessment:
    """LLM'den dönen ham yanıtı ayıklar, JSON olarak okur ve Pydantic v2 modeliyle doğrular.

    Markdown kod blokları (```json ... ```) veya ek çevreleyici karakterler temizlenir.
    """
    if not raw_text or not raw_text.strip():
        raise ValueError("LLM yanıtı boş geldi.")

    text = raw_text.strip()

    # 1. Markdown kod bloğu temizleme
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    # 2. JSON nesnesi sınırlarını yakalama ({ ve })
    start_idx = text.find("{")
    end_idx = text.rfind("}")
    if start_idx != -1 and end_idx != -1 and end_idx > start_idx:
        text = text[start_idx : end_idx + 1]

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"LLM yanıtı geçerli bir JSON formatında değil: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"LLM yanıtı bir JSON nesnesi (dict) değil: {type(data)}")

    try:
        return AIVulnerabilityAssessment.model_validate(data)
    except ValidationError as exc:
        raise ValueError(f"LLM çıktısı AIVulnerabilityAssessment şemasıyla uyuşmuyor: {exc}") from exc


class Layer3LLMVerifier(BaseScanLayer):
    """Layer 3: AI / LLM Destekli Bağlamsal Doğrulama ve Otomatik Yama Motoru."""

    def __init__(self, config: Layer3Config | None = None) -> None:
        self.config = config or Layer3Config()

    @property
    def name(self) -> str:
        return "Layer 3: AI / LLM Contextual Verifier"

    @property
    def layer_type(self) -> ScanLayer:
        return ScanLayer.LAYER3_LLM

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Yapılandırılmış sağlayıcıya (OpenAI, Gemini, Anthropic, Ollama) HTTP isteği gönderir."""
        provider = self.config.provider.lower().strip()
        timeout = self.config.timeout_seconds

        with httpx.Client(timeout=timeout) as client:
            if provider == "openai":
                url = self.config.base_url or "https://api.openai.com/v1/chat/completions"
                headers = {
                    "Authorization": f"Bearer {self.config.api_key or ''}",
                    "Content-Type": "application/json",
                }
                payload = {
                    "model": self.config.model,
                    "temperature": self.config.temperature,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                }
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return data["choices"][0]["message"]["content"]

            elif provider == "gemini":
                api_key = self.config.api_key or ""
                if self.config.base_url:
                    url = self.config.base_url
                else:
                    url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.config.model}:generateContent?key={api_key}"
                headers = {"Content-Type": "application/json"}
                payload = {
                    "systemInstruction": {"parts": [{"text": system_prompt}]},
                    "contents": [{"parts": [{"text": user_prompt}]}],
                    "generationConfig": {
                        "temperature": self.config.temperature,
                        "responseMimeType": "application/json",
                    },
                }
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]

            elif provider == "anthropic":
                url = self.config.base_url or "https://api.anthropic.com/v1/messages"
                headers = {
                    "x-api-key": self.config.api_key or "",
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                }
                payload = {
                    "model": self.config.model,
                    "max_tokens": 1024,
                    "system": system_prompt,
                    "messages": [{"role": "user", "content": user_prompt}],
                }
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return data["content"][0]["text"]

            elif provider in ("ollama", "local"):
                url = self.config.base_url or "http://localhost:11434/api/chat"
                headers = {"Content-Type": "application/json"}
                payload = {
                    "model": self.config.model,
                    "stream": False,
                    "format": "json",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                }
                response = client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                data = response.json()
                return data["message"]["content"]

            else:
                raise ValueError(
                    f"Desteklenmeyen LLM sağlayıcısı: '{self.config.provider}'. "
                    f"Desteklenenler: openai, gemini, anthropic, ollama"
                )

    def verify_candidates(
        self,
        candidates: list[Finding],
        context: dict[str, Any] | None = None
    ) -> list[Finding]:
        """Önceki katmanlardan gelen aday bulguları filtreler ve LLM ile doğrular."""
        if not self.config.enabled or not candidates:
            return candidates

        # 1. Hangi adayların LLM'e gönderileceğini belirle
        to_verify: list[Finding] = []
        for finding in candidates:
            if finding.layer == ScanLayer.LAYER1_SECRETS:
                if not self.config.verify_secrets:
                    finding.metadata["llm_status"] = "bypassed_deterministic_secret"
                    continue
                if finding.confidence == ConfidenceLevel.HIGH:
                    finding.metadata["llm_status"] = "bypassed_deterministic_secret"
                    continue
                to_verify.append(finding)
            else:
                to_verify.append(finding)

        # 2. API anahtarı denetimi
        provider_norm = self.config.provider.lower().strip()
        is_local_provider = provider_norm in ("ollama", "local")
        if not is_local_provider and not self.config.api_key:
            logger.info("Layer 3: API anahtarı tanımlanmadığı için LLM doğrulama atlandı.")
            for f in to_verify:
                f.metadata["llm_status"] = "skipped_no_api_key"
            return candidates

        # 3. max_candidates sınırını uygula
        max_limit = self.config.max_candidates
        targets = to_verify[:max_limit]
        skipped_over_limit = to_verify[max_limit:]
        for f in skipped_over_limit:
            f.metadata["llm_status"] = "skipped_candidate_limit"

        # 4. Hedef bulguları sırayla doğrula
        for finding in targets:
            try:
                system_prompt, user_prompt = build_verification_prompt(finding)
                raw_response = self._call_llm(system_prompt, user_prompt)
                assessment = parse_llm_json_response(raw_response)

                finding.verified_by_llm = True
                finding.llm_reasoning = assessment.explanation
                finding.severity = assessment.severity
                if assessment.cwe_id:
                    finding.cwe_id = assessment.cwe_id

                # Yanlış pozitif denetimi
                finding.is_false_positive = (
                    assessment.false_positive_probability >= self.config.fp_probability_threshold
                )

                # Unified Diff üretimi
                original_snippet = finding.location.snippet or ""
                diff_str = generate_unified_diff(
                    original_snippet,
                    assessment.secure_code_patch,
                    finding.location.file_path,
                    finding.location.start_line,
                )

                cwe_num = assessment.cwe_id.replace("CWE-", "").strip() if assessment.cwe_id else ""
                refs = [f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"] if cwe_num else []

                finding.remediation = Remediation(
                    description=assessment.explanation,
                    code_snippet=assessment.secure_code_patch,
                    diff=diff_str if diff_str else None,
                    references=refs,
                )

                finding.metadata["ai_assessment"] = assessment.model_dump()
                finding.metadata["false_positive_probability"] = assessment.false_positive_probability
                finding.metadata["llm_status"] = "verified"

            except Exception as exc:
                logger.warning(
                    "Layer 3 LLM doğrulama hatası (Bulgu ID: %s, Kural: %s): %s",
                    finding.id,
                    finding.rule_id,
                    exc,
                )
                finding.metadata["llm_status"] = f"error: {str(exc)}"
                finding.verified_by_llm = False

        return candidates

    def scan_path(
        self,
        target_path: Path,
        files: Sequence[Path],
        context: dict[str, Any] | None = None
    ) -> list[Finding]:
        """Aday bulguları LLM ile doğrular ve zenginleştirir."""
        if context and "candidates" in context:
            return self.verify_candidates(context["candidates"], context)
        return []


__all__ = [
    "Layer3LLMVerifier",
    "build_verification_prompt",
    "generate_unified_diff",
    "parse_llm_json_response",
]
