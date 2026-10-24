"""Layer 1: Deterministik Sır, API Anahtarı & Shannon Entropi Avcısı ve Gizlilik Maskeleme Motoru.

Bu katman, kaynak kod ve yapılandırma dosyalarında gömülü API anahtarları, bulut kimlik
bilgileri, özel anahtarlar (Private Keys), JWT token'ları ve yüksek entropili sırları
milisaniyeler içinde yerel olarak tespit eder ve gizlilik maskelemesi (redaction) uygular.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass
import math
from pathlib import Path
import re
from typing import Any, Sequence
import yaml

from aisast.config import Layer1Config
from aisast.layers import BaseScanLayer
from aisast.models import (
    CodeLocation,
    ConfidenceLevel,
    Finding,
    Remediation,
    ScanLayer,
    ScannableFile,
    SeverityLevel,
    VulnerabilityCategory,
)


# ==========================================
# 1. Shannon Entropi Hesaplayıcısı
# ==========================================

def calculate_shannon_entropy(data: str) -> float:
    r"""Verilen karakter dizisinin Shannon entropisini bit cinsinden hesaplar (0.0 - 8.0).

    Matematiksel Formül:
        H(X) = -\sum_{i=1}^{n} P(x_i) \log_2 P(x_i)

    Args:
        data: Analiz edilecek karakter dizisi (string).

    Returns:
        Bit cinsinden Shannon entropi değeri (0.0 - 8.0). Boş string için 0.0 döner.
    """
    if not data:
        return 0.0

    length = len(data)
    counts = collections.Counter(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)

    return 0.0 if abs(entropy) < 1e-9 else float(entropy)


# ==========================================
# 2. Gizlilik Koruması & Maskeleme (Redaction)
# ==========================================

def mask_secret(secret: str, visible_prefix: int = 4, visible_suffix: int = 3) -> str:
    """Sırrı güvenli bir şekilde maskeler.

    - 8 veya daha az karakterli sırlarda tamamı maskelenir: "*" * len(secret)
    - 8 karakterden uzun sırlarda başta visible_prefix, sonda visible_suffix bırakılır,
      orta kısım 8 adet '*' ile gizlenir. (Örn: sk-proj-1234567890abcdef -> sk-p********def)

    Args:
        secret: Maskelenecek açık metin sır.
        visible_prefix: Başta açık bırakılacak karakter sayısı.
        visible_suffix: Sonda açık bırakılacak karakter sayısı.

    Returns:
        Maskelenmiş güvenli string.
    """
    if not secret:
        return ""
    if len(secret) <= 8 or len(secret) <= (visible_prefix + visible_suffix):
        return "*" * len(secret)
    return f"{secret[:visible_prefix]}{'*' * 8}{secret[-visible_suffix:]}"


def redact_line_snippet(line: str, secret: str) -> str:
    """Satır kod parçacığı içindeki açık metin sırrı maskelenmiş haliyle değiştirir."""
    if not line or not secret:
        return line
    masked = mask_secret(secret)
    return line.replace(secret, masked)


# ==========================================
# 3. Yanlış Pozitif Filtreleme Mekanizması
# ==========================================

KNOWN_PLACEHOLDERS = (
    "example",
    "placeholder",
    "your_api_key",
    "your-api-key",
    "your_key",
    "your-key",
    "your_token",
    "your-token",
    "your_password",
    "your-password",
    "changeme",
    "change_me",
    "todo",
    "fixme",
    "dummy",
    "sample",
    "test_key",
    "test-key",
    "xxxxxx",
    "mysecretkey",
    "replace_me",
    "insert_here",
)

UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

COMMON_FILE_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".html", ".htm", ".css", ".scss", ".json", ".yaml", ".yml",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".md", ".txt", ".tar",
    ".gz", ".zip", ".lock", ".toml", ".xml", ".csv", ".woff", ".woff2"
)


def is_likely_false_positive_secret(candidate: str, line: str = "") -> bool:
    """Aday sır değerinin sahte/örnek/yanlış pozitif olup olmadığını denetler.

    Filtrelenen durumlar:
    - Bilinen sahte/örnek kelimeler (placeholder, example, changeme, vb.)
    - Standart UUID formatları
    - Ortam değişkeni referansları (${...}, os.getenv, os.environ, process.env)
    - URL'ler (Slack webhook hariç) ve yerel dosya yolları (/usr/, C:\\, vb.)
    - Tamamen harflerden oluşan doğal dil kelimeleri / sınıf isimleri
    - Tekrar eden veya sıralı karakter dizileri
    """
    if not candidate or len(candidate) < 6:
        return True

    candidate_lower = candidate.lower()
    line_lower = line.lower() if line else ""

    # 1. Standart UUID formatı kontrolü
    if UUID_PATTERN.match(candidate):
        return True

    # 2. Ortam değişkeni referansları
    if candidate.startswith(("${", "$", "%")) or candidate.endswith("}"):
        return True
    if any(env_token in line_lower for env_token in ("os.getenv", "os.environ", "process.env", "system.getenv", "env[")):
        return True

    # 3. Bilinen sahte/örnek kelimeler
    for ph in KNOWN_PLACEHOLDERS:
        if ph in candidate_lower:
            return True

    # Sıralı/basit sayılar ve harfler
    if candidate_lower in ("123456", "12345678", "123456789", "1234567890", "abcdef", "abcdef123456"):
        return True
    if set(candidate_lower).issubset(set("123456")):
        return True
    if set(candidate_lower).issubset(set("abcdef")) and len(candidate) <= 12:
        return True

    # Tekrar eden karakterler (düşük çeşitlilik)
    if len(set(candidate)) <= 2:
        return True

    # 4. Dosya yolları ve genel URL'ler
    if candidate.startswith(("http://", "https://")):
        if not candidate.startswith("https://hooks.slack.com/services/"):
            return True
    if any(p in candidate_lower for p in ("/usr/", "/etc/", "/var/", "/home/", "/opt/", "c:\\", "d:\\")):
        return True
    if any(candidate_lower.endswith(ext) for ext in COMMON_FILE_EXTENSIONS):
        return True
    if candidate.count("/") >= 2 or candidate.count("\\") >= 2:
        return True

    # 5. Tamamen harflerden oluşan doğal dil kelimeleri / sınıf isimleri (rakam veya özel karakter yoksa)
    if candidate.isalpha():
        # Sadece küçük veya sadece büyük harf
        if candidate.islower() or candidate.isupper():
            return True
        # Karma harf (CamelCase) olsa bile rakam veya özel karakter (+, /, =, _, -) içermiyorsa
        return True

    return False


# ==========================================
# 4. Kural Kataloğu & Deterministik Desenler
# ==========================================

@dataclass(frozen=True)
class SecretRule:
    """Layer 1 deterministik sır kuralı veri yapısı."""
    rule_id: str
    title: str
    description: str
    pattern: re.Pattern[str]
    severity: SeverityLevel = SeverityLevel.CRITICAL
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    category: VulnerabilityCategory = VulnerabilityCategory.SECRET_LEAK
    cwe_id: str = "CWE-798"
    owasp_category: str = "A07:2021 - Identification and Authentication Failures"
    secret_group: int = 0


DEFAULT_SECRET_RULES: list[SecretRule] = [
    SecretRule(
        rule_id="SEC001",
        title="AWS Access Key ID Detected",
        description="Kaynak kodda açık AWS Access Key ID bulundu.",
        pattern=re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC002",
        title="AWS Secret Access Key Assignment Detected",
        description="Kaynak kodda açık AWS Secret Access Key ataması bulundu.",
        pattern=re.compile(r"(?i)(?:aws_secret_access_key|aws_secret_key|aws_secret|secret_access_key)\s*[:=]\s*[\"']([A-Za-z0-9/+=]{40})[\"']"),
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC003",
        title="OpenAI API Key Detected",
        description="Kaynak kodda açık OpenAI API anahtarı bulundu.",
        pattern=re.compile(r"\b(sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,})\b"),
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC004",
        title="Anthropic API Key Detected",
        description="Kaynak kodda açık Anthropic API anahtarı bulundu.",
        pattern=re.compile(r"\b(sk-ant-api03-[A-Za-z0-9_-]{20,})\b"),
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC005",
        title="Google Cloud / Gemini API Key Detected",
        description="Kaynak kodda açık Google Cloud / Gemini API anahtarı bulundu.",
        pattern=re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"),
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC006",
        title="GitHub Personal Access Token Detected",
        description="Kaynak kodda açık GitHub Token (PAT, OAuth, App) bulundu.",
        pattern=re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{22,})\b"),
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC007",
        title="Stripe API Secret / Restricted Key Detected",
        description="Kaynak kodda açık Stripe API anahtarı bulundu.",
        pattern=re.compile(r"\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,})\b"),
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC008",
        title="Slack Token & Webhook Detected",
        description="Kaynak kodda açık Slack Token veya Webhook URL bulundu.",
        pattern=re.compile(r"\b(xox[baprs]-[0-9a-zA-Z-]{10,48}|https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,})\b"),
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC009",
        title="Cryptographic Private Key Detected",
        description="Kaynak kodda açık kriptografik özel anahtar (Private Key) başlığı bulundu.",
        pattern=re.compile(r"(-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----)"),
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC010",
        title="JSON Web Token (JWT) Detected",
        description="Kaynak kodda açık JSON Web Token (JWT) bulundu.",
        pattern=re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"),
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.MEDIUM,
        category=VulnerabilityCategory.SECRET_LEAK,
        secret_group=1,
    ),
    SecretRule(
        rule_id="SEC011",
        title="Database Connection URI with Credentials Detected",
        description="Kimlik bilgisi içeren veritabanı bağlantı URI adresi bulundu.",
        pattern=re.compile(r"\b((?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s\"']+:(?:([^@\s\"']{3,}))@[^\s\"']+)\b"),
        severity=SeverityLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        category=VulnerabilityCategory.HARDCODED_CREDENTIAL,
        secret_group=2,
    ),
    SecretRule(
        rule_id="SEC012",
        title="Generic Hardcoded Secret / Password Assignment Detected",
        description="Değişken veya anahtar atamasında sabit kodlanmış parola/sır bulundu.",
        pattern=re.compile(r"(?i)\b(?:[a-z0-9_]*_)?(?:password|passwd|pwd|secret|api_key|apikey|access_token|auth_token|client_secret|private_key)\b\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']"),
        severity=SeverityLevel.HIGH,
        confidence=ConfidenceLevel.MEDIUM,
        category=VulnerabilityCategory.HARDCODED_CREDENTIAL,
        secret_group=1,
    ),
]


# ==========================================
# 5. Metin İçinde Toplu Sır Gizleme (Redaction)
# ==========================================

def redact_secrets_in_text(text: str, custom_replacement: str = "[REDACTED_SECRET]") -> str:
    """Verilen metin içindeki tüm bilinen sırları ve yüksek entropili değerleri custom_replacement ile değiştirir.

    Layer 3 LLM gizlilik kalkanı için kullanılır.
    """
    if not text:
        return text

    redacted = text

    # 1. Tanımlı deterministik kurallara göre değiştir
    for rule in DEFAULT_SECRET_RULES:
        def make_replacer(group_idx: int, rep: str):
            def _repl(m: re.Match[str]) -> str:
                full = m.group(0)
                try:
                    s = m.start(group_idx) - m.start(0)
                    e = m.end(group_idx) - m.start(0)
                    return full[:s] + rep + full[e:]
                except (IndexError, ValueError):
                    return rep
            return _repl

        redacted = rule.pattern.sub(make_replacer(rule.secret_group, custom_replacement), redacted)

    # 2. Yüksek entropili tırnak içi dizgeleri değiştir
    quoted_pattern = re.compile(r"""(["'])([A-Za-z0-9+/=_\-!@#$%^&*~]{20,})\1""")
    def _quoted_entropy_repl(m: re.Match[str]) -> str:
        quote = m.group(1)
        val = m.group(2)
        if val == custom_replacement:
            return m.group(0)
        if calculate_shannon_entropy(val) >= 4.5 and not is_likely_false_positive_secret(val):
            return f"{quote}{custom_replacement}{quote}"
        return m.group(0)

    redacted = quoted_pattern.sub(_quoted_entropy_repl, redacted)
    return redacted


# ==========================================
# 6. Satır İçi İhmal (Inline Ignore) Deseni
# ==========================================

INLINE_IGNORE_PATTERN = re.compile(
    r"(?:#|//|/\*)\s*(?:aisast:\s*ignore|nosec)\b",
    re.IGNORECASE,
)


# ==========================================
# 7. Layer 1 Sır Tarayıcısı Sınıfı
# ==========================================

class Layer1SecretScanner(BaseScanLayer):
    """Layer 1 Sır ve Kimlik Bilgisi Tarayıcısı.

    Deterministik Regex Katalogları, Shannon Entropisi ve Gizlilik Maskeleme Motoru.
    """

    def __init__(self, config: Layer1Config | None = None) -> None:
        self.config = config or Layer1Config()
        self.rules: list[SecretRule] = []

        if self.config.detect_common_tokens:
            self.rules.extend(DEFAULT_SECRET_RULES)

        if self.config.custom_rules_path:
            custom_rules = self._load_custom_rules(self.config.custom_rules_path)
            self.rules.extend(custom_rules)

    @property
    def name(self) -> str:
        return "Layer 1: Secrets & Entropy Scanner"

    @property
    def layer_type(self) -> ScanLayer:
        return ScanLayer.LAYER1_SECRETS

    def _load_custom_rules(self, path_str: str) -> list[SecretRule]:
        """Özel YAML kural dosyasından ek sır kurallarını yükler."""
        p = Path(path_str)
        if not p.is_file():
            return []

        try:
            with open(p, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
        except Exception:
            return []

        rules_data: list[dict[str, Any]] = []
        if isinstance(data, dict) and "rules" in data:
            rules_data = data["rules"]
        elif isinstance(data, list):
            rules_data = data

        loaded_rules: list[SecretRule] = []
        for item in rules_data:
            if not isinstance(item, dict):
                continue
            try:
                rule_id = str(item.get("rule_id", "CUSTOM_SEC"))
                title = str(item.get("title", "Custom Secret Detected"))
                description = str(item.get("description", "Özel kural ile tespit edilen sır."))
                pattern_str = item["pattern"]
                compiled_pat = re.compile(pattern_str, re.MULTILINE)
                sev_str = str(item.get("severity", "HIGH")).upper()
                conf_str = str(item.get("confidence", "HIGH")).upper()
                cat_str = str(item.get("category", "SECRET_LEAK")).upper()

                loaded_rules.append(
                    SecretRule(
                        rule_id=rule_id,
                        title=title,
                        description=description,
                        pattern=compiled_pat,
                        severity=SeverityLevel(sev_str),
                        confidence=ConfidenceLevel(conf_str),
                        category=VulnerabilityCategory(cat_str),
                        cwe_id=str(item.get("cwe_id", "CWE-798")),
                        owasp_category=str(item.get("owasp_category", "A07:2021 - Identification and Authentication Failures")),
                        secret_group=int(item.get("secret_group", 0)),
                    )
                )
            except Exception:
                continue
        return loaded_rules

    def _is_line_ignored(self, line: str) -> bool:
        """Satırın inline ignore (# aisast: ignore, # nosec, vb.) içerip içermediğini kontrol eder."""
        return bool(INLINE_IGNORE_PATTERN.search(line))

    def _create_remediation(self, rule_id: str, title: str) -> Remediation:
        """Kurala özgü iyileştirme ve düzeltme önerisi oluşturur."""
        return Remediation(
            description=(
                "Açık metin sırrı/kimlik bilgisini derhal kaynak koddan kaldırın ve "
                ".env dosyasına veya işletim sistemi ortam değişkenlerine (Environment Variables) taşıyın. "
                "Sızmış olan anahtarı derhal ilgili servis konsolundan iptal edin (rotate)."
            ),
            code_snippet=(
                "# Güvenli Kullanım Örneği:\n"
                "import os\n"
                'secret_value = os.getenv("API_KEY")\n'
            ),
            references=[
                "https://cwe.mitre.org/data/definitions/798.html",
                "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            ],
        )

    def scan_line(
        self,
        line: str,
        line_no: int,
        file_path_str: str,
    ) -> list[Finding]:
        """Tek bir kod satırını sırlar ve entropi anomalileri için analiz eder."""
        if self._is_line_ignored(line):
            return []

        findings: list[Finding] = []
        matched_secrets: set[str] = set()
        matched_spans: list[tuple[int, int]] = []

        # 1. Aşama: Belirli Regex Kuralları (SEC001 - SEC011 ve Özel Kurallar)
        specific_rules = [r for r in self.rules if r.rule_id != "SEC012"]
        for rule in specific_rules:
            for match in rule.pattern.finditer(line):
                try:
                    secret = match.group(rule.secret_group)
                except (IndexError, ValueError):
                    secret = match.group(0)

                if not secret:
                    continue

                # Bariz placeholder tespiti
                if any(ph in secret.lower() for ph in ("your_api_key", "your-api-key", "placeholder_key", "insert_here")):
                    continue

                matched_secrets.add(secret)
                try:
                    col_start = match.start(rule.secret_group) + 1
                    col_end = match.end(rule.secret_group)
                except (IndexError, ValueError):
                    col_start = match.start(0) + 1
                    col_end = match.end(0)

                matched_spans.append((col_start, col_end))
                masked = mask_secret(secret)

                finding = Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=f"{rule.description} (Maskelenmiş: {masked})",
                    severity=rule.severity,
                    confidence=rule.confidence,
                    category=rule.category,
                    layer=ScanLayer.LAYER1_SECRETS,
                    location=CodeLocation(
                        file_path=file_path_str,
                        start_line=line_no,
                        end_line=line_no,
                        start_column=col_start,
                        end_column=col_end,
                        snippet=redact_line_snippet(line.strip(), secret),
                    ),
                    cwe_id=rule.cwe_id,
                    owasp_category=rule.owasp_category,
                    remediation=self._create_remediation(rule.rule_id, rule.title),
                    metadata={"masked_secret": masked, "rule_id": rule.rule_id},
                )
                findings.append(finding)

        # 2. Aşama: Genel Parola/Sır Ataması (SEC012)
        generic_rule = next((r for r in self.rules if r.rule_id == "SEC012"), None)
        if generic_rule:
            for match in generic_rule.pattern.finditer(line):
                secret = match.group(generic_rule.secret_group)
                if not secret:
                    continue

                # Zaten daha spesifik bir kural ile yakalandıysa mükerrer üretme
                if secret in matched_secrets:
                    continue

                if is_likely_false_positive_secret(secret, line):
                    continue

                matched_secrets.add(secret)
                col_start = match.start(generic_rule.secret_group) + 1
                col_end = match.end(generic_rule.secret_group)
                matched_spans.append((col_start, col_end))
                masked = mask_secret(secret)

                finding = Finding(
                    rule_id=generic_rule.rule_id,
                    title=generic_rule.title,
                    description=f"{generic_rule.description} (Maskelenmiş: {masked})",
                    severity=generic_rule.severity,
                    confidence=generic_rule.confidence,
                    category=generic_rule.category,
                    layer=ScanLayer.LAYER1_SECRETS,
                    location=CodeLocation(
                        file_path=file_path_str,
                        start_line=line_no,
                        end_line=line_no,
                        start_column=col_start,
                        end_column=col_end,
                        snippet=redact_line_snippet(line.strip(), secret),
                    ),
                    cwe_id=generic_rule.cwe_id,
                    owasp_category=generic_rule.owasp_category,
                    remediation=self._create_remediation(generic_rule.rule_id, generic_rule.title),
                    metadata={"masked_secret": masked, "rule_id": generic_rule.rule_id},
                )
                findings.append(finding)

        # 3. Aşama: Shannon Entropi Avcısı (SEC_ENTROPY_01)
        if self.config.entropy_threshold > 0:
            quoted_strings_pattern = re.compile(r"""["']([A-Za-z0-9+/=_\-!@#$%^&*~]{20,})["']""")
            for match in quoted_strings_pattern.finditer(line):
                candidate = match.group(1)

                # Zaten eşleşmiş bir sır ise mükerrer üretme
                if candidate in matched_secrets or any(candidate in s for s in matched_secrets):
                    continue

                col_start = match.start(1) + 1
                col_end = match.end(1)

                # Önceki eşleşen sütun aralıklarıyla çakışma kontrolü
                if any(cs <= col_start <= ce or cs <= col_end <= ce for cs, ce in matched_spans):
                    continue

                entropy = calculate_shannon_entropy(candidate)
                if entropy >= self.config.entropy_threshold:
                    if is_likely_false_positive_secret(candidate, line):
                        continue

                    masked = mask_secret(candidate)
                    finding = Finding(
                        rule_id="SEC_ENTROPY_01",
                        title="High-Entropy Secret Candidate",
                        description=(
                            f"Yüksek Shannon entropisine sahip potansiyel sır/token tespit edildi "
                            f"(Entropi: {entropy:.2f} >= {self.config.entropy_threshold:.2f}, Maskelenmiş: {masked})."
                        ),
                        severity=SeverityLevel.MEDIUM,
                        confidence=ConfidenceLevel.LOW,
                        category=VulnerabilityCategory.SECRET_LEAK,
                        layer=ScanLayer.LAYER1_SECRETS,
                        location=CodeLocation(
                            file_path=file_path_str,
                            start_line=line_no,
                            end_line=line_no,
                            start_column=col_start,
                            end_column=col_end,
                            snippet=redact_line_snippet(line.strip(), candidate),
                        ),
                        cwe_id="CWE-798",
                        owasp_category="A07:2021 - Identification and Authentication Failures",
                        remediation=Remediation(
                            description=(
                                "Yüksek rastgeleliğe (entropi) sahip bu dize bir şifreleme anahtarı, "
                                "oturum sırrı veya erişim belirteci olabilir. Kod tabanından kaldırıp "
                                "ortam değişkenlerine taşıyın."
                            ),
                            code_snippet=(
                                "# Güvenli Kullanım:\n"
                                "import os\n"
                                'secret_value = os.getenv("APP_SECRET")\n'
                            ),
                            references=["https://cwe.mitre.org/data/definitions/798.html"],
                        ),
                        metadata={"entropy": round(entropy, 2), "masked_secret": masked},
                    )
                    findings.append(finding)

        return findings

    def scan_path(
        self,
        target_path: Path,
        files: Sequence[Path],
        context: dict[str, Any] | None = None
    ) -> list[Finding]:
        """Dosyaları sırlar ve API anahtarları için tarar.

        - `--staged` diff kapsamında satır aralığı denetimi uygular.
        - Satır içi ignore ve false positive filtrelerini çalıştırır.
        - Tüm bulguları maskelenmiş snippet'lerle raporlar.
        """
        if not files:
            return []

        all_findings: list[Finding] = []
        scannable_map: dict[str, ScannableFile] = {}
        if context and "scannable_files" in context:
            scannable_map = context["scannable_files"]

        for file_path in files:
            p = file_path if isinstance(file_path, Path) else Path(file_path)
            if not p.is_file():
                continue

            # ScannableFile bağlamını ara
            p_str = str(p)
            p_resolved = str(p.resolve())
            scannable_file = scannable_map.get(p_str) or scannable_map.get(p_resolved)

            # Raporlama için göreceli yol belirleme
            try:
                rel_path = str(p.relative_to(target_path))
                if rel_path == ".":
                    rel_path = p.name
            except Exception:
                rel_path = scannable_file.relative_path if scannable_file else p.name

            try:
                content = p.read_text(encoding="utf-8", errors="replace")
            except Exception:
                continue

            for line_no, raw_line in enumerate(content.splitlines(), start=1):
                # Git diff --staged kapsam kontrolü
                if scannable_file and not scannable_file.is_line_in_scope(line_no):
                    continue

                line_findings = self.scan_line(
                    line=raw_line,
                    line_no=line_no,
                    file_path_str=rel_path,
                )
                all_findings.extend(line_findings)

        return all_findings
