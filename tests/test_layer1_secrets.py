"""AI-SAST FAZ 2 Test Paketi: Layer 1 Sır & Entropi Avcısı ve Gizlilik Maskeleme Motoru.

Deterministik Regex Katalogları (12+ kural), Shannon Entropi Hesaplayıcısı,
Gizlilik Koruması (Maskeleme ve Redaction), False-Positive Filtreleri,
Inline Ignore, --staged Kapsam Uyumu ve Özel YAML Kural Testleri.
"""

from __future__ import annotations

from pathlib import Path
import pytest

from aisast.config import Layer1Config
from aisast.layers.layer1_secrets import (
    DEFAULT_SECRET_RULES,
    Layer1SecretScanner,
    SecretRule,
    calculate_shannon_entropy,
    is_likely_false_positive_secret,
    mask_secret,
    redact_line_snippet,
    redact_secrets_in_text,
)
from aisast.models import (
    ConfidenceLevel,
    LineRange,
    ScanLayer,
    ScannableFile,
    SeverityLevel,
    VulnerabilityCategory,
)


# ==========================================
# 1. Shannon Entropi Hesaplama Testleri
# ==========================================

def test_calculate_shannon_entropy_empty_and_uniform():
    """Boş string ve tek karakter tekrarının entropisi 0.0 olmalıdır."""
    assert calculate_shannon_entropy("") == 0.0
    assert calculate_shannon_entropy("aaaaaaaa") == 0.0
    assert calculate_shannon_entropy("11111111111111") == 0.0


def test_calculate_shannon_entropy_gradual_diversity():
    """Karakter çeşitliliği arttıkça entropi matematiksel olarak yükselmelidir."""
    low_ent = calculate_shannon_entropy("password123")
    assert 2.5 <= low_ent <= 3.8

    # Yüksek entropili rastgele token
    high_ent = calculate_shannon_entropy("4bC3!dE9@fG2#hI8$jK1%L0^mN5&oP7*")
    assert high_ent >= 4.5


# ==========================================
# 2. Gizlilik Koruması & Maskeleme Testleri
# ==========================================

def test_mask_secret_short_and_long():
    """mask_secret kısa ve uzun dizgileri kurallara göre güvenli maskelemelidir."""
    assert mask_secret("") == ""
    # 8 veya daha az karakter tamamı maskelenir
    assert mask_secret("12345678") == "********"
    assert mask_secret("abc") == "***"

    # Uzun sırlar: başından 4, sonundan 3 karakter, ortası 8 adet '*'
    raw_secret = "sk-proj-1234567890abcdef"
    masked = mask_secret(raw_secret, visible_prefix=4, visible_suffix=3)
    assert masked == "sk-p********def"
    assert "1234567890" not in masked


def test_redact_line_snippet():
    """redact_line_snippet satır içindeki sırrı açık metin bırakmadan maskelemelidir."""
    raw_line = '    api_key = "sk-proj-1234567890abcdef"'
    secret = "sk-proj-1234567890abcdef"
    snippet = redact_line_snippet(raw_line, secret)

    assert secret not in snippet
    assert "sk-p********def" in snippet
    assert 'api_key = "sk-p********def"' in snippet


def test_redact_secrets_in_text():
    """redact_secrets_in_text fonksiyonu metindeki tüm bilinen sırları [REDACTED_SECRET] ile temizlemelidir."""
    multiline_code = """
def initialize_clients():
    openai_key = "sk-proj-1234567890abcdef1234567890"
    aws_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    github_token = "ghp_1234567890abcdef1234567890abcdef1234"
    db_conn = "postgresql://dbuser:supersecretpass@localhost:5432/proddb"
    return True
"""
    clean_text = redact_secrets_in_text(multiline_code, custom_replacement="[REDACTED_SECRET]")

    assert "sk-proj-1234567890abcdef1234567890" not in clean_text
    assert "AKIAIOSFODNN7EXAMPLE" not in clean_text
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in clean_text
    assert "ghp_1234567890abcdef1234567890abcdef1234" not in clean_text
    assert "supersecretpass" not in clean_text
    assert "[REDACTED_SECRET]" in clean_text


# ==========================================
# 3. Deterministik Regex Kuralları Testleri (SEC001 - SEC012)
# ==========================================

@pytest.fixture
def scanner() -> Layer1SecretScanner:
    return Layer1SecretScanner(Layer1Config(enabled=True, entropy_threshold=4.5))


def test_rule_sec001_aws_access_key(scanner: Layer1SecretScanner):
    """SEC001: AWS Access Key ID tespiti ve maskelenmesi."""
    line = 'aws_access_key_id = "AKIA1234567890ABCDEF"'
    findings = scanner.scan_line(line, 1, "config.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC001"
    assert f.severity == SeverityLevel.CRITICAL
    assert f.confidence == ConfidenceLevel.HIGH
    assert "AKIA1234567890ABCDEF" not in f.location.snippet
    assert "AKIA********DEF" in f.location.snippet


def test_rule_sec002_aws_secret_key(scanner: Layer1SecretScanner):
    """SEC002: AWS Secret Access Key atama tespiti."""
    line = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    findings = scanner.scan_line(line, 10, "deploy.py")

    assert len(findings) >= 1
    f = next(item for item in findings if item.rule_id == "SEC002")
    assert f.severity == SeverityLevel.CRITICAL
    assert "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" not in f.location.snippet


def test_rule_sec003_openai_api_key(scanner: Layer1SecretScanner):
    """SEC003: OpenAI API Key (sk-proj-...) tespiti."""
    line = 'client = OpenAI(api_key="sk-proj-abc123xyz789000111222333444555")'
    findings = scanner.scan_line(line, 5, "ai_service.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC003"
    assert f.severity == SeverityLevel.CRITICAL
    assert "sk-proj-abc123xyz789000111222333444555" not in f.location.snippet
    assert "sk-p********555" in f.location.snippet


def test_rule_sec004_anthropic_api_key(scanner: Layer1SecretScanner):
    """SEC004: Anthropic API Key tespiti."""
    line = 'ANTHROPIC_KEY = "sk-ant-api03-abcdef1234567890abcdef12345"'
    findings = scanner.scan_line(line, 1, "settings.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC004"
    assert f.severity == SeverityLevel.CRITICAL
    assert "sk-ant-api03-abcdef1234567890abcdef12345" not in f.location.snippet


def test_rule_sec005_google_gemini_api_key(scanner: Layer1SecretScanner):
    """SEC005: Google Cloud / Gemini API Key tespiti."""
    line = 'const geminiKey = "AIzaSyD1234567890abcdef1234567890abcdef";'
    findings = scanner.scan_line(line, 15, "app.ts")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC005"
    assert f.severity == SeverityLevel.HIGH
    assert "AIzaSyD1234567890abcdef1234567890abcdef" not in f.location.snippet


def test_rule_sec006_github_tokens(scanner: Layer1SecretScanner):
    """SEC006: GitHub Token (ghp ve github_pat) tespiti."""
    line1 = 'gh_token = "ghp_1234567890abcdef1234567890abcdef1234"'
    line2 = 'fine_token = "github_pat_11AAAAAAA01234567890abcdef1234567890"'

    f1 = scanner.scan_line(line1, 1, "repo.py")
    assert len(f1) == 1
    assert f1[0].rule_id == "SEC006"
    assert "ghp_1234567890abcdef1234567890abcdef1234" not in f1[0].location.snippet

    f2 = scanner.scan_line(line2, 2, "repo.py")
    assert len(f2) == 1
    assert f2[0].rule_id == "SEC006"
    assert "github_pat_11AAAAAAA01234567890abcdef1234567890" not in f2[0].location.snippet


def test_rule_sec007_stripe_api_key(scanner: Layer1SecretScanner):
    """SEC007: Stripe Live / Test Secret Key tespiti."""
    dummy_stripe = "sk_" + "live_1234567890abcdef12345678"
    line = f'stripe.api_key = "{dummy_stripe}"'
    findings = scanner.scan_line(line, 8, "billing.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC007"
    assert f.severity == SeverityLevel.CRITICAL
    assert dummy_stripe not in f.location.snippet


def test_rule_sec008_slack_token_and_webhook(scanner: Layer1SecretScanner):
    """SEC008: Slack Token ve Webhook URI tespiti."""
    dummy_slack = "xox" + "b-1234567890-abcdefghijklmnop"
    dummy_hook = "https://" + "hooks." + "slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx"
    line1 = f'slack_token = "{dummy_slack}"'
    line2 = f'webhook = "{dummy_hook}"'

    f1 = scanner.scan_line(line1, 1, "alert.py")
    assert len(f1) == 1
    assert f1[0].rule_id == "SEC008"

    f2 = scanner.scan_line(line2, 2, "alert.py")
    assert len(f2) == 1
    assert f2[0].rule_id == "SEC008"


def test_rule_sec009_cryptographic_private_key(scanner: Layer1SecretScanner):
    """SEC009: Özel anahtar (Private Key) başlığı tespiti."""
    line = "-----BEGIN RSA PRIVATE KEY-----"
    findings = scanner.scan_line(line, 1, "id_rsa")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC009"
    assert f.severity == SeverityLevel.CRITICAL


def test_rule_sec010_jwt_token(scanner: Layer1SecretScanner):
    """SEC010: JSON Web Token (JWT) tespiti."""
    raw_jwt = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ."
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    )
    line = f'auth_header = "Bearer {raw_jwt}"'
    findings = scanner.scan_line(line, 12, "auth.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC010"
    assert f.severity == SeverityLevel.HIGH
    assert raw_jwt not in f.location.snippet


def test_rule_sec011_database_connection_uri(scanner: Layer1SecretScanner):
    """SEC011: Kimlik bilgisi içeren veritabanı URI tespiti ve parola maskeleme."""
    line = 'DATABASE_URL = "postgresql://dbadmin:SuperSecretPass123!@localhost:5432/appdb"'
    findings = scanner.scan_line(line, 4, "db.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC011"
    assert f.severity == SeverityLevel.CRITICAL
    assert "SuperSecretPass123!" not in f.location.snippet
    assert "Supe********23!" in f.location.snippet


def test_rule_sec012_generic_password_assignment(scanner: Layer1SecretScanner):
    """SEC012: Değişken atamasında sabit parola tespiti."""
    line = 'admin_password = "K9#m$L2!zP8@wQ1?"'
    findings = scanner.scan_line(line, 20, "config.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC012"
    assert f.category == VulnerabilityCategory.HARDCODED_CREDENTIAL
    assert "K9#m$L2!zP8@wQ1?" not in f.location.snippet


# ==========================================
# 4. Yüksek Entropi ve False-Positive Testleri
# ==========================================

def test_sec_entropy_01_detection(scanner: Layer1SecretScanner):
    """SEC_ENTROPY_01: Belirli bir kurala uymayan yüksek entropili rastgele dize tespiti."""
    line = 'session_blob = "4bC3!dE9@fG2#hI8$jK1%L0^mN5&oP7*"'
    findings = scanner.scan_line(line, 7, "token.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "SEC_ENTROPY_01"
    assert f.severity == SeverityLevel.MEDIUM
    assert "4bC3!dE9@fG2#hI8$jK1%L0^mN5&oP7*" not in f.location.snippet


def test_false_positive_filtering_placeholders_uuids_and_env(scanner: Layer1SecretScanner):
    """Örnek değerler, UUID'ler ve os.getenv çağrıları yanlış pozitif olarak elenmelidir."""
    samples = [
        'password = "changeme_example"',
        'api_key = "your_api_key_here"',
        'test_secret = "sample_test_key_12345"',
        'uuid_id = "123e4567-e89b-12d3-a456-426614174000"',
        'token = os.getenv("GITHUB_TOKEN")',
        'api_key = os.environ.get("OPENAI_KEY")',
        'env_secret = "${DATABASE_PASSWORD}"',
        'class_name = "UserAuthenticationManagerControllerService"',
    ]

    for line in samples:
        findings = scanner.scan_line(line, 1, "test.py")
        assert len(findings) == 0, f"Yanlış pozitif üretildi: {line} -> {findings}"


def test_deduplication_between_regex_and_entropy(scanner: Layer1SecretScanner):
    """Spesifik bir regex kuralı eşleştiğinde aynı değer için mükerrer entropi bulgusu üretilmemelidir."""
    line = 'client_key = "sk-proj-1234567890abcdef1234567890"'
    findings = scanner.scan_line(line, 1, "main.py")

    # Yalnızca SEC003 üretilmeli; SEC012 veya SEC_ENTROPY_01 mükerrer olarak üretilmemelidir
    assert len(findings) == 1
    assert findings[0].rule_id == "SEC003"


# ==========================================
# 5. Satır İçi İhmal (Inline Ignore) Testleri
# ==========================================

def test_inline_ignore_comments(scanner: Layer1SecretScanner):
    """# aisast: ignore, # nosec veya // aisast: ignore içeren satırlar atlanmalıdır."""
    ignored_lines = [
        'aws_key = "AKIA1234567890ABCDEF" # aisast: ignore',
        'aws_key = "AKIA1234567890ABCDEF" # aisast:ignore',
        'openai_key = "sk-proj-1234567890abcdef1234567890" # nosec',
        f'stripe_key = "{"sk_" + "live_1234567890abcdef12345678"}" // aisast: ignore',
        'jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozS6tqT_example" /* aisast: ignore */',
    ]

    for line in ignored_lines:
        findings = scanner.scan_line(line, 1, "ignored.py")
        assert len(findings) == 0, f"İhmal satırı işlenmemeliydi: {line}"


# ==========================================
# 6. Dosya Düzeyi ve --staged Kapsam Testleri
# ==========================================

def test_staged_scope_filtering_in_scan_path(tmp_path: Path):
    """--staged modunda sadece changed_ranges içindeki satırlar taranmalıdır."""
    target_file = tmp_path / "credentials.py"
    target_file.write_text(
        """# Satır 1: Başlık
aws_old = "AKIA1111111111111111"
# Satır 3: Açıklama
# Satır 4: Açıklama
aws_new = "AKIA2222222222222222"
# Satır 6: Bitiş
""",
        encoding="utf-8",
    )

    scanner = Layer1SecretScanner()

    # Senaryo 1: Tam Tarama (staged_diff=False) -> 2 bulgu
    findings_full = scanner.scan_path(tmp_path, [target_file])
    assert len(findings_full) == 2

    # Senaryo 2: Staged Tarama (Sadece 5. satır değişti) -> Yalnızca 1 bulgu
    scannable = ScannableFile(
        path=target_file,
        relative_path="credentials.py",
        size_bytes=target_file.stat().st_size,
        line_count=6,
        is_staged_diff=True,
        changed_ranges=[LineRange(start_line=5, end_line=5)],
    )

    context = {
        "scannable_files": {str(target_file): scannable, str(target_file.resolve()): scannable}
    }

    findings_staged = scanner.scan_path(tmp_path, [target_file], context=context)
    assert len(findings_staged) == 1
    assert findings_staged[0].location.start_line == 5
    assert "AKIA2222222222222222" not in findings_staged[0].location.snippet


# ==========================================
# 7. Özel YAML Kural Dosyası Testi
# ==========================================

def test_custom_rules_yaml_loading(tmp_path: Path):
    """Özel YAML kural dosyasından tanımlanan kuralların yüklenip taranabilmesi."""
    rules_file = tmp_path / "custom_rules.yaml"
    rules_file.write_text(
        """
rules:
  - rule_id: "CORP_TOKEN_01"
    title: "Corporate Internal SSO Secret"
    description: "Şirket içi SSO gizli anahtarı tespit edildi."
    pattern: "(corp_sso_[A-Za-z0-9]{24})"
    severity: "CRITICAL"
    confidence: "HIGH"
    category: "SECRET_LEAK"
    secret_group: 1
""",
        encoding="utf-8",
    )

    cfg = Layer1Config(custom_rules_path=str(rules_file))
    scanner = Layer1SecretScanner(config=cfg)

    line = 'sso_auth = "corp_sso_abcdef1234567890abcdef12"'
    findings = scanner.scan_line(line, 1, "sso.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "CORP_TOKEN_01"
    assert f.title == "Corporate Internal SSO Secret"
    assert f.severity == SeverityLevel.CRITICAL
    assert "corp_sso_abcdef1234567890abcdef12" not in f.location.snippet
    assert "corp********f12" in f.location.snippet
