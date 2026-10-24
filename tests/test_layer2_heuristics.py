"""AI-SAST FAZ 3 Test Paketi: Layer 2 AST & Sezgisel Statik Analiz ve Bağlam Penceresi.

Aşağıdaki yetenekleri doğrular:
1. Python AST Analizi (ast.NodeVisitor):
   - AST_SQLI_01: f-string, %, + ve .format() ile SQL enjeksiyonu tespiti
   - Güvenli parametreli SQL sorgularında 0 Yanlış Pozitif (False Positive)
   - AST_CMD_01: os.system, os.popen ve subprocess.run(shell=True) tespiti (shell=False güvenli)
   - AST_EXEC_01: eval ve exec tespiti (ast.literal_eval güvenli)
   - AST_DESER_01: pickle ve yaml.load (SafeLoader'sız) tespiti (yaml.safe_load güvenli)
   - AST_CRYPTO_01: hashlib.md5 ve sha1 tespiti (usedforsecurity=False ve sha256 güvenli)
   - AST_TLS_01: requests/httpx verify=False ve ssl._create_unverified_context tespiti
   - AST_PATH_01: tempfile.mktemp ve request içeren dosya açma işlemleri
2. Çoklu Dil Sezgisel (Heuristic Regex) Kuralları:
   - HEUR_XSS_01, HEUR_SQLI_01, HEUR_CMD_01, HEUR_PATH_01, HEUR_CONF_01
3. Mükerrer (Duplicate) Önleme:
   - AST'nin bulduğu satır ve kategoride Heuristic kuralın mükerrer bulgu üretmemesi
4. Gizlilik Korumalı Bağlam Penceresi (extract_context_window):
   - +-5 satırlık kod bağlamı ve context_code içinde API anahtarlarının [REDACTED_SECRET] olarak maskelenmesi
5. Filtreler:
   - Satır içi ignore (# aisast: ignore, # nosec)
   - Git diff --staged kapsamı (ScannableFile.changed_ranges)
   - Ciddiyet eşiği (rule_severity_threshold)
6. Hata Toleransı:
   - SyntaxError içeren dosyalarda çökmeden heuristik taramaya devam etme
"""

from __future__ import annotations

from pathlib import Path
import pytest

from aisast.config import Layer2Config
from aisast.layers.layer2_heuristics import (
    HEURISTIC_RULES,
    Layer2HeuristicScanner,
    extract_context_window,
)
from aisast.models import (
    LineRange,
    ScannableFile,
    ScanLayer,
    SeverityLevel,
    VulnerabilityCategory,
)


@pytest.fixture
def default_scanner() -> Layer2HeuristicScanner:
    """Varsayılan Layer 2 tarayıcısını döner."""
    return Layer2HeuristicScanner(Layer2Config())


# ==========================================
# 1. AST_SQLI_01: SQL Injection & FP Önleme
# ==========================================

def test_ast_sqli_fstring(default_scanner: Layer2HeuristicScanner):
    """f-string ile birleştirilen SQL sorgusunu tespit eder."""
    code = 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")\n'
    findings = default_scanner.scan_code(code, file_path_str="app.py")
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "AST_SQLI_01"
    assert f.category == VulnerabilityCategory.SQL_INJECTION
    assert f.severity == SeverityLevel.CRITICAL
    assert f.cwe_id == "CWE-89"
    assert "f-string" in f.description


def test_ast_sqli_percent(default_scanner: Layer2HeuristicScanner):
    """% operatörü ile oluşturulan dinamik SQL sorgusunu tespit eder."""
    code = 'cursor.execute("SELECT * FROM users WHERE username = \'%s\'" % (uname,))\n'
    findings = default_scanner.scan_code(code, file_path_str="db.py")
    assert any(f.rule_id == "AST_SQLI_01" for f in findings)


def test_ast_sqli_format(default_scanner: Layer2HeuristicScanner):
    """.format() çağrısıyla oluşturulan dinamik SQL sorgusunu tespit eder."""
    code = 'cursor.execute("SELECT * FROM users WHERE id = {}".format(uid))\n'
    findings = default_scanner.scan_code(code, file_path_str="repo.py")
    assert any(f.rule_id == "AST_SQLI_01" for f in findings)


def test_ast_sqli_concat(default_scanner: Layer2HeuristicScanner):
    """+ operatörü ile birleştirilen SQL sorgusunu tespit eder."""
    code = 'cursor.execute("SELECT * FROM users WHERE name = " + user_input)\n'
    findings = default_scanner.scan_code(code, file_path_str="views.py")
    assert any(f.rule_id == "AST_SQLI_01" for f in findings)


def test_ast_sqli_dynamic_assignment(default_scanner: Layer2HeuristicScanner):
    """Doğrudan değişkene atanan dinamik SQL sorgusunu tespit eder."""
    code = 'sql_query = f"DELETE FROM sessions WHERE token = \'{token}\'"\n'
    findings = default_scanner.scan_code(code, file_path_str="auth.py")
    assert any(f.rule_id == "AST_SQLI_01" for f in findings)


def test_ast_sqli_parameterized_no_false_positive(default_scanner: Layer2HeuristicScanner):
    """Parametreli güvenli SQL sorgularında KESİNLİKLE bulgu üretmez (0 False Positive)."""
    safe_code = """
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
cursor.execute("SELECT * FROM users WHERE name = %s", (name,))
session.execute(text("SELECT * FROM products WHERE price > :price"), {"price": 100})
"""
    findings = default_scanner.scan_code(safe_code, file_path_str="safe_db.py")
    sqli_findings = [f for f in findings if f.category == VulnerabilityCategory.SQL_INJECTION]
    assert len(sqli_findings) == 0


# ==========================================
# 2. AST_CMD_01: OS Command Injection
# ==========================================

def test_ast_cmd_os_system(default_scanner: Layer2HeuristicScanner):
    """os.system ve os.popen çağrılarını yakalar."""
    code = """
import os
os.system("ping " + ip_address)
stream = os.popen(user_cmd)
"""
    findings = default_scanner.scan_code(code, file_path_str="cmd.py")
    cmd_findings = [f for f in findings if f.rule_id == "AST_CMD_01"]
    assert len(cmd_findings) == 2
    assert all(f.severity == SeverityLevel.CRITICAL for f in cmd_findings)
    assert all(f.cwe_id == "CWE-78" for f in cmd_findings)


def test_ast_cmd_subprocess_shell_true(default_scanner: Layer2HeuristicScanner):
    """subprocess.run(..., shell=True) kullanımını yakalar."""
    code = 'subprocess.run(f"cat {user_file}", shell=True)\n'
    findings = default_scanner.scan_code(code, file_path_str="runner.py")
    assert any(f.rule_id == "AST_CMD_01" for f in findings)


def test_ast_cmd_subprocess_safe_no_false_positive(default_scanner: Layer2HeuristicScanner):
    """subprocess.run(..., shell=False) veya argüman listeli güvenli çağrılarda bulgu üretmez."""
    code = """
import subprocess
subprocess.run(["ls", "-la", "/tmp"], check=True)
subprocess.run(["echo", "hello"], shell=False)
"""
    findings = default_scanner.scan_code(code, file_path_str="safe_runner.py")
    cmd_findings = [f for f in findings if f.rule_id == "AST_CMD_01"]
    assert len(cmd_findings) == 0


# ==========================================
# 3. AST_EXEC_01: eval / exec & literal_eval
# ==========================================

def test_ast_exec_eval_and_exec(default_scanner: Layer2HeuristicScanner):
    """eval() ve exec() çağrılarını yakalar."""
    code = """
result = eval(user_payload)
exec(f"def dynamic_{fn_name}(): pass")
"""
    findings = default_scanner.scan_code(code, file_path_str="calc.py")
    exec_findings = [f for f in findings if f.rule_id == "AST_EXEC_01"]
    assert len(exec_findings) == 2
    assert all(f.cwe_id == "CWE-95" for f in exec_findings)


def test_ast_exec_literal_eval_safe_no_false_positive(default_scanner: Layer2HeuristicScanner):
    """ast.literal_eval() güvenlidir, bulgu üretmez."""
    code = """
import ast
data = ast.literal_eval(safe_string)
"""
    findings = default_scanner.scan_code(code, file_path_str="safe_ast.py")
    assert len(findings) == 0


# ==========================================
# 4. AST_DESER_01: Insecure Deserialization
# ==========================================

def test_ast_deser_pickle_and_yaml_unsafe(default_scanner: Layer2HeuristicScanner):
    """pickle.loads() ve güvensiz yaml.load() çağrılarını yakalar."""
    code = """
import pickle
import yaml

obj = pickle.loads(raw_bytes)
cfg = yaml.load(yaml_str)
cfg_full = yaml.load(yaml_str, Loader=yaml.Loader)
"""
    findings = default_scanner.scan_code(code, file_path_str="loader.py")
    deser_findings = [f for f in findings if f.rule_id == "AST_DESER_01"]
    assert len(deser_findings) == 3
    assert all(f.cwe_id == "CWE-502" for f in deser_findings)
    assert all(f.severity == SeverityLevel.CRITICAL for f in deser_findings)


def test_ast_deser_safe_no_false_positive(default_scanner: Layer2HeuristicScanner):
    """yaml.safe_load() ve yaml.load(..., Loader=SafeLoader) güvenlidir, bulgu üretmez."""
    code = """
import yaml
d1 = yaml.safe_load(data)
d2 = yaml.load(data, Loader=yaml.SafeLoader)
d3 = yaml.load(data, Loader=SafeLoader)
"""
    findings = default_scanner.scan_code(code, file_path_str="safe_yaml.py")
    deser_findings = [f for f in findings if f.rule_id == "AST_DESER_01"]
    assert len(deser_findings) == 0


# ==========================================
# 5. AST_CRYPTO_01: Weak Cryptographic Hash
# ==========================================

def test_ast_crypto_md5_sha1(default_scanner: Layer2HeuristicScanner):
    """hashlib.md5(), hashlib.sha1() ve hashlib.new('md5') kullanımlarını yakalar."""
    code = """
import hashlib
h1 = hashlib.md5(b"secret").hexdigest()
h2 = hashlib.sha1(b"password").digest()
h3 = hashlib.new("md5")
"""
    findings = default_scanner.scan_code(code, file_path_str="crypto.py")
    crypto_findings = [f for f in findings if f.rule_id == "AST_CRYPTO_01"]
    assert len(crypto_findings) == 3
    assert all(f.cwe_id == "CWE-328" for f in crypto_findings)
    assert all(f.category == VulnerabilityCategory.WEAK_CRYPTO for f in crypto_findings)


def test_ast_crypto_safe_no_false_positive(default_scanner: Layer2HeuristicScanner):
    """hashlib.sha256() ve usedforsecurity=False parametresi güvenlidir."""
    code = """
import hashlib
good_hash = hashlib.sha256(b"data").hexdigest()
checksum = hashlib.md5(b"file_content", usedforsecurity=False).hexdigest()
good_new = hashlib.new("sha256")
"""
    findings = default_scanner.scan_code(code, file_path_str="safe_crypto.py")
    crypto_findings = [f for f in findings if f.rule_id == "AST_CRYPTO_01"]
    assert len(crypto_findings) == 0


# ==========================================
# 6. AST_TLS_01: Disabled SSL Verification
# ==========================================

def test_ast_tls_verify_false(default_scanner: Layer2HeuristicScanner):
    """requests.get(..., verify=False) ve ssl._create_unverified_context çağrılarını yakalar."""
    code = """
import requests
import ssl

ctx = ssl._create_unverified_context()
resp = requests.get("https://internal.corp", verify=False)
"""
    findings = default_scanner.scan_code(code, file_path_str="network.py")
    tls_findings = [f for f in findings if f.rule_id == "AST_TLS_01"]
    assert len(tls_findings) == 2
    assert all(f.cwe_id == "CWE-295" for f in tls_findings)
    assert all(f.severity == SeverityLevel.HIGH for f in tls_findings)


# ==========================================
# 7. AST_PATH_01: Path Traversal / Temp File
# ==========================================

def test_ast_path_traversal(default_scanner: Layer2HeuristicScanner):
    """tempfile.mktemp ve request içeren open() çağrılarını yakalar."""
    code = """
import tempfile
temp_name = tempfile.mktemp()
with open(request.args.get("file")) as f:
    data = f.read()
"""
    findings = default_scanner.scan_code(code, file_path_str="files.py")
    path_findings = [f for f in findings if f.rule_id == "AST_PATH_01"]
    assert len(path_findings) == 2


# ==========================================
# 8. Çoklu Dil Sezgisel (Heuristic) Kuralları
# ==========================================

def test_heuristic_xss(default_scanner: Layer2HeuristicScanner):
    """DOM XSS (.innerHTML, dangerouslySetInnerHTML) desenlerini yakalar."""
    js_code = """
document.getElementById("output").innerHTML = userInput;
const el = <div dangerouslySetInnerHTML={{ __html: rawHtml }} />;
document.write(untrusted);
"""
    findings = default_scanner.scan_code(js_code, file_path_str="component.jsx")
    xss_findings = [f for f in findings if f.rule_id == "HEUR_XSS_01"]
    assert len(xss_findings) >= 2
    assert all(f.category == VulnerabilityCategory.XSS for f in xss_findings)
    assert all(f.cwe_id == "CWE-79" for f in xss_findings)


def test_heuristic_sqli(default_scanner: Layer2HeuristicScanner):
    """JS / TS dosyalarında ham SQL dize birleştirmesini yakalar."""
    ts_code = 'const query = "SELECT * FROM accounts WHERE id = \'" + req.body.id + "\'";\n'
    findings = default_scanner.scan_code(ts_code, file_path_str="db.ts")
    assert any(f.rule_id == "HEUR_SQLI_01" for f in findings)


def test_heuristic_cmd(default_scanner: Layer2HeuristicScanner):
    """Node.js child_process.exec ve PHP shell_exec çağrılarını yakalar."""
    php_code = '<?php $output = shell_exec("ls -la " . $_GET["dir"]); ?>\n'
    findings = default_scanner.scan_code(php_code, file_path_str="index.php")
    assert any(f.rule_id == "HEUR_CMD_01" for f in findings)


def test_heuristic_path(default_scanner: Layer2HeuristicScanner):
    """Dosya okuma fonksiyonlarında req.query ve ../ desenini yakalar."""
    js_code = 'fs.readFile(req.query.filename, "utf8", (err, data) => {});\n'
    findings = default_scanner.scan_code(js_code, file_path_str="server.js")
    assert any(f.rule_id == "HEUR_PATH_01" for f in findings)


def test_heuristic_config(default_scanner: Layer2HeuristicScanner):
    """DEBUG=True ve Access-Control-Allow-Origin: * güvensiz yapılandırmalarını yakalar."""
    cfg_code = """
DEBUG = True
headers["Access-Control-Allow-Origin"] = "*"
"""
    findings = default_scanner.scan_code(cfg_code, file_path_str="settings.py")
    conf_findings = [f for f in findings if f.rule_id == "HEUR_CONF_01"]
    assert len(conf_findings) == 2


# ==========================================
# 9. AST - Heuristic Duplicate Önleme
# ==========================================

def test_ast_heuristic_no_duplicate(default_scanner: Layer2HeuristicScanner):
    """Aynı satır ve kategori için AST zaten bulgu ürettiyse Heuristic mükerrer bulgu üretmez."""
    code = 'cursor.execute("SELECT * FROM users WHERE name = \'" + user_input + "\'")\n'
    findings = default_scanner.scan_code(code, file_path_str="query.py")
    sqli_findings = [f for f in findings if f.category == VulnerabilityCategory.SQL_INJECTION]
    # Sadece 1 adet SQL Injection bulgusu olmalı (AST öncelikli)
    assert len(sqli_findings) == 1
    assert sqli_findings[0].rule_id == "AST_SQLI_01"


# ==========================================
# 10. Gizlilik Korumalı Bağlam Penceresi
# ==========================================

def test_context_window_and_redaction(default_scanner: Layer2HeuristicScanner):
    """Bağlam penceresinin +-5 satırı içerdiğini ve içindeki sırların [REDACTED_SECRET] olarak maskelendiğini doğrular."""
    lines = [
        "import os",
        "import requests",
        'OPENAI_API_KEY = "sk-proj-123456789012345678901234567890"',  # Maskelenmeli!
        "# Kullanıcı sorgu fonksiyonu",
        "def fetch_user(uid):",
        '    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',  # Tetikleyici satır 6
        "    return cursor.fetchone()",
        "",
        "def helper():",
        "    pass",
    ]
    code = "\n".join(lines)
    findings = default_scanner.scan_code(code, file_path_str="service.py")
    assert len(findings) == 1
    finding = findings[0]

    ctx = finding.metadata.get("context_window")
    assert ctx is not None
    assert ctx["trigger_line"] == 6
    assert ctx["context_start_line"] == 1  # 6 - 5 = 1
    assert ctx["context_end_line"] == 10   # 6 + 5 = 11 > 10 => 10

    # Gizlilik doğrulaması: OPENAI_API_KEY değeri maskelenmiş olmalı
    assert "sk-proj-123456789012345678901234567890" not in ctx["context_code"]
    assert "[REDACTED_SECRET]" in ctx["context_code"]


def test_extract_context_window_standalone():
    """extract_context_window yardımcı fonksiyonunu sınır durumlarıyla test eder."""
    lines = [f"line {i}" for i in range(1, 21)]
    # Ortada
    ctx = extract_context_window(lines, trigger_line=10, radius=3)
    assert ctx["context_start_line"] == 7
    assert ctx["context_end_line"] == 13
    assert ctx["trigger_line"] == 10

    # Başta (1. satır)
    ctx_start = extract_context_window(lines, trigger_line=1, radius=5)
    assert ctx_start["context_start_line"] == 1
    assert ctx_start["context_end_line"] == 6

    # Sonda (20. satır)
    ctx_end = extract_context_window(lines, trigger_line=20, radius=5)
    assert ctx_end["context_start_line"] == 15
    assert ctx_end["context_end_line"] == 20


# ==========================================
# 11. Filtreler: Satır İçi Ignore, Staged Scope, Severity
# ==========================================

def test_inline_ignore_filters(default_scanner: Layer2HeuristicScanner):
    """# aisast: ignore ve # nosec etiketli satırların göz ardı edildiğini doğrular."""
    code = """
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # aisast: ignore
os.system(user_cmd)  # nosec
document.getElementById("t").innerHTML = raw;  // aisast: ignore
"""
    findings = default_scanner.scan_code(code, file_path_str="ignored.py")
    assert len(findings) == 0


def test_staged_scope_filtering(default_scanner: Layer2HeuristicScanner):
    """Git diff --staged kapsamı dışındaki satırların taranmadığını doğrular."""
    code = (
        "# line 1: safe\n"
        'cursor.execute(f"SELECT * FROM t WHERE id = {x}")\n'  # Satır 2: Kapsam dışı
        "# line 3: safe\n"
        'os.system(cmd)\n'  # Satır 4: Kapsamda (LineRange 4-4)
        "# line 5: safe\n"
    )
    scannable = ScannableFile(
        path=Path("dummy.py"),
        relative_path="dummy.py",
        size_bytes=len(code),
        line_count=5,
        is_staged_diff=True,
        changed_ranges=[LineRange(start_line=4, end_line=4)],
    )

    findings = default_scanner.scan_code(code, file_path_str="dummy.py", scannable_file=scannable)
    assert len(findings) == 1
    assert findings[0].rule_id == "AST_CMD_01"
    assert findings[0].location.start_line == 4


def test_rule_severity_threshold():
    """rule_severity_threshold seviyesinin altındaki bulguların filtrelendiğini doğrular."""
    # Threshold = HIGH yapıldığında MEDIUM seviyesindeki AST_CRYPTO_01 filtrelenmeli
    config = Layer2Config(rule_severity_threshold=SeverityLevel.HIGH)
    scanner = Layer2HeuristicScanner(config=config)

    code = """
import hashlib
h = hashlib.md5(b"weak")  # MEDIUM -> Filtrelenmeli
cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # CRITICAL -> Raporlanmalı
"""
    findings = scanner.scan_code(code, file_path_str="thresh.py")
    assert len(findings) == 1
    assert findings[0].rule_id == "AST_SQLI_01"
    assert findings[0].severity == SeverityLevel.CRITICAL


# ==========================================
# 12. Hata Toleransı: SyntaxError
# ==========================================

def test_syntax_error_graceful_recovery(default_scanner: Layer2HeuristicScanner):
    """Geçersiz Python sözdizimine sahip dosyalarda çökmeden heuristik kurallarla devam eder."""
    invalid_py_code = """
def broken_syntax(
    # Eksik parantez ve bozuk sözdizim
DEBUG = True
"""
    findings = default_scanner.scan_code(invalid_py_code, file_path_str="broken.py")
    # AST hata vermesine rağmen heuristik DEBUG=True tespit edilmeli
    assert any(f.rule_id == "HEUR_CONF_01" for f in findings)


# ==========================================
# 13. scan_path ve scan_file Entegrasyonu
# ==========================================

def test_scan_path_integration(tmp_path: Path, default_scanner: Layer2HeuristicScanner):
    """scan_path fonksiyonunun diskteki dosyaları başarıyla taradığını doğrular."""
    vuln_file = tmp_path / "vuln.py"
    vuln_file.write_text(
        'import os\n'
        'def run_cmd(c):\n'
        '    os.system(c)\n',
        encoding="utf-8"
    )

    findings = default_scanner.scan_path(target_path=tmp_path, files=[vuln_file])
    assert len(findings) == 1
    assert findings[0].rule_id == "AST_CMD_01"
    assert findings[0].location.file_path == "vuln.py"
    assert findings[0].remediation is not None
    assert "subprocess" in findings[0].remediation.code_snippet
