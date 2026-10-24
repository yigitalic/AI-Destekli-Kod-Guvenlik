"""AI-SAST Komut Satırı Arayüzü (CLI).

Typer ve Rich kütüphaneleriyle güçlendirilmiş, modern, renkli ve
kullanıcı dostu terminal arayüzü.
"""

from __future__ import annotations

import os
from pathlib import Path
import sys
from typing import Optional

# Windows konsolunda UTF-8 desteğini etkinleştir
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
import typer

from aisast import __version__
from aisast.config import (
    DEFAULT_IGNORE_PATTERNS,
    ScannerConfig,
    load_config,
)
from aisast.models import SeverityLevel
from aisast.reporting import ConsoleReporter, export_report
from aisast.scanner import (
    GitScanError,
    ScanPipeline,
    discover_files,
    discover_scannable_files,
)

app = typer.Typer(
    name="aisast",
    help="AI Destekli Kod Güvenliği & Sır Tarayıcı CLI (AI-Powered SAST & Secret Scanner)",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()


BANNER = r"""[bold cyan]
     /\   |_   ____   /\    ____|__   
    /  \  | | / ___| /  \  / ___|  |  
   / /\ \ | | \___ \/ /\ \ \___ \  |  
  / ____ \| |  ___) / ____ \ ___) | |  
 /_/    \_\_| |____/_/    \_\____/  |_|
[/bold cyan]
[dim]AI Destekli Kod Güvenliği & Sır Tarayıcı CLI v{version}[/dim]
[dim]Geliştirici: Yiğit Ali Çolakoğlu | github.com/yigitalic[/dim]
""".format(version=__version__)


@app.command("version")
def version_command() -> None:
    """Yüklü aisast sürümünü ve mimari durumunu görüntüler."""
    console.print(BANNER)
    info_table = Table(show_header=False, box=None)
    info_table.add_row("[bold cyan]Versiyon:[/bold cyan]", f"[green]{__version__}[/green]")
    info_table.add_row("[bold cyan]Python Desteği:[/bold cyan]", "3.11+")
    info_table.add_row("[bold cyan]Mimari Fazı:[/bold cyan]", "[green]Kararlı Sürüm (v0.1.0 - Production Ready)[/green]")
    info_table.add_row("[bold cyan]Tarama Motoru:[/bold cyan]", "Aktif (Diff Hunk Parser, Ignore & Binary Filtresi)")
    info_table.add_row("[bold cyan]Layer 1 (Secrets):[/bold cyan]", "Aktif (12+ Regex Kuralı, Shannon Entropisi & Maskeleme)")
    info_table.add_row("[bold cyan]Layer 2 (Heuristics):[/bold cyan]", "Aktif (Python AST NodeVisitor, Çoklu Dil Regex & Maskeli Context Window)")
    info_table.add_row("[bold cyan]Layer 3 (AI/LLM):[/bold cyan]", "Aktif (Multi-Provider, Redaction Shield, Pydantic v2 Structured Output & Diff Motoru)")
    info_table.add_row("[bold cyan]Pre-Commit Hook:[/bold cyan]", "Aktif (`aisast init-hook` ile tek tıkla kurulum)")
    info_table.add_row("[bold cyan]Raporlama Formatları:[/bold cyan]", "Rich Console (Diff/Syntax), JSON, SARIF v2.1.0, Markdown")
    info_table.add_row("[bold cyan]Docker Desteği:[/bold cyan]", "Üretim Hazır (Dockerfile & .dockerignore)")
    console.print(Panel(info_table, title="[bold]Sistem Bilgileri[/bold]", border_style="blue"))


@app.command("init")
def init_command(
    directory: Path = typer.Option(
        Path("."),
        "--dir", "-d",
        help="Yapılandırma dosyalarının oluşturulacağı dizin."
    ),
    force: bool = typer.Option(
        False,
        "--force", "-f",
        help="Var olan dosyaların üzerine yaz."
    )
) -> None:
    """Varsayılan .aisast.yaml ve .aisastignore dosyalarını oluşturur."""
    target_dir = directory.resolve()
    target_dir.mkdir(parents=True, exist_ok=True)

    config_path = target_dir / ".aisast.yaml"
    ignore_path = target_dir / ".aisastignore"

    if config_path.exists() and not force:
        console.print(f"[yellow]Uyarı:[/] '{config_path}' zaten mevcut. Üzerine yazmak için --force kullanın.")
    else:
        default_cfg = ScannerConfig()
        config_path.write_text(default_cfg.to_yaml_string(), encoding="utf-8")
        console.print(f"[bold green]✓[/bold green] Yapılandırma oluşturuldu: [cyan]{config_path}[/cyan]")

    if ignore_path.exists() and not force:
        console.print(f"[yellow]Uyarı:[/] '{ignore_path}' zaten mevcut. Üzerine yazmak için --force kullanın.")
    else:
        ignore_content = "# aisast ignore file\n" + "\n".join(DEFAULT_IGNORE_PATTERNS) + "\n"
        ignore_path.write_text(ignore_content, encoding="utf-8")
        console.print(f"[bold green]✓[/bold green] İhmal listesi oluşturuldu: [cyan]{ignore_path}[/cyan]")


@app.command("init-hook")
def init_hook_command(
    directory: Path = typer.Option(
        Path("."),
        "--dir", "-d",
        help="Git deposunun bulunduğu kök dizin."
    ),
    fail_on: str = typer.Option(
        "HIGH",
        "--fail-on",
        help="Commit'i bloklayacak asgari ciddiyet seviyesi (CRITICAL, HIGH, MEDIUM, LOW)."
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Pre-commit sırasında Layer 3 AI doğrulamasını etkinleştir."
    ),
    force: bool = typer.Option(
        False,
        "--force", "-f",
        help="Mevcut pre-commit hook dosyasının üzerine yaz."
    ),
) -> None:
    """Git pre-commit hook betiğini kurarak commit öncesi güvenlik taramasını otomatikleştirir."""
    target_dir = directory.resolve()
    git_dir = target_dir / ".git"

    if not git_dir.exists() or not git_dir.is_dir():
        console.print(f"[bold red]Hata:[/] '{target_dir}' bir Git deposu değil (.git dizini bulunamadı).")
        raise typer.Exit(code=1)

    fail_on_upper = fail_on.upper()
    try:
        SeverityLevel(fail_on_upper)
    except ValueError:
        console.print(f"[bold red]Hata:[/] Geçersiz --fail-on değeri: {fail_on}. Seçenekler: CRITICAL, HIGH, MEDIUM, LOW")
        raise typer.Exit(code=1)

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hooks_dir / "pre-commit"

    if hook_path.exists() and not force:
        console.print(f"[yellow]Uyarı:[/] '{hook_path}' zaten mevcut. Üzerine yazmak için --force (-f) kullanın.")
        return

    ai_flag = "--ai" if ai else "--no-ai"

    # LF (\n) satır sonlarıyla POSIX shell betiği
    hook_content = f"""#!/usr/bin/env sh
# AI-SAST (aisast) Pre-Commit Security Hook
# Otomatik olarak 'aisast init-hook' tarafından oluşturulmuştur.
# Commit bekleyen (staged) değişiklikleri tarar ve güvenlik eşiğini aşan bulgu varsa commit'i engeller.

AI_ARG="{ai_flag}"

echo "[aisast] Staged dosyalar güvenlik taramasından geçiriliyor..."

if command -v aisast >/dev/null 2>&1; then
    aisast scan --staged --fail-on {fail_on_upper} $AI_ARG
    RET=$?
elif command -v python >/dev/null 2>&1; then
    python -m aisast scan --staged --fail-on {fail_on_upper} $AI_ARG
    RET=$?
elif command -v python3 >/dev/null 2>&1; then
    python3 -m aisast scan --staged --fail-on {fail_on_upper} $AI_ARG
    RET=$?
else
    echo "❌ [aisast] HATA: aisast veya python çalıştırılabilir dosyası bulunamadı!"
    exit 1
fi

if [ $RET -ne 0 ]; then
    echo ""
    echo "❌ [aisast] Commit güvenlik politikaları nedeniyle bloklandı!"
    echo "   Belirlenen eşik ({fail_on_upper}) veya üzerinde güvenlik zafiyeti / sır tespit edildi."
    echo "   Lütfen bulguları düzeltin veya acil durumlarda satır sonuna '# aisast: ignore' ekleyin."
    echo "   (Commit'i zorlamak için: git commit --no-verify)"
    exit $RET
fi

echo "✅ [aisast] Güvenlik taraması başarıyla geçti. Commit onaylandı."
exit 0
"""
    # Windows'ta da kesin LF (\n) garantisi
    hook_path.write_bytes(hook_content.replace("\r\n", "\n").encode("utf-8"))

    # Çalıştırma yetkisi ver (chmod +x)
    try:
        current_mode = os.stat(hook_path).st_mode
        os.chmod(hook_path, current_mode | 0o755)
    except Exception:
        pass

    info_table = Table(show_header=False, box=None)
    info_table.add_row("[bold cyan]Hook Konumu:[/bold cyan]", f"[green]{hook_path}[/green]")
    info_table.add_row("[bold cyan]Fail-On Eşiği:[/bold cyan]", f"[bold red]{fail_on_upper}[/bold red]")
    info_table.add_row("[bold cyan]Layer 3 (AI):[/bold cyan]", "[green]Aktif (--ai)[/green]" if ai else "[dim]Devre Dışı (--no-ai)[/dim]")
    info_table.add_row("[bold cyan]Tetikleyici:[/bold cyan]", "`git commit` (sadece staged diff)")

    console.print(Panel(info_table, title="[bold green]✓ Git Pre-Commit Hook Başarıyla Kuruldu[/bold green]", border_style="green"))


@app.command("check-config")
def check_config_command(
    config_file: Optional[Path] = typer.Option(
        None,
        "--config", "-c",
        help="Doğrulanacak konfigürasyon dosyasının yolu."
    )
) -> None:
    """Geçerli yapılandırmayı ve etkin kuralları denetler."""
    try:
        cfg = load_config(config_path=config_file)
        console.print("[bold green]✓ Yapılandırma başarıyla yüklendi ve doğrulandı![/bold green]\n")

        table = Table(title="[bold cyan]Aktif Yapılandırma Parametreleri[/bold cyan]")
        table.add_column("Bileşen", style="magenta")
        table.add_column("Parametre", style="cyan")
        table.add_column("Değer", style="white")

        table.add_row("Genel", "Hedef Yol", cfg.target_path)
        table.add_row("Genel", "İhmal Deseni Sayısı", str(len(cfg.ignore_patterns)))
        table.add_row("Genel", "Staged Modu (Git Diff)", "[yellow]Evet[/yellow]" if cfg.staged_only else "Hayır")
        table.add_row("Genel", ".gitignore Dikkate Al", "[green]Evet[/green]" if cfg.respect_gitignore else "[red]Hayır[/red]")

        table.add_row("Layer 1", "Etkin", "[green]Evet[/green]" if cfg.layer1.enabled else "[red]Hayır[/red]")
        table.add_row("Layer 1", "Entropi Eşiği", str(cfg.layer1.entropy_threshold))
        table.add_row("Layer 1", "Yaygın Token Tespiti", str(cfg.layer1.detect_common_tokens))

        table.add_row("Layer 2", "Etkin", "[green]Evet[/green]" if cfg.layer2.enabled else "[red]Hayır[/red]")
        table.add_row("Layer 2", "AST Analizi", str(cfg.layer2.enable_ast))
        table.add_row("Layer 2", "Sezgisel Analiz", str(cfg.layer2.enable_heuristics))

        table.add_row("Layer 3", "Etkin", "[green]Evet[/green]" if cfg.layer3.enabled else "[yellow]Hayır (Devre dışı)[/yellow]")
        table.add_row("Layer 3", "Sağlayıcı / Model", f"{cfg.layer3.provider} / {cfg.layer3.model}")
        table.add_row("Layer 3", "API Key Tanımlı", "[green]Evet[/green]" if cfg.layer3.api_key else "[dim]Hayır[/dim]")

        table.add_row("Raporlama", "Format", cfg.reporting.output_format)
        table.add_row("Raporlama", "Fail-On Eşiği", cfg.reporting.fail_on_severity.value if cfg.reporting.fail_on_severity else "Yok")

        console.print(table)
    except Exception as exc:
        console.print(f"[bold red]Hata:[/] Yapılandırma yüklenemedi: {exc}")
        raise typer.Exit(code=1)


@app.command("scan")
def scan_command(
    target: Path = typer.Argument(
        Path("."),
        help="Taranacak dizin veya dosya yolu."
    ),
    format_type: str = typer.Option(
        "rich",
        "--format", "-f",
        help="Çıktı formatı: rich, json, sarif, markdown (veya md)"
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Raporun kaydedileceği dosya yolu."
    ),
    layer1: Optional[bool] = typer.Option(
        None,
        "--layer1/--no-layer1",
        help="Layer 1 (Sır ve Regex) taramasını etkinleştir/devre dışı bırak."
    ),
    layer2: Optional[bool] = typer.Option(
        None,
        "--layer2/--no-layer2",
        help="Layer 2 (AST & Sezgisel) analizini etkinleştir/devre dışı bırak."
    ),
    layer3: Optional[bool] = typer.Option(
        None,
        "--layer3/--no-layer3",
        help="Layer 3 (AI / LLM) doğrulamasını etkinleştir/devre dışı bırak."
    ),
    no_ai: bool = typer.Option(
        False,
        "--no-ai",
        help="Layer 3 (AI/LLM) analizini devre dışı bırakır."
    ),
    ai: bool = typer.Option(
        False,
        "--ai",
        help="Layer 3 (AI/LLM) analizini etkinleştirir."
    ),
    provider: Optional[str] = typer.Option(
        None,
        "--provider",
        help="LLM sağlayıcısı: openai, gemini, anthropic, ollama"
    ),
    model: Optional[str] = typer.Option(
        None,
        "--model",
        help="Kullanılacak LLM model adı"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity", "-s",
        help="Görüntülenecek asgari ciddiyet seviyesi: CRITICAL, HIGH, MEDIUM, LOW, INFO"
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Belirtilen ciddiyette bulgu varsa CLI hata koduyla (2) çıkar: CRITICAL, HIGH, MEDIUM, LOW"
    ),
    config_file: Optional[Path] = typer.Option(
        None,
        "--config", "-c",
        help="Özel yapılandırma dosyası."
    ),
    staged: bool = typer.Option(
        False,
        "--staged",
        help="Sadece git diff --staged (commit bekleyen) değişiklikleri tara."
    ),
    gitignore: Optional[bool] = typer.Option(
        None,
        "--gitignore/--no-gitignore",
        help=".gitignore dosyasını dikkate al/alma."
    ),
    dry_run: bool = typer.Option(
        False,
        "--dry-run",
        help="Taramayı başlatmadan sadece hedeflenen ve atlanan dosyaları listeler."
    ),
) -> None:
    """Hedef kod tabanında güvenlik açıkları ve gömülü sırlar için hibrit tarama gerçekleştirir."""
    # CLI Overrides derleme
    overrides: dict[str, Any] = {"target_path": str(target)}

    if staged:
        overrides["staged_only"] = True
    if gitignore is not None:
        overrides["respect_gitignore"] = gitignore
    if layer1 is not None:
        overrides["layer1__enabled"] = layer1
    if layer2 is not None:
        overrides["layer2__enabled"] = layer2
    if no_ai:
        overrides["layer3__enabled"] = False
    elif ai:
        overrides["layer3__enabled"] = True
    elif layer3 is not None:
        overrides["layer3__enabled"] = layer3

    if provider:
        overrides["layer3__provider"] = provider
    if model:
        overrides["layer3__model"] = model

    if format_type:
        overrides["reporting__output_format"] = format_type
    if output:
        overrides["reporting__output_file"] = str(output)
    if fail_on:
        try:
            overrides["reporting__fail_on_severity"] = SeverityLevel(fail_on.upper())
        except ValueError:
            console.print(f"[bold red]Hata:[/] Geçersiz --fail-on değeri: {fail_on}. Seçenekler: CRITICAL, HIGH, MEDIUM, LOW")
            raise typer.Exit(code=1)

    cfg = load_config(config_path=config_file, overrides=overrides)

    # Dry-run modunda sadece dosya keşfi ve yapılandırmayı sun
    if dry_run:
        console.print(Panel("[bold yellow]DRY-RUN (Simülasyon Modu)[/bold yellow]\nHiçbir tarama motoru çalıştırılmayacak.", border_style="yellow"))
        try:
            scannable_files, skipped_files = discover_scannable_files(
                target_path=Path(cfg.target_path),
                config=cfg,
            )
        except GitScanError as exc:
            console.print(f"[bold red]Git Hatası:[/] {exc}")
            raise typer.Exit(code=1)

        console.print(f"[bold cyan]Hedef Yol:[/] {cfg.target_path}")
        console.print(f"[bold cyan]Tarama Modu:[/] {'[yellow]Git Diff (--staged)[/yellow]' if cfg.staged_only else 'Tam Tarama (Full Scan)'}")
        console.print(f"[bold cyan].gitignore Dikkate Al:[/] {'[green]Evet[/green]' if cfg.respect_gitignore else '[red]Hayır[/red]'}")
        console.print(f"[bold green]Taranacak Dosya Sayısı:[/] {len(scannable_files)}")
        console.print(f"[bold red]Atlanacak Dosya Sayısı:[/] {len(skipped_files)}")
        if scannable_files:
            console.print("\n[dim]Taranacak Dosyalar (İlk 10):[/dim]")
            for sf in scannable_files[:10]:
                if sf.is_staged_diff and sf.changed_ranges:
                    ranges_str = ", ".join(f"{r.start_line}-{r.end_line}" for r in sf.changed_ranges)
                    console.print(f"  • [bold white]{sf.relative_path}[/] [dim]({sf.path})[/dim] -> [cyan]Değişen Satırlar: {ranges_str}[/cyan] [dim]({sf.line_count} satır)[/dim]")
                else:
                    console.print(f"  • [bold white]{sf.relative_path}[/] [dim]({sf.path})[/dim] [dim]({sf.line_count} satır)[/dim]")
        return

    # Tarama boru hattını başlat
    try:
        pipeline = ScanPipeline(cfg)
        result = pipeline.run(target_override=target)
    except GitScanError as exc:
        console.print(f"[bold red]Git Hatası:[/] {exc}")
        raise typer.Exit(code=1)

    # İsteğe bağlı ciddiyet filtreleme
    if severity:
        try:
            min_sev = SeverityLevel(severity.upper())
            result.findings = result.filter_by_severity(min_sev)
            result.recalculate_summary()
        except ValueError:
            console.print(f"[bold red]Hata:[/] Geçersiz --severity değeri: {severity}")
            raise typer.Exit(code=1)

    # Çıktı formatına göre raporlama
    out_format = format_type or cfg.reporting.output_format
    export_report(
        result=result,
        format_type=out_format,
        output_file=output or cfg.reporting.output_file,
        console=console,
    )

    # CI/CD fail_on kontrolü
    check_fail_sev = cfg.reporting.fail_on_severity
    if check_fail_sev:
        has_failure = any(
            not f.is_false_positive and f.severity.is_greater_or_equal(check_fail_sev)
            for f in result.findings
        )
        if has_failure:
            console.print(
                f"\n[bold red]CI/CD Başarısız:[/] '{check_fail_sev.value}' veya daha yüksek "
                f"ciddiyette bulgular tespit edildi. (Exit code: 2)"
            )
            raise typer.Exit(code=2)


def main() -> None:
    """CLI giriş noktası."""
    app()


if __name__ == "__main__":
    main()
