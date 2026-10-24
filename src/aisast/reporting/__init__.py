"""AI-SAST Raporlama Modülü.

Konsol (Rich), JSON, SARIF (Static Analysis Results Interchange Format) ve
Markdown formatlarında güvenlik tarama sonuçlarının sunumu ve dışa aktarımı.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any, Optional

# Windows konsolunda UTF-8 karakter desteğini garantiye al
if sys.platform == "win32":
    try:
        if sys.stdout and hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if sys.stderr and hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

from rich.box import ROUNDED
from rich.console import Console, Group
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from aisast.models import Finding, ScanResult, SeverityLevel


class ConsoleReporter:
    """Rich kütüphanesini kullanarak interaktif terminal raporu oluşturur."""

    def __init__(self, console: Optional[Console] = None) -> None:
        self.console = console or Console()

    def render(self, result: ScanResult, show_snippets: bool = True) -> None:
        """Tarama sonucunu konsola basar."""
        summary = result.summary
        metrics = result.metrics

        # Aktif bulguları ve yanlış pozitifleri ayır
        active_findings = [f for f in result.findings if not f.is_false_positive]
        fp_count = sum(1 for f in result.findings if f.is_false_positive)

        # Ciddiyet Özeti Tablosu
        summary_table = Table(box=ROUNDED, show_header=True, header_style="bold cyan")
        summary_table.add_column("Ciddiyet", justify="center")
        summary_table.add_column("Sayı", justify="center")
        summary_table.add_column("Açıklama", justify="left")

        summary_table.add_row(
            "[bold red]CRITICAL[/bold red]",
            str(summary.critical_count),
            "Acil müdahale gerektiren yüksek riskli zafiyetler veya ifşa olmuş sırlar"
        )
        summary_table.add_row(
            "[bold orange1]HIGH[/bold orange1]",
            str(summary.high_count),
            "Ciddi güvenlik açıkları ve istismar edilebilir zayıflıklar"
        )
        summary_table.add_row(
            "[bold yellow]MEDIUM[/bold yellow]",
            str(summary.medium_count),
            "Orta düzey güvenlik zafiyetleri ve yapılandırma eksiklikleri"
        )
        summary_table.add_row(
            "[bold blue]LOW[/bold blue]",
            str(summary.low_count),
            "Düşük riskli kod kalitesi ve güvenli kodlama uyarıları"
        )
        summary_table.add_row(
            "[dim]INFO[/dim]",
            str(summary.info_count),
            "Bilgilendirici notlar ve istatistiki tespitler"
        )

        overview_text = (
            f"[bold]Hedef:[/] [green]{result.target_path}[/]\n"
            f"[bold]Taranan Dosyalar:[/] {metrics.scanned_files} "
            f"([dim]Atlanan: {metrics.skipped_files}[/]) | "
            f"[bold]Süre:[/] {metrics.duration_seconds:.2f}s | "
            f"[bold]Toplam Bulgu:[/] {summary.total_findings}"
        )
        if fp_count > 0:
            overview_text += f" | [bold magenta]AI Elenen Yanlış Pozitif:[/] {fp_count}"

        self.console.print(Panel(overview_text, title="[bold cyan]aisast Güvenlik Tarama Özeti[/bold cyan]", border_style="cyan"))
        self.console.print(summary_table)

        # Bulgular Tablosu
        if active_findings:
            self.console.print("\n[bold underline]Detaylı Güvenlik Bulguları:[/bold underline]\n")
            findings_table = Table(box=ROUNDED, show_header=True, header_style="bold magenta")
            findings_table.add_column("ID / Kural", style="dim", width=14)
            findings_table.add_column("Ciddiyet", justify="center", width=10)
            findings_table.add_column("Kategori / Başlık", width=30)
            findings_table.add_column("Dosya & Satır", style="cyan")
            findings_table.add_column("Katman", justify="center")

            for f in active_findings:
                sev_color = {
                    SeverityLevel.CRITICAL: "bold red",
                    SeverityLevel.HIGH: "bold orange1",
                    SeverityLevel.MEDIUM: "bold yellow",
                    SeverityLevel.LOW: "bold blue",
                    SeverityLevel.INFO: "dim",
                }.get(f.severity, "white")

                layer_text = f.layer.value.replace("LAYER", "L")
                if f.verified_by_llm:
                    layer_text += " [green]✓ AI[/green]"

                findings_table.add_row(
                    f.rule_id,
                    f"[{sev_color}]{f.severity.value}[/{sev_color}]",
                    f"[bold]{f.title}[/bold]\n[dim]{f.category.value}[/dim]",
                    f"{f.location.file_path}:{f.location.start_line}",
                    layer_text,
                )

            self.console.print(findings_table)

            # Kod & Diff (Yama) Panelleri
            if show_snippets:
                self.console.print("\n[bold underline]Kod & Otomatik Yama (Diff) Önizlemeleri:[/bold underline]\n")
                displayed_findings = active_findings[:15]
                for f in displayed_findings:
                    sev_border_color = {
                        SeverityLevel.CRITICAL: "red",
                        SeverityLevel.HIGH: "bright_red",
                        SeverityLevel.MEDIUM: "yellow",
                        SeverityLevel.LOW: "blue",
                        SeverityLevel.INFO: "dim",
                    }.get(f.severity, "white")

                    panel_elements: list[Any] = []

                    # Bilgi satırları
                    info_lines = [
                        f"[bold]{f.title}[/bold] ([dim]{f.category.value}[/dim])",
                        f"[dim]Konum: {f.location.file_path}:{f.location.start_line}[/dim]",
                    ]
                    if f.cwe_id:
                        info_lines.append(f"[dim]CWE: {f.cwe_id}[/dim]")
                    if f.description:
                        info_lines.append(f"{f.description}")
                    panel_elements.append(Text.from_markup("\n".join(info_lines)))

                    # LLM Değerlendirmesi
                    if f.llm_reasoning:
                        panel_elements.append(Text.from_markup(f"\n[bold magenta]AI Değerlendirmesi:[/] {f.llm_reasoning}"))

                    # Çözüm ve Diff/Snippet
                    has_diff = bool(f.remediation and f.remediation.diff)
                    has_code_patch = bool(f.remediation and f.remediation.code_snippet)

                    if f.remediation and f.remediation.description:
                        panel_elements.append(Text.from_markup(f"\n[cyan]Çözüm:[/] {f.remediation.description}"))

                    if has_diff and f.remediation and f.remediation.diff:
                        panel_elements.append(Text.from_markup("\n[bold green]Otomatik Yama (Unified Diff):[/bold green]"))
                        panel_elements.append(Syntax(f.remediation.diff, "diff", theme="monokai", line_numbers=False))
                    elif f.location.snippet and has_code_patch and f.remediation and f.remediation.code_snippet:
                        snip_text = Text()
                        snip_text.append("\n- Zafiyetli Kod:\n", style="bold red")
                        snip_text.append(f"  {f.location.snippet}\n", style="red")
                        snip_text.append("+ Güvenli Öneri:\n", style="bold green")
                        snip_text.append(f"  {f.remediation.code_snippet}", style="green")
                        panel_elements.append(snip_text)
                    elif f.location.snippet:
                        snip_text = Text()
                        snip_text.append("\nKod Parçacığı:\n", style="bold yellow")
                        snip_text.append(f"  {f.location.snippet}", style="yellow")
                        panel_elements.append(snip_text)

                    panel_title = f"[{sev_border_color} bold][{f.severity.value}] {f.rule_id}[/{sev_border_color} bold]"
                    self.console.print(
                        Panel(
                            Group(*panel_elements),
                            title=panel_title,
                            border_style=sev_border_color,
                        )
                    )

                if len(active_findings) > 15:
                    self.console.print(f"[dim]... ve {len(active_findings) - 15} bulgu daha (tüm listeyi görmek için -f json, -f sarif veya -f markdown kullanın).[/dim]\n")
        else:
            self.console.print("\n[bold green]✓ Tebrikler! Herhangi bir güvenlik açığı veya sır tespit edilmedi.[/bold green]\n")


class JSONReporter:
    """Sonuçları standart JSON biçiminde serileştirir."""

    @staticmethod
    def render(result: ScanResult, indent: int = 2) -> str:
        return result.model_dump_json(indent=indent)


class SARIFReporter:
    """Sonuçları OASIS SARIF v2.1.0 JSON biçiminde serileştirir."""

    @staticmethod
    def render(result: ScanResult, indent: int = 2) -> str:
        return json.dumps(result.to_sarif_dict(), indent=indent, ensure_ascii=False)


class MarkdownReporter:
    """Sonuçları GitHub Flavored Markdown (GFM) biçiminde serileştirir."""

    @staticmethod
    def render(result: ScanResult) -> str:
        summary = result.summary
        metrics = result.metrics
        active_findings = [f for f in result.findings if not f.is_false_positive]
        fp_count = sum(1 for f in result.findings if f.is_false_positive)

        lines: list[str] = [
            "# 🛡️ AI-SAST Güvenlik Tarama Raporu",
            "",
            f"- **Hedef:** `{result.target_path}`",
            f"- **Taranan Dosyalar:** {metrics.scanned_files} (Atlanan: {metrics.skipped_files})",
            f"- **Toplam Satır (LOC):** {metrics.total_lines_of_code}",
            f"- **Tarama Süresi:** {metrics.duration_seconds:.2f}s",
            f"- **Toplam Aktif Bulgu:** {summary.total_findings}",
        ]

        if fp_count > 0:
            lines.append(f"- **AI Tarafından Elenen Yanlış Pozitif:** {fp_count}")

        lines.extend([
            "",
            "## 📊 Ciddiyet Özeti",
            "",
            "| Ciddiyet | Sayı | Açıklama |",
            "|:---|:---:|:---|",
            f"| 🔴 **CRITICAL** | {summary.critical_count} | Acil müdahale gerektiren yüksek riskli zafiyetler veya ifşa olmuş sırlar |",
            f"| 🟠 **HIGH** | {summary.high_count} | Ciddi güvenlik açıkları ve istismar edilebilir zayıflıklar |",
            f"| 🟡 **MEDIUM** | {summary.medium_count} | Orta düzey güvenlik zafiyetleri ve yapılandırma eksiklikleri |",
            f"| 🔵 **LOW** | {summary.low_count} | Düşük riskli kod kalitesi ve güvenli kodlama uyarıları |",
            f"| ⚪ **INFO** | {summary.info_count} | Bilgilendirici notlar ve istatistiki tespitler |",
            "",
            "## 🛡️ Güvenlik Bulguları",
            "",
        ])

        if not active_findings:
            lines.append("> **✓ Tebrikler!** Herhangi bir aktif güvenlik açığı veya sır tespit edilmedi.\n")
            return "\n".join(lines)

        lines.append(f"Toplam **{len(active_findings)}** aktif güvenlik bulgusu tespit edilmiştir:\n")

        for idx, f in enumerate(active_findings, 1):
            ai_badge = " *(✓ AI Doğrulandı)*" if f.verified_by_llm else ""
            lines.extend([
                f"### {idx}. [{f.severity.value}] {f.rule_id}: {f.title}",
                "",
                f"- **Dosya & Satır:** `{f.location.file_path}:{f.location.start_line}`",
                f"- **Katman:** `{f.layer.value}`{ai_badge}",
                f"- **Kategori:** `{f.category.value}`",
                f"- **Güven Seviyesi:** `{f.confidence.value}`",
            ])
            if f.cwe_id:
                lines.append(f"- **CWE:** `{f.cwe_id}`")
            if f.owasp_category:
                lines.append(f"- **OWASP:** `{f.owasp_category}`")

            lines.extend([
                "",
                "**Açıklama:**",
                f"{f.description}",
            ])

            if f.llm_reasoning:
                lines.extend([
                    "",
                    "**AI Bağlamsal Analizi:**",
                    f"> {f.llm_reasoning}",
                ])

            if f.location.snippet:
                lines.extend([
                    "",
                    "**Mevcut Kod:**",
                    "```python",
                    f"{f.location.snippet}",
                    "```",
                ])

            if f.remediation:
                if f.remediation.description:
                    lines.extend([
                        "",
                        "**Önerilen Çözüm:**",
                        f"{f.remediation.description}",
                    ])
                if f.remediation.diff:
                    lines.extend([
                        "",
                        "**Otomatik Yama (Diff):**",
                        "```diff",
                        f"{f.remediation.diff}",
                        "```",
                    ])
                elif f.remediation.code_snippet:
                    lines.extend([
                        "",
                        "**Önerilen Güvenli Kod:**",
                        "```python",
                        f"{f.remediation.code_snippet}",
                        "```",
                    ])
                if f.remediation.references:
                    lines.extend([
                        "",
                        "**Referanslar:**",
                    ])
                    for ref in f.remediation.references:
                        lines.append(f"- <{ref}>" if ref.startswith("http") else f"- {ref}")

            lines.append("")

        return "\n".join(lines)


def export_report(
    result: ScanResult,
    format_type: str = "rich",
    output_file: Optional[str | Path] = None,
    console: Optional[Console] = None
) -> str | None:
    """Seçilen format türüne göre rapor oluşturur veya dosyaya kaydeder."""
    output_str: Optional[str] = None
    c = console or Console()

    norm_format = format_type.lower()
    if norm_format == "json":
        output_str = JSONReporter.render(result)
    elif norm_format == "sarif":
        output_str = SARIFReporter.render(result)
    elif norm_format in ("markdown", "md"):
        output_str = MarkdownReporter.render(result)
    else:
        # Rich konsol çıktısı
        ConsoleReporter(c).render(result)
        return None

    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(output_str, encoding="utf-8")
        c.print(f"[bold green]✓[/bold green] Rapor kaydedildi: [cyan]{out_path.resolve()}[/cyan]")
    else:
        # Stdout'a doğrudan bas (Unix borulama ve testler için temiz çıktı)
        print(output_str)

    return output_str


__all__ = [
    "ConsoleReporter",
    "JSONReporter",
    "SARIFReporter",
    "MarkdownReporter",
    "export_report",
]
