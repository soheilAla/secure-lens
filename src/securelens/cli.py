import typer

from securelens.assess.jev import JevAssessor
from securelens.collectors.repository import RepositoryCollector
from securelens.core.config import get_settings
from securelens.core.runner import ScanRunner, default_analyzers

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main():
    pass


@app.command()
def scan(
    path: str = typer.Argument(".", help="Target directory to scan"),
    jev: bool = typer.Option(True, "--jev/--no-jev", help="Enable JEV assessment"),
):
    settings = get_settings()
    assessor = None

    if jev:
        if settings.api_key:
            assessor = JevAssessor(
                model=settings.model or "jev-1.13-free",
                api_key=settings.api_key,
                base_url=settings.base_url or None,
            )
        else:
            typer.echo(
                "Notice: JEV skipped (no API_KEY configured in environment or .env). "
                "Use --no-jev to silence.",
                err=True,
            )

    runner = ScanRunner(
        collector=RepositoryCollector(),
        analyzers=default_analyzers(),
        assessor=assessor,
    )
    report = runner.run(path)

    typer.echo(f"Scanning: {report.target}")
    typer.echo(f"Files collected: {report.files_collected}")
    typer.echo(f"Files skipped: {report.files_skipped}")
    typer.echo(f"Findings: {len(report.assessed_findings)}")

    for item in report.assessed_findings:
        finding = item.finding
        location = (
            f"{finding.file}:{finding.line_start}-{finding.line_end}"
            if finding.line_start and finding.line_end
            else finding.file or "No specific file"
        )
        tag = item.final_severity.value.upper()
        if item.assessment and not item.assessment.fallback:
            expl = "EXPLOITABLE" if item.assessment.exploitable else "NOT EXPLOITABLE"
            prob = item.assessment.exploitable_probability
            typer.echo(f"  [{tag}] [{expl} {prob:.0%}] {location} — {finding.title}")
        elif item.assessment and item.assessment.fallback:
            typer.echo(f"  [{tag}] [FALLBACK] {location} — {finding.title}")
        else:
            typer.echo(f"  [{tag}] {location} — {finding.title}")

        for evidence in finding.evidence:
            typer.echo(f"       {evidence.content}")


if __name__ == "__main__":
    app()
