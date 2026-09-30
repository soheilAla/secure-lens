import typer

from securelens.analyzers.env import EnvAnalyzer
from securelens.analyzers.secrets import SecretAnalyzer
from securelens.collectors.repository import RepositoryCollector
from securelens.core.runner import ScanRunner

app = typer.Typer(no_args_is_help=True)


@app.callback()
def main():
    pass


@app.command()
def scan(path: str):
    runner = ScanRunner(
        collector=RepositoryCollector(), analyzers=[EnvAnalyzer(), SecretAnalyzer()]
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
        typer.echo(
            f"  [{item.final_severity.value.upper()}] {location} — {finding.title}"
        )


if __name__ == "__main__":
    app()
