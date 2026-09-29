import typer
from rich import print

app = typer.Typer(help="ICS Attack Dataset Lab")

@app.command()
def doctor() -> None:
    """Check that the local project CLI is working."""
    print("[green]icslab is ready[/green]")

if __name__ == "__main__":
    app()
