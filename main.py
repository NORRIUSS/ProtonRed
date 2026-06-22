"""
Entry point — CLI or API server.
"""
import sys
import asyncio
import subprocess
from pathlib import Path


def run_server():
    import uvicorn
    from config import settings
    uvicorn.run(
        "api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        log_level=settings.LOG_LEVEL.lower(),
        reload=False,
    )


def setup_atomics(path: str = "./atomics"):
    """Clone Atomic Red Team atomics directory."""
    target = Path(path)
    if target.exists():
        print(f"[+] Atomics already at {target.resolve()}")
        return
    print(f"[*] Cloning Atomic Red Team atomics to {target}...")
    result = subprocess.run(
        ["git", "clone", "--depth=1",
         "https://github.com/redcanaryco/atomic-red-team.git",
         "_art_tmp"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"[-] Clone failed: {result.stderr}")
        sys.exit(1)
    import shutil
    shutil.move("_art_tmp/atomics", str(target))
    shutil.rmtree("_art_tmp", ignore_errors=True)
    print(f"[+] Atomics downloaded to {target.resolve()}")


async def run_cli(target: str, objective: str, model: str, api_key: str, max_iter: int):
    """Run agent in CLI mode with rich output."""
    try:
        from rich.console import Console
        from rich.live import Live
        from rich.table import Table
        console = Console()
    except ImportError:
        print("pip install rich")
        sys.exit(1)

    from core.atomic_engine import AtomicEngine
    from core.agent import stream_agent_run
    from providers import get_provider
    from providers.base import ProviderConfig

    console.print(f"\n[bold green]PROTONRED[/bold green] — [cyan]{target}[/cyan]")
    console.print(f"Objective: [yellow]{objective}[/yellow]")
    console.print(f"Model: [blue]{model}[/blue]\n")

    engine = AtomicEngine()
    count = engine.load_all()
    console.print(f"[dim]Loaded {count} techniques[/dim]\n")

    provider = get_provider(model, ProviderConfig(api_key=api_key))

    async for event in stream_agent_run(provider, engine, target, objective, max_iter):
        if event.type == "thought":
            console.print(f"[purple]→ THINK[/purple] {event.data.get('thought', '')[:200]}")
        elif event.type == "tool_call":
            console.print(f"[cyan]  TOOL[/cyan]  {event.data.get('tool')} {str(event.data.get('args', {}))[:80]}")
        elif event.type == "tool_result":
            result = event.data.get("result", {})
            if result.get("success") is True:
                console.print(f"[green]  ✓[/green]    {result.get('test_name', '')}")
            elif result.get("success") is False:
                console.print(f"[red]  ✗[/red]    exit:{result.get('exit_code')} {result.get('stderr','')[:80]}")
        elif event.type == "finding":
            sev = event.data.get("severity", "info").upper()
            color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "yellow", "INFO": "blue"}.get(sev, "white")
            console.print(f"[bold {color}]  [{sev}][/bold {color}] [{event.data.get('technique_id')}] {event.data.get('title')}")
        elif event.type == "done":
            console.print(f"\n[bold green]DONE[/bold green] {event.data.get('summary', '')}")
        elif event.type == "error":
            console.print(f"[bold red]ERROR[/bold red] {event.data.get('message')}")


def main():
    import argparse
    parser = argparse.ArgumentParser(description="ProtonRed Pentest Tool")
    sub = parser.add_subparsers(dest="command")

    # server
    srv = sub.add_parser("server", help="Start API server + Web UI")

    # setup
    setup = sub.add_parser("setup", help="Download Atomic Red Team atomics")
    setup.add_argument("--path", default="./atomics")

    # run (CLI mode)
    run = sub.add_parser("run", help="Run agent in CLI mode")
    run.add_argument("--target", required=True)
    run.add_argument("--objective", required=True)
    run.add_argument("--model", default="claude-sonnet-4-6")
    run.add_argument("--api-key", default="")
    run.add_argument("--max-iter", type=int, default=20)

    args = parser.parse_args()

    if args.command == "server" or args.command is None:
        print("[*] Starting ProtonRed server...")
        print("[*] Web UI: http://localhost:8000")
        print("[*] API Docs: http://localhost:8000/docs")
        run_server()

    elif args.command == "setup":
        setup_atomics(args.path)

    elif args.command == "run":
        asyncio.run(run_cli(
            target=args.target,
            objective=args.objective,
            model=args.model,
            api_key=args.api_key,
            max_iter=args.max_iter,
        ))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
