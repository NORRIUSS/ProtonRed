"""
Run the same atomic tests through both engines (native and invoke-atomic)
against one target and print the results side by side.

Use this on the lab DC before switching DEFAULT_ENGINE to invoke-atomic.
The ProtonRed server must be running (start.ps1).

Examples:
  # remote DC over WinRM
  python tools/compare_engines.py --host 192.168.50.162 --user Administrator --password ... --domain-joined
  # this machine
  python tools/compare_engines.py --local
  # custom test list: TECHNIQUE:INDEX (0-based, like the API)
  python tools/compare_engines.py --local --tests T1082:0 T1033:0 T1547.001:0
"""
import argparse
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "client"))

from pentest_client import PentestClient, Target, TestSelection  # noqa: E402

# Discovery tests from the confirmed-working list, plus one persistence test
# with a cleanup step (Run key) to check cleanup on both engines.
DEFAULT_TESTS = ["T1082:0", "T1033:0", "T1016:0", "T1087.001:7", "T1201:5", "T1547.001:0"]
DOMAIN_TESTS = ["T1087.002:0", "T1069.002:0"]


def _parse_tests(items: list[str]) -> list[TestSelection]:
    out = []
    for item in items:
        tid, _, idx = item.partition(":")
        out.append(TestSelection(technique_id=tid.upper(), test_index=int(idx or 0)))
    return out


def _row(r: dict) -> str:
    out = (r.get("stdout") or r.get("stderr") or r.get("skip_reason") or "").strip().replace("\n", " ")
    return f"{r.get('outcome') or '?':<15} exit={str(r.get('exit_code')):<4} cleanup={r.get('cleanup_status') or '-':<9} {out[:60]}"


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--api", default="http://localhost:8000")
    ap.add_argument("--local", action="store_true", help="test this machine instead of a WinRM host")
    ap.add_argument("--host")
    ap.add_argument("--user", default="Administrator")
    ap.add_argument("--password", default="")
    ap.add_argument("--transport", default="ntlm")
    ap.add_argument("--os", default="windows", choices=("windows", "linux", "macos"), help="target OS platform")
    ap.add_argument("--standard-user", action="store_true", help="target account is not admin")
    ap.add_argument("--domain-joined", action="store_true", help="also run AD discovery tests")
    ap.add_argument("--tests", nargs="+", help="TECHNIQUE:INDEX list (default: a discovery+persistence set)")
    args = ap.parse_args()

    if not args.local and not args.host:
        ap.error("give --host (WinRM target) or --local")

    target = Target(
        name="local" if args.local else args.host,
        target_id="cmp",
        os_platform=args.os,
        privilege="standard_user" if args.standard_user else "admin",
        connection="local" if args.local else "remote",
        domain_joined=args.domain_joined,
        host="localhost" if args.local else args.host,
        winrm_username="" if args.local else args.user,
        winrm_password="" if args.local else args.password,
        winrm_transport=args.transport,
    )
    tests = args.tests or (DEFAULT_TESTS + (DOMAIN_TESTS if args.domain_joined else []))
    selections = _parse_tests(tests)

    results: dict[str, dict] = {}
    async with PentestClient(args.api, timeout=60.0) as client:
        health = await client.health()
        ia = (health.get("engines") or {}).get("invoke-atomic") or {}
        if ia and not ia.get("available"):
            print(f"invoke-atomic engine unavailable on the server: {ia}")
            return 1
        for engine in ("native", "invoke-atomic"):
            print(f"==> running {len(selections)} tests with engine={engine}")
            job = await client.run_job([target], selections, engine=engine)
            rows = job.by_target[0]["results"] if job.by_target else []
            results[engine] = {(r["technique_id"], r.get("test_index", 0)): r for r in rows}

    print()
    mismatches = 0
    for sel in selections:
        key = (sel.technique_id, sel.test_index)
        n, i = results["native"].get(key, {}), results["invoke-atomic"].get(key, {})
        same = n.get("outcome") == i.get("outcome")
        mismatches += not same
        print(f"{sel.technique_id}:{sel.test_index}  {'same' if same else 'DIFF'}")
        print(f"   native        {_row(n)}")
        print(f"   invoke-atomic {_row(i)}")
    print()
    print(f"{len(selections) - mismatches}/{len(selections)} tests produced the same outcome on both engines.")
    return 0 if mismatches == 0 else 2


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
