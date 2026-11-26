"""
Download the pinned PowerShell modules used by the `invoke-atomic` engine into
vendor/modules/ (gitignored):

  vendor/modules/Invoke-AtomicRedTeam/   Red Canary's official ART runner
  vendor/modules/powershell-yaml/        its RequiredModules dependency

Both are used unmodified. ProtonRed copies them to remote targets over WinRM,
so targets need no internet access and no PSGallery.

Usage:  python tools/fetch_vendor.py [--force]
"""
import argparse
import hashlib
import io
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULES = ROOT / "vendor" / "modules"

PACKAGES = [
    {
        "name": "Invoke-AtomicRedTeam",
        "version": "2.3.0",
        "url": "https://github.com/redcanaryco/invoke-atomicredteam/archive/refs/tags/v2.3.0.zip",
        "sha256": "692bd386cbf37c7e6735824c11eb3579715993602305747419eb25e5899f506b",
        # GitHub archives wrap everything in one top-level folder.
        "strip_top_dir": True,
        "keep": ("Invoke-AtomicRedTeam.psd1", "Invoke-AtomicRedTeam.psm1", "Public/", "Private/", "LICENSE.txt"),
    },
    {
        "name": "powershell-yaml",
        "version": "0.4.12",
        "url": "https://www.powershellgallery.com/api/v2/package/powershell-yaml/0.4.12",
        "sha256": "d4602bc7a4a093766520422d53ca8b09acde162286fae11e2ee6c8edfea07810",
        "strip_top_dir": False,
        # A .nupkg is a zip; drop the NuGet packaging metadata.
        "drop": ("_rels/", "package/", "[Content_Types].xml", "powershell-yaml.nuspec", "Tests/", "build.ps1"),
    },
]


def _download(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "protonred-fetch-vendor"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def _extract(pkg: dict, data: bytes, dest: Path) -> None:
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            name = info.filename
            if pkg.get("strip_top_dir"):
                name = name.split("/", 1)[1] if "/" in name else ""
            if not name or name.endswith("/"):
                continue
            if any(name == d or name.startswith(d) for d in pkg.get("drop", ())):
                continue
            keep = pkg.get("keep")
            if keep and not any(name == k or name.startswith(k) for k in keep):
                continue
            target = (dest / name).resolve()
            if dest.resolve() not in target.parents:
                raise RuntimeError(f"unsafe path in archive: {info.filename}")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info))
    (dest / ".protonred-version").write_text(pkg["version"], encoding="utf-8")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="re-download even if present")
    args = ap.parse_args()

    MODULES.mkdir(parents=True, exist_ok=True)
    for pkg in PACKAGES:
        dest = MODULES / pkg["name"]
        marker = dest / ".protonred-version"
        if not args.force and marker.exists() and marker.read_text(encoding="utf-8").strip() == pkg["version"]:
            print(f"[ok] {pkg['name']} {pkg['version']} already present")
            continue
        print(f"[..] downloading {pkg['name']} {pkg['version']}")
        data = _download(pkg["url"])
        digest = hashlib.sha256(data).hexdigest()
        if digest != pkg["sha256"]:
            print(f"[!!] sha256 mismatch for {pkg['name']}: got {digest}, expected {pkg['sha256']}", file=sys.stderr)
            return 1
        if dest.exists():
            shutil.rmtree(dest)
        dest.mkdir(parents=True)
        _extract(pkg, data, dest)
        print(f"[ok] {pkg['name']} {pkg['version']} -> {dest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
