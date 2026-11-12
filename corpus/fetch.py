"""Fetch and verify the public BLC1 benchmark corpus.

The corpus is code, not data: this script downloads every manifest entry from
its pinned URL, verifies the archive against the recorded SHA-256, extracts the
target member, and verifies the extracted PE file byte-for-byte. Nothing is
redistributed; a fresh machine rebuilds the identical corpus from upstream.

Usage:
    python corpus/fetch.py                 # lite profile (default)
    python corpus/fetch.py --profile full  # everything
    python corpus/fetch.py --only rg,fd    # subset by id prefix
    python corpus/fetch.py --check         # verify local files only, no network

Requirements: Python 3.10+, no third-party packages. Entries whose archive is
an MSI additionally need a 7z binary (``--seven-zip`` or 7z on PATH) that can
open it; this is documented per entry in the manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

CORPUS_DIR = Path(__file__).resolve().parent
MANIFEST_PATH = CORPUS_DIR / "manifest.json"
DOWNLOADS_DIR = CORPUS_DIR / "downloads"
FILES_DIR = CORPUS_DIR / "files"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: Path) -> None:
    if not url.startswith("https://"):
        raise RuntimeError(f"refusing non-HTTPS corpus URL: {url}")
    request = urllib.request.Request(url, headers={"User-Agent": "blc1-corpus/1.0"})  # noqa: S310 - scheme restricted to https above
    with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310
        if response.status != 200:
            raise RuntimeError(f"HTTP {response.status} for {url}")
        tmp = dest.with_suffix(dest.suffix + ".part")
        with tmp.open("wb") as out:
            shutil.copyfileobj(response, out, 1 << 20)
        tmp.replace(dest)


def seven_zip_candidates(explicit: str | None) -> list[str]:
    found: list[str] = []
    if explicit:
        found.append(explicit)
    on_path = shutil.which("7z") or shutil.which("7za")
    if on_path:
        found.append(on_path)
    for candidate in (
        Path(r"C:\Program Files\7-Zip\7z.exe"),
        Path(r"C:\Program Files (x86)\7-Zip\7z.exe"),
    ):
        if candidate.exists():
            found.append(str(candidate))
    return found


def extract_member(
    archive: Path, entry: dict, workdir: Path, seven_zip: str | None
) -> bytes:
    """Return the target member bytes from a downloaded archive."""
    kind = entry["archive"]["type"]
    member = entry["archive"]["member"]
    if kind == "raw":
        return archive.read_bytes()
    if kind == "zip":
        with zipfile.ZipFile(archive) as bundle:
            return bundle.read(member)
    if kind == "msi":
        candidates = seven_zip_candidates(seven_zip)
        if not candidates:
            raise RuntimeError(
                f"entry {entry['id']}: MSI extraction needs a 7z binary; "
                "pass --seven-zip or install 7-Zip"
            )
        tool = candidates[0]
        out_dir = workdir / f"msi-{entry['id']}"
        out_dir.mkdir(parents=True, exist_ok=True)
        subprocess.run(  # noqa: S603 - tool path and member come from the pinned manifest
            [tool, "e", "-y", f"-o{out_dir}", str(archive), member],
            check=True,
            capture_output=True,
        )
        return (out_dir / member).read_bytes()
    raise RuntimeError(f"entry {entry['id']}: unsupported archive type {kind!r}")


def process_entry(entry: dict, check_only: bool, seven_zip: str | None) -> str:
    target = FILES_DIR / entry["file"]
    expected_sha = entry["sha256"]
    if target.exists():
        actual = sha256_file(target)
        if actual == expected_sha and target.stat().st_size == entry["size"]:
            return "ok (cached, hash verified)"
        target.unlink()
        if check_only:
            return "FAIL (hash mismatch)"
    if check_only:
        return "MISSING"

    archive_name = entry["url"].rsplit("/", 1)[-1]
    archive_path = DOWNLOADS_DIR / archive_name
    if archive_path.exists() and sha256_file(archive_path) == entry["source_sha256"]:
        pass  # cached download still matches upstream
    else:
        print(f"  downloading {entry['url']}")
        download(entry["url"], archive_path)
        archive_sha = sha256_file(archive_path)
        if archive_sha != entry["source_sha256"]:
            archive_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"entry {entry['id']}: upstream archive hash changed "
                f"(expected {entry['source_sha256']}, got {archive_sha}); "
                "do not silently re-pin — investigate the upstream change first"
            )

    payload = extract_member(archive_path, entry, DOWNLOADS_DIR, seven_zip)
    digest = hashlib.sha256(payload).hexdigest()
    if digest != expected_sha or len(payload) != entry["size"]:
        raise RuntimeError(
            f"entry {entry['id']}: extracted file mismatch "
            f"(expected {entry['size']} bytes / {expected_sha[:12]}…, "
            f"got {len(payload)} bytes / {digest[:12]}…)"
        )
    target.write_bytes(payload)
    return "ok (fetched, hash verified)"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", default="lite", choices=["lite", "full"])
    parser.add_argument("--only", default=None, help="comma-separated id prefixes")
    parser.add_argument("--check", action="store_true", help="verify local files only")
    parser.add_argument(
        "--seven-zip", default=None, help="path to a 7z binary for MSI entries"
    )
    args = parser.parse_args()

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    entries = [
        e
        for e in manifest["entries"]
        if args.profile in e["profiles"] or (args.profile == "full")
    ]
    if args.only:
        wanted = {part.strip() for part in args.only.split(",")}
        entries = [e for e in entries if any(e["id"].startswith(w) for w in wanted)]
    if not entries:
        print("no manifest entries selected")
        return 1

    DOWNLOADS_DIR.mkdir(exist_ok=True)
    FILES_DIR.mkdir(exist_ok=True)
    failures = 0
    for entry in entries:
        try:
            status = process_entry(entry, args.check, args.seven_zip)
        except Exception as error:  # report every entry, fail at the end
            status = f"FAIL ({error})"
            failures += 1
        print(f"{entry['id']:>28}: {status}")
    print(f"\n{len(entries) - failures}/{len(entries)} entries verified")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
