"""Run the BLC1 vs 7-Zip benchmark over the public corpus.

For every selected manifest entry:

1. BLC1 encodes the file, then decodes the archive and verifies the
   byte-exact round trip (SHA-256 of input vs. restored output).
2. 7-Zip compresses the same file with the documented baseline command:
   ``7z a -t7z -mx=9 -m0=BCJ -m1=LZMA2``.
3. Sizes, wall times, and per-file deltas are recorded to
   ``corpus/results/<profile>.json``; existing results are reused unless
   ``--force`` is given, so long runs can be resumed after interruptions.

The summary prints both headline metrics — mean of per-file deltas and the
aggregate byte sum — plus the worst case, per the corpus doctrine.

Usage:
    python corpus/benchmark.py                          # lite profile
    python corpus/benchmark.py --profile full --only rg,fd
    python corpus/benchmark.py --seven-zip corpus/tools/7z.exe

Run from the repository root with the package importable
(``pip install -e .`` or PYTHONPATH=src).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
CORPUS_DIR = Path(__file__).resolve().parent
RESULTS_DIR = CORPUS_DIR / "results"

SEVEN_ZIP_ARGS = ["a", "-t7z", "-mx=9", "-m0=BCJ", "-m1=LZMA2"]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_blc1(source: Path, workdir: Path) -> dict:
    archive = workdir / "blc1.blc1"
    restored = workdir / "restored.bin"
    start = time.perf_counter()
    subprocess.run(  # noqa: S603 - fixed interpreter and module
        [sys.executable, "-m", "bincompress", "encode", str(source), str(archive)],
        check=True,
        capture_output=True,
    )
    encode_seconds = time.perf_counter() - start
    start = time.perf_counter()
    subprocess.run(  # noqa: S603 - fixed interpreter and module
        [sys.executable, "-m", "bincompress", "decode", str(archive), str(restored)],
        check=True,
        capture_output=True,
    )
    decode_seconds = time.perf_counter() - start
    roundtrip_ok = sha256_file(restored) == sha256_file(source)
    return {
        "size": archive.stat().st_size,
        "encode_seconds": round(encode_seconds, 2),
        "decode_seconds": round(decode_seconds, 2),
        "roundtrip_ok": roundtrip_ok,
    }


def run_7zip(seven_zip: str, source: Path, workdir: Path) -> dict:
    archive = workdir / "baseline.7z"
    start = time.perf_counter()
    subprocess.run(  # noqa: S603 - caller-supplied pinned tool path
        [seven_zip, *SEVEN_ZIP_ARGS, str(archive), str(source)],
        check=True,
        capture_output=True,
    )
    encode_seconds = time.perf_counter() - start
    return {"size": archive.stat().st_size, "encode_seconds": round(encode_seconds, 2)}


def benchmark_entry(entry: dict, seven_zip: str) -> dict:
    source = FILES_PATH / entry["file"]
    with tempfile.TemporaryDirectory(prefix="blc1-bench-") as tmp:
        workdir = Path(tmp)
        blc1 = run_blc1(source, workdir)
        seven = run_7zip(seven_zip, source, workdir)
    delta_pct = (blc1["size"] - seven["size"]) / seven["size"] * 100
    return {
        "id": entry["id"],
        "track": entry["track"],
        "tier": entry["tier"],
        "split": entry["split"],
        "input_size": source.stat().st_size,
        "blc1": blc1,
        "seven_zip": seven,
        "delta_pct": round(delta_pct, 3),
    }


def summarize(results: list[dict]) -> None:
    usable = [r for r in results if "error" not in r and r["blc1"]["roundtrip_ok"]]
    if not usable:
        print("no successful results")
        return
    deltas = [r["delta_pct"] for r in usable]
    total_in = sum(r["input_size"] for r in usable)
    total_blc1 = sum(r["blc1"]["size"] for r in usable)
    total_7z = sum(r["seven_zip"]["size"] for r in usable)
    aggregate = (total_blc1 - total_7z) / total_7z * 100
    mean_delta = sum(deltas) / len(deltas)
    worst = max(usable, key=lambda r: r["delta_pct"])
    print(f"\nfiles: {len(usable)}  (input {total_in:,} bytes)")
    print(
        f"aggregate:  BLC1 {total_blc1:,}  vs  7-Zip {total_7z:,}  -> {aggregate:+.3f}%"
    )
    print(f"mean per-file delta: {mean_delta:+.3f}%")
    print(f"worst case: {worst['id']} at {worst['delta_pct']:+.3f}%")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--profile", default="lite", choices=["lite", "full"])
    parser.add_argument("--only", default=None, help="comma-separated id prefixes")
    parser.add_argument("--force", action="store_true", help="re-run existing results")
    parser.add_argument("--seven-zip", default=str(CORPUS_DIR / "tools" / "7z.exe"))
    args = parser.parse_args()

    seven_zip = args.seven_zip
    if not Path(seven_zip).exists():
        print(f"7-Zip binary not found: {seven_zip}", file=sys.stderr)
        return 1

    manifest = json.loads((CORPUS_DIR / "manifest.json").read_text(encoding="utf-8"))
    entries = [
        e
        for e in manifest["entries"]
        if args.profile in e["profiles"] or args.profile == "full"
    ]
    if args.only:
        wanted = {part.strip() for part in args.only.split(",")}
        entries = [e for e in entries if any(e["id"].startswith(w) for w in wanted)]

    RESULTS_DIR.mkdir(exist_ok=True)
    results_path = RESULTS_DIR / f"{args.profile}.json"
    existing: dict[str, dict] = {}
    if results_path.exists():
        existing = {r["id"]: r for r in json.loads(results_path.read_text())}

    results: dict[str, dict] = dict(existing)
    for entry in entries:
        if (
            entry["id"] in results
            and not args.force
            and "error" not in results[entry["id"]]
        ):
            print(f"{entry['id']:>16}: cached")
            continue
        print(f"{entry['id']:>16}: encoding…", flush=True)
        try:
            result = benchmark_entry(entry, seven_zip)
        except subprocess.CalledProcessError as error:
            stderr = (error.stderr or b"").decode(errors="replace").strip()
            result = {
                "id": entry["id"],
                "track": entry["track"],
                "tier": entry["tier"],
                "split": entry["split"],
                "input_size": (FILES_PATH / entry["file"]).stat().st_size,
                "error": stderr.splitlines()[-1] if stderr else str(error),
            }
            results[entry["id"]] = result
            results_path.write_text(json.dumps(list(results.values()), indent=2))
            print(f"{entry['id']:>16}: FAILED: {result['error']}", flush=True)
            continue
        results[entry["id"]] = result
        results_path.write_text(json.dumps(list(results.values()), indent=2))
        print(
            f"{entry['id']:>16}: BLC1 {result['blc1']['size']:,} "
            f"({result['blc1']['encode_seconds']}s)  7z {result['seven_zip']['size']:,} "
            f"({result['seven_zip']['encode_seconds']}s)  delta {result['delta_pct']:+.3f}%  "
            f"roundtrip {result['blc1']['roundtrip_ok']}",
            flush=True,
        )

    ordered = [results[e["id"]] for e in entries if e["id"] in results]
    summarize(ordered)
    return 0


FILES_PATH = CORPUS_DIR / "files"

if __name__ == "__main__":
    sys.exit(main())
