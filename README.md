# BLC1

[![CI](https://github.com/poetetriste/blc1/actions/workflows/ci.yml/badge.svg)](https://github.com/poetetriste/blc1/actions/workflows/ci.yml)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-research%20prototype-orange.svg)](#project-status)

**Structure-aware, byte-exact compression for Windows PE binaries.**

BLC1 is an experimental lossless codec that uses executable and PE metadata as a
compression model. Instead of treating a binary as an opaque byte stream, it separates
instruction structure from typed values, transforms PE tables, and recompresses
embedded DEFLATE streams while preserving the original file exactly.

## Current result

On a 13-file local PE corpus, BLC1 produced a smaller complete archive than 7-Zip
26.06 with explicit BCJ + LZMA2 on every sample.

| Metric | BLC1 | 7-Zip BCJ + LZMA2 |
|---|---:|---:|
| Input | 7,747,339 bytes | 7,747,339 bytes |
| Archive | **2,393,037 bytes** | 2,777,776 bytes |
| Compression ratio | **3.2375:1** | 2.7890:1 |
| Wins | **13 / 13** | 0 / 13 |

The BLC1 total is **384,739 bytes smaller**, a **13.851% reduction in archive size**.
All BLC1 outputs decoded byte-exactly and passed SHA-256 verification.

This is a promising exploratory result, not a world-record claim. The corpus is small,
locally assembled, and not fully redistributable. See [the full benchmark](BENCHMARK.md)
for per-file results, exact settings, and limitations, and
[the reproduction guide](docs/REPRODUCING.md) for the publication bar.

## Why it compresses

- Defensive PE parsing preserves headers, sections, gaps, and overlays.
- x86/x64 instructions are split into skeleton and typed value streams.
- Branches and RIP-relative references are normalized before coding.
- `.pdata`, `.reloc`, pointer tables, and two-byte words use reversible transforms.
- Embedded DEFLATE streams can be represented through bit-exact preflate metadata.
- Instruction skeletons compete across adaptive PPMd orders.
- Every segment chooses among raw, LZMA2, BCJ + LZMA2, and semantic methods only
  after complete framing overhead is counted.
- Independent blocks provide decoder-side stream multiplexing.
- Declared sizes bound decoding and a full-file SHA-256 protects integrity.

Read [the architecture overview](docs/ARCHITECTURE.md) for the complete pipeline.

## Quick start

Requirements: Windows x64 and Python 3.12.

```powershell
git clone https://github.com/poetetriste/blc1.git
cd blc1
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
```

Compress and restore a file:

```powershell
bincompress encode C:\path\to\input.exe output.blc1
bincompress decode output.blc1 restored.exe
```

Inspect which segments and streams consume the archive:

```powershell
bincompress profile C:\path\to\input.exe
```

BLC1 refuses to overwrite an existing output path. The current encoder optimizes for
archive size and can be slow because it evaluates multiple representations.

## Development

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m ruff format --check src tests
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m pytest
```

The current suite contains 81 tests covering framing, corruption handling, PE parsing,
instruction transforms, PPMd, preflate, profiling, and exact round trips. Contributions
should follow [CONTRIBUTING.md](CONTRIBUTING.md), especially the reproducibility rules.

## Project status

BLC1 is a research prototype and the format is not stable. It is not yet suitable for
production archival or processing untrusted data. Current work is focused on:

1. a public, checksum-pinned PE benchmark corpus;
2. time and peak-memory measurement;
3. clean-machine packaging and independent reproduction;
4. PAQ8PX and cmix maximum-ratio comparisons;
5. further resource, import/export, and typed-stream transforms.

The competitive landscape and experimental directions are tracked in
[MARKET_MAP.md](MARKET_MAP.md).

## Third-party component

The Windows package bundles the native decoder from Microsoft preflate-rs 0.7.6 under
Apache-2.0. Its exact binary hash and attribution are recorded in [NOTICE](NOTICE).
Archives that do not select the embedded-DEFLATE method do not invoke this DLL.

## License

Licensed under the [Apache License 2.0](LICENSE).
