# Reproducing results

The published 13-file snapshot is a local exploratory result. Several inputs are
Windows system binaries and therefore are not redistributed. This document separates
what can be reproduced from what still requires a public corpus.

## Environment

- Windows 10 x64
- Python 3.12.16
- BLC1 revision recorded by the repository commit
- iced-x86 1.22.0
- pyppmd 1.3.1
- 7-Zip 26.06 x64 standalone console build

Install BLC1 in a fresh environment:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
```

## Verify one file

```powershell
bincompress encode C:\path\to\input.exe output.blc1 --preset 9
bincompress decode output.blc1 restored.exe
Get-FileHash C:\path\to\input.exe -Algorithm SHA256
Get-FileHash restored.exe -Algorithm SHA256
```

The decoder also verifies the digest stored in the archive. The two displayed hashes
must match.

## Produce the comparison archive

With `7za.exe` from 7-Zip 26.06 on `PATH`:

```powershell
7za a -t7z -mx=9 -m0=BCJ -m1=LZMA2 baseline.7z C:\path\to\input.exe
7za l -slt baseline.7z
```

The listing must report `Method = BCJ LZMA2`. Compare complete file sizes for
`output.blc1` and `baseline.7z`; do not subtract container headers.

## Inspect BLC1 composition

```powershell
bincompress profile C:\path\to\input.exe --preset 9
```

The profile reports global framing, each PE segment, the selected method, and the raw
and stored sizes of independently coded streams.

## Publication bar

A leaderboard-quality result still needs:

1. a redistributable, checksum-pinned PE corpus;
2. scripted acquisition and benchmark execution;
3. wall-clock encode/decode time and peak-memory measurements;
4. current 7-Zip, PAQ8PX, cmix, and relevant executable packer baselines;
5. reproduction on at least one clean machine by an independent party.

Until those conditions are met, cite the result as a local benchmark snapshot, not a
world record.
