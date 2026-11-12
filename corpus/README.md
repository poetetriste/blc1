# Public PE benchmark corpus

The corpus is **code, not data**. Nothing here is redistributed: `manifest.json`
pins an upstream URL, version, license, and SHA-256 for every sample, and
`fetch.py` rebuilds the byte-identical file set from upstream on any machine.

## Usage

```console
python corpus/fetch.py                 # lite profile (~10 files, default)
python corpus/fetch.py --profile full  # all entries, incl. ARM64 and XL tiers
python corpus/fetch.py --check         # verify local files, no network
python corpus/fetch.py --only rg,fd    # subset by id prefix
python corpus/inspect_toolchain.py     # dump machine type, Rich header, markers
```

Downloads land in `corpus/downloads/` (cache), extracted PE files in
`corpus/files/`. Both directories are gitignored. MSI entries (7-Zip) need a
`7z` binary: pass `--seven-zip <path>` or put `7z` on PATH.

## Integrity doctrine

- Every entry verifies twice: the downloaded archive against `source_sha256`,
  and the extracted member against `sha256` + `size`.
- If an upstream archive changes under a pinned URL, fetch **fails loudly**.
  Do not silently re-pin: investigate first, then update the manifest with a
  changelog note.
- New entries are added with exact versions and hashes, never with "latest"
  URLs.

## Profiles and splits

- **lite**: ~10 files, one representative per compiler family, no XL tier.
  For iteration and CI.
- **full**: everything, including ARM64 track and XL stress files (rclone,
  hugo).
- **split**: `train` entries are the only legal input for tuning heuristics,
  transform orders, and PPMd parameters. `eval` entries are held out for
  published numbers. The split is by project *family*; both profiles use the
  same split.

## Tiers

S < 0.5 MB, M 0.5–5 MB, L 5–30 MB, XL > 30 MB. XL files would dominate any
byte-sum metric, so publish both the per-file mean and the aggregate, as
decided in the corpus design notes.

## Tracks

- `pe-x64` — main track.
- `pe-x86` — 32-bit coverage (Notepad++, PuTTY).
- `pe-arm64` — foreign-ISA control: shows how much of the win comes from PE
  structure vs. x86 semantics, and baselines a future ARM64 parser. Not part
  of the headline x86/x64 aggregate.

## Toolchain evidence

`compiler` claims are backed by `toolchain_evidence` per entry, produced by
`inspect_toolchain.py`: Rich header build ids for MSVC-family builds, string
markers for Rust/Go/FPC/Delphi. Notably, PuTTY carries no Rich header because
upstream cross-compiles official Windows builds with clang-cl/lld-link — a
useful non-MSVC control inside the "classic C" category.
