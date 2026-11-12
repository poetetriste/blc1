# Binary lossless compression market map

Snapshot date: 2026-11-11.

## Competitive groups

| Group | Reference implementations | What they optimize | Gap relevant to this project |
|---|---|---|---|
| Production general-purpose | Zstandard, LZ4, Brotli | Throughput, mature APIs, broad deployment | Limited executable semantics |
| Dense classical | XZ/LZMA2, 7-Zip, bzip3 | Small archives with practical decoders | Mostly generic matching plus BCJ-style filters |
| Format-aware graph systems | OpenZL | Specialized transform graphs with a universal decoder | Requires a data description; no dedicated PE/ELF instruction model found |
| Modular transform pipelines | Kanzi | Runtime-selected BWT, CM, LZ, ANS, and content transforms | Broad rather than executable-specialized |
| Maximum-ratio context mixing | PAQ8PX, cmix, ZPAQ | Minimum size at extreme CPU and memory cost | Impractical speed; PAQ8PX already has a strong x86/x64 model |
| Neural predictive coding | NNCP, Nacrith | Model probability plus arithmetic coding | Nacrith's NC06 sends opaque binary bytes to gzip/LZMA |
| Executable packers | UPX | A compressed file that remains directly runnable | Loader stubs, signatures, relocations, and security form a separate product |

## Closest prior art

### Nacrith NC06

The code segments printable text runs, neural-compresses those runs, merges the
remaining binary chunks, and chooses gzip, LZMA, or raw storage for that blob. It is
an important direct competitor to any broad “LLM compressor for binaries” claim, but
it does not model opaque machine code, PE/ELF metadata, relocations, or instruction
operands.

### PAQ8PX

PAQ8PX combines an E8/E9-style reversible transform with an x86/x64 instruction
state machine. The model tracks prefixes, opcode families, ModRM, SIB, immediate and
displacement states, branch categories, and instruction history. Its ratio is the
quality target; its runtime and memory profile leave room for a practical system.

### OpenZL

OpenZL validates the product direction: specialized reversible transforms can beat a
generic codec while retaining a universal decoder. Its numeric delta, transpose,
bitsplit, and learned graph selector are architectural references. The opportunity is
an executable-specific analyzer and transform family.

### UPX

UPX uses architecture filters and NRV/LZMA, then adds a loader stub so the packed
program remains runnable. That property must be benchmarked separately from ordinary
archive compression.

## Proposed product wedge

The first target is a self-contained archive codec for PE/COFF, followed by ELF and
WASM. It should parse structure and expose separate streams for:

1. instruction opcodes and prefixes;
2. ModRM/SIB and register fields;
3. immediates and displacements;
4. relative branch and call targets;
5. relocations and address-like values;
6. imports, exports, symbols, and strings;
7. resources, padding, and opaque/already-compressed regions.

Each transform must be reversible and independently selectable. A lightweight model
can later score candidate transforms or predict instruction fields. Opaque data keeps
a raw/store fallback.

## Benchmark doctrine

No single universal “best compressor” claim is acceptable. Publish separate tracks:

- **Archive track:** complete self-contained archive size, encode/decode speed, peak
  memory, hashes, and byte-exact round trip.
- **Shared-model track:** payload plus an explicit statement of model identity and
  model-size amortization.
- **Runnable-packer track:** final executable size, startup cost, runtime memory,
  signature behavior, AV false positives, and functional execution tests.

The initial corpus must include Silesia controls plus a reproducible, version-pinned
set of open PE, ELF, and WASM binaries. Training and evaluation families must be
separated to prevent compiler/project memorization.

## Primary references

- https://github.com/meta/zstd
- https://github.com/lz4/lz4
- https://github.com/google/brotli
- https://github.com/tukaani-project/xz
- https://github.com/ip7z/7zip
- https://github.com/facebook/openzl
- https://github.com/flanglet/kanzi
- https://github.com/hxim/paq8px
- https://github.com/byronknoll/cmix
- https://bellard.org/nncp/
- https://github.com/robtacconelli/Nacrith-GPU
- https://github.com/upx/upx
- https://github.com/inikep/lzbench
- https://www.mattmahoney.net/dc/silesia.html
