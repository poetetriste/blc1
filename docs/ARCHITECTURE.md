# Architecture

BLC1 is a lossless, structure-aware container for Windows PE files. The encoder
evaluates reversible representations per segment and stores a method only when its
complete framed size beats the simpler alternatives.

## Pipeline

```text
input bytes
    |
    v
defensive PE parser -----> generic whole-file fallback
    |
    v
headers / sections / gaps / overlay
    |
    +--> raw or LZMA2
    +--> x86 BCJ + LZMA2
    +--> semantic instruction multiplexer
    +--> .pdata / .reloc column transforms
    +--> relocation-directed pointer transforms
    +--> embedded DEFLATE recompression
    |
    v
bounded BLC1 framing + original SHA-256
```

## PE coverage

The parser emits a complete, non-overlapping sequence of segments. Headers, section
padding, inter-section gaps, certificate data, and overlays remain represented. If a
file is not a valid supported PE image, the generic segment path keeps the codec
lossless rather than guessing structure.

## Executable sections

iced-x86 decodes x86 and x64 instructions. The encoder separates instruction shape
from values such as branches, immediates, displacements, and RIP-relative references.
The skeleton competes between LZMA and adaptive PPMd orders; typed value streams use
independent reversible transforms and LZMA coding. Decoder-side multiplexing restores
the exact original instruction bytes.

## Data sections

PE metadata drives transforms rather than byte-frequency guesses alone:

- `.pdata` and `.reloc` are columnized into more homogeneous streams;
- base relocations identify absolute pointers suitable for normalization;
- two-byte word transposition targets UTF-16-like layouts;
- resource data is inspected for embedded DEFLATE streams and can be represented by
  preflate metadata plus recompressed content.

## Selection and integrity

Every candidate pays its own framing cost during selection. The decoder rejects
unknown methods, inconsistent lengths, truncated streams, trailing data where
forbidden, and final SHA-256 mismatches. Declared original sizes bound decompression.

## Non-goals for the current prototype

- stable long-term archive compatibility;
- runnable executable packing;
- ELF, Mach-O, or WebAssembly specialization;
- low-latency encoding;
- a claim of universal or absolute maximum-ratio leadership.
