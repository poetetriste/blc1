# BLC1 PE benchmark snapshot

Snapshot date: 2026-11-11.

This is an exploratory local-corpus result, not yet an independently reproduced
leaderboard. Every number is the complete archive size. Every BLC1 archive was
decoded and compared byte-for-byte with its input; the codec also verifies SHA-256.

## Baseline

- 7-Zip 26.06 x64 standalone console build, released 2026-11-06.
- Command: `7za a -t7z -mx=9 -m0=BCJ -m1=LZMA2 output.7z input`.
- Archive inspection reports `Method = BCJ LZMA2` and includes normal 7z headers.
- BLC1 uses preset 9 and includes its complete container, segment metadata, and digest.
  Its adaptive resource path uses Microsoft preflate-rs 0.7.6 with internal Zstandard
  level 14 only when the complete representation is smaller.
- Executable instruction skeletons additionally compete with PPMd Variant H using a
  256 MiB model and an adaptive order from 8, 16, 20, 24, or 32. Typed constants remain
  in independently coded LZMA streams.

## Results

| Input | Arch | Input bytes | BLC1 | 7-Zip | BLC1 delta |
|---|---|---:|---:|---:|---:|
| Windows `7z.exe` | x64 | 533,504 | 151,021 | 173,415 | -12.914% |
| Windows `notepad.exe` | x64 | 360,448 | 139,792 | 178,697 | -21.771% |
| Windows PowerShell | x64 | 495,616 | 131,588 | 136,626 | -3.687% |
| Windows `kernel32.dll` | x64 | 861,992 | 273,752 | 315,861 | -13.331% |
| Windows `notepad.exe` | x86 | 307,712 | 137,326 | 169,414 | -18.941% |
| Windows `kernel32.dll` | x86 | 707,744 | 238,209 | 266,885 | -10.745% |
| 7-Zip `7z.exe` | x64 | 564,736 | 160,715 | 184,299 | -12.797% |
| 7-Zip `7zFM.exe` | x64 | 990,720 | 256,777 | 299,151 | -14.165% |
| 7-Zip `7zG.exe` | x64 | 712,704 | 197,449 | 227,506 | -13.212% |
| OpenVPN | x64 | 902,144 | 272,785 | 329,795 | -17.286% |
| Cygwin `ssh-keygen.exe` | x64 | 479,251 | 134,250 | 156,720 | -14.338% |
| Android Studio launcher | x64 | 692,376 | 239,722 | 274,714 | -12.738% |
| Android Studio `fsnotifier.exe` | x64 | 138,392 | 59,651 | 64,693 | -7.794% |
| **Total** | mixed | **7,747,339** | **2,393,037** | **2,777,776** | **-13.851%** |

BLC1 is smaller on 13 of 13 samples and saves 384,739 bytes in aggregate. The
margin ranges from 3.687% to 21.771%. Adaptive PPMd order selection reduced the
preceding BLC1 total by another 9,050 bytes (0.377%) with no corpus regressions.

## Important limitations

- Eleven samples are x64 and only two are x86.
- Several files come from the local Windows installation and are not a redistributable corpus.
- Results have not yet been reproduced on a clean machine.
- Encode time is currently high because the research encoder exhaustively evaluates LZMA
  context settings and multiple reversible transforms. The Python prototype prioritizes size.
- The selected PPMd configuration allocates a 256 MiB model per active skeleton encoder or
  decoder. Peak memory, parallelism, and lower-memory Pareto points still require measurement.
- Archives that select the preflate method require the bundled versioned native decoder DLL;
  clean-machine packaging and non-Windows builds still need verification.
- No claim is made yet for ELF, WASM, arbitrary binaries, runnable packing, decode speed,
  peak memory, or maximum-ratio compressors such as PAQ8PX.

The next publication-quality milestone is a version-pinned public PE corpus, a scripted
benchmark harness, speed and memory measurements, and independent reproduction.

<!-- PUBLIC-CORPUS:BEGIN -->

## Public corpus (lite profile)

Every file below is fetched and hash-verified by `corpus/fetch.py` from
pinned upstream releases; see `corpus/manifest.json` for versions,
licenses, and toolchain evidence. Baseline: 7-Zip 26.06 with
`7z a -t7z -mx=9 -m0=BCJ -m1=LZMA2`. Every BLC1 archive was decoded
and matched byte-for-byte against its input.

| Entry | Track | Compiler | Input bytes | BLC1 | 7-Zip | BLC1 delta |
|---|---|---|---:|---:|---:|---:|
| 7-Zip 26.06 | pe-x64 | MSVC | 574,464 | 163,728 | 187,864 | -12.848% |
| PuTTY 0.85 | pe-x64 | clang-cl (cross-build) | 1,706,136 | 790,791 | 843,695 | -6.271% |
| fd 10.5.2 | pe-x64 | Rust (MSVC ABI) | 4,163,584 | 916,563 | 1,107,137 | -17.213% |
| ripgrep 15.2.0 | pe-x64 | Rust (MSVC ABI) | 4,218,880 | 1,083,271 | 1,259,805 | -14.013% |
| bat 0.26.1 | pe-x64 | Rust (MSVC ABI) | 7,342,592 | 2,574,307 | 2,861,780 | -10.045% |
| PeaZip 11.4.0 | pe-x64 | FreePascal / Lazarus | 7,729,152 | 1,311,172 | 1,648,114 | -20.444% |
| Notepad++ 8.9.9.1 | pe-x86 | MSVC | 7,794,672 | 3,061,537 | 3,665,128 | -16.468% |
| Notepad++ 8.9.9.1 | pe-x64 | MSVC | 8,594,928 | 3,220,673 | 3,883,637 | -17.071% |
| **Total** | mixed | mixed | **42,124,408** | **13,122,042** | **15,457,160** | **-15.107%** |

BLC1 is smaller on 8 of 8 samples. Mean per-file delta: -14.297%. Worst case: putty-x64 at -6.271%; best case: peazip-x64 at -20.444%.

Encoder wall time (research prototype, preset 9): BLC1 1208s total vs 7-Zip 6.0s. Speed is not yet a published metric; see limitations.

Entries absent from this table are pending an encoder run; the
section is regenerated by `corpus/report.py --write`.

<!-- PUBLIC-CORPUS:END -->
