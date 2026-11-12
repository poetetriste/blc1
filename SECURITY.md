# Security policy

## Supported versions

BLC1 is a research prototype and has no production-supported release yet. Security
fixes are applied to the current `main` branch.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not open
a public issue for archive parsing, memory exhaustion, path handling, or native decoder
vulnerabilities until a fix is available.

Include the smallest reproducer you can share, the affected revision, expected impact,
and whether the issue is reachable during compression, decompression, or both.

## Current scope

The decoder validates framing, declared sizes, and SHA-256 integrity, but it has not
received an independent security audit. Do not process untrusted archives in a
privileged context. The bundled preflate native library is loaded only for archives
that select the embedded-DEFLATE method.
