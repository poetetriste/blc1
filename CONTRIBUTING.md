# Contributing

BLC1 is an experimental format. Contributions are welcome, especially when they
improve compression without weakening exact restoration, decoder bounds, or
benchmark reproducibility.

## Development setup

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
```

Before opening a pull request, run:

```powershell
.\.venv\Scripts\python.exe -m ruff format --check src tests
.\.venv\Scripts\python.exe -m ruff check src tests
.\.venv\Scripts\python.exe -m pytest
```

## Ground rules

- Preserve byte-exact round trips and add a regression test for every format change.
- Treat archive input as untrusted and keep all decoded sizes explicitly bounded.
- Report complete archive sizes, not payload-only figures.
- Pin competitor versions and commands in benchmark reports.
- Do not add proprietary binaries, Windows system files, or generated archives.
- Separate measured results from hypotheses and avoid unverified record claims.

Format changes should document compatibility impact in the pull request. Until a
stable specification exists, archives produced by development versions may not remain
compatible with later revisions.
