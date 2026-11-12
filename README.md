# NutriLabel

**NutriLabel** is a command-line Python package capability inspector that generates a single-screen "Nutrition Facts" label for Python packages before you install them, mapping outbound network access, child process execution, environment variable reads, filesystem references, install hooks, and version-to-version capability diffs.

Before running `pip install` or upgrading a dependency, developers rarely know whether a library only performs pure in-memory computation or also opens sockets, spawns shell commands, reads `AWS_*` environment variables, or runs custom `setup.py` hooks. NutriLabel downloads and unpacks distributions safely without executing code, statically inspects the Python AST, and summarizes package capabilities neutrally at a glance.

---

## Who It's For

- **Python application and backend developers** evaluating third-party PyPI packages or auditing dependency upgrades before adding them to `requirements.txt` or `pyproject.toml`.
- **Open-source maintainers and CI engineers** tracking capability drift across dependency releases (`nutrilabel diff pkg 2.0.0 2.1.0`).

---

## What It's Built With

- **Language:** Python 3.10+
- **Core Architecture:** Pure Python standard library (`ast`, `zipfile`, `tarfile`, `urllib.request`, `argparse`, `json`, `unittest`) with **zero external runtime dependencies**.
- **Test Suite:** Compatible with both `pytest` and `python -m unittest`.

---

## Features

- **Zero-Execution Archive & PyPI Inspector:** Inspects PyPI distributions, `.whl` wheels, `.tar.gz` sdists, or local source directories without running `pip install` or executing `setup.py`.
- **Single-Screen "Nutrition Facts" Label:** Summarizes file count, lines of code, declared dependencies, capability badges (`[Pure-Computation]`, `[Network-Enabled]`, `[Subprocess-Capable]`, `[Env-Configured]`), and an overall complexity/caution grade (`A`–`D`).
- **Built-in AST Capability Detectors (`NL001` – `NL005`):**
  - `NL001` (`Network Access`): Detects `socket`, `urllib`, `http.client`, `requests`, `httpx`, `aiohttp` calls and hardcoded URL/IP endpoints (`⚠`).
  - `NL002` (`Process Execution`): Detects `subprocess.*`, `os.system`, `os.popen`, `os.exec*`, and `pty.spawn`.
  - `NL003` (`Environment & Filesystem`): Detects `os.environ` / `os.getenv` reads (highlighting key prefixes such as `AWS_*`, `GITHUB_*`, `TOKEN`) and sensitive path references (`~/.ssh`, `~/.aws`, `/etc/passwd`).
  - `NL004` (`Install Hooks & Dynamic Eval`): Detects `setup.py` custom `cmdclass` hooks and `eval()`, `exec()`, or `base64.b64decode` + `exec` patterns.
  - `NL005` (`Native Binary Extensions`): Detects pre-compiled `.so`, `.pyd`, `.dll`, and `.dylib` binaries.
- **Version-to-Version Capability Diff (`nutrilabel diff`):** Compares two versions of a package and highlights newly introduced capabilities (e.g., *"Process Execution newly added in 2.1.0"*).

```text
 ┌──────────────────────────────────────────────────────┐
 │ Package Nutrition Facts       requests-toolkit 2.1.0 │
 │ Files: 2 · Lines: 22 · Deps: 2                       │
 ├──────────────────────────────────────────────────────┤
 │ Network Access              Present   2 place(s)     │
 │   └ Hardcoded Endpoints     1 found   ⚠              │
 │ Process Execution           Present   1 place(s)     │
 │ Environment Read            Present   AWS_SECRET_AC… │
 │ Home/Sensitive Files        Present   ~/.ssh ⚠       │
 │ Install-Time Execution      Present   cmdclass ⚠     │
 │ Obfuscation (base64+exec)   None                     │
 │ Native Binary Extensions    None                     │
 ├──────────────────────────────────────────────────────┤
 │ Overall: Grade C (4 notable item(s))                 │
 │ Badges: [Network-Enabled], [Subprocess-Capable], [E… │
 └──────────────────────────────────────────────────────┘
 Details: nutrilabel requests-toolkit --explain
```

---

## How to Run It

### 1. Install

```bash
git clone https://github.com/Dharmogata/nutrilabel.git
cd nutrilabel
pip install -e .
```

### 2. Inspect a Package or Compare Versions

```bash
# Inspect a PyPI package or local directory/wheel
nutrilabel requests-toolkit
nutrilabel ./path/to/package --explain

# Export Nutrition Facts as JSON or Markdown
nutrilabel ./path/to/package --format json
nutrilabel ./path/to/package --explain --format markdown

# Compare capabilities between two package versions or directories
nutrilabel diff requests 2.31.0 2.32.0
nutrilabel diff ./pkg-v2.0 ./pkg-v2.1

# List all built-in AST capability detectors
nutrilabel rules
```

### 3. Run the Test Suite

```bash
# Using pytest
pytest -v

# Or using standard library unittest
PYTHONPATH=src python -m unittest discover -s tests -v
```

---

## Planned Work Ahead (TODO & Roadmap)

NutriLabel has **200+ hours of planned engineering work** detailed in [ROADMAP.md](ROADMAP.md):

- [ ] **Phase 2 (~35h): Extended AST Capability Catalog (`NL006`–`NL020`) & String Constant Folding** (detect `ctypes`/`cffi` native FFI loading, `pickle`/`marshal` deserialization, clipboard/keychain access, `getattr(os, "sys" + "tem")` constant-folding resolution, and `importlib` dynamic imports).
- [ ] **Phase 3 (~40h): Transitive Dependency Tree Nutrition Aggregator** (resolve the full dependency graph from `Requires-Dist` / `requirements.lock` / `poetry.lock` / `uv.lock` and distinguish direct package capabilities from transitive dependency capabilities).
- [ ] **Phase 4 (~35h): Lockfile & Pull Request Diff Auditor (`nutrilabel audit-diff`)** (parse `git diff` changes to `requirements.txt`, `pyproject.toml`, `poetry.lock`, and `uv.lock` to generate capability diff summaries automatically on pull requests).
- [ ] **Phase 5 (~40h): Context-Aware Capability Profiles & Policy Budgets (`.nutrilabel.toml`)** (declare expected package capability profiles so a pure data parser gaining `Network Access` fails CI while an HTTP client using `socket` passes cleanly).
- [ ] **Phase 6 (~35h): CycloneDX SBOM Capability Annotations, SARIF Exporter & SVG Badge Generator** (export capability profiles as CycloneDX properties, SARIF v2.1.0 reports, and embeddable SVG Nutrition Facts cards for READMEs).

See [ROADMAP.md](ROADMAP.md) for the complete specification.

---

## License

Released under the [MIT License](LICENSE).
