# NutriLabel Engineering Roadmap (200+ Hours)

This roadmap details the planned multi-phase evolution of **NutriLabel** from a single-package AST capability inspector and version differ into a transitive dependency nutrition aggregator, lockfile diff auditor, declarative capability policy engine, and CycloneDX SBOM annotator.

---

## Phase 1: Core Archive Extractor, AST Capability Detectors & Version Differ (Completed - v0.1.0)
- [x] Zero-execution package extractor (`extractor.py`) supporting local directories, `.whl` wheels, `.tar.gz` sdists, and PyPI JSON API downloads.
- [x] Foundational AST capability detectors `NL001` (network & hardcoded endpoints), `NL002` (subprocess & shell execution), `NL003` (environment variables & sensitive paths), `NL004` (`setup.py` hooks & dynamic/encoded eval), and `NL005` (native binaries).
- [x] Box-drawn terminal Nutrition Facts label formatter, `--explain` code snippet reporter, and `json`/`markdown` exporters.
- [x] Version-to-version capability diff engine (`nutrilabel diff`).

---

## Phase 2: Extended AST Capability Detectors (`NL006`–`NL020`) & Constant Folding (~35 Hours)
- [ ] **AST String Constant Folder (`constant_folder.py`):** Evaluate static string concatenations (`"sys" + "tem"`), `chr()` joins, and tuple unpacking before running detectors so indirect lookups like `getattr(os, "sys" + "tem")` are resolved.
- [ ] **Detector `NL006` (Foreign Function Interfaces):** Detect `ctypes.CDLL`, `ctypes.windll`, and `cffi.FFI().dlopen` native library invocation.
- [ ] **Detector `NL007` (Unsafe Deserialization):** Detect `pickle.loads`, `yaml.load` (without `SafeLoader`), `marshal.loads`, and `shelve.open`.
- [ ] **Detector `NL008` (Filesystem Write & Temp Mutation):** Distinguish read-only filesystem operations from file writes, deletions (`shutil.rmtree`, `os.remove`), and permission changes (`os.chmod`).
- [ ] **Detector `NL009` – `NL020`:** Thread/multiprocessing spawning, signal handlers, Monkey-patching `builtins`, import hook registration (`sys.meta_path`), and telemetry beacon heuristics.

---

## Phase 3: Transitive Dependency Tree Nutrition Aggregator (~40 Hours)
- [ ] **Dependency Graph Resolver (`resolver.py`):** Recursively inspect `Requires-Dist` metadata across direct and transitive dependencies with local wheel caching in `.nutrilabel_cache/`.
- [ ] **Direct vs Transitive Attribution Matrix:** Clearly separate capabilities present in the top-level package from capabilities inherited through transitive sub-dependencies (e.g., `pkg -> urllib3 -> socket`).
- [ ] **Sub-Dependency Bloat & Capability Hotspot Ranking:** Identify which transitive dependency contributes the largest number of notable capabilities or lines of code.

---

## Phase 4: Lockfile & Pull Request Upgrade Auditor (`audit-diff`) (~35 Hours)
- [ ] **Multi-Format Lockfile Parser (`lockfile.py`):** Parse `requirements.txt`, `poetry.lock`, `Pipfile.lock`, and `uv.lock` before and after a Git commit or branch update.
- [ ] **Automated Upgrade Diff Summary (`nutrilabel audit-diff --since origin/main`):** For every added or bumped package in a pull request, compute and render the capability delta table automatically.

---

## Phase 5: Declarative Capability Budgets & Policy Engine (`.nutrilabel.toml`) (~40 Hours)
- [ ] **Capability Budget Configuration:** Allow teams to declare allowed capabilities per dependency category in `pyproject.toml` or `.nutrilabel.toml` (e.g., `allow_process = ["pytest", "black"]`, `forbid_install_hooks = true`).
- [ ] **CI Gate Mode (`nutrilabel check-policy`):** Return non-zero exit codes only when a package introduces an unapproved capability or when a version upgrade adds a new capability class not present in the previous version.

---

## Phase 6: CycloneDX SBOM Annotations, SARIF & SVG Nutrition Cards (~35 Hours)
- [ ] **CycloneDX v1.5 Capability Extension:** Export detected capabilities as standardized CycloneDX component properties for software bill of materials (SBOM) pipelines.
- [ ] **SARIF v2.1.0 Output:** Emit structured SARIF reports for GitHub Code Scanning integration.
- [ ] **SVG Nutrition Label Generator (`nutrilabel badge --svg label.svg`):** Render crisp, standalone SVG Nutrition Facts labels that open-source maintainers can embed in their project READMEs to document their package's exact runtime footprint.
