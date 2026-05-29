# Services Package Init Documentation

**File:** `/home/weast/docker/NOC_IFC/src/services/__init__.py`

---

**Purpose:** Module loader that dynamically imports the monolithic `services.py` from the parent directory (`src/services.py`) and installs it as the `src.services` package module. This allows the package to expose both the monolithic module's functions and the subpackage modules (`logic.py`, `ioc_extractor.py`, etc.) under the same namespace.

**Flow:**
1. Resolves the absolute path to `src/services.py` (parent of the `__init__.py` file's directory)
2. Creates a module spec from that file path
3. Creates a module from the spec
4. Preserves `__path__` so that submodules (`logic`, `ioc_extractor`, etc.) can be resolved
5. Registers the module under `src.services` in `sys.modules`
6. Executes the module to load all functions and classes

**Dependencies:** `importlib.util`, `sys`, `pathlib.Path`
