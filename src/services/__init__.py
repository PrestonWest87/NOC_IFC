import importlib.util
import sys
from pathlib import Path

_services_path = Path(__file__).resolve().parent.parent / "services.py"
_spec = importlib.util.spec_from_file_location("src.services", str(_services_path))
_mod = importlib.util.module_from_spec(_spec)
_mod.__path__ = __path__  # preserve __path__ so submodules (logic, ioc_extractor, etc.) resolve
sys.modules["src.services"] = _mod
_spec.loader.exec_module(_mod)
