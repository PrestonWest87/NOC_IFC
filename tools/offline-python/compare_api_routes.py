"""Compare Python and C# OpenAPI HTTP routes, ignoring documented retirements."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
from urllib.parse import urlparse
from urllib.request import urlopen


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options", "trace"}
PATH_PARAMETER = re.compile(r"\{[^{}]+\}")
RETIRED_OPERATIONS = {
    ("get", "/api/v1/admin/ml-counts"),
    ("post", "/api/v1/admin/ml-retrain"),
    ("get", "/api/v1/application-settings/ml-counts"),
    ("post", "/api/v1/application-settings/ml-retrain"),
    ("post", "/api/v1/dashboard/articles/feedback"),
}


def load_spec(source: str) -> dict:
    """Read an OpenAPI document from a local path or HTTP(S) URL."""
    if urlparse(source).scheme in {"http", "https"}:
        with urlopen(source, timeout=20) as response:
            return json.load(response)
    return json.loads(Path(source).read_text(encoding="utf-8"))


def normalize_path(path: str) -> str:
    """Ignore path-parameter names and ASP.NET route constraints when comparing shape."""
    normalized = PATH_PARAMETER.sub("{}", path)
    return normalized.rstrip("/") or "/"


def operations(spec: dict) -> set[tuple[str, str]]:
    """Extract normalized HTTP method/path pairs; WebSocket is not in OpenAPI."""
    return {
        (method.lower(), normalize_path(path))
        for path, definition in spec.get("paths", {}).items()
        if path != "/openapi/v1.json"
        for method in definition
        if method.lower() in HTTP_METHODS and path != "/ws"
    }


def compare_specs(python_spec: dict, csharp_spec: dict) -> tuple[set, set, set]:
    python_operations = operations(python_spec)
    csharp_operations = operations(csharp_spec)
    retired = {(method, normalize_path(path)) for method, path in RETIRED_OPERATIONS}
    missing = python_operations - csharp_operations
    ignored = missing & retired
    return missing - ignored, csharp_operations - python_operations, ignored


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("python_spec", help="Python OpenAPI JSON path or URL")
    parser.add_argument("csharp_spec", help="C# OpenAPI JSON path or URL")
    args = parser.parse_args()
    try:
        python_spec = load_spec(args.python_spec)
        csharp_spec = load_spec(args.csharp_spec)
        python_operations = operations(python_spec)
        csharp_operations = operations(csharp_spec)
        missing, extra, retired = compare_specs(python_spec, csharp_spec)
    except (OSError, ValueError, json.JSONDecodeError) as exception:
        parser.exit(2, f"Unable to compare OpenAPI documents: {exception}\n")

    print(f"Python operations: {len(python_operations)}")
    print(f"C# operations: {len(csharp_operations)}")
    if retired:
        print("Intentionally retired:")
        for method, path in sorted(retired):
            print(f"  {method.upper()} {path}")
    if missing:
        print("Missing from C#:")
        for method, path in sorted(missing):
            print(f"  {method.upper()} {path}")
    if extra:
        print("Only in C#:")
        for method, path in sorted(extra):
            print(f"  {method.upper()} {path}")
    if not missing and not extra:
        print("Route shapes match after the documented classifier/feedback removals.")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
