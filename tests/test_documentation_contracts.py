import re
import unittest
from pathlib import Path
from urllib.parse import unquote

from src.api.main import app
from src.core.scheduler_registry import JOB_REGISTRY
from src.models import Base


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


class DocumentationContractTests(unittest.TestCase):
    def test_api_reference_covers_every_openapi_operation(self):
        api_reference = (REPOSITORY_ROOT / "docs/API.md").read_text()
        for path, methods in app.openapi()["paths"].items():
            route = path.removeprefix("/api/v1") or "/"
            for method in methods:
                if method.lower() in {"head", "options"}:
                    continue
                with self.subTest(method=method.upper(), path=route):
                    self.assertIn(f"{method.upper()} {route}", api_reference)

    def test_database_schema_reference_covers_all_tables_columns_and_nullability(self):
        reference = (REPOSITORY_ROOT / "docs/DATABASE_SCHEMA.md").read_text().splitlines()
        heading = re.compile(r"^###\s+\d+(?:\.\d+)?\s+`([^`]+)`")
        documented_columns: dict[str, set[str]] = {}
        mismatches = []
        table_name = None
        nullable_index = None

        for line_number, line in enumerate(reference, start=1):
            match = heading.match(line)
            if match:
                table_name = match.group(1)
                documented_columns.setdefault(table_name, set())
                nullable_index = None
                continue

            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if cells and cells[0] == "Column" and "Nullable" in cells:
                nullable_index = cells.index("Nullable")
                continue

            if table_name not in Base.metadata.tables or not cells or not cells[0].startswith("`"):
                continue

            column_name = cells[0].strip("`")
            table = Base.metadata.tables[table_name]
            if column_name not in table.c:
                continue
            documented_columns[table_name].add(column_name)

            model_type = type(table.c[column_name].type).__name__
            if model_type == "String" and table.c[column_name].type.length:
                model_type += f"({table.c[column_name].type.length})"
            documented_type = cells[1].strip("`*") if len(cells) > 1 else ""
            if documented_type != model_type:
                mismatches.append(
                    f"line {line_number} {table_name}.{column_name}: documented type {documented_type}, model {model_type}"
                )

            if nullable_index is not None and len(cells) > nullable_index:
                expected = "YES" if table.c[column_name].nullable else "NO"
                actual = cells[nullable_index]
                if actual != expected:
                    mismatches.append(
                        f"line {line_number} {table_name}.{column_name}: documented {actual}, model {expected}"
                    )

        if set(Base.metadata.tables) != set(documented_columns):
            mismatches.append("documented table headings do not match the mapped model tables")
        for name, table in Base.metadata.tables.items():
            missing = set(table.c.keys()) - documented_columns.get(name, set())
            if missing:
                mismatches.append(f"{name}: undocumented columns {sorted(missing)}")

        self.assertEqual([], mismatches, "\n".join(mismatches))

    def test_database_schema_index_summary_covers_non_primary_indexes(self):
        reference = (REPOSITORY_ROOT / "docs/DATABASE_SCHEMA.md").read_text().splitlines()
        try:
            start = next(index for index, line in enumerate(reference) if line == "### Index Summary by Table")
        except StopIteration:
            self.fail("Database schema reference has no index summary section")
        documented: dict[str, set[str]] = {}
        for line in reference[start + 1:]:
            if line.startswith("### "):
                break
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) < 2 or not cells[0].startswith("`"):
                continue
            table_name = cells[0].strip("`")
            documented.setdefault(table_name, set()).update(re.findall(r"`([^`]+)`", cells[1]))

        missing = []
        for table_name, table in Base.metadata.tables.items():
            indexed_columns = {
                column.name
                for index in table.indexes
                for column in index.columns
                if not column.primary_key
            }
            indexed_columns.update(
                column.name for column in table.columns
                if (column.index or column.unique) and not column.primary_key
            )
            absent = indexed_columns - documented.get(table_name, set())
            if absent:
                missing.append(f"{table_name}: {sorted(absent)}")
        self.assertEqual([], missing, "\n".join(missing))

    def test_environment_reference_covers_template_variables(self):
        template = (REPOSITORY_ROOT / ".env.example").read_text()
        reference = (REPOSITORY_ROOT / "docs/reference/config/env_example.md").read_text()
        variables = re.findall(r"^([A-Z][A-Z0-9_]*)=", template, flags=re.MULTILINE)
        missing = [name for name in variables if f"`{name}`" not in reference]
        self.assertEqual([], missing, f"Environment reference omits: {', '.join(missing)}")

    def test_routed_pages_components_and_api_routes_have_reference_pages(self):
        sources_and_docs = (
            (REPOSITORY_ROOT / "web/src/pages", REPOSITORY_ROOT / "docs/reference/web/pages", ".tsx", ".md"),
            (REPOSITORY_ROOT / "web/src/components", REPOSITORY_ROOT / "docs/reference/web/components", ".tsx", ".md"),
            (REPOSITORY_ROOT / "src/api/routes", REPOSITORY_ROOT / "docs/reference/api/routes", ".py", ".md"),
        )
        missing = []
        for source_dir, docs_dir, source_suffix, docs_suffix in sources_and_docs:
            for source in source_dir.glob(f"*{source_suffix}"):
                if source.stem == "__init__":
                    continue
                reference = docs_dir / f"{source.stem}{docs_suffix}"
                if not reference.is_file():
                    missing.append(reference.relative_to(REPOSITORY_ROOT).as_posix())
        self.assertEqual([], missing, f"Missing source references: {', '.join(missing)}")

    def test_scheduler_reference_covers_registered_jobs(self):
        reference = (REPOSITORY_ROOT / "docs/SCHEDULER.md").read_text()
        missing = [job["function"] for job in JOB_REGISTRY.values() if job["function"] not in reference]
        self.assertEqual([], missing, f"Scheduler guide omits: {', '.join(missing)}")

    def test_operations_reference_matches_scheduler_registry_defaults(self):
        reference = (REPOSITORY_ROOT / "docs/OPERATIONS_REFERENCE.md").read_text()
        section = reference.split("## Frequency Controls", 1)[1].split(
            "The WebSocket dashboard broadcaster", 1
        )[0]
        documented = {}
        for line in section.splitlines():
            if not line.startswith("|"):
                continue
            cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
            if len(cells) != 3:
                continue
            for key in re.findall(r'JOB_REGISTRY\["([^"]+)"\]', cells[1]):
                documented[key] = cells[2]

        self.assertEqual(set(JOB_REGISTRY), set(documented))
        for key, job in JOB_REGISTRY.items():
            with self.subTest(job=key):
                if job["schedule_type"] == "interval":
                    unit = job["unit"].removesuffix("s") if job["every_value"] == 1 else job["unit"]
                    expected = f'{job["every_value"]} {unit}'
                elif job["schedule_type"] == "daily":
                    expected = f'daily {job["run_at"]} {job["timezone"]}'
                else:
                    expected = f'{job["weekday"]} {job["run_at"]} {job["timezone"]}'
                self.assertIn(expected.casefold(), documented[key].casefold())
                if not job.get("can_disable", True):
                    self.assertIn("cannot be disabled", documented[key].casefold())

    def test_local_markdown_links_resolve(self):
        link_pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
        code_fence = re.compile(r"```.*?```", flags=re.DOTALL)
        broken = []

        markdown_files = list((REPOSITORY_ROOT / "docs").rglob("*.md"))
        markdown_files.extend(REPOSITORY_ROOT.glob("*.md"))
        for source in markdown_files:
            markdown = code_fence.sub("", source.read_text())
            for destination in link_pattern.findall(markdown):
                target = destination.strip().split(maxsplit=1)[0].strip("<>")
                if not target or re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                    continue
                target_path = unquote(target.split("#", 1)[0])
                if not target_path:
                    continue
                resolved = (source.parent / target_path).resolve()
                if not resolved.exists():
                    broken.append(f"{source.relative_to(REPOSITORY_ROOT)} -> {target}")

        self.assertEqual([], broken, "\n".join(broken))


if __name__ == "__main__":
    unittest.main()
