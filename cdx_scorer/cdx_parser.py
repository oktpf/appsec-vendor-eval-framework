"""Parse CycloneDX 1.6 JSON SBOM reports into normalized component records."""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Component:
    """A single software component from a CycloneDX BOM."""
    name: str
    version: str
    license_id: Optional[str]          # e.g. "MIT", "GPL-3.0-or-later"
    license_name: Optional[str]        # free-text fallback
    license_expression: Optional[str]  # e.g. "(BSD-3-Clause OR GPL-2.0)"
    purl: str                          # package URL
    is_dev: bool                       # dependency-type = dev
    component_type: str                # library, application, framework
    found_depends_on: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)  # full raw record for debugging


def parse_cdx_report(path: str | Path) -> dict:
    """Parse a CycloneDX JSON report and return metadata + component list.

    Returns dict with keys:
      metadata: tool name, version, specVersion
      components: list[Component]
      dependencies: raw dependency graph
    """
    path = Path(path)
    raw = json.loads(path.read_text())

    # Validate BOM format
    bom_format = raw.get("bomFormat", "")
    spec_ver = raw.get("specVersion", "")

    # Extract tool metadata
    tool_name = "unknown"
    tool_ver = ""
    meta_tools = raw.get("metadata", {}).get("tools", [])
    if meta_tools:
        first = meta_tools[0] if isinstance(meta_tools, list) else meta_tools
        if isinstance(first, dict):
            tool_name = first.get("name", first.get("vendor", "unknown"))
            tool_ver = first.get("version", "")

    # Extract dependency graph
    deps_raw = raw.get("dependencies", [])
    depends_on_map = {}
    for dep in deps_raw:
        ref = dep.get("ref", "")
        depends_on_map[ref] = dep.get("dependsOn", [])

    # Parse components
    components = []
    for comp in raw.get("components", []):
        name = comp.get("name", "")
        version = comp.get("version", "")
        purl = comp.get("purl", f"pkg:unknown/{name}@{version}")
        component_type = comp.get("type", "library")

        # Extract license info
        license_id = None
        license_name = None
        license_expression = None
        licenses_raw = comp.get("licenses", [])
        if licenses_raw:
            for lic_entry in licenses_raw:
                if "expression" in lic_entry:
                    license_expression = lic_entry["expression"]
                elif "license" in lic_entry:
                    inner = lic_entry["license"]
                    if "id" in inner:
                        license_id = inner["id"]
                    elif "name" in inner:
                        license_name = inner["name"]

        # Extract dev/prod context from properties
        is_dev = False
        for prop in comp.get("properties", []):
            pname = prop.get("name", "")
            pval = prop.get("value", "")
            if pname in ("dependency-type", "cdx:dependency-type") and pval == "dev":
                is_dev = True

        # Look up transitive dependents
        found_deps = depends_on_map.get(purl, [])

        components.append(Component(
            name=name,
            version=version,
            license_id=license_id,
            license_name=license_name,
            license_expression=license_expression,
            purl=purl,
            is_dev=is_dev,
            component_type=component_type,
            found_depends_on=found_deps,
            raw=comp,
        ))

    return {
        "metadata": {
            "tool_name": tool_name,
            "tool_version": tool_ver,
            "bom_format": bom_format,
            "spec_version": spec_ver,
            "total_components": len(components),
        },
        "components": components,
        "dependencies": depends_on_map,
    }


def load_cdx_reports(directory: str | Path) -> dict[str, dict]:
    """Load all CycloneDX JSON files from a directory, keyed by tool name.

    Directory layout:
      ./reports/
        tool-a.json
        tool-b.json
        subdir/tool-c.json

    Returns {tool_name: parsed_report}
    """
    directory = Path(directory)
    reports = {}

    for fpath in sorted(directory.rglob("*.json")):
        try:
            report = parse_cdx_report(fpath)
            tool = report["metadata"]["tool_name"]
            # Avoid duplicate tool names by appending parent dir
            stem = fpath.stem
            if stem != tool:
                tool = f"{tool} ({stem})"
            reports[tool] = report
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            print(f"  SKIP {fpath.name}: {e}")

    return reports
