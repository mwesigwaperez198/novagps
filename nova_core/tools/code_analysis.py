"""Code analysis and security audit tools for the NovaGPS codebase."""

import ast
import hashlib
import json
import os
import re
from pathlib import Path
from typing import Optional

from ..tools import Tool, ToolResult, ToolRegistry
from ..config import get_config


class SecretLeakDetector(Tool):
    name = "secret_scan"
    description = "Scan the codebase for hardcoded secrets, API keys, passwords, and tokens."
    category = "code_analysis"

    def execute(self, directory: str = "", **kwargs) -> ToolResult:
        cfg = get_config()
        scan_dir = Path(directory) if directory else cfg.backend_dir
        if not scan_dir.exists():
            scan_dir = cfg.project_root

        patterns = [
            (r"(?:api[_-]?key|apikey)\s*[=:]\s*['\"]([^'\"]{8,})", "API key"),
            (r"(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{4,})", "Password"),
            (r"(?:secret[_-]?key|SECRET_KEY)\s*[=:]\s*['\"]([^'\"]{8,})", "Secret key"),
            (r"(?:token|bearer)\s*[=:]\s*['\"]([A-Za-z0-9_\-\.]{20,})", "Token"),
            (r"ghp_[A-Za-z0-9]{36}", "GitHub PAT"),
            (r"sk-[A-Za-z0-9]{20,}", "OpenAI API key"),
            (r"xoxb-[A-Za-z0-9\-]+", "Slack bot token"),
            (r"(?:jdbc|mysql|postgresql)://[^\s'\"}]+", "Database connection string"),
        ]

        findings = []
        scanned_files = 0

        for fpath in scan_dir.rglob("*.py"):
            if ".git" in str(fpath) or "__pycache__" in str(fpath) or "test_" in fpath.name:
                continue
            try:
                content = fpath.read_text(errors="replace")
                scanned_files += 1
                for pattern, label in patterns:
                    for match in re.finditer(pattern, content, re.IGNORECASE):
                        line_num = content[:match.start()].count("\n") + 1
                        value_preview = match.group(1)[:8] + "..." if match.lastindex else match.group(0)[:16] + "..."
                        findings.append({
                            "file": str(fpath.relative_to(cfg.project_root)),
                            "line": line_num,
                            "type": label,
                            "preview": value_preview,
                            "severity": "critical" if label in ("GitHub PAT", "Secret key", "Password") else "high",
                        })
            except Exception:
                continue

        web_exts = (".js", ".jsx", ".ts", ".tsx", ".env", ".env.example", ".env.local")
        for ext in web_exts:
            for fpath in cfg.project_root.rglob(f"*{ext}"):
                if "node_modules" in str(fpath) or "dist" in str(fpath) or ".git" in str(fpath):
                    continue
                try:
                    content = fpath.read_text(errors="replace")
                    scanned_files += 1
                    for pattern, label in patterns:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            line_num = content[:match.start()].count("\n") + 1
                            value_preview = match.group(1)[:8] + "..." if match.lastindex else match.group(0)[:16] + "..."
                            findings.append({
                                "file": str(fpath.relative_to(cfg.project_root)),
                                "line": line_num,
                                "type": label,
                                "preview": value_preview,
                                "severity": "critical",
                            })
                except Exception:
                    continue

        return ToolResult(
            success=True,
            output={
                "files_scanned": scanned_files,
                "findings": findings,
                "finding_count": len(findings),
                "risk_level": "critical" if any(f["severity"] == "critical" for f in findings) else
                             "high" if findings else "low",
            },
        )


class CodeComplexityAnalyzer(Tool):
    name = "complexity_scan"
    description = "Analyze code complexity and identify overly complex functions."
    category = "code_analysis"

    def execute(self, file_path: str = "", **kwargs) -> ToolResult:
        cfg = get_config()
        target = Path(file_path) if file_path else cfg.backend_dir / "main.py"

        if not target.exists():
            return ToolResult(success=False, output=None, error=f"File not found: {target}")

        try:
            source = target.read_text()
            tree = ast.parse(source)

            functions = []
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    lines = source.count("\n") + 1
                    func_source = ast.get_source_segment(source, node)
                    complexity = self._calc_complexity(node)
                    loc = func_source.count("\n") if func_source else 0

                    functions.append({
                        "name": node.name,
                        "line": node.lineno,
                        "complexity": complexity,
                        "loc": loc,
                        "risk": "high" if complexity > 15 or loc > 100 else
                               "medium" if complexity > 8 or loc > 50 else "low",
                    })

            functions.sort(key=lambda f: f["complexity"], reverse=True)

            return ToolResult(
                success=True,
                output={
                    "file": str(target),
                    "total_functions": len(functions),
                    "high_complexity": [f for f in functions if f["risk"] == "high"],
                    "top_10": functions[:10],
                },
            )
        except Exception as e:
            return ToolResult(success=False, output=None, error=str(e))

    def _calc_complexity(self, node) -> int:
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity


class DependencyAudit(Tool):
    name = "dependency_audit"
    description = "Audit Python and JavaScript dependencies for known issues."
    category = "code_analysis"

    def execute(self, **kwargs) -> ToolResult:
        cfg = get_config()
        findings = []

        req_file = cfg.backend_dir / "requirements.txt"
        if req_file.exists():
            content = req_file.read_text()
            for line in content.strip().split("\n"):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                pkg = re.split(r"[>=<~!]", line)[0].strip()
                version_spec = line[len(pkg):].strip()
                findings.append({
                    "ecosystem": "python",
                    "package": pkg,
                    "version_spec": version_spec,
                    "pinned": "=" in version_spec,
                    "has_upper_bound": "<" in version_spec,
                })

        pkg_file = cfg.project_root / "frontend" / "package.json"
        if pkg_file.exists():
            try:
                pkg_data = json.loads(pkg_file.read_text())
                for section in ["dependencies", "devDependencies"]:
                    for pkg, ver in pkg_data.get(section, {}).items():
                        findings.append({
                            "ecosystem": "javascript",
                            "package": pkg,
                            "version_spec": ver,
                            "pinned": bool(re.match(r"^[=]?\d+(?:\.\d+){1,2}(?:[-+][0-9A-Za-z.\-]+)?$", ver)),
                            "section": section,
                        })
            except Exception:
                pass

        return ToolResult(
            success=True,
            output={
                "dependencies": findings,
                "total": len(findings),
                "python_deps": len([f for f in findings if f["ecosystem"] == "python"]),
                "js_deps": len([f for f in findings if f["ecosystem"] == "javascript"]),
            },
        )


class DuplicateExportDetector(Tool):
    name = "duplicate_export_scan"
    description = "Detect duplicate exports in TypeScript/JavaScript files that break builds."
    category = "code_analysis"

    def execute(self, directory: str = "", **kwargs) -> ToolResult:
        cfg = get_config()
        scan_dir = Path(directory) if directory else cfg.project_root / "frontend"

        if not scan_dir.exists():
            return ToolResult(success=False, output=None, error=f"Directory not found: {scan_dir}")

        duplicates = []
        scanned = 0
        javascript_exts = (".ts", ".tsx", ".js", ".jsx")

        files = []
        for ext in javascript_exts:
            files.extend(scan_dir.rglob(f"*{ext}"))
        files.sort()

        for fpath in files:
            if "node_modules" in str(fpath) or "dist" in str(fpath):
                continue
            try:
                content = fpath.read_text(errors="replace")
                scanned += 1
                export_pattern = r"export\s+(?:const|function|class|let|var|default)\s+(\w+)"
                exports = re.findall(export_pattern, content)

                seen = {}
                for exp in exports:
                    if exp in seen:
                        seen[exp] += 1
                    else:
                        seen[exp] = 1

                for exp, count in seen.items():
                    if count > 1:
                        duplicates.append({
                            "file": str(fpath.relative_to(cfg.project_root)),
                            "export": exp,
                            "count": count,
                        })
            except Exception:
                continue

        return ToolResult(
            success=True,
            output={
                "files_scanned": scanned,
                "duplicates_found": len(duplicates),
                "duplicates": duplicates,
            },
        )


def register_code_analysis_tools(registry: ToolRegistry):
    for tool_cls in [SecretLeakDetector, CodeComplexityAnalyzer, DependencyAudit, DuplicateExportDetector]:
        registry.register(tool_cls())
