#!/usr/bin/env python3
"""Convert CodeMender JSON report to standard SARIF v2.1.0 for GitHub Code Scanning.

Usage: cm_to_sarif.py <input-report.json> <output-report.sarif>
"""
from __future__ import annotations

import json
import os
import sys


def _get(d: dict, *keys, default=""):
    for k in keys:
        if k in d and d[k] not in (None, ""):
            return d[k]
    return default


def extract_findings(raw: str) -> list[dict]:
    s = (raw or "").strip()
    if not s:
        return []
    candidates = [s]
    for opener, closer in (("[", "]"), ("{", "}")):
        i, j = s.find(opener), s.rfind(closer)
        if i != -1 and j > i:
            candidates.append(s[i : j + 1])
    for c in candidates:
        try:
            data = json.loads(c)
        except json.JSONDecodeError:
            continue
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]
        if isinstance(data, dict):
            for key in ("findings", "Findings", "results", "data"):
                if isinstance(data.get(key), list):
                    return [x for x in data[key] if isinstance(x, dict)]
            return [data]
    return []


def severity_to_level(sev: str) -> str:
    s = str(sev or "").upper()
    if s in ("CRITICAL", "HIGH"):
        return "error"
    if s == "MEDIUM":
        return "warning"
    return "note"


def main() -> int:
    in_path = sys.argv[1] if len(sys.argv) > 1 else ""
    out_path = sys.argv[2] if len(sys.argv) > 2 else ""

    raw = ""
    if in_path and os.path.exists(in_path):
        with open(in_path, encoding="utf-8", errors="replace") as fh:
            raw = fh.read()

    findings = extract_findings(raw)

    rules_map: dict[str, dict] = {}
    results = []

    for f in findings:
        fid = str(_get(f, "FindingID", "finding_id", "id", default="CM-VULN"))
        rule_id = str(_get(f, "RuleID", "rule_id", "type", "cwe", default=f"CodeMender/{fid}"))
        title = str(_get(f, "Title", "title", default="Security Finding"))
        desc = str(_get(f, "Description", "description", default=title))
        sev = str(_get(f, "Severity", "severity", default="HIGH")).upper()
        level = severity_to_level(sev)
        file_path = str(_get(f, "FilePath", "file_path", "file", default=""))
        
        # Clean relative path
        if file_path.startswith("./"):
            file_path = file_path[2:]

        try:
            line = int(_get(f, "LineNumber", "line_number", "line", default=1) or 1)
        except (ValueError, TypeError):
            line = 1

        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_id.replace("-", ""),
                "shortDescription": {"text": title},
                "fullDescription": {"text": desc},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "precision": "high",
                    "security-severity": "8.0" if level == "error" else "5.0",
                },
            }

        result = {
            "ruleId": rule_id,
            "level": level,
            "message": {
                "text": f"[{sev}] {title}: {desc}"
            },
        }

        if file_path:
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {
                            "startLine": line,
                            "startColumn": 1,
                        },
                    }
                }
            ]

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Google CodeMender",
                        "semanticVersion": "0.11.0",
                        "informationUri": "https://cloud.google.com/gemini-enterprise-agent-platform",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    if out_path:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(sarif, fh, indent=2)
        print(f"Generated SARIF report with {len(results)} findings -> {out_path}")
    else:
        json.dump(sarif, sys.stdout, indent=2)

    return 0


if __name__ == "__main__":
    sys.exit(main())
