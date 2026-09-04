#!/usr/bin/env python3
"""
Render nac-validate results as a GitHub step summary.

TWO SOURCES, CLEAR PRECEDENCE
  --format json is authoritative for everything about a FINDING: severity,
  title, explanation, recommendation, references, affected_items_label. These
  are all present in the JSON payload.

  The rule files are parsed only to build the INVENTORY - which rules exist, in
  which tier, and in which file. The JSON lists failing rules only, so without
  this there is no way to report "12 of 16 rules passed", and no way to name the
  file that needs an explanation added.

  Rule files are parsed with ast, never imported. Importing would require
  nac_validate to be present in this interpreter (it is not - nac-validate runs
  in its own environment) and would execute module-level code, which a reporting
  tool must never do.

Usage:
  validate_summary.py REPORT.json --rules DIR [--rules DIR] [--exitcode N]
"""

import argparse
import ast
import json
import os
import sys

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

# Rule-file attributes worth reading for the inventory.
ATTR_NAMES = frozenset({"id", "description", "severity"})

# Cap per-rule findings so one broad rule cannot exhaust the 1 MiB step-summary
# limit. The full list stays in the artifact and the job log.
MAX_FINDINGS_PER_RULE = 25

# Rules whose findings lead the summary regardless of ID ordering. A
# segmentation breach is the headline; naming and metadata are detail.
PRIORITY_RULE_IDS = ("210",)


def esc_cell(text):
    """Make text safe for a markdown table cell."""
    return str(text).replace("|", "\|").replace("\n", " ")


def parse_rule_attrs(path):
    """
    Read the `Rule` class attributes from a rule file without importing it.
    Returns a dict, or None if there is no `Rule` class.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=path)
    except (OSError, SyntaxError) as exc:
        raise ValueError(f"{type(exc).__name__}: {exc}") from exc

    for node in ast.walk(tree):
        if not (isinstance(node, ast.ClassDef) and node.name == "Rule"):
            continue

        attrs = {}
        for stmt in node.body:
            if isinstance(stmt, ast.Assign):
                targets = [t for t in stmt.targets if isinstance(t, ast.Name)]
                value = stmt.value
            elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                targets = [stmt.target]
                value = stmt.value
            else:
                continue

            if value is None:
                continue
            for target in targets:
                if target.id not in ATTR_NAMES:
                    continue
                try:
                    attrs[target.id] = ast.literal_eval(value)
                except (ValueError, SyntaxError):
                    pass  # computed value, not a literal
        return attrs

    return None


def load_inventory(rule_dirs):
    """
    id -> {severity, description, tier, filename}, plus unreadable files.

    A file that cannot be parsed is reported rather than raised: it may still
    have run inside nac-validate, so this is a reporting gap, not a validation
    failure.
    """
    inventory = {}
    problems = []

    for rule_dir in rule_dirs:
        tier = os.path.basename(rule_dir.rstrip("/")) or rule_dir
        if not os.path.isdir(rule_dir):
            problems.append((tier, "-", "rule directory not found"))
            continue

        for fname in sorted(os.listdir(rule_dir)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue

            try:
                attrs = parse_rule_attrs(os.path.join(rule_dir, fname))
            except ValueError as exc:
                problems.append((tier, fname, str(exc)))
                continue

            if attrs is None:
                problems.append((tier, fname, "no class named 'Rule' found"))
                continue

            rid = str(attrs.get("id", "")).strip()
            if not rid:
                problems.append((tier, fname, "Rule has no literal 'id'"))
                continue
            if rid in inventory:
                problems.append((
                    tier, fname,
                    f"duplicate rule id '{rid}' - also declared by "
                    f"{inventory[rid]['tier']}/{inventory[rid]['filename']}"
                ))

            inventory[rid] = {
                "severity": str(attrs.get("severity", "HIGH")).upper(),
                "description": attrs.get("description", ""),
                "tier": tier,
                "filename": fname,
            }

    return inventory, problems


def normalise_error(err):
    """
    Return (path, message).

    Structured rules set both `path` and `message`, and some also prefix the
    message with the path - strip the duplicate so the bullet reads cleanly.
    Simple string-list rules embed the path as a "path - message" prefix, which
    is split out here.
    """
    if isinstance(err, dict):
        message = str(err.get("message", "")).strip()
        path = str(err.get("path") or "").strip()
    else:
        message = str(err).strip()
        path = ""

    if path and message.startswith(path):
        message = message[len(path):].lstrip()
        if message.startswith("-"):
            message = message[1:].lstrip()
    elif not path and " - " in message:
        candidate, _, rest = message.partition(" - ")
        if candidate and " " not in candidate:
            path, message = candidate, rest

    return path, message


def block(text):
    """Collapse a triple-quoted attribute into markdown-safe lines."""
    if not text:
        return ""
    return "\n".join(ln.rstrip() for ln in str(text).strip().splitlines())


def build_findings(semantic, inventory):
    findings = []
    for entry in semantic:
        rid = str(entry.get("rule_id", "?"))
        inv = inventory.get(rid, {})
        findings.append({
            "id": rid,
            # JSON is authoritative; the inventory only fills gaps.
            "description": entry.get("description") or inv.get("description", ""),
            "severity": str(entry.get("severity")
                            or inv.get("severity", "HIGH")).upper(),
            "title": entry.get("title", ""),
            "explanation": entry.get("explanation", ""),
            "recommendation": entry.get("recommendation", ""),
            "affected_items_label": entry.get("affected_items_label")
                                    or "Affected items",
            "references": list(entry.get("references") or []),
            "errors": entry.get("errors") or [],
            "tier": inv.get("tier", "unknown"),
            "filename": inv.get("filename", "?"),
        })

    findings.sort(key=lambda f: (
        0 if f["id"] in PRIORITY_RULE_IDS else 1,
        SEVERITY_ORDER.get(f["severity"], 9),
        f["id"],
    ))
    return findings


def render(report, inventory, problems, exitcode):
    out = []
    syntax = report.get("syntax_errors") or []
    findings = build_findings(report.get("semantic_errors") or [], inventory)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + len(f["errors"])
    total = sum(counts.values())

    out += ["# 1. Data model validation", ""]

    if exitcode == 0:
        tiers = len({i["tier"] for i in inventory.values()})
        out += ["## ✅ Passed", "",
                f"All **{len(inventory)}** rules satisfied across "
                f"{tiers} tier(s)."]
    elif exitcode == 2:
        out += ["## ❌ Syntax / schema validation failed", "",
                "The YAML could not be parsed or does not match the schema. "
                "Semantic rules were **not** evaluated."]
    elif exitcode == 3:
        out += ["## ❌ Configuration error", "",
                "nac-validate could not run - missing schema or invalid rule "
                "directory. **Nothing was validated.** Do not read this as a "
                "pass."]
    else:
        out += [f"## ❌ {total} violation(s) - plan blocked", "",
                "Every violation blocks the pipeline regardless of severity. "]
    out.append("")

    if problems:
        out += ["### ⚠️ Rule files that could not be read", "",
                "These files were not parsed for the inventory below. They may "
                "still have run - check the raw output.", "",
                "| tier | file | problem |", "| --- | --- | --- |"]
        for tier, fname, why in problems:
            out.append(f"| `{tier}` | `{fname}` | {esc_cell(why)} |")
        out.append("")

    if syntax:
        out += ["### Syntax errors", "", "```text"]
        for err in syntax[:MAX_FINDINGS_PER_RULE]:
            out.append(normalise_error(err)[1])
        if len(syntax) > MAX_FINDINGS_PER_RULE:
            out.append(f"... {len(syntax) - MAX_FINDINGS_PER_RULE} more")
        out += ["```", ""]

    if total:
        out += ["| severity | violations | rules |", "| --- | --- | --- |"]
        for sev in ("HIGH", "MEDIUM", "LOW"):
            if not counts.get(sev):
                continue
            ids = sorted({f["id"] for f in findings if f["severity"] == sev})
            out.append(f"| {SEVERITY_ICON.get(sev, '')} {sev} | {counts[sev]} | "
                       f"{', '.join('`' + i + '`' for i in ids)} |")
        out.append("")

    for f in findings:
        icon = SEVERITY_ICON.get(f["severity"], "")
        heading = f["title"] or f["description"] or f"Rule {f['id']}"

        out += ["---", "",
                f"### {icon} `{f['id']}` {heading}", "",
                f"**{f['severity']}** · `{f['tier']}` · "
                f"{len(f['errors'])} violation(s)"]
        if f["title"] and f["description"]:
            out += ["", f"_{f['description']}_"]
        out += ["", f"**{f['affected_items_label']}**", ""]

        shown = f["errors"][:MAX_FINDINGS_PER_RULE]
        for err in shown:
            path, message = normalise_error(err)
            if path and message:
                # Two trailing spaces force a hard line break inside the bullet,
                # so the path and message do not run together on one line.
                out.append(f"- `{path}`  ")
                out.append(f"  {message}")
            elif path:
                out.append(f"- `{path}`")
            else:
                out.append(f"- {message}")
        if len(f["errors"]) > len(shown):
            out.append(f"- _... {len(f['errors']) - len(shown)} more - see the "
                       f"raw output below_")
        out.append("")

        why = block(f["explanation"])
        if why:
            out += ["### Why this matters", "",
                    why, "", "", ""]

        fix = block(f["recommendation"])
        if fix:
            out += ["**How to fix**", ""]
            # An indented recommendation is almost always a YAML snippet.
            if any(ln.startswith(("  ", "\t")) for ln in fix.splitlines()):
                out += ["```yaml", fix, "```"]
            else:
                out.append(fix)
            out.append("")

        for ref in f["references"]:
            out.append(f"- [reference]({ref})")
        if f["references"]:
            out.append("")

        if not why and not fix:
            out += [f"> This rule has no `explanation` or `recommendation`. "
                    f"Add them to `{f['tier']}/{f['filename']}` so this section "
                    f"tells the reader why it matters and how to fix it.", ""]

    failed = {f["id"] for f in findings}
    passed = sorted((rid for rid in inventory if rid not in failed),
                    key=lambda r: (inventory[r]["tier"], r))
    if passed:
        out += ["---", "",
                f"<details><summary>{len(passed)} of {len(inventory)} rules "
                f"passed</summary>", "",
                "| rule | tier | severity | check |",
                "| --- | --- | --- | --- |"]
        for rid in passed:
            i = inventory[rid]
            out.append(f"| `{rid}` | {i['tier']} | {i['severity']} | "
                       f"{esc_cell(i['description'])} |")
        out += ["", "</details>", ""]

    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report", help="nac-validate --format json output")
    ap.add_argument("--rules", action="append", default=[],
                    help="rule directory (repeatable)")
    ap.add_argument("--exitcode", type=int, default=1)
    args = ap.parse_args()

    try:
        with open(args.report) as fh:
            report = json.load(fh)
    except (OSError, ValueError) as exc:
        # Never let the renderer mask a validation failure.
        print("# 1. Data model validation")
        print("")
        print(f"⚠️ Could not read the JSON report (`{exc}`). "
              f"nac-validate exited **{args.exitcode}** - see the job log.")
        return 0

    inventory, problems = load_inventory(args.rules)
    print(render(report, inventory, problems, args.exitcode))
    return 0


if __name__ == "__main__":
    sys.exit(main())