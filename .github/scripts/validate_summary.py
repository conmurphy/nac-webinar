#!/usr/bin/env python3
"""
Render nac-validate results as a GitHub step summary.

Reads the JSON report (--format json) for findings, and STATICALLY parses the
rule files for the context attributes the JSON payload omits: severity, title,
explanation, recommendation, references.

Deliberately does NOT import the rule modules. Two reasons:
  1. Rules import nac_validate (RuleBase, Violation), which is only present in
     the interpreter nac-validate itself runs under - not necessarily the system
     python3 that executes this script.
  2. Importing executes module-level code. A rule with a startup consistency
     guard would raise, and a reporting tool must never have side effects.

ast.literal_eval on the class body gives every attribute we need, since they are
all plain literals.

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

# Class attributes worth surfacing. Anything else in the rule body is ignored.
ATTR_NAMES = frozenset({
    "id", "description", "severity", "title", "explanation",
    "recommendation", "affected_items_label", "references",
})

# Cap per-rule findings so one broad rule cannot blow the 1 MiB step-summary
# limit. The full list stays in the artifact and the job log.
MAX_FINDINGS_PER_RULE = 25

# Rules whose findings should lead the summary regardless of ID ordering.
# Segmentation breaches are the headline finding; everything else is detail.
PRIORITY_RULE_IDS = ("210",)


def esc_cell(text):
    """Make text safe for a markdown table cell."""
    return str(text).replace("|", "\|").replace("\n", " ")


def parse_rule_attrs(path):
    """
    Extract the `Rule` class attributes from a rule file without importing it.
    Returns a dict, or None if the file has no `Rule` class.
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
            # Plain assignment: severity = "HIGH"
            if isinstance(stmt, ast.Assign):
                targets = [t for t in stmt.targets if isinstance(t, ast.Name)]
                value = stmt.value
            # Annotated assignment: id: str = "101"
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
                    # f-string or computed value - not a literal, skip it.
                    pass
        return attrs

    return None


def load_rule_metadata(rule_dirs):
    """
    id -> metadata dict, plus a list of files that could not be read.

    A file that cannot be parsed is reported rather than raised: a rule that will
    not load is itself worth surfacing, because it did not evaluate.
    """
    meta = {}
    problems = []

    for rule_dir in rule_dirs:
        tier = os.path.basename(rule_dir.rstrip("/")) or rule_dir
        if not os.path.isdir(rule_dir):
            problems.append((tier, "-", "rule directory not found"))
            continue

        for fname in sorted(os.listdir(rule_dir)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            path = os.path.join(rule_dir, fname)

            try:
                attrs = parse_rule_attrs(path)
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

            if rid in meta:
                problems.append((
                    tier, fname,
                    f"duplicate rule id '{rid}' - also declared by "
                    f"{meta[rid]['tier']}/{meta[rid]['filename']}"
                ))

            refs = attrs.get("references") or []
            if isinstance(refs, str):
                refs = [refs]

            meta[rid] = {
                "severity": str(attrs.get("severity", "HIGH")).upper(),
                "description": attrs.get("description", ""),
                "title": attrs.get("title", ""),
                "explanation": attrs.get("explanation", ""),
                "recommendation": attrs.get("recommendation", ""),
                "affected_items_label": attrs.get("affected_items_label",
                                                  "Affected items"),
                "references": list(refs),
                "tier": tier,
                "filename": fname,
            }

    return meta, problems


def normalise_error(err):
    """
    Return (path, message).

    JSON errors are objects, not strings. Simple string-list rules produce
    {"message": "..."}; structured rules using Violation add "path" and
    "details". A bare string is also handled in case the format changes.
    """
    if isinstance(err, dict):
        message = str(err.get("message", "")).strip()
        path = str(err.get("path") or "").strip()
    else:
        message = str(err).strip()
        path = ""

    # Simple rules embed the path as a "path - message" prefix.
    if not path and " - " in message:
        candidate, _, rest = message.partition(" - ")
        if " " not in candidate and candidate:
            path, message = candidate, rest

    return path, message


def block(text):
    """Collapse a triple-quoted attribute into markdown-safe lines."""
    if not text:
        return ""
    return "\n".join(ln.rstrip() for ln in str(text).strip().splitlines())


def sort_key(finding):
    priority = 0 if finding["id"] in PRIORITY_RULE_IDS else 1
    return (priority, SEVERITY_ORDER.get(finding["severity"], 9), finding["id"])


def render(report, meta, problems, exitcode):
    out = []
    syntax = report.get("syntax_errors") or []
    semantic = report.get("semantic_errors") or []

    findings = []
    for entry in semantic:
        rid = str(entry.get("rule_id", "?"))
        info = meta.get(rid, {})
        findings.append({
            "id": rid,
            "description": entry.get("description") or info.get("description", ""),
            "errors": entry.get("errors") or [],
            "meta": info,
            "severity": info.get("severity", "HIGH"),
        })
    findings.sort(key=sort_key)

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + len(f["errors"])
    total = sum(counts.values())

    out.append("# 1. Data model validation")
    out.append("")

    if exitcode == 0:
        out.append("## ✅ Passed")
        out.append("")
        out.append(f"All **{len(meta)}** rules satisfied across "
                   f"{len({m['tier'] for m in meta.values()})} tier(s).")
    elif exitcode == 2:
        out.append("## ❌ Syntax / schema validation failed")
        out.append("")
        out.append("The YAML could not be parsed or does not match the schema. "
                   "Semantic rules were **not** evaluated.")
    elif exitcode == 3:
        out.append("## ❌ Configuration error")
        out.append("")
        out.append("nac-validate could not run - missing schema or invalid rule "
                   "directory. **Nothing was validated.** Do not read this as a "
                   "pass.")
    else:
        out.append(f"## ❌ {total} violation(s) - plan blocked")
        out.append("")
        out.append("Every violation blocks the pipeline regardless of severity. "
                   "Severity indicates urgency, not whether the gate opens.")
    out.append("")

    if problems:
        out.append("### ⚠️ Rules that could not be read")
        out.append("")
        out.append("Context for these rules is unavailable, so their findings "
                   "below show without an explanation or fix.")
        out.append("")
        out.append("| tier | file | problem |")
        out.append("| --- | --- | --- |")
        for tier, fname, why in problems:
            out.append(f"| `{tier}` | `{fname}` | {esc_cell(why)} |")
        out.append("")

    if syntax:
        out.append("### Syntax errors")
        out.append("")
        out.append("```text")
        for err in syntax[:MAX_FINDINGS_PER_RULE]:
            _, message = normalise_error(err)
            out.append(message)
        if len(syntax) > MAX_FINDINGS_PER_RULE:
            out.append(f"... {len(syntax) - MAX_FINDINGS_PER_RULE} more")
        out.append("```")
        out.append("")

    if total:
        out.append("| severity | violations | rules |")
        out.append("| --- | --- | --- |")
        for sev in ("HIGH", "MEDIUM", "LOW"):
            if not counts.get(sev):
                continue
            ids = sorted({f["id"] for f in findings if f["severity"] == sev})
            out.append(f"| {SEVERITY_ICON.get(sev, '')} {sev} | {counts[sev]} | "
                       f"{', '.join('`' + i + '`' for i in ids)} |")
        out.append("")

    for f in findings:
        info = f["meta"]
        icon = SEVERITY_ICON.get(f["severity"], "")
        heading = info.get("title") or f["description"] or f"Rule {f['id']}"
        tier = info.get("tier", "unknown")

        out.append("---")
        out.append("")
        out.append(f"### {icon} `{f['id']}` {heading}")
        out.append("")
        out.append(f"**{f['severity']}** · `{tier}` · "
                   f"{len(f['errors'])} violation(s)")
        if info.get("title") and f["description"]:
            out.append("")
            out.append(f"_{f['description']}_")
        out.append("")

        out.append(f"**{info.get('affected_items_label') or 'Affected items'}**")
        out.append("")
        shown = f["errors"][:MAX_FINDINGS_PER_RULE]
        for err in shown:
            path, message = normalise_error(err)
            if path:
                out.append(f"- `{path}`")
                out.append(f"  {message}")
            else:
                out.append(f"- {message}")
        if len(f["errors"]) > len(shown):
            out.append(f"- _... {len(f['errors']) - len(shown)} more - see the "
                       f"raw output below_")
        out.append("")

        why = block(info.get("explanation"))
        if why:
            out.append("<details><summary>Why this matters</summary>")
            out.append("")
            out.append(why)
            out.append("")
            out.append("</details>")
            out.append("")

        fix = block(info.get("recommendation"))
        if fix:
            out.append("**How to fix**")
            out.append("")
            # An indented recommendation is almost always a YAML snippet.
            if any(ln.startswith(("  ", "\t")) for ln in fix.splitlines()):
                out.append("```yaml")
                out.append(fix)
                out.append("```")
            else:
                out.append(fix)
            out.append("")

        refs = info.get("references") or []
        for ref in refs:
            out.append(f"- [reference]({ref})")
        if refs:
            out.append("")

        if not why and not fix:
            out.append(f"> No `explanation` or `recommendation` set on this "
                       f"rule. Add them to "
                       f"`{tier}/{info.get('filename', '?')}` so this section "
                       f"tells the reader what to do.")
            out.append("")

    failed_ids = {f["id"] for f in findings}
    passed = sorted((rid for rid in meta if rid not in failed_ids),
                    key=lambda r: (meta[r]["tier"], r))
    if passed:
        out.append("---")
        out.append("")
        out.append(f"<details><summary>{len(passed)} of {len(meta)} rules "
                   f"passed</summary>")
        out.append("")
        out.append("| rule | tier | severity | check |")
        out.append("| --- | --- | --- | --- |")
        for rid in passed:
            m = meta[rid]
            out.append(f"| `{rid}` | {m['tier']} | {m['severity']} | "
                       f"{esc_cell(m['description'])} |")
        out.append("")
        out.append("</details>")
        out.append("")

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

    meta, problems = load_rule_metadata(args.rules)
    print(render(report, meta, problems, args.exitcode))
    return 0


if __name__ == "__main__":
    sys.exit(main())