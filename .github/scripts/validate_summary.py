#!/usr/bin/env python3
"""
Render nac-validate results as a GitHub step summary.

Reads the JSON report (--format json) for findings, and imports the rule modules
to recover the context attributes the JSON payload omits: severity, title,
explanation, recommendation and references. That way the text already written in
each rule file is reused rather than duplicated in the workflow.

Usage:
  validate_summary.py REPORT.json --rules DIR [--rules DIR] [--exitcode N]

Exit codes mirrored from nac-validate:
  0 pass | 1 semantic violations | 2 syntax/schema error | 3 configuration error
"""

import argparse
import importlib.util
import json
import os
import sys

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡"}

# Cap per-rule findings so one broad rule cannot blow the 1 MiB step-summary
# limit. The full list stays in the artifact and the job log.
MAX_FINDINGS_PER_RULE = 25


def load_rule_metadata(rule_dirs):
    """
    id -> {severity, title, explanation, recommendation, references,
           affected_items_label, tier, filename}

    Rules are imported, not parsed: the attributes are plain class fields and
    importing is both simpler and immune to formatting changes. An import failure
    is recorded rather than raised - a rule that will not load is itself a
    finding worth surfacing.
    """
    meta = {}
    broken = []

    for rule_dir in rule_dirs:
        tier = os.path.basename(rule_dir.rstrip("/")) or rule_dir
        if not os.path.isdir(rule_dir):
            continue

        for fname in sorted(os.listdir(rule_dir)):
            if not fname.endswith(".py") or fname.startswith("_"):
                continue
            path = os.path.join(rule_dir, fname)
            modname = f"_nacrule_{tier}_{fname[:-3]}".replace("-", "_")

            try:
                spec = importlib.util.spec_from_file_location(modname, path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                rule = getattr(module, "Rule")
            except Exception as exc:                      # noqa: BLE001
                broken.append((tier, fname, f"{type(exc).__name__}: {exc}"))
                continue

            rid = str(getattr(rule, "id", "")).strip()
            if not rid:
                broken.append((tier, fname, "Rule class has no 'id' attribute"))
                continue

            if rid in meta:
                broken.append((
                    tier, fname,
                    f"duplicate rule id '{rid}' - also declared by "
                    f"{meta[rid]['tier']}/{meta[rid]['filename']}"
                ))

            meta[rid] = {
                "severity": str(getattr(rule, "severity", "HIGH")).upper(),
                "description": getattr(rule, "description", ""),
                "title": getattr(rule, "title", ""),
                "explanation": getattr(rule, "explanation", ""),
                "recommendation": getattr(rule, "recommendation", ""),
                "references": list(getattr(rule, "references", []) or []),
                "affected_items_label": getattr(rule, "affected_items_label",
                                                "Affected Items"),
                "tier": tier,
                "filename": fname,
            }

    return meta, broken


def block(text):
    """Collapse a triple-quoted attribute into a markdown-safe paragraph."""
    if not text:
        return ""
    lines = [ln.rstrip() for ln in str(text).strip().splitlines()]
    return "\n".join(lines)


def render(report, meta, broken, exitcode):
    out = []
    syntax = report.get("syntax_errors") or []
    semantic = report.get("semantic_errors") or []

    findings = []
    for entry in semantic:
        rid = str(entry.get("rule_id", "?"))
        info = meta.get(rid, {})
        findings.append({
            "id": rid,
            "description": entry.get("description")
                           or info.get("description", ""),
            "errors": entry.get("errors") or [],
            "meta": info,
            "severity": info.get("severity", "HIGH"),
        })

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["id"]))

    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + len(f["errors"])
    total = sum(counts.values())

    out.append("# 1. Data model validation")
    out.append("")

    # ---- verdict -----------------------------------------------------------
    if exitcode == 0:
        out.append("## ✅ Passed")
        out.append("")
        out.append(f"All **{len(meta)}** rules satisfied. No violations found.")
    elif exitcode == 2:
        out.append("## ❌ Syntax / schema validation failed")
        out.append("")
        out.append("The YAML could not be parsed or does not match the schema. "
                   "Semantic rules were **not** evaluated.")
    elif exitcode == 3:
        out.append("## ❌ Configuration error")
        out.append("")
        out.append("nac-validate could not run: a schema is missing, or a rule "
                   "directory is invalid. **Nothing was validated** - do not "
                   "read this as a pass.")
    else:
        blockers = counts["HIGH"] + counts["MEDIUM"] + counts["LOW"]
        out.append(f"## ❌ {blockers} violation(s) - plan blocked")
        out.append("")
        out.append("Every violation blocks, regardless of severity. "
                   "Severity indicates urgency, not whether the gate opens.")
    out.append("")

    # ---- rules that failed to load ----------------------------------------
    if broken:
        out.append("### ⚠️ Rules that could not be loaded")
        out.append("")
        out.append("These rules did **not** evaluate. A rule that fails to load "
                   "is indistinguishable from a rule that passes.")
        out.append("")
        out.append("| tier | file | problem |")
        out.append("| --- | --- | --- |")
        for tier, fname, why in broken:
            out.append(f"| `{tier}` | `{fname}` | {why.replace('|', '\|')} |")
        out.append("")

    # ---- syntax errors ----------------------------------------------------
    if syntax:
        out.append("### Syntax errors")
        out.append("")
        out.append("```text")
        for err in syntax[:MAX_FINDINGS_PER_RULE]:
            out.append(str(err))
        if len(syntax) > MAX_FINDINGS_PER_RULE:
            out.append(f"... {len(syntax) - MAX_FINDINGS_PER_RULE} more")
        out.append("```")
        out.append("")

    # ---- severity roll-up -------------------------------------------------
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

    # ---- per-rule detail --------------------------------------------------
    for f in findings:
        info = f["meta"]
        icon = SEVERITY_ICON.get(f["severity"], "")
        heading = info.get("title") or f["description"] or f"Rule {f['id']}"
        tier = info.get("tier", "?")

        out.append("---")
        out.append("")
        out.append(f"### {icon} `{f['id']}` {heading}")
        out.append("")
        out.append(f"**{f['severity']}** · {tier} tier · "
                   f"{len(f['errors'])} violation(s)")
        if info.get("title") and f["description"]:
            out.append("")
            out.append(f"_{f['description']}_")
        out.append("")

        label = info.get("affected_items_label") or "Affected items"
        out.append(f"**{label}**")
        out.append("")
        shown = f["errors"][:MAX_FINDINGS_PER_RULE]
        for err in shown:
            # Findings are "path - message"; split so the path renders as code
            # and the message stays readable.
            text = str(err).strip()
            path, sep, message = text.partition(" - ")
            if sep and " " not in path:
                out.append(f"- `{path}`  \n  {message}")
            else:
                out.append(f"- {text}")
        if len(f["errors"]) > len(shown):
            out.append(f"- _... {len(f['errors']) - len(shown)} more - see the "
                       f"full output below_")
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
            # Indented recommendation text is almost always a YAML snippet.
            if any(ln.startswith(("  ", "\t")) for ln in fix.splitlines()):
                out.append("```yaml")
                out.append(fix)
                out.append("```")
            else:
                out.append(fix)
            out.append("")

        for ref in info.get("references") or []:
            out.append(f"- [reference]({ref})")
        if info.get("references"):
            out.append("")

    # ---- rules that passed ------------------------------------------------
    failed_ids = {f["id"] for f in findings}
    passed = sorted((rid for rid in meta if rid not in failed_ids),
                    key=lambda r: (meta[r]["tier"], r))
    if passed:
        out.append("---")
        out.append("")
        out.append(f"<details><summary>{len(passed)} rule(s) passed</summary>")
        out.append("")
        out.append("| rule | tier | check |")
        out.append("| --- | --- | --- |")
        for rid in passed:
            m = meta[rid]
            out.append(f"| `{rid}` | {m['tier']} | "
                       f"{m['description'].replace('|', '\|')} |")
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
        # Never let the summary renderer mask a validation failure.
        print(f"# 1. Data model validation\n\n"
              f"⚠️ Could not read the JSON report (`{exc}`). "
              f"nac-validate exited **{args.exitcode}** - see the job log.")
        return 0

    meta, broken = load_rule_metadata(args.rules)
    print(render(report, meta, broken, args.exitcode))
    return 0


if __name__ == "__main__":
    sys.exit(main())