#!/usr/bin/env python3
"""
Tidy a nac-analytics ND markdown report for GitHub step summaries.

Two problems with the raw report:
  1. The Warnings section carries operational noise (TLS verification off,
     snapshot paging limits) that is true but irrelevant to a change review.
  2. violating_rules is emitted as a raw Python repr, e.g.
       [{'ruleName': 'X', 'ruleType': 'configuration', 'violationsCount': 1}]
     which is unreadable in a summary.

Outputs:
  --clean-out       the full report with noise warnings dropped and the
                    violating_rules cell replaced by a readable list
  --violations-out  just the violations, for the top level of the summary
"""

import argparse
import ast
import re
import sys

# Warnings that are environmental rather than change-relevant.
NOISE = (
    "TLS certificate verification is disabled",
    "more 'online' snapshot(s) exist",
)

ROW_RE = re.compile(r"^\|\s*violating_rules\s*\|\s*(.*?)\s*\|\s*$")


def parse_rules(cell):
    """Python-repr list of dicts -> list of (name, type, count)."""
    try:
        data = ast.literal_eval(cell)
    except (ValueError, SyntaxError):
        return None
    if not isinstance(data, list):
        return None
    out = []
    for item in data:
        if not isinstance(item, dict):
            continue
        out.append((
            str(item.get("ruleName", "?")),
            str(item.get("ruleType", "")),
            item.get("violationsCount", ""),
        ))
    return out


def render_rules(rules, violated_total=None):
    """Bulleted list. Rule type is hoisted out if uniform."""
    if not rules:
        return ["_No violating rules reported._"]

    types = {t for _, t, _ in rules if t}
    uniform = types.pop() if len(types) == 1 else None

    lines = []
    if violated_total is not None and len(rules) < violated_total:
        lines.append(
            f"_Showing {len(rules)} of {violated_total} violated rules "
            f"(the API truncates this list)._"
        )
        lines.append("")
    if uniform:
        lines.append(f"Rule type: **{uniform}**")
        lines.append("")

    for name, rtype, count in sorted(rules):
        try:
            n = int(count)
            plural = "violation" if n == 1 else "violations"
            suffix = f" — {n} {plural}"
        except (TypeError, ValueError):
            suffix = ""
        tag = "" if uniform else f" _({rtype})_" if rtype else ""
        lines.append(f"- `{name}`{suffix}{tag}")
    return lines


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("report")
    ap.add_argument("--clean-out", default="nd-prechange-clean.md")
    ap.add_argument("--violations-out", default="nd-violations.md")
    args = ap.parse_args()

    try:
        with open(args.report) as fh:
            lines = fh.read().splitlines()
    except OSError as e:
        print(f"cannot read {args.report}: {e}", file=sys.stderr)
        for path in (args.clean_out, args.violations_out):
            with open(path, "w") as fh:
                fh.write("_No Nexus Dashboard report available._\n")
        return 0

    # violated_rules count, so we can say "showing N of M"
    violated_total = None
    for ln in lines:
        m = re.match(r"^\|\s*violated_rules\s*\|\s*(\d+)\s*\|\s*$", ln)
        if m:
            violated_total = int(m.group(1))
            break

    rules = None
    clean = []
    in_warnings = False
    dropped = 0

    for ln in lines:
        if ln.startswith("## "):
            in_warnings = ln.lower().startswith("## warning")

        if in_warnings and any(p in ln for p in NOISE):
            dropped += 1
            continue

        m = ROW_RE.match(ln)
        if m:
            rules = parse_rules(m.group(1))
            if rules is not None:
                # Keep the table intact; point at the list below it.
                clean.append(f"| violating_rules | {len(rules)} "
                             f"(listed below) |")
                continue

        clean.append(ln)

    if rules:
        clean.append("")
        clean.append("### Violating rules")
        clean.append("")
        clean.extend(render_rules(rules, violated_total))
        clean.append("")

    with open(args.clean_out, "w") as fh:
        fh.write("\n".join(clean).rstrip() + "\n")

    with open(args.violations_out, "w") as fh:
        if rules is None:
            fh.write("_No compliance violation data in the report._\n")
        else:
            fh.write("\n".join(render_rules(rules, violated_total)) + "\n")

    print(f"dropped {dropped} noise warning(s); "
          f"parsed {len(rules) if rules else 0} violating rule(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())