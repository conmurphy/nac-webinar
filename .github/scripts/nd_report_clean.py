#!/usr/bin/env python3
"""
Tidy a nac-analytics ND markdown report for GitHub step summaries.

Three problems with the raw report:
  1. The Warnings section carries operational noise (TLS verification off,
     snapshot paging limits) that is true but irrelevant to a change review.
  2. violating_rules is emitted as a raw Python repr, e.g.
       [{'ruleName': 'X', 'ruleType': 'configuration', 'violationsCount': 1}]
     which is unreadable in a summary.
  3. Two counts that matter to a reviewer are buried in the field table and
     easy to miss:
       - violated_rules > len(violating_rules)  -> the list is truncated
       - enforced_rules < configuration_rules   -> rules exist but cannot fail

Outputs:
  --clean-out       the full report with noise warnings dropped and the
                    violating_rules cell replaced by a readable list
  --violations-out  just the violations, for the top level of the summary.
                    Written EMPTY when there is nothing to report, so the
                    caller's `[ -s ... ]` test skips the section entirely.

Emits ::warning:: workflow commands on stdout for truncated or unenforced
compliance rules, so the caller does not need to re-derive them from JSON.
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

# Single-value rows of the field table: | name | value |
# The leading-letter class keeps the '| --- | --- |' separator out.
FIELD_RE = re.compile(r"^\|\s*([A-Za-z_][A-Za-z0-9_]*)\s*\|\s*(.*?)\s*\|\s*$")


def as_int(value, default=None):
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


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


def render_rules(rules, violated_total=None, scope=None):
    """Bulleted list, worst first. Rule type is hoisted out if uniform."""
    if not rules:
        return ["_No violating rules reported._"]

    types = {t for _, t, _ in rules if t}
    uniform = types.pop() if len(types) == 1 else None

    lines = []
    if violated_total is not None and len(rules) < violated_total:
        lines.append(
            f"⚠️ _Showing {len(rules)} of {violated_total} violated rules — "
            f"the API truncates this list, so the report is incomplete._"
        )
        lines.append("")
    if scope:
        lines.append(f"Scope: _{scope}_")
        lines.append("")
    if uniform:
        lines.append(f"Rule type: **{uniform}**")
        lines.append("")

    # Highest violation count first, then alphabetical.
    ordered = sorted(rules, key=lambda r: (-(as_int(r[2], 0) or 0), r[0]))
    for name, rtype, count in ordered:
        n = as_int(count)
        if n is None:
            suffix = ""
        else:
            suffix = f" — {n} violation" + ("" if n == 1 else "s")
        tag = "" if uniform else (f" _({rtype})_" if rtype else "")
        lines.append(f"- `{name}`{suffix}{tag}")
    return lines


def render_caveats(fields, rules):
    """Reviewer-facing caveats derived from the compliance field table."""
    lines = []

    declared = as_int(fields.get("violated_rules"))
    listed = len(rules) if rules is not None else None
    if declared is not None and listed is not None and listed < declared:
        lines.append(
            f"- ⚠️ Compliance list is **incomplete**: {declared} violated "
            f"rules declared, {listed} returned. The CLI's compliance read "
            f"path is not paging."
        )

    enforced = as_int(fields.get("enforced_rules"))
    configured = as_int(fields.get("configuration_rules"))
    if enforced is not None and configured is not None and enforced < configured:
        gap = configured - enforced
        lines.append(
            f"- ⚠️ **{gap} of {configured}** configuration rules are not "
            f"enforced and therefore cannot fail this gate."
        )

    return lines


def drop_empty_warnings(lines):
    """Remove a '## Warnings' heading left with no body after noise removal.

    Deliberately scoped to the Warnings heading only. A generic empty-section
    sweep would also eat the report's H1 title whenever the next line is a
    heading, which is not worth the risk.
    """
    out = []
    i = 0
    while i < len(lines):
        ln = lines[i]
        if ln.strip().lower().startswith("## warning"):
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j >= len(lines) or lines[j].startswith("#"):
                i = j
                continue
        out.append(ln)
        i += 1
    return out


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
        with open(args.clean_out, "w") as fh:
            fh.write("_No Nexus Dashboard report available._\n")
        # Empty, so the caller's -s test skips the section.
        open(args.violations_out, "w").close()
        return 0

    # Harvest the single-value field rows once, up front.
    fields = {}
    for ln in lines:
        m = FIELD_RE.match(ln)
        if m and not ROW_RE.match(ln):
            fields.setdefault(m.group(1), m.group(2))

    violated_total = as_int(fields.get("violated_rules"))
    scope = fields.get("scope") or None

    rules = None
    clean = []
    in_warnings = False
    dropped = 0

    for ln in lines:
        # Reset on ANY heading, not just h2, so noise filtering cannot leak
        # past the Warnings section.
        if ln.startswith("#"):
            in_warnings = ln.strip().lower().startswith("## warning")

        if in_warnings and any(p in ln for p in NOISE):
            dropped += 1
            continue

        m = ROW_RE.match(ln)
        if m:
            rules = parse_rules(m.group(1))
            if rules is not None:
                # Keep the table intact. Only promise a list when one exists.
                pointer = f"{len(rules)} (listed below)" if rules else "0"
                clean.append(f"| violating_rules | {pointer} |")
                continue

        clean.append(ln)

    clean = drop_empty_warnings(clean)

    caveats = render_caveats(fields, rules)

    if rules:
        clean.append("")
        clean.append("### Violating rules")
        clean.append("")
        clean.extend(render_rules(rules, violated_total, scope))
        clean.append("")

    if caveats:
        clean.append("")
        clean.append("### Compliance reporting caveats")
        clean.append("")
        clean.extend(caveats)
        clean.append("")

    with open(args.clean_out, "w") as fh:
        fh.write("\n".join(clean).rstrip() + "\n")

    # Empty file when there is nothing worth a summary section.
    with open(args.violations_out, "w") as fh:
        if rules:
            body = render_rules(rules, violated_total, scope)
            if caveats:
                body += [""] + caveats
            fh.write("\n".join(body) + "\n")
        elif caveats:
            fh.write("\n".join(caveats) + "\n")
        # else: leave empty

    # Workflow annotations, so the caller does not re-derive these from JSON.
    for line in caveats:
        print("::warning::" + line.lstrip("- ").replace("**", ""))

    print(
        f"dropped {dropped} noise warning(s); "
        f"parsed {0 if not rules else len(rules)} violating rule(s); "
        f"{len(caveats)} caveat(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())