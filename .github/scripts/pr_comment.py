#!/usr/bin/env python3
"""
Render the ACI NaC pull request review comment.

Exists as a Python script rather than inline JavaScript inside the workflow for
one reason: the "reproduce locally" snippet contains shell line-continuation
backslashes, and a backslash crossing the YAML -> JavaScript boundary is a
reliable source of breakage. In a JS string literal '...\' escapes the closing
quote and throws SyntaxError; in a template literal a backslash-newline silently
joins the lines. Python triple-quoted strings have neither problem.

Reads job results from the environment and report artifacts from disk, writes
markdown to stdout. The workflow's github-script step only performs the upsert.

Usage:
  pr_comment.py --validate-dir DIR --plan-dir DIR [--marker STR]
"""

import argparse
import os
import sys

# GitHub rejects issue comment bodies over 65536 characters.
COMMENT_LIMIT = 65536

# Cap the raw text blocks well below the limit so the verdict, the gate table and
# the validation detail always survive.
MAX_VALIDATE_RAW = 20000
MAX_PLAN_RAW = 30000

RAW_PLAN_SUMMARY = "<details><summary>Raw terraform plan</summary>"


def read_first(*candidates):
    """
    Return the contents of the first candidate path that exists and is non-empty.

    Several candidates are tried because upload-artifact v4 strips the common
    leading path from an artifact. A file uploaded as aci-config/tfplan.txt can
    therefore land either flattened at the root or still nested, depending on
    what else was in the same artifact.
    """
    for path in candidates:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        if text.strip():
            return text
    return ""


def env(name, default=""):
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def gate_icon(result, plan_exitcode=None):
    """Map a job result to a status cell."""
    if result == "success":
        if plan_exitcode is None:
            return "✅ passed"
        return "⚠️ changes" if plan_exitcode == "2" else "✅ no changes"
    if result == "skipped":
        return "⏭️ skipped"
    if result == "cancelled":
        return "⏹️ cancelled"
    return "❌ failed"


def build_verdict(val_result, plan_result, plan_exit, run_url):
    """Headline plus a plain-language 'what happens next'."""
    if val_result != "success":
        return (
            "## ❌ Blocked at data model validation",
            "Fix the violations below and push again. No Terraform plan was "
            "produced, so there is nothing to review yet.",
        )
    if plan_result == "skipped":
        return (
            "## ⏭️ Terraform plan did not run",
            f"Validation passed but the plan job was skipped. Check the "
            f"[run]({run_url}) for the reason.",
        )
    if plan_result != "success":
        return (
            "## ❌ Validation passed, Terraform plan failed",
            f"The data model is valid but the plan did not complete. See the "
            f"[job logs]({run_url}).",
        )
    if plan_exit == "0":
        return (
            "## ✅ Validation passed · no infrastructure changes",
            "Safe to merge. The apply job will be skipped because the plan is "
            "empty.",
        )
    if plan_exit == "2":
        return (
            "## ✅ Validation passed · changes ready to apply",
            "Merging this PR re-runs validation and the plan against `main`, "
            "then holds the apply for environment approval before anything "
            "reaches APIC.",
        )
    return (
        "## ⚠️ Plan finished in an unexpected state",
        f"Terraform exited {plan_exit or '?'}, which is neither 'no changes' "
        f"(0) nor 'changes present' (2). Review before merging.",
    )


def reproduce_block():
    """
    The local reproduction command.

    A plain triple-quoted string, so the trailing backslashes are literal and
    need no escaping.
    """
    return """\
nac-validate \
  -s tests-and-validations/01-pre-deploy-validation-rules/schemas/apic_schema.yaml \
  -r tests-and-validations/01-pre-deploy-validation-rules/rules/local-rules \
  -r tests-and-validations/01-pre-deploy-validation-rules/rules/pipeline-rules \
  aci-config/data\
"""


def strip_h1(markdown):
    """
    Remove a leading H1 from an embedded report.

    validate-summary.md is rendered for the job summary, where it owns the page.
    Inside this comment it is a section, and two H1s read as two documents.
    """
    lines = markdown.strip().splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    return "\n".join(lines).strip()


def render(args):
    val_result = env("VALIDATE_RESULT", "unknown")
    plan_result = env("PLAN_RESULT", "skipped")
    plan_exit = env("PLAN_EXITCODE")
    plan_line = env("PLAN_SUMMARY", "unknown")
    high = env("VAL_HIGH", "0")
    medium = env("VAL_MEDIUM", "0")
    low = env("VAL_LOW", "0")
    scope = env("SCOPE")
    run_url = env("RUN_URL")
    head_sha = env("HEAD_SHA")

    val_summary = read_first(os.path.join(args.validate_dir,
                                          "validate-summary.md"))
    val_raw = read_first(os.path.join(args.validate_dir, "validate-all.txt"))
    plan_table = read_first(
        os.path.join(args.plan_dir, "plan-summary.md"),
        os.path.join(args.plan_dir, "aci-config", "plan-summary.md"),
    )
    plan_raw = read_first(
        os.path.join(args.plan_dir, "tfplan.txt"),
        os.path.join(args.plan_dir, "aci-config", "tfplan.txt"),
    )

    verdict, next_step = build_verdict(val_result, plan_result, plan_exit,
                                       run_url)

    out = [
        args.marker,
        "# ACI Network as Code — change review",
        "",
        verdict,
        "",
        "| gate | result | detail |",
        "| --- | --- | --- |",
        f"| 1. Data model validation | {gate_icon(val_result)} | "
        f"{high} HIGH · {medium} MEDIUM · {low} LOW |",
        f"| 2. Terraform plan | {gate_icon(plan_result, plan_exit)} | "
        f"`{plan_line}` |",
        "| 3. Apply to APIC | ⏸️ on merge | requires environment approval |",
        "",
        f"**What happens next:** {next_step}",
        "",
        "---",
        "",
    ]

    # ---- validation detail -------------------------------------------------
    if val_summary.strip():
        out.append(strip_h1(val_summary))
    elif val_raw.strip():
        out += [
            "## 1. Data model validation",
            "",
            "```text",
            val_raw[:MAX_VALIDATE_RAW].rstrip(),
            "```",
        ]
    else:
        out += [
            "## 1. Data model validation",
            "",
            "_No validation report artifact was produced. See the "
            f"[job logs]({run_url})._",
        ]
    out += ["", "---", ""]

    # ---- plan detail -------------------------------------------------------
    out += ["## 2. Terraform plan", ""]
    if plan_result == "skipped":
        out.append("_Skipped: data model validation must pass first._")
    elif plan_result != "success":
        out.append(f"_The plan job did not complete ({plan_result}). See the "
                   f"[job logs]({run_url})._")
    else:
        out += [f"`{plan_line}`", ""]
        if plan_table.strip():
            out += [plan_table.strip(), ""]
        out += [
            "**Post-deploy test scope:** "
            f"`{scope or 'all configured subnets (full sweep)'}`",
            "",
        ]
        if plan_raw.strip():
            out += [
                RAW_PLAN_SUMMARY,
                "",
                "```hcl",
                plan_raw[:MAX_PLAN_RAW].rstrip(),
                "```",
                "</details>",
            ]

    # ---- footer ------------------------------------------------------------
    out += [
        "",
        "---",
        "",
        "<sub>Reproduce validation locally:</sub>",
        "",
        "```bash",
        reproduce_block(),
        "```",
        "",
    ]
    footer = f"<sub>[Full run and step summary]({run_url})"
    if head_sha:
        footer += f" · commit `{head_sha[:7]}`"
    footer += "</sub>"
    out.append(footer)

    return "\n".join(out)


def truncate(body, run_url):
    """
    Bring the body under GitHub's comment limit.

    The raw plan goes first: it is the largest block and the least essential, and
    the verdict must always survive.
    """
    if len(body) <= COMMENT_LIMIT:
        return body

    idx = body.find(RAW_PLAN_SUMMARY)
    if idx > 0:
        body = (body[:idx]
                + f"_Raw terraform plan omitted to stay within GitHub's "
                  f"comment size limit. See the [job summary]({run_url})._\n")

    if len(body) <= COMMENT_LIMIT:
        return body

    notice = f"\n\n_... truncated. See the [job summary]({run_url})._"
    return body[:COMMENT_LIMIT - len(notice) - 1] + notice


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--validate-dir", default="reports/validate")
    ap.add_argument("--plan-dir", default="reports/plan")
    ap.add_argument("--marker", default="<!-- aci-nac-report -->",
                    help="hidden HTML comment used to find and update this "
                         "comment on later runs")
    args = ap.parse_args()

    body = truncate(render(args), env("RUN_URL"))
    sys.stdout.write(body)
    sys.stdout.write("\n")

    # Size goes to stderr so it lands in the job log without polluting stdout.
    print(f"rendered {len(body)} characters", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())