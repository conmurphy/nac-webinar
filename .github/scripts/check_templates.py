#!/usr/bin/env python3
"""
Parse-check nac-test Robot templates without touching the fabric.

WHY
    nac-test renders every template through Jinja before Robot ever sees it, so a
    single malformed tag aborts the WHOLE suite - including tests that would have
    passed. That failure currently surfaces only after the pipeline has reached
    the post-deploy job, which on a merge means after terraform apply has already
    changed the fabric. This check moves it to the validate gate, where it costs
    milliseconds and blocks nothing else.

    Two real defects motivated it:
      - a {% for %} written as PROSE inside a docstring, which Jinja dutifully
        tried to execute: "Expected an expression, got 'end of statement block'"
      - a block tag inside a test BODY, which with trim_blocks=True swallowed the
        following newline and joined two Robot lines into one

WHAT IT DOES NOT DO
    Compiles templates; it does not render them. Rendering needs the merged data
    model and would duplicate what nac-test already does. Compilation catches
    every syntax error, which is the class that aborts the run.

    It therefore cannot catch a missing Robot KEYWORD - that is resolved by Robot
    at execution time, not by Jinja at compile time. See --lint for a heuristic
    that catches the whitespace-join defect.

FILTERS
    Custom and Ansible-style filters (community.general.json_query and friends)
    are registered in nac-test's own environment, not here. Jinja resolves filter
    names at COMPILE time, so an unknown filter would raise and produce a false
    failure. Unknown filters are therefore stubbed - this check is about syntax,
    not about whether a filter exists.

Usage:
  check_templates.py TEMPLATE_DIR [--lint] [--trim-blocks/--no-trim-blocks]
"""

import argparse
import os
import re
import sys

try:
    from jinja2 import Environment, FileSystemLoader, TemplateSyntaxError
except ImportError:
    sys.stderr.write(
        "jinja2 is not importable by this interpreter. Run this with the "
        "interpreter nac-test itself uses, e.g.\n"
        "  PY=$(head -1 \"$(command -v nac-test)\" | sed 's|^#!||' | awk '{print $1}')\n"
        "  \"$PY\" .github/scripts/check_templates.py TEMPLATE_DIR\n"
    )
    sys.exit(3)

TEMPLATE_SUFFIXES = (".robot", ".resource")

# Jinja block keywords. A tag opening with anything else is either a typo or
# prose that Jinja will try to execute.
BLOCK_KEYWORDS = frozenset({
    "for", "endfor", "if", "elif", "else", "endif", "set", "endset",
    "macro", "endmacro", "call", "endcall", "filter", "endfilter",
    "block", "endblock", "extends", "include", "import", "from",
    "raw", "endraw", "with", "endwith", "do", "break", "continue",
    "trans", "endtrans", "pluralize", "autoescape", "endautoescape",
})

BLOCK_TAG = re.compile(r"\{%-?\s*(\w+)")
ANY_BLOCK_TAG_LINE = re.compile(r"^(\s*)\{%-?\s")
SECTION_HEADER = re.compile(r"^\*\*\*\s*(.+?)\s*\*\*\*")


class PermissiveFilters(dict):
    """
    Returns a passthrough for any filter this environment does not know about.

    Jinja validates filter names during compilation, so without this every
    template using a nac-test or Ansible filter would fail the check for a
    reason that has nothing to do with syntax.
    """

    def __missing__(self, key):
        return lambda value, *args, **kwargs: value


def build_env(template_dir, trim_blocks):
    env = Environment(
        loader=FileSystemLoader(template_dir),
        # Mirrors nac-test. trim_blocks in particular is what makes a block tag
        # inside a test body eat the following newline, so checking with it off
        # would validate a file that still breaks at runtime.
        trim_blocks=trim_blocks,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters = PermissiveFilters(env.filters)
    env.tests = PermissiveFilters(env.tests)
    return env


def find_templates(template_dir):
    found = []
    for root, _dirs, files in os.walk(template_dir):
        for name in sorted(files):
            if name.endswith(TEMPLATE_SUFFIXES) and not name.startswith("."):
                full = os.path.join(root, name)
                found.append((full, os.path.relpath(full, template_dir)))
    return sorted(found, key=lambda p: p[1])


def check_syntax(env, rel_path):
    """Compile one template. Returns None on success, or an error string."""
    try:
        env.get_template(rel_path.replace(os.sep, "/"))
    except TemplateSyntaxError as exc:
        where = f"line {exc.lineno}" if exc.lineno else "unknown line"
        detail = f"{where}: {exc.message}"
        if exc.source:
            lines = exc.source.splitlines()
            if exc.lineno and 0 < exc.lineno <= len(lines):
                detail += f"\n      >>> {lines[exc.lineno - 1].strip()}"
        return detail
    except Exception as exc:                                   # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"
    return None


def lint_stray_tags(full_path):
    """
    Heuristic checks that compilation cannot catch.

    1. A tag whose first word is not a Jinja keyword. Almost always prose
       mentioning Jinja syntax, which Jinja then tries to execute.
    2. An INDENTED block tag inside the Test Cases section. Test-generating
       loops sit at column 0; an indented one is inside a test body, where
       trim_blocks will swallow the newline and join the next Robot line onto
       the previous keyword. Heuristic, so reported as a warning.
    """
    warnings = []
    section = ""
    with open(full_path, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, start=1):
            header = SECTION_HEADER.match(line)
            if header:
                section = header.group(1).lower()
                continue

            for match in BLOCK_TAG.finditer(line):
                word = match.group(1)
                if word not in BLOCK_KEYWORDS:
                    warnings.append(
                        f"line {lineno}: tag opens with '{word}', which is not a "
                        f"Jinja keyword - is this prose that should not be in "
                        f"braces?\n      >>> {line.strip()}"
                    )

            if "test case" in section:
                indented = ANY_BLOCK_TAG_LINE.match(line)
                if indented and indented.group(1):
                    keyword = BLOCK_TAG.search(line)
                    word = keyword.group(1) if keyword else "?"
                    if word in BLOCK_KEYWORDS and word not in ("raw", "endraw"):
                        warnings.append(
                            f"line {lineno}: indented '{word}' block tag inside "
                            f"Test Cases. With trim_blocks=True this swallows the "
                            f"following newline and joins the next Robot line onto "
                            f"the previous keyword. Move the loop above the test "
                            f"name, or into a Robot keyword.\n      >>> {line.strip()}"
                        )
    return warnings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("template_dir")
    ap.add_argument("--lint", action="store_true",
                    help="also run heuristic checks for stray and misplaced tags")
    ap.add_argument("--no-trim-blocks", dest="trim_blocks",
                    action="store_false", default=True,
                    help="compile without trim_blocks (nac-test uses it ON)")
    ap.add_argument("--strict-lint", action="store_true",
                    help="treat lint warnings as failures")
    args = ap.parse_args()

    if not os.path.isdir(args.template_dir):
        print(f"::error::template directory not found: {args.template_dir}")
        return 3

    templates = find_templates(args.template_dir)
    if not templates:
        print(f"::error::no {' or '.join(TEMPLATE_SUFFIXES)} files under "
              f"{args.template_dir} - the check would pass vacuously")
        return 3

    print(f"checking {len(templates)} template(s) under {args.template_dir} "
          f"(trim_blocks={args.trim_blocks})")

    env = build_env(args.template_dir, args.trim_blocks)
    errors, warnings = 0, 0

    for full_path, rel_path in templates:
        problem = check_syntax(env, rel_path)
        notes = lint_stray_tags(full_path) if args.lint else []

        if problem:
            errors += 1
            print(f"  FAIL  {rel_path}")
            print(f"        {problem}")
            # Annotation with a file/line so it appears inline on the PR diff.
            print(f"::error file={full_path}::Jinja syntax error - {problem}")
        elif notes:
            print(f"  warn  {rel_path}")
        else:
            print(f"  ok    {rel_path}")

        for note in notes:
            warnings += 1
            print(f"        {note}")
            level = "error" if args.strict_lint else "warning"
            print(f"::{level} file={full_path}::{note.splitlines()[0]}")

    print(f"\n{len(templates) - errors} of {len(templates)} template(s) compile; "
          f"{warnings} lint warning(s)")

    if errors:
        print("::error::one or more templates will not render - nac-test would "
              "abort the entire suite, including tests unrelated to the fault")
        return 1
    if warnings and args.strict_lint:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())