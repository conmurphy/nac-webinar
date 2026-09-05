#!/usr/bin/env python3
"""
Parse-check nac-test Robot templates without touching the fabric.

WHY
    nac-test renders every template through Jinja before Robot sees it, so one
    malformed tag aborts the WHOLE suite - including tests that would have
    passed. Catching it at the validate gate costs milliseconds; catching it in
    the post-deploy job means it surfaces after terraform apply has already
    changed the fabric.

RELATIONSHIP TO 'nac-test --dry-run'
    The dry run is the AUTHORITATIVE syntax check: it uses nac-test's own Jinja
    environment, with the real filter registry, and additionally resolves every
    Robot keyword and argument count. Anything it rejects is genuinely broken.

    This script exists for two things the dry run cannot give:
      1. Per-file failure with a line number and a PR diff annotation. nac-test
         aborts the entire render on the first bad template.
      2. The whitespace-join lint (--lint), which no compiler can catch: a Jinja
         block tag inside a test body swallows the following newline, and the
         joined line is often still a VALID keyword call with an extra argument.
         It compiles, resolves, and fails only at execution time.

    If the compile half ever becomes a maintenance burden, run with --lint-only
    and let the dry run own syntax.

FILTER STUBBING
    Jinja resolves filter names at COMPILE time, so a filter registered by
    nac-test (community.general.json_query and friends) would fail here as
    "No filter named ...". Unknown filters are therefore stubbed.

    IMPORTANT: Jinja's compiler looks filters up with .get(), NOT with [], so a
    dict subclass implementing only __missing__ is never consulted. That was a
    live defect in this script - every Ansible-style filter reported a false
    syntax error. The get() override below is the hook that actually matters.

    Consequence worth knowing: a MISTYPED filter name is stubbed rather than
    reported. Stubbed names are listed at the end so a typo is at least visible,
    and --strict-filters turns that into a failure if you keep an allowlist.

Usage:
  check_templates.py TEMPLATE_DIR [--lint] [--lint-only] [--strict-lint]
                                  [--strict-filters] [--known-filter NAME]
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

# Filters known to be provided by nac-test or an Ansible collection. Listing them
# keeps them out of the "stubbed" report, so that report only ever shows names
# worth a second look.
DEFAULT_KNOWN_FILTERS = frozenset({
    "community.general.json_query",
    "ansible.netcommon.ipaddr",
    "ansible.utils.ipaddr",
    "ipaddr",
    "json_query",
})

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

# A Jinja join with a SINGLE space feeding a Robot argument position. Robot
# separates arguments on TWO or more spaces, so this collapses a list into one
# argument. Silent, because the resulting keyword call is still valid - this bug
# made 'Create List 1101 1102' produce the single string "1101 1102", which then
# missed every NODE_MGMT_MAP key and skipped the test claiming the map was unset.
SINGLE_SPACE_JOIN = re.compile(
    r"\{\{[^}]*\|\s*join\(\s*['\"] ['\"]\s*\)[^}]*\}\}"
)
ARG_LIST_KEYWORDS = ("Create List", "Create Dictionary")


class StubbingRegistry(dict):
    """
    Filter/test registry that yields a passthrough for anything it lacks.

    get() is overridden because that is what Jinja's compiler calls. __missing__
    is overridden too, for any code path that uses subscript access. __contains__
    is deliberately NOT overridden: returning True unconditionally would break
    the membership test inside get() and make every lookup return None.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.stubbed = set()

    def _stub(self, key):
        self.stubbed.add(key)
        return lambda value, *args, **kwargs: value

    def get(self, key, default=None):
        if dict.__contains__(self, key):
            return dict.__getitem__(self, key)
        return self._stub(key)

    def __missing__(self, key):
        return self._stub(key)


def build_env(template_dir):
    env = Environment(
        loader=FileSystemLoader(template_dir),
        # Mirrors nac-test. trim_blocks in particular is what makes a block tag
        # inside a test body eat the following newline, so checking without it
        # would validate a file that still breaks at runtime.
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
    )
    env.filters = StubbingRegistry(env.filters)
    env.tests = StubbingRegistry(env.tests)
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


def lint_file(full_path):
    """
    Heuristic checks that compilation cannot catch.

    1. A tag whose first word is not a Jinja keyword - almost always prose
       mentioning Jinja syntax, which Jinja then tries to execute.
    2. An INDENTED block tag inside Test Cases. Test-generating loops sit at
       column 0; an indented one is inside a test body, where trim_blocks
       swallows the newline and joins the next Robot line onto the previous
       keyword.
    3. join(' ') feeding a keyword that takes a list of arguments.
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

            if SINGLE_SPACE_JOIN.search(line) and any(
                kw in line for kw in ARG_LIST_KEYWORDS
            ):
                warnings.append(
                    f"line {lineno}: join(' ') feeding a list keyword. Robot "
                    f"splits arguments on TWO or more spaces, so this produces "
                    f"ONE argument containing the whole joined string. Use "
                    f"join(',') and Split String inside the "
                    f"keyword.\n      >>> {line.strip()}"
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
                            f"following newline and joins the next Robot line "
                            f"onto the previous keyword. Move the loop above the "
                            f"test name, or into a Robot "
                            f"keyword.\n      >>> {line.strip()}"
                        )
    return warnings


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("template_dir")
    ap.add_argument("--lint", action="store_true",
                    help="also run heuristic checks for stray and misplaced tags")
    ap.add_argument("--lint-only", action="store_true",
                    help="skip compilation and run only the heuristics; use when "
                         "nac-test --dry-run already owns syntax checking")
    ap.add_argument("--strict-lint", action="store_true",
                    help="treat lint warnings as failures")
    ap.add_argument("--strict-filters", action="store_true",
                    help="fail when a filter had to be stubbed, i.e. is not in "
                         "the known-filter allowlist")
    ap.add_argument("--known-filter", action="append", default=[],
                    metavar="NAME",
                    help="filter name provided by nac-test at runtime "
                         "(repeatable); suppresses it from the stubbed report")
    args = ap.parse_args()

    if not os.path.isdir(args.template_dir):
        print(f"::error::template directory not found: {args.template_dir}")
        return 3

    templates = find_templates(args.template_dir)
    if not templates:
        print(f"::error::no {' or '.join(TEMPLATE_SUFFIXES)} files under "
              f"{args.template_dir} - the check would pass vacuously")
        return 3

    known = set(DEFAULT_KNOWN_FILTERS) | set(args.known_filter)
    do_lint = args.lint or args.lint_only

    mode = "lint only" if args.lint_only else "compile" + (" + lint" if args.lint else "")
    print(f"checking {len(templates)} template(s) under {args.template_dir} "
          f"({mode}, trim_blocks=True)")

    env = None if args.lint_only else build_env(args.template_dir)
    errors, warnings = 0, 0

    for full_path, rel_path in templates:
        problem = None if env is None else check_syntax(env, rel_path)
        notes = lint_file(full_path) if do_lint else []

        if problem:
            errors += 1
            print(f"  FAIL  {rel_path}")
            print(f"        {problem}")
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

    unexpected = sorted((env.filters.stubbed | env.tests.stubbed) - known) if env else []
    expected = sorted((env.filters.stubbed | env.tests.stubbed) & known) if env else []

    if expected:
        print(f"\nstubbed known runtime filters: {', '.join(expected)}")
    if unexpected:
        print(f"\nstubbed UNKNOWN filters: {', '.join(unexpected)}")
        print("  These compiled because unknown filters are stubbed. If one is a "
              "typo, nac-test will fail on it - add it to --known-filter once "
              "confirmed, or fix the name.")
        for name in unexpected:
            level = "error" if args.strict_filters else "warning"
            print(f"::{level}::unknown Jinja filter '{name}' was stubbed for this "
                  f"check - confirm nac-test provides it")

    checked = len(templates)
    if env is not None:
        print(f"\n{checked - errors} of {checked} template(s) compile; "
              f"{warnings} lint warning(s)")
    else:
        print(f"\n{checked} template(s) linted; {warnings} warning(s)")

    if errors:
        print("::error::one or more templates will not render - nac-test would "
              "abort the entire suite, including tests unrelated to the fault")
        return 1
    if warnings and args.strict_lint:
        return 1
    if unexpected and args.strict_filters:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())