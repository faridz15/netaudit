#!/usr/bin/env python3
"""
NetAudit command line interface.

The web app is for reading a single device carefully. This is for the other
case: running the same checks across a directory of configs, on a schedule or
in a pipeline, and failing a build when something regresses.

    python cli.py audit samples/branch-router-01.cfg
    python cli.py audit configs/ --format csv --output findings.csv
    python cli.py audit configs/ --fail-under 80
    python cli.py drift baseline.cfg current.cfg

Exit codes:
    0  every device met the threshold
    1  at least one device fell below --fail-under
    2  bad arguments or unreadable input
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from netaudit.drift import compare_configs
from netaudit.parser import parse_config
from netaudit.report import to_csv, to_markdown, to_remediation_config
from netaudit.rules import run_audit

CONFIG_SUFFIXES = {".cfg", ".txt", ".conf", ".config"}


def collect_paths(target: Path) -> list[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(p for p in target.rglob("*") if p.suffix.lower() in CONFIG_SUFFIXES)
    return []


def cmd_audit(args: argparse.Namespace) -> int:
    target = Path(args.path)
    paths = collect_paths(target)

    if not paths:
        print(f"No configuration files found at {target}", file=sys.stderr)
        return 2

    chunks: list[str] = []
    below: list[tuple[str, int]] = []

    for path in paths:
        try:
            text = path.read_text(errors="replace")
        except OSError as exc:
            print(f"Could not read {path}: {exc}", file=sys.stderr)
            return 2

        result = run_audit(parse_config(text))

        if result.score() < args.fail_under:
            below.append((result.hostname, result.score()))

        if args.format == "markdown":
            chunks.append(to_markdown(result))
        elif args.format == "csv":
            csv_text = to_csv(result)
            # Only the first file keeps its header row
            chunks.append(csv_text if not chunks else csv_text.split("\r\n", 1)[1])
        elif args.format == "remediation":
            chunks.append(to_remediation_config(result))
        else:  # summary
            c = result.counts_by_severity()
            chunks.append(
                f"{result.score():>3}/100  {result.grade()}  {result.hostname:<20} "
                f"{result.failed_count:>2} findings  "
                f"(C{c['CRITICAL']} H{c['HIGH']} M{c['MEDIUM']} L{c['LOW']})  {path}"
            )

    output = "\n".join(chunks) if args.format == "summary" else "\n\n".join(chunks)

    if args.output:
        Path(args.output).write_text(output)
        print(f"Wrote {args.output} ({len(paths)} device(s))")
    else:
        print(output)

    if below:
        print(f"\n{len(below)} device(s) below the threshold of {args.fail_under}:", file=sys.stderr)
        for host, score in below:
            print(f"  {host}: {score}", file=sys.stderr)
        return 1

    return 0


def cmd_drift(args: argparse.Namespace) -> int:
    baseline = Path(args.baseline)
    current = Path(args.current)

    for p in (baseline, current):
        if not p.is_file():
            print(f"Not a file: {p}", file=sys.stderr)
            return 2

    drift = compare_configs(baseline.read_text(errors="replace"),
                            current.read_text(errors="replace"))

    print(f"Baseline : {drift.baseline_hostname}  score {drift.baseline_score}/100")
    print(f"Current  : {drift.current_hostname}  score {drift.current_score}/100")
    print(f"Delta    : {drift.score_delta:+d}")
    print()
    print(drift.summary_line())

    if drift.security_changes:
        print("\nSecurity-relevant changes")
        for category, changes in drift.by_category().items():
            print(f"\n  {category}")
            for ch in changes:
                sign = "+" if ch.action == "added" else "-"
                print(f"    {sign} {ch.line.strip()}")

    if args.include_routine and drift.routine_changes:
        print(f"\nOther changes ({len(drift.routine_changes)})")
        for ch in drift.routine_changes:
            sign = "+" if ch.action == "added" else "-"
            print(f"    {sign} {ch.line.strip()}")

    return 1 if drift.score_delta < 0 else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netaudit",
        description="Audit Cisco IOS configurations against a hardening baseline.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_audit = sub.add_parser("audit", help="Audit a config file or a directory of configs")
    p_audit.add_argument("path", help="Config file or directory")
    p_audit.add_argument("--format", choices=["summary", "markdown", "csv", "remediation"],
                         default="summary")
    p_audit.add_argument("--output", "-o", help="Write to a file instead of stdout")
    p_audit.add_argument("--fail-under", type=int, default=0, metavar="SCORE",
                         help="Exit 1 if any device scores below this (default 0, never fail)")
    p_audit.set_defaults(func=cmd_audit)

    p_drift = sub.add_parser("drift", help="Compare two snapshots of a device")
    p_drift.add_argument("baseline")
    p_drift.add_argument("current")
    p_drift.add_argument("--include-routine", action="store_true",
                         help="Also list changes that are not security-relevant")
    p_drift.set_defaults(func=cmd_drift)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
