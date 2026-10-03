"""Command-line entry point: python -m harness run ..."""

from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from harness import __version__
from harness.defences import DEFENCES, get_defence
from harness.providers import get_provider
from harness.report import render_markdown
from harness.runner import load_cases, results_as_dicts, run, summarise

ROOT = Path(__file__).resolve().parent.parent


def safe_filename(name: str) -> str:
    """Model IDs can contain / and : (e.g. 'vendor/model:free'). Keep filenames portable."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="harness", description="LLM prompt injection & data leakage test harness")
    sub = p.add_subparsers(dest="command", required=True)

    r = sub.add_parser("run", help="Run test cases against the target app")
    r.add_argument("--provider", required=True, choices=["mock-echo", "mock-refuse", "anthropic", "openai-compatible", "openrouter"])
    r.add_argument("--model", help="Model ID (required for openai-compatible and openrouter)")
    r.add_argument("--base-url", help="Base URL for an OpenAI-compatible API")
    r.add_argument("--effort", choices=["low", "medium", "high", "xhigh", "max"], help="Anthropic effort level")
    r.add_argument("--defence", default="none", choices=sorted(DEFENCES))
    r.add_argument("--cases", type=Path, default=ROOT / "cases")
    r.add_argument("--only", help="Comma-separated case IDs or categories to run")
    r.add_argument("--trials", type=int, default=5)
    r.add_argument("--workers", type=int, default=4)
    r.add_argument("--out", type=Path, default=ROOT / "reports")
    r.add_argument("--fail-above", type=float, help="Exit 1 if attack success rate exceeds this (0-1). For CI gating.")

    sub.add_parser("list", help="List test cases").add_argument("--cases", type=Path, default=ROOT / "cases")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cases = load_cases(args.cases)

    if args.command == "list":
        for c in cases:
            print(f"{c.id:5} {c.category:20} {', '.join(c.owasp):8} {c.title}")
        return 0

    if args.only:
        wanted = {s.strip() for s in args.only.split(",")}
        cases = [c for c in cases if c.id in wanted or c.category in wanted]
        if not cases:
            print(f"No cases match --only {args.only}")
            return 2

    provider = get_provider(args.provider, args.model, args.base_url, args.effort)
    defence = get_defence(args.defence)
    total = len(cases) * args.trials
    print(f"Running {len(cases)} cases x {args.trials} trials = {total} calls against {provider.name}/{provider.model} (defence: {defence.name})")

    results = run(cases, provider, defence, args.trials, args.workers)
    summary = summarise(cases, results)
    now = datetime.now(timezone.utc)
    meta = {
        "harness_version": __version__,
        "target": "TicketAssist v1",
        "defence": defence.name,
        "provider": provider.name,
        "model": provider.model,
        "trials": args.trials,
        "timestamp": now.strftime("%Y-%m-%d %H:%M"),
    }

    args.out.mkdir(parents=True, exist_ok=True)
    stem = safe_filename(f"{now:%Y%m%d-%H%M%S}-{provider.name}-{provider.model}-{defence.name}")
    md_path, json_path = args.out / f"{stem}.md", args.out / f"{stem}.json"
    md_path.write_text(render_markdown(summary, meta))
    json_path.write_text(json.dumps({"meta": meta, "summary": summary, "trials": results_as_dicts(results)}, indent=2))

    rate = summary["overall"]["rate"]
    print(f"Attack success rate: {'n/a' if rate is None else f'{rate:.0%}'}  |  report: {md_path}")
    if args.fail_above is not None and rate is not None and rate > args.fail_above:
        print(f"FAIL: attack success rate {rate:.0%} exceeds threshold {args.fail_above:.0%}")
        return 1
    return 0
