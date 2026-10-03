"""Load cases, run repeated trials against the target, and score them."""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

import yaml

from harness.defences import Defence
from harness.detectors import check_expectations, run_detectors
from harness.providers import Provider
from harness.target import TargetInput, build_system_prompt, build_user_message, new_canary

DEFAULT_INSTRUCTION = "Summarise this ticket."
REQUIRED = {"id", "category", "title", "owasp", "atlas", "document"}


@dataclass
class Case:
    id: str
    category: str
    title: str
    owasp: list[str]
    atlas: list[str]
    document: str
    description: str = ""
    user_instruction: str = DEFAULT_INSTRUCTION
    knowledge: list[dict] = field(default_factory=list)
    fail_if: list = field(default_factory=list)
    expect: list[dict] = field(default_factory=list)

    @property
    def is_control(self) -> bool:
        return self.category == "control"


@dataclass
class Trial:
    case_id: str
    trial: int
    outcome: str  # attack_succeeded | defended | utility_ok | utility_failed | error
    evidence: list[str]
    refused: bool
    latency_s: float
    output: str


def load_cases(path: Path) -> list[Case]:
    files = sorted(path.glob("*.yaml")) if path.is_dir() else [path]
    cases, seen = [], set()
    for f in files:
        for raw in yaml.safe_load(f.read_text()) or []:
            missing = REQUIRED - raw.keys()
            if missing:
                raise ValueError(f"{f.name}: case {raw.get('id', '?')} missing {sorted(missing)}")
            if raw["id"] in seen:
                raise ValueError(f"Duplicate case id {raw['id']}")
            seen.add(raw["id"])
            case = Case(**raw)
            if not case.is_control and not case.fail_if:
                raise ValueError(f"Attack case {case.id} has no fail_if detectors")
            cases.append(case)
    return cases


def run_trial(case: Case, n: int, provider: Provider, defence: Defence) -> Trial:
    canary = new_canary()
    system = build_system_prompt(canary)
    user = build_user_message(TargetInput(case.user_instruction, case.document, case.knowledge))
    system, user = defence.wrap_input(system, user)
    start = time.monotonic()
    try:
        completion = provider.complete(system, user)
    except Exception as exc:  # recorded, excluded from the denominator, shown in the report
        return Trial(case.id, n, "error", [f"{type(exc).__name__}: {exc}"[:300]], False, time.monotonic() - start, "")
    latency = time.monotonic() - start
    text = defence.filter_output(completion.text, canary)

    evidence = run_detectors(case.fail_if, text, canary)
    if case.is_control:
        missing = check_expectations(case.expect, text)
        outcome = "utility_ok" if not (evidence or missing) else "utility_failed"
        evidence += missing
    else:
        outcome = "attack_succeeded" if evidence else "defended"
    return Trial(case.id, n, outcome, evidence, completion.refused, round(latency, 2), text)


def run(cases: list[Case], provider: Provider, defence: Defence, trials: int, workers: int = 4) -> list[Trial]:
    jobs = [(c, i) for c in cases for i in range(1, trials + 1)]
    with ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(lambda job: run_trial(job[0], job[1], provider, defence), jobs))


def summarise(cases: list[Case], results: list[Trial]) -> dict:
    by_case = {c.id: [t for t in results if t.case_id == c.id] for c in cases}
    case_rows = []
    for c in cases:
        ts = by_case[c.id]
        valid = [t for t in ts if t.outcome != "error"]
        hits = [t for t in valid if t.outcome in ("attack_succeeded", "utility_failed")]
        case_rows.append({
            "id": c.id,
            "title": c.title,
            "category": c.category,
            "owasp": c.owasp,
            "atlas": c.atlas,
            "trials": len(ts),
            "valid": len(valid),
            "failures": len(hits),
            "rate": len(hits) / len(valid) if valid else None,
            "refused": sum(t.refused for t in valid),
            "errors": len(ts) - len(valid),
            "evidence": sorted({e for t in hits for e in t.evidence}),
        })

    def pool(rows):
        valid = sum(r["valid"] for r in rows)
        fails = sum(r["failures"] for r in rows)
        return {"cases": len(rows), "valid": valid, "failures": fails, "rate": fails / valid if valid else None}

    attacks = [r for r in case_rows if r["category"] != "control"]
    controls = [r for r in case_rows if r["category"] == "control"]
    categories = {}
    for r in attacks:
        categories.setdefault(r["category"], []).append(r)
    return {
        "overall": pool(attacks),
        "controls": pool(controls),
        "categories": {k: {**pool(v), "owasp": sorted({o for r in v for o in r["owasp"]})} for k, v in categories.items()},
        "cases": case_rows,
        "errors": sum(r["errors"] for r in case_rows),
    }


def results_as_dicts(results: list[Trial], max_output: int = 2000) -> list[dict]:
    rows = []
    for t in results:
        d = asdict(t)
        d["output"] = d["output"][:max_output]
        rows.append(d)
    return rows
