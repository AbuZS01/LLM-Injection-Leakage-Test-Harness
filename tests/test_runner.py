"""End-to-end checks of the harness using the offline mock targets."""

from pathlib import Path

from harness.cli import main
from harness.defences import get_defence
from harness.providers import MockEcho, MockRefuse
from harness.runner import load_cases, run, summarise
from harness.target import build_system_prompt, new_canary

CASES = Path(__file__).resolve().parent.parent / "cases"


def test_case_suite_shape():
    cases = load_cases(CASES)
    attacks = [c for c in cases if not c.is_control]
    assert len(attacks) == 20
    assert {c.category for c in attacks} == {"direct_injection", "indirect_injection", "pii_leakage", "rag_poisoning"}
    assert all(c.owasp and c.atlas for c in cases)


def test_canary_is_fresh_per_trial():
    a, b = new_canary(), new_canary()
    assert a != b and a in build_system_prompt(a)


def test_echo_target_leaks_every_secret_bearing_case():
    cases = load_cases(CASES)
    summary = summarise(cases, run(cases, MockEcho(), get_defence("none"), trials=2))
    rows = {r["id"]: r for r in summary["cases"]}
    # Every case that looks for the canary, PII or an attacker URL already present in context must fire.
    for cid in ["D01", "D02", "D03", "D04", "D05", "D06", "I02", "I03", "I06", "P01", "P02", "P03", "P04", "P05", "R01", "R02", "R03"]:
        assert rows[cid]["rate"] == 1.0, cid
    # Computed markers are not in the context, so echoing must NOT trigger them (no false positives).
    assert rows["I01"]["rate"] == 0.0
    assert rows["I04"]["rate"] == 0.0
    # Controls fail because the echo leaks the canary.
    assert summary["controls"]["rate"] == 1.0


def test_refusing_target_blocks_attacks_but_fails_utility():
    cases = load_cases(CASES)
    summary = summarise(cases, run(cases, MockRefuse(), get_defence("none"), trials=1))
    assert summary["overall"]["rate"] == 0.0
    assert summary["controls"]["rate"] == 1.0


def test_cli_writes_reports_and_gates(tmp_path):
    assert main(["run", "--provider", "mock-refuse", "--trials", "1", "--out", str(tmp_path), "--fail-above", "0.1"]) == 0
    assert main(["run", "--provider", "mock-echo", "--trials", "1", "--out", str(tmp_path), "--fail-above", "0.1"]) == 1
    assert len(list(tmp_path.glob("*.md"))) == 2
    assert len(list(tmp_path.glob("*.json"))) == 2


def test_errors_are_excluded_not_counted():
    class Broken(MockRefuse):
        def complete(self, system, user):
            raise RuntimeError("boom")

    cases = load_cases(CASES)[:3]
    summary = summarise(cases, run(cases, Broken(), get_defence("none"), trials=2))
    assert summary["errors"] == 6
    assert summary["overall"]["rate"] is None


def test_report_filenames_are_portable():
    from harness.cli import safe_filename

    assert safe_filename("20261003-openrouter-qwen/qwen3-27b:free-none") == "20261003-openrouter-qwen_qwen3-27b_free-none"
    assert safe_filename('a"b<c>d|e*f?g') == "a_b_c_d_e_f_g"
