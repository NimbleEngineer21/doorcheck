"""Contracts shared by pinned snapshots and freshly recorded scanner output."""

import json
import os
from pathlib import Path

import pytest

from doorcheck.adapters.base import Parsed
from doorcheck.adapters.guarddog import GuardDog, GuardDogDependencies
from doorcheck.adapters.osv import OsvScanner
from doorcheck.adapters.semgrep import Semgrep
from doorcheck.adapters.zizmor import Zizmor
from tests.adapters_support import FIXTURES, as_recorded

ROOT = Path(os.environ.get("DOORCHECK_LIVE_FIXTURES", str(FIXTURES)))


def output(tool: str, case: str = "unsafe") -> bytes:
    return (ROOT / "tools" / tool / f"{case}.json").read_bytes()


def test_live_semgrep_preserves_suppressed_and_visible_matches() -> None:
    parsed = Semgrep().parse(output("semgrep"), as_recorded(ROOT / "integrations/unsafe"))
    assert parsed.problems == ()
    assert {(f.rule_id, f.location.path, f.location.line) for f in parsed.findings} == {
        ("test-unauth-view-path-join", "__init__.py", 18),
        ("test-unauth-view-path-join", "suppressed.py", 16),
    }


def test_live_zizmor_preserves_findings_despite_repository_suppressions() -> None:
    parsed = Zizmor().parse(output("zizmor"), as_recorded(ROOT / "integrations/unsafe"))
    assert parsed.problems == ()
    assert {f.rule_id for f in parsed.findings} == {
        "zizmor/template-injection",
        "zizmor/excessive-permissions",
    }


def test_live_guarddog_preserves_code_observations() -> None:
    parsed = GuardDog().parse(output("guarddog"), as_recorded(ROOT / "integrations/unsafe"))
    assert {f.rule_id for f in parsed.findings} >= {
        "guarddog/capability-network-lolbas",
        "guarddog/capability-process-spawn",
        "guarddog/threat-process-download-exec",
        "guarddog/threat-runtime-obfuscation-base64exec",
    }


def test_live_osv_still_reports_the_known_vulnerable_pin() -> None:
    parsed = OsvScanner().parse(output("osv-scanner"), as_recorded(ROOT / "integrations/unsafe"))
    assert any(
        f.rule_id == "osv/known-vulnerability"
        and f.params["package"] == "requests"
        and f.location.path == "manifest.json"
        and f.location.line == 6
        for f in parsed.findings
    )
    assert {(p.key, p.location.line) for p in parsed.problems if p.location} == {
        ("problem.requirement_outside_pypi", 8),
        ("problem.requirement_outside_pypi", 9),
    }


def test_live_dependency_checks_preserve_dynamic_errors_and_missing_packages() -> None:
    data = output("guarddog-dependencies")
    parsed = GuardDogDependencies().parse(data, as_recorded(ROOT / "integrations/unsafe"))
    assert {f.params["package"] for f in parsed.findings} >= {"requests", "icmplib"}
    assert {(p.key, p.location.line) for p in parsed.problems if p.location} >= {
        ("problem.requirement_outside_pypi", 8),
        ("problem.requirement_outside_pypi", 9),
        ("problem.dependency_not_checked", 10),
    }
    expected = {
        (item["dependency"], check, str(detail))
        for item in json.loads(data)
        for check, detail in item["result"]["errors"].items()
    }
    actual = {
        (p.params["package"], p.params["check"], p.params["detail"])
        for p in parsed.problems
        if p.key == "problem.tool_check_failed"
    }
    # Problem details are bounded by the model, as they are in the original snapshots.
    from doorcheck.findings import param

    assert actual == {
        (param(package), param(check), param(detail)) for package, check, detail in expected
    }


@pytest.mark.parametrize("tool", ["semgrep", "guarddog"])
def test_live_clean_code_has_no_observations(tool: str) -> None:
    reader = Semgrep() if tool == "semgrep" else GuardDog()
    assert reader.parse(output(tool, "clean"), as_recorded(ROOT / "integrations/clean")) == Parsed()
