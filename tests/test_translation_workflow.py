"""Translation workflow holds secrets only in trusted code and returns review artifacts."""

import re
from pathlib import Path

import yaml

from doorcheck.messages.localization import context
from tools.deepl import plan


def workflow():
    return yaml.load(
        Path(".github/workflows/translations.yml").read_text(),
        Loader=yaml.BaseLoader,  # noqa: S506 - strings/lists/mappings only
    )


def test_translation_dispatch_is_main_only_and_read_only():
    data = workflow()
    assert set(data["on"]) == {"workflow_dispatch"}
    assert data["permissions"] == {}
    assert data["concurrency"] == {"group": "translations-deepl", "cancel-in-progress": "false"}
    job = data["jobs"]["refresh"]
    assert job["if"] == "github.ref == 'refs/heads/main'"
    assert job["timeout-minutes"] == "20"
    assert job["permissions"] == {"contents": "read", "pull-requests": "read"}
    checkout = job["steps"][0]
    assert checkout["with"] == {"ref": "main", "persist-credentials": "false"}
    assert all(
        re.fullmatch(r".+@[0-9a-f]{40}", step["uses"]) for step in job["steps"] if "uses" in step
    )


def test_pr_head_is_frozen_and_fixed_data_paths_are_read_from_fork_repository():
    steps = workflow()["jobs"]["refresh"]["steps"]
    read = next(s for s in steps if s.get("name", "").startswith("Read English"))
    assert "DEEPL_API_KEY" not in read.get("env", {})
    text = read["run"]
    assert "--json headRefOid,headRepository,headRepositoryOwner" in text
    assert ".headRepositoryOwner.login" in text and ".headRepository.name" in text
    assert '"repos/$HEAD_OWNER/$HEAD_NAME/contents/src/doorcheck/messages/$NAME"' in text
    assert "for NAME in en.json translation-context.json; do" in text
    assert '-f ref="$HEAD_SHA"' in text
    assert '[[ "$HEAD_SHA" =~ ^[0-9a-f]{40}$ ]]' in text
    assert '[[ "$HEAD_OWNER" =~ ^[A-Za-z0-9-]+$ ]]' in text
    assert '[[ "$HEAD_NAME" =~ ^[A-Za-z0-9_.-]+$ ]]' in text
    assert "translation-source-commit.txt" in text
    assert not any("${{" in step.get("run", "") for step in steps)


def test_only_trusted_refresh_step_has_provider_secret_and_artifact_is_reviewable():
    steps = workflow()["jobs"]["refresh"]["steps"]
    secret_steps = [s for s in steps if "DEEPL_API_KEY" in s.get("env", {})]
    assert len(secret_steps) == 1
    refresh = secret_steps[0]
    assert refresh["env"]["DEEPL_API_KEY"] == "${{ secrets.DEEPL_API_KEY }}"
    assert '--max-characters "$MAX_CHARACTERS"' in refresh["run"]
    assert '--locales "$TARGET_LOCALES"' in refresh["run"]
    assert "--available-only --write" in refresh["run"]
    upload = steps[-1]
    assert upload["with"]["name"] == "translation-refresh"
    assert upload["with"]["retention-days"] == "14"
    assert upload["with"]["if-no-files-found"] == "error"
    assert "${{ runner.temp }}/translations" in upload["with"]["path"]
    assert "translation-source-commit.txt" in upload["with"]["path"]


def test_default_dispatch_budget_can_refresh_default_locale():
    inputs = workflow()["on"]["workflow_dispatch"]["inputs"]
    rows, total = plan(inputs["locales"]["default"].split(","), context())
    assert set(rows) == {"de"}
    assert total <= int(inputs["max_characters"]["default"])


def test_localization_gate_is_part_of_normal_pr_ci():
    data = yaml.load(
        Path(".github/workflows/ci.yml").read_text(),
        Loader=yaml.BaseLoader,  # noqa: S506 - strings/lists/mappings only
    )
    entries = data["jobs"]["check"]["strategy"]["matrix"]["include"]
    assert {"name": "localization", "run": "uv run python -m tools.localization --check"} in entries
