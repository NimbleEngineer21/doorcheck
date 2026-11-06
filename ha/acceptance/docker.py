"""Run the acceptance suite in a pinned, network-isolated official HA image."""

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4

from tools.corpus import fetch, load
from tools.release import project_version, wheel_name

from .evidence import validate
from .fixtures import REFERENCES

ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    profiles = json.loads(Path(__file__).with_name("images.json").read_text())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=profiles, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    profile = profiles[args.profile]
    cases = {case.id: case for case in load(ROOT / "benchmark/corpus.toml")}
    for case, _ in REFERENCES:
        fetch(cases[case], ROOT / ".benchmark-cache")
    image = profile["image"]
    # The wheel `uv build` writes for this checkout's version.
    wheel = f"dist/{wheel_name(project_version(ROOT))}"
    subprocess.run(["docker", "pull", image], check=True, stdout=sys.stderr)  # noqa: S603,S607 - fixed executable, digest-pinned image
    name = f"doorcheck-acceptance-{uuid4().hex}"
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "256",
        "--memory",
        "1g",
        "--cpus",
        "2",
        "--read-only",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=128m",  # noqa: S108 - private container tmpfs
        "--mount",
        f"type=bind,src={ROOT / 'ha/acceptance'},dst=/work/ha/acceptance,readonly",
        "--mount",
        (
            f"type=bind,src={ROOT / 'custom_components/doorcheck'},"
            "dst=/work/ha/custom_components/doorcheck,readonly"
        ),
        "--mount",
        f"type=bind,src={ROOT / wheel},dst=/work/{wheel},readonly",
        "--env",
        "PYTHONPATH=/work/ha",
        "--workdir",
        "/work/ha",
        "--entrypoint",
        "python",
        image,
        "-m",
        "acceptance",
        "--expected-ha",
        profile["version"],
        "--validation-status",
        str(profile["rest_validation_status"]),
        "--wheel",
        f"/work/{wheel}",
    ]
    for case, domain in REFERENCES:
        tree = Path(".benchmark-cache") / case / "custom_components" / domain
        command[2:2] = ["--mount", f"type=bind,src={ROOT / tree},dst=/work/{tree},readonly"]
    with tempfile.TemporaryFile(mode="w+") as output:
        try:
            result = subprocess.run(command, check=False, stdout=output, timeout=300)  # noqa: S603 - fixed command, no shell
        finally:
            subprocess.run(  # noqa: S603 - remove only this generated container
                ["docker", "rm", "--force", name],  # noqa: S607 - developer Docker executable
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        output.seek(0)
        evidence = validate(json.loads(output.read(128 * 1024)))
    evidence["container_image"] = image
    evidence["profile"] = args.profile
    evidence["reference_commits"] = {case: cases[case].commit for case, _ in REFERENCES}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(evidence, indent=2) + "\n")
    print(
        json.dumps(
            {
                "profile": args.profile,
                "status": evidence["status"],
                "checks": evidence.get("checks", {}),
            },
            indent=2,
        )
    )
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
