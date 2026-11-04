"""Verify the actual disposable-container boundaries before booting HA."""

import os
import socket
from pathlib import Path


def active_interfaces() -> set[str]:
    return {
        name
        for _, name in socket.if_nameindex()
        if int((Path("/sys/class/net") / name / "flags").read_text().strip(), 16) & 1
    }


def boundaries() -> dict[str, bool]:
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    return {
        "network_loopback_only": active_interfaces() == {"lo"},
        "capabilities_dropped": int(status["CapEff"].strip(), 16) == 0,
        "no_new_privileges": status["NoNewPrivs"].strip() == "1",
        "root_readonly": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
        "source_readonly": bool(
            os.statvfs("/work/ha/custom_components/doorcheck").f_flag & os.ST_RDONLY
        ),
        "repository_mount_is_scoped": not Path("/work/pyproject.toml").exists(),
        "docker_socket_not_mounted": not Path("/var/run/docker.sock").exists(),
        "memory_capped": Path("/sys/fs/cgroup/memory.max").read_text().strip() == "1073741824",
        "pids_capped": Path("/sys/fs/cgroup/pids.max").read_text().strip() == "256",
        "cpu_capped": Path("/sys/fs/cgroup/cpu.max").read_text().strip() == "200000 100000",
    }
