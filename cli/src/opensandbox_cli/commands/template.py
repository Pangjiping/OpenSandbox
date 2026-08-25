# Copyright 2026 Alibaba Group Holding Ltd.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""SandboxTemplate commands: declarative golden-image builds.

Build a Firecracker rootfs (and optional snapshot / OverlayBD layers) from an
OCI archive, emit a content-addressed manifest, and publish the artifacts to
an S3-compatible object store.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import click
import yaml

from opensandbox_cli.template_builder import (
    FORMATS,
    BuildResult,
    build_manifest,
    load_template,
    sha256_file,
    stage_convert,
    stage_package,
    stage_snapshot,
    stage_validate_boot,
    template_defaults,
    validate_template,
    write_checksums,
)

# The guest init skeleton injected as PID 1 in managed mode: mounts the base
# filesystems, brings loopback up, sources the sandbox env, starts execd via
# the bootstrap script and the entrypoint, then gates SANDBOX_READY on the
# template's readiness precedence (custom probe → execd /ping → warmup +
# healthcheck).
GUEST_INIT_HEAD = """#!/bin/sh
set -eu
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
mountpoint -q /proc || mount -t proc proc /proc
mountpoint -q /sys || mount -t sysfs sysfs /sys
mountpoint -q /dev || mount -t devtmpfs devtmpfs /dev
mkdir -p /dev/pts /dev/shm /run /tmp
mountpoint -q /dev/pts || mount -t devpts devpts /dev/pts
mountpoint -q /run || mount -t tmpfs tmpfs /run
mountpoint -q /tmp || mount -t tmpfs tmpfs /tmp
ip link set lo up 2>/dev/null || true
exec </dev/console >/dev/console 2>&1
hostname sandbox
[ -f /etc/sandbox-init.env ] && . /etc/sandbox-init.env
if [ -x /opt/opensandbox/bootstrap.sh ]; then
  setsid /bin/sh /opt/opensandbox/bootstrap.sh &
fi
if [ -n "${ENTRYPOINT:-}" ]; then
  setsid /bin/sh -c "$ENTRYPOINT" &
fi
"""

# Readiness probe implementations (one per priority tier).
GUEST_INIT_READY = """
ready_tcp() {
  host=${1#tcp://}; host=${host%%:*}; port=${1##*:}
  (exec 3<>/dev/tcp/"$host"/"$port") 2>/dev/null
}
ready_cmd() { /bin/sh -c "${1#cmd://}" >/dev/null 2>&1; }
ready_execd_ping() { (exec 3<>/dev/tcp/127.0.0.1/44772) 2>/dev/null; }

if [ -n "${READINESS_PROBE:-}" ]; then
  case "$READINESS_PROBE" in
    tcp://*) until ready_tcp "$READINESS_PROBE"; do sleep 1; done ;;
    cmd://*) until ready_cmd "$READINESS_PROBE"; do sleep 1; done ;;
    *) echo "SANDBOX_STARTUP_FAILED invalid_probe"; exit 1 ;;
  esac
elif [ -x /opt/opensandbox/execd ]; then
  # Default readiness: execd HTTP /ping.
  until ready_execd_ping; do sleep 1; done
else
  # Fallback: time-based warmup plus the template healthcheck (the image
  # CMD-SHELL is used when no healthcheck is declared).
  sleep "${WARMUP_SECONDS:-60}"
  if [ -n "${HEALTHCHECK:-}" ]; then
    until /bin/sh -c "$HEALTHCHECK" >/dev/null 2>&1; do sleep 1; done
  fi
fi
echo SANDBOX_READY
while true; do sleep 3600; done
"""


def guest_init_script(spec: dict) -> str:
    """Render the guest init script with the template's readiness settings."""
    readiness = spec.get("readiness", {})
    env_lines = []
    if readiness.get("probe"):
        env_lines.append(f"export READINESS_PROBE={readiness['probe']!r}")
    if readiness.get("warmupSeconds") is not None:
        env_lines.append(f"export WARMUP_SECONDS={int(readiness['warmupSeconds'])}")
    if readiness.get("healthCheck"):
        env_lines.append(f"export HEALTHCHECK={readiness['healthCheck']!r}")
    return GUEST_INIT_HEAD + "\n".join(env_lines) + "\n" + GUEST_INIT_READY


@click.group("template", invoke_without_command=True)
@click.pass_context
def template_group(ctx: click.Context) -> None:
    """Declarative golden-image builds (SandboxTemplate)."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


# ---- init ----------------------------------------------------------------


@template_group.command("init")
@click.option("--name", "-n", default="example-sandbox", show_default=True, help="Template name.")
@click.option("--output", "-o", default="sandboxtemplate.yaml", show_default=True, help="Output file.")
def template_init(name: str, output: str) -> None:
    """Generate a SandboxTemplate skeleton with documented defaults."""
    document = template_defaults()
    document["metadata"]["name"] = name
    target = Path(output)
    if target.exists():
        raise click.ClickException(f"{target} already exists; refusing to overwrite")
    target.write_text(
        yaml.safe_dump(document, sort_keys=False),
        encoding="utf-8",
    )
    click.echo(f"wrote {target}")


# ---- validate ------------------------------------------------------------


@template_group.command("validate")
@click.option("--file", "-f", "template_file", required=True, type=click.Path(exists=True, path_type=Path))
def template_validate(template_file: Path) -> None:
    """Validate a SandboxTemplate file."""
    try:
        spec = load_template(template_file)
    except (ValueError, yaml.YAMLError) as exc:
        raise click.ClickException(f"invalid template: {exc}") from exc
    errors = validate_template(spec)
    if errors:
        for error in errors:
            click.echo(f"error: {error}", err=True)
        raise click.ClickException(f"template validation failed ({len(errors)} errors)")
    click.echo("template is valid")


# ---- build ---------------------------------------------------------------


@template_group.command("build")
@click.option("--file", "-f", "template_file", required=True, type=click.Path(exists=True, path_type=Path))
@click.option("--oci-archive", required=True, type=click.Path(exists=True, path_type=Path), help="Local OCI archive (save-image output) of spec.image.")
@click.option("--format", "format_", type=click.Choice(FORMATS), help="Override spec.output.format.")
@click.option("--workdir", type=click.Path(path_type=Path), help="Build workspace (default: temp dir).")
@click.option("--execd-dir", type=click.Path(exists=True, path_type=Path), help="Directory with execd/bootstrap.sh/prepare.sh/bwrap to inject.")
@click.option("--kernel", type=click.Path(exists=True, path_type=Path), help="Guest kernel image (vmlinux) path.")
@click.option("--oci2rootfs", type=click.Path(exists=True, path_type=Path), help="oci2rootfs binary path (default: PATH).")
@click.option("--firecracker", type=click.Path(exists=True, path_type=Path), help="firecracker binary path (default: PATH).")
@click.option("--overlaybd-import", type=click.Path(exists=True, path_type=Path), help="overlaybd-import-raw binary path (default: PATH).")
@click.option("--ready-timeout", type=float, default=300, show_default=True, help="Seconds to wait for guest readiness.")
@click.option("--push", is_flag=True, help="Push artifacts to spec.output.publish after a successful build.")
def template_build(
    template_file: Path,
    oci_archive: Path,
    format_: str | None,
    workdir: Path | None,
    execd_dir: Path | None,
    kernel: Path | None,
    oci2rootfs: str | None,
    firecracker: str | None,
    overlaybd_import: str | None,
    ready_timeout: float,
    push: bool,
) -> None:
    """Build the golden image described by the template.

    Runs the convert stage (and validate-boot; plus snapshot and package for
    the snapshot/overlaybd formats), then emits manifest.json and SHA256SUMS.
    Requires root (loop mount) and /dev/kvm for formats that boot.
    """
    spec = load_template(template_file)
    errors = validate_template(spec)
    if errors:
        for error in errors:
            click.echo(f"error: {error}", err=True)
        raise click.ClickException("template is invalid")

    fmt = format_ or spec.get("output", {}).get("format", "ext4")
    if fmt not in FORMATS:
        raise click.ClickException(f"unsupported format: {fmt}")

    oci2rootfs_bin = oci2rootfs or os.environ.get("OSB_OCI2ROOTFS") or _require("oci2rootfs")
    firecracker_bin = firecracker or os.environ.get("OSB_FIRECRACKER") or _require("firecracker")
    overlaybd_bin = overlaybd_import or os.environ.get("OSB_OVERLAYBD_IMPORT") or _require("overlaybd-import-raw")
    kernel_path = kernel or _resolve_kernel(spec)

    guest_init_file = _guest_init_file(spec)
    source_digest = sha256_file(oci_archive)
    created = tempfile.mkdtemp(prefix="osb-template-", dir=str(workdir) if workdir else None)
    directory = Path(created)
    result = BuildResult(directory=directory)
    try:
        started = time.monotonic()
        rootfs, _ = stage_convert(spec, directory, oci_archive, execd_dir, oci2rootfs_bin, str(guest_init_file))
        result.files["rootfs.ext4"] = rootfs
        result.timing["convertMs"] = round((time.monotonic() - started) * 1000)

        if fmt in ("snapshot", "overlaybd"):
            api_socket = directory / "boot.sock"
            console_log = directory / "boot.console.log"
            vmm = stage_validate_boot(spec, directory, kernel_path, firecracker_bin, api_socket, console_log, ready_timeout)
            try:
                vmstate, memory = stage_snapshot(spec, directory, vmm, ready_timeout)
            finally:
                vmm.stop()
            result.files["vmstate.snap"] = vmstate
            result.files["memory.snap"] = memory
            result.restored = True
            result.restore_iterations = 1
            result.files["vmlinux"] = kernel_path
            result.timing["bootMs"] = round((time.monotonic() - started) * 1000)
        else:
            # Boot-only validation gate for the ext4 format.
            api_socket = directory / "boot.sock"
            console_log = directory / "boot.console.log"
            vmm = stage_validate_boot(spec, directory, kernel_path, firecracker_bin, api_socket, console_log, ready_timeout)
            vmm.stop()
            result.files["vmlinux"] = kernel_path
            result.timing["bootMs"] = round((time.monotonic() - started) * 1000)

        if fmt == "overlaybd":
            memory = result.files.get("memory.snap")
            stage_package(directory, overlaybd_bin, result.files["rootfs.ext4"], memory)
            result.files["overlaybd/rootfs/layer.lsmt"] = directory / "overlaybd" / "rootfs" / "layer.lsmt"
            if memory is not None:
                result.files["overlaybd/memory/layer.lsmt"] = directory / "overlaybd" / "memory" / "layer.lsmt"

        manifest = build_manifest(
            spec, result,
            kernel_digest=sha256_file(kernel_path) if kernel_path.exists() else "",
            source_digest=source_digest,
            format_override=fmt,
        )
        manifest_path = directory / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        result.files["manifest.json"] = manifest_path
        write_checksums(directory, result.files)

        click.echo(json.dumps(manifest, indent=2))
        click.echo(f"artifacts: {directory}")
        if push:
            _push(directory, spec)
    except Exception as exc:
        click.echo(f"build failed: {exc}", err=True)
        raise click.ClickException(str(exc)) from exc


# ---- push ----------------------------------------------------------------


@template_group.command("push")
@click.option("--artifacts", required=True, type=click.Path(exists=True, path_type=Path), help="Build output directory (containing manifest.json).")
@click.option("--publish", "publish_target", help="s3:// destination; defaults to spec.output.publish in the build manifest.")
def template_push(artifacts: Path, publish_target: str | None) -> None:
    """Publish a build output directory to an S3-compatible object store.

    Uses the `aws` CLI found on PATH; artifacts are uploaded under a digest
    namespace with relative paths preserved, then manifest.json is uploaded
    last.
    """
    publish = publish_target
    if not publish:
        manifest_path = artifacts / "manifest.json"
        if manifest_path.exists():
            publish = json.loads(manifest_path.read_text(encoding="utf-8")).get("publish")
    _push(artifacts, {"output": {"publish": publish}} if publish else {})


def _push(directory: Path, spec: dict) -> None:
    publish = spec.get("output", {}).get("publish")
    if not publish:
        raise click.ClickException("no publish target: set spec.output.publish or pass --publish")
    if not publish.startswith("s3://"):
        raise click.ClickException("publish target must be an s3:// URI")

    aws = shutil.which("aws")
    if aws is None:
        raise click.ClickException("aws CLI not found on PATH; install it or use rclone")

    manifest_path = directory / "manifest.json"
    if not manifest_path.exists():
        raise click.ClickException(f"no manifest.json in {directory}; run `osb template build` first")

    # Artifacts are published under a digest namespace (one namespace per
    # build), preserving relative paths so overlaybd layers do not collide.
    # The manifest is uploaded last so consumers never observe a
    # half-published artifact set.
    namespace = sha256_file(manifest_path)[:16]
    base = f"{publish.rstrip('/')}/{namespace}"
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path == manifest_path:
            continue
        _run_sync(aws, path, f"{base}/{path.relative_to(directory)}")
    _run_sync(aws, manifest_path, f"{base}/manifest.json")
    click.echo(f"published to {base}")


def _run_sync(aws: str, path: Path, destination: str) -> None:
    subprocess.run(
        [aws, "s3", "cp", str(path), destination],
        check=True,
        capture_output=True,
    )


# ---- helpers -------------------------------------------------------------


def _require(name: str) -> str:
    found = shutil.which(name)
    if not found:
        raise click.ClickException(
            f"required tool '{name}' not found on PATH; install it or pass its path"
        )
    return found


def _resolve_kernel(spec: dict) -> Path:
    """Resolve the kernel: --kernel flag, KERNEL env, or a local file named by
    spec.kernel."""
    name = spec.get("kernel", "")
    for candidate in (Path(name), Path.cwd() / name):
        if candidate.is_file():
            return candidate
    raise click.ClickException(
        f"kernel {name!r} not found locally; pass --kernel or set OSB_KERNEL"
    )


def _guest_init_file(spec: dict) -> Path:
    """Materialize the guest init skeleton (with the template's readiness
    settings) for injection."""
    import tempfile as _tempfile

    handle = _tempfile.NamedTemporaryFile(
        mode="w", prefix="osb-guest-init-", suffix=".sh", delete=False
    )
    handle.write(guest_init_script(spec))
    handle.close()
    os.chmod(handle.name, 0o755)
    return Path(handle.name)
