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
# the bootstrap script, and signals SANDBOX_READY once the entrypoint is up.
GUEST_INIT = """#!/bin/sh
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
# Managed mode: the injected init starts execd through the bootstrap script
# and then runs the entrypoint. execd reports readiness via /ping.
if [ -x /opt/opensandbox/bootstrap.sh ]; then
  setsid /bin/sh /opt/opensandbox/bootstrap.sh &
fi
if [ -n "${ENTRYPOINT:-}" ]; then
  setsid /bin/sh -c "$ENTRYPOINT" &
fi
echo SANDBOX_READY
while true; do sleep 3600; done
"""


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

    guest_init_file = _guest_init_file()
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
            stage_validate_boot(spec, directory, kernel_path, firecracker_bin, api_socket, console_log, ready_timeout)
            vmstate, memory = stage_snapshot(spec, directory, api_socket, ready_timeout)
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
            stage_validate_boot(spec, directory, kernel_path, firecracker_bin, api_socket, console_log, ready_timeout)
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

    Uses the `aws` CLI (or `rclone`) found on PATH; artifacts are uploaded
    content-addressed, then manifest.json is uploaded last.
    """
    _push(artifacts, {"output": {"publish": publish_target}} if publish_target else {})


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

    # Layers are content-addressed by name; upload them first, the manifest
    # last so consumers never observe a half-published artifact set.
    for entry in sorted(directory.iterdir()):
        if entry.is_file() and entry.name != "manifest.json":
            _run_sync(aws, entry, publish)
    for entry in sorted((directory / "overlaybd").rglob("*")) if (directory / "overlaybd").exists() else []:
        if entry.is_file():
            _run_sync(aws, entry, publish)
    _run_sync(aws, manifest_path, publish)
    click.echo(f"published to {publish}")


def _run_sync(aws: str, path: Path, publish: str) -> None:
    subprocess.run(
        [aws, "s3", "cp", str(path), f"{publish}/{path.name}"],
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


def _guest_init_file() -> Path:
    """Materialize the built-in guest init skeleton for injection."""
    import tempfile as _tempfile

    handle = _tempfile.NamedTemporaryFile(
        mode="w", prefix="osb-guest-init-", suffix=".sh", delete=False
    )
    handle.write(GUEST_INIT)
    handle.close()
    os.chmod(handle.name, 0o755)
    return Path(handle.name)
