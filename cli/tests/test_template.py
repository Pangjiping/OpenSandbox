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

"""SandboxTemplate command and build-engine tests."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from click.testing import CliRunner

from opensandbox_cli.commands.template import (
    guest_init_script,
    template_build,
    template_group,
    template_init,
    template_validate,
)
from opensandbox_cli.template_builder import (
    BuildResult,
    build_manifest,
    load_template,
    parse_quantity,
    validate_template,
    write_checksums,
)

TEMPLATE = {
    "apiVersion": "sandbox.opensandbox.io/v1alpha1",
    "kind": "SandboxTemplate",
    "metadata": {"name": "demo"},
    "spec": {
        "image": "registry.example.com/sandbox:v1.0.0",
        "entrypoint": ["/opt/app/run.sh", "--flag"],
        "execd": "registry.example.com/execd:v1.0.0",
        "kernel": "vmlinux-6.1.177",
        "machine": {"vcpu": "4", "memory": "8Gi"},
        "init": "/usr/local/sbin/sandbox-init",
        "envs": [{"name": "FOO", "value": "bar"}],
        "readiness": {"probe": "tcp://127.0.0.1:44772", "warmupSeconds": 60},
        "output": {"rootfsSize": "30Gi", "format": "overlaybd", "publish": "s3://bucket/sandbox-images/"},
    },
}


@pytest.fixture()
def template_file(tmp_path: Path) -> Path:
    path = tmp_path / "sandboxtemplate.yaml"
    path.write_text(yaml.safe_dump(TEMPLATE, sort_keys=False), encoding="utf-8")
    return path


def test_parse_quantity() -> None:
    assert parse_quantity("4") == 4
    assert parse_quantity("4000m") == 4
    assert parse_quantity("512Mi") == 512 * 1024**2
    assert parse_quantity("8Gi") == 8 * 1024**3
    with pytest.raises(ValueError):
        parse_quantity("abc")


def test_validate_template(template_file: Path) -> None:
    spec = load_template(template_file)
    assert validate_template(spec) == []

    bad = dict(spec)
    bad["output"] = {"format": "qcow2"}
    assert any("format" in error for error in validate_template(bad))

    bad = dict(spec)
    bad["machine"] = {"vcpu": "lots", "memory": "8Gi"}
    assert any("vcpu" in error for error in validate_template(bad))

    bad = dict(spec)
    bad["readiness"] = {"probe": "http://127.0.0.1:8080/"}
    assert any("probe" in error for error in validate_template(bad))


def test_template_init(tmp_path: Path) -> None:
    runner = CliRunner()
    target = tmp_path / "out.yaml"
    result = runner.invoke(template_init, ["--name", "demo", "--output", str(target)])
    assert result.exit_code == 0, result.output
    document = yaml.safe_load(target.read_text())
    assert document["metadata"]["name"] == "demo"
    assert document["spec"]["output"]["format"] == "ext4"
    assert validate_template(document["spec"]) == []

    # Refuses to overwrite.
    result = runner.invoke(template_init, ["--name", "demo", "--output", str(target)])
    assert result.exit_code != 0


def test_template_validate_command(template_file: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(template_validate, ["--file", str(template_file)])
    assert result.exit_code == 0, result.output
    assert "template is valid" in result.output


def test_build_manifest(tmp_path: Path) -> None:
    spec = load_template(tmp_path / "nonexistent") if False else TEMPLATE["spec"]
    files = {}
    for name in ("rootfs.ext4", "vmstate.snap", "memory.snap"):
        path = tmp_path / name
        path.write_bytes(b"x" * 4096)
        files[name] = path

    result = BuildResult(directory=tmp_path, files=files, restored=True, restore_iterations=1)
    manifest = build_manifest(spec, result, kernel_digest="deadbeef", source_digest="cafebabe")

    assert manifest["schemaVersion"] == 1
    assert manifest["sourceImage"] == "registry.example.com/sandbox:v1.0.0"
    assert manifest["kernel"]["digest"] == "deadbeef"
    assert manifest["machine"] == {"vcpu": "4", "memory": "8Gi"}
    assert manifest["compatibility"]["architecture"]
    assert manifest["entrypoint"] == ["/opt/app/run.sh", "--flag"]
    assert manifest["init"] == "/usr/local/sbin/sandbox-init"
    assert manifest["envs"] == [{"name": "FOO", "value": "bar"}]
    assert manifest["validation"]["booted"] is True
    assert manifest["validation"]["restored"] is True
    assert set(manifest["files"]) == {"rootfs.ext4", "vmstate.snap", "memory.snap"}
    assert manifest["files"]["rootfs.ext4"]["sha256"]

    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    files["manifest.json"] = manifest_path
    write_checksums(tmp_path, files)


def test_template_group_help() -> None:
    runner = CliRunner()
    result = runner.invoke(template_group, ["--help"])
    assert result.exit_code == 0
    for command in ("init", "validate", "build", "push"):
        assert command in result.output


def test_build_manifest_format_override(template_file: Path) -> None:
    """A --format override must be reflected in the manifest, not the
    template's original format."""
    spec = TEMPLATE["spec"]
    result = BuildResult(directory=Path("/tmp"), files={})
    manifest = build_manifest(spec, result, kernel_digest="", source_digest="", format_override="snapshot")
    assert manifest["format"] == "snapshot"
    assert manifest["publish"] == "s3://bucket/sandbox-images/"


def test_guest_init_readiness_rendering() -> None:
    """The guest init script must encode the template's readiness settings:
    probe first, execd /ping default, warmup+healthcheck fallback."""
    spec = TEMPLATE["spec"]
    script = guest_init_script(spec)
    assert "READINESS_PROBE='tcp://127.0.0.1:44772'" in script
    assert "ready_tcp" in script

    no_probe = dict(spec)
    no_probe["readiness"] = {"warmupSeconds": 90}
    script = guest_init_script(no_probe)
    assert "READINESS_PROBE=" not in script
    assert "WARMUP_SECONDS=90" in script
    assert "ready_execd_ping" in script

    free_init = dict(no_probe)
    free_init["init"] = ""
    free_init["readiness"] = {"warmupSeconds": 30, "healthCheck": "true"}
    script = guest_init_script(free_init)
    assert "HEALTHCHECK='true'" in script


def test_template_build_requires_tools(template_file: Path, tmp_path: Path) -> None:
    """A build without the external tools must fail fast with a clear error,
    not half-way through the pipeline."""
    archive = tmp_path / "image.oci.tar"
    archive.write_bytes(b"not-a-real-oci-archive")
    runner = CliRunner()
    result = runner.invoke(
        template_build,
        ["--file", str(template_file), "--oci-archive", str(archive), "--format", "ext4"],
    )
    assert result.exit_code != 0
    assert "oci2rootfs" in result.output or "required tool" in result.output
