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

"""Install OpenSandbox AI skills/rules for various AI coding tools."""

from __future__ import annotations

import importlib.resources
import shutil
from pathlib import Path

import click

from opensandbox_cli.utils import handle_errors

# ---------------------------------------------------------------------------
# Target definitions
# ---------------------------------------------------------------------------

# All supported targets and their install strategies.
# "copy"   → copy the skill file to the target directory as-is
# "append" → append the skill content into a single target file (with dedup)

_TARGETS: dict[str, dict] = {
    "claude": {
        "strategy": "copy",
        "dest_dir": Path.home() / ".claude" / "skills" / "troubleshoot-sandbox",
        "dest_file": "SKILL.md",
        "label": "Claude Code",
    },
    "cursor": {
        "strategy": "copy",
        "dest_dir": Path.home() / ".cursor" / "rules",
        "dest_file": "opensandbox-troubleshoot.mdc",
        "label": "Cursor",
    },
    "codex": {
        "strategy": "append",
        "dest_file": Path.home() / ".codex" / "instructions.md",
        "label": "Codex",
    },
    "copilot": {
        "strategy": "append",
        "dest_file": Path.home() / ".github" / "copilot-instructions.md",
        "label": "GitHub Copilot",
    },
    "windsurf": {
        "strategy": "append",
        "dest_file": Path.home() / ".windsurfrules",
        "label": "Windsurf",
    },
    "cline": {
        "strategy": "append",
        "dest_file": Path.home() / ".clinerules",
        "label": "Cline",
    },
}

_ALL_TARGET_NAMES = list(_TARGETS.keys())

# Marker used for dedup in append-mode targets
_MARKER_BEGIN = "<!-- BEGIN opensandbox-troubleshoot -->"
_MARKER_END = "<!-- END opensandbox-troubleshoot -->"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_skill_source() -> Path:
    """Locate the bundled skill file shipped with the CLI package."""
    # The skill file is bundled under opensandbox_cli/skills/
    pkg = importlib.resources.files("opensandbox_cli") / "skills" / "opensandbox-troubleshoot.md"
    # For older Python or zipped packages, we may need to extract
    if hasattr(pkg, "__fspath__"):
        return Path(str(pkg))
    # Fallback: try resolving as a traversable
    with importlib.resources.as_file(pkg) as p:
        return Path(p)


def _read_skill_content(source: Path) -> str:
    """Read the skill markdown content."""
    return source.read_text(encoding="utf-8")


def _install_copy(target_cfg: dict, content: str) -> Path:
    """Install by copying to a dedicated file in the target directory."""
    dest_dir = Path(target_cfg["dest_dir"])
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / target_cfg["dest_file"]
    dest.write_text(content, encoding="utf-8")
    return dest


def _install_append(target_cfg: dict, content: str) -> Path:
    """Install by appending (with dedup markers) into a single file."""
    dest = Path(target_cfg["dest_file"])
    dest.parent.mkdir(parents=True, exist_ok=True)

    marked_block = f"\n{_MARKER_BEGIN}\n{content}\n{_MARKER_END}\n"

    if dest.exists():
        existing = dest.read_text(encoding="utf-8")
        # Remove old block if present
        if _MARKER_BEGIN in existing:
            before = existing[: existing.index(_MARKER_BEGIN)]
            after_marker = existing[existing.index(_MARKER_END) + len(_MARKER_END) :]
            existing = before.rstrip("\n") + after_marker.lstrip("\n")
        # Append
        new_content = existing.rstrip("\n") + "\n" + marked_block
    else:
        new_content = marked_block.lstrip("\n")

    dest.write_text(new_content, encoding="utf-8")
    return dest


def _install_target(name: str, content: str) -> Path:
    """Install skill for a single target, returns the destination path."""
    cfg = _TARGETS[name]
    if cfg["strategy"] == "copy":
        return _install_copy(cfg, content)
    else:
        return _install_append(cfg, content)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@click.group("skills", invoke_without_command=True)
@click.pass_context
def skills_group(ctx: click.Context) -> None:
    """🧠 Manage AI coding skills for OpenSandbox."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@skills_group.command("install")
@click.option(
    "--target", "-t",
    type=click.Choice(_ALL_TARGET_NAMES + ["all"], case_sensitive=False),
    default="claude",
    show_default=True,
    help="Target AI tool to install skill for.",
)
@click.option("--force", "-f", is_flag=True, default=False, help="Overwrite existing skill without prompting.")
@handle_errors
def skills_install(target: str, force: bool) -> None:
    """Install OpenSandbox troubleshooting skill for AI coding tools."""
    source = _get_skill_source()
    content = _read_skill_content(source)

    targets = _ALL_TARGET_NAMES if target == "all" else [target]

    for t in targets:
        cfg = _TARGETS[t]
        label = cfg["label"]

        # Check if already exists (for copy-mode targets)
        if cfg["strategy"] == "copy":
            dest = Path(cfg["dest_dir"]) / cfg["dest_file"]
        else:
            dest = Path(cfg["dest_file"])

        if dest.exists() and not force:
            if not click.confirm(f"  {label}: {dest} already exists. Overwrite?", default=True):
                click.echo(f"  ⏭  {label}: skipped")
                continue

        installed_path = _install_target(t, content)
        click.echo(f"  ✅ {label}: {installed_path}")

    click.echo()
    click.echo("Done! Restart your AI coding tool to pick up the new skill.")


@skills_group.command("list")
@handle_errors
def skills_list() -> None:
    """List supported AI tool targets and their install status."""
    click.echo("Supported targets:\n")
    for name, cfg in _TARGETS.items():
        label = cfg["label"]
        if cfg["strategy"] == "copy":
            dest = Path(cfg["dest_dir"]) / cfg["dest_file"]
        else:
            dest = Path(cfg["dest_file"])

        status = "✅ installed" if dest.exists() else "—  not installed"
        click.echo(f"  {name:<10}  {label:<20}  {status}  ({dest})")


@skills_group.command("uninstall")
@click.option(
    "--target", "-t",
    type=click.Choice(_ALL_TARGET_NAMES + ["all"], case_sensitive=False),
    default="claude",
    show_default=True,
    help="Target AI tool to uninstall skill from.",
)
@handle_errors
def skills_uninstall(target: str) -> None:
    """Remove OpenSandbox troubleshooting skill from AI coding tools."""
    targets = _ALL_TARGET_NAMES if target == "all" else [target]

    for t in targets:
        cfg = _TARGETS[t]
        label = cfg["label"]

        if cfg["strategy"] == "copy":
            dest_dir = Path(cfg["dest_dir"])
            dest = dest_dir / cfg["dest_file"]
            if dest.exists():
                shutil.rmtree(dest_dir)
                click.echo(f"  🗑  {label}: removed {dest_dir}")
            else:
                click.echo(f"  ⏭  {label}: not installed")
        else:
            dest = Path(cfg["dest_file"])
            if dest.exists():
                existing = dest.read_text(encoding="utf-8")
                if _MARKER_BEGIN in existing:
                    before = existing[: existing.index(_MARKER_BEGIN)]
                    after = existing[existing.index(_MARKER_END) + len(_MARKER_END) :]
                    cleaned = before.rstrip("\n") + after.lstrip("\n")
                    if cleaned.strip():
                        dest.write_text(cleaned, encoding="utf-8")
                        click.echo(f"  🗑  {label}: removed skill block from {dest}")
                    else:
                        dest.unlink()
                        click.echo(f"  🗑  {label}: removed {dest}")
                else:
                    click.echo(f"  ⏭  {label}: no OpenSandbox skill found in {dest}")
            else:
                click.echo(f"  ⏭  {label}: not installed")
