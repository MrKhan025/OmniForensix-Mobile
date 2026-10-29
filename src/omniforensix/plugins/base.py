"""Base contract and automatic discovery registry for mobile forensic artifact plugins."""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar
from pydantic import BaseModel, Field

from omniforensix.core.timestamps import ForensicTimestamp


class OSType(str, Enum):
    ANDROID = "android"
    IOS = "ios"
    CROSS_PLATFORM = "cross_platform"


class ArtifactRecord(BaseModel):
    """Standardized forensic artifact record emitted by all Android and iOS plugins."""

    plugin_name: str
    os_type: OSType
    category: str
    artifact_type: str
    source_file: str
    record_id: str
    timestamp: ForensicTimestamp | None = None
    summary: str
    attributes: dict[str, Any] = Field(default_factory=dict)
    deleted_recovered: bool = False


class ArtifactPlugin(ABC):
    """Abstract base class for modular artifact parsers."""

    name: str = "base_plugin"
    os_type: OSType = OSType.CROSS_PLATFORM
    category: str = "General"
    description: str = ""
    target_globs: tuple[str, ...] = ()

    def find_matching_files(self, workspace_dir: Path) -> list[Path]:
        """Locate all files in workspace_dir matching any pattern in target_globs."""
        matched: set[Path] = set()
        for pattern in self.target_globs:
            for path in workspace_dir.rglob(pattern):
                if path.is_file():
                    matched.add(path)
        return sorted(matched)

    @abstractmethod
    def parse_file(self, file_path: Path, workspace_dir: Path) -> list[ArtifactRecord]:
        """Parse a single matched artifact file and return normalized ArtifactRecord objects."""

    def run(self, workspace_dir: Path) -> list[ArtifactRecord]:
        """Locate and parse all matching files within workspace_dir."""
        records: list[ArtifactRecord] = []
        for file_path in self.find_matching_files(workspace_dir):
            records.extend(self.parse_file(file_path, workspace_dir))
        return records


PLUGIN_REGISTRY: dict[str, type[ArtifactPlugin]] = {}
T = TypeVar("T", bound=type[ArtifactPlugin])


def register_plugin(cls: T) -> T:
    """Class decorator that registers an ArtifactPlugin subclass in the global registry."""
    PLUGIN_REGISTRY[cls.name] = cls
    return cls


def get_registered_plugins(os_filter: OSType | None = None) -> list[ArtifactPlugin]:
    """Instantiate all registered plugins, optionally filtered by operating system."""
    # Ensure platform submodules are imported so decorators execute
    import omniforensix.plugins.android  # noqa: F401
    import omniforensix.plugins.ios  # noqa: F401

    plugins: list[ArtifactPlugin] = []
    for plugin_cls in PLUGIN_REGISTRY.values():
        if os_filter is None or plugin_cls.os_type in {os_filter, OSType.CROSS_PLATFORM}:
            plugins.append(plugin_cls())
    return plugins
