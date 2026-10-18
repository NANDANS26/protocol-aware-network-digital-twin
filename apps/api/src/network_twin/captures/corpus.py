"""Corpus repository and loader for Phase 09 capture verification."""

import json
from pathlib import Path

from network_twin.captures.models import CaptureManifestItem
from network_twin.config import settings


def get_captures_dir() -> Path:
    """Returns absolute path to the capture directory."""
    # Check project data/captures first
    p = Path(settings.data_dir) / "captures"
    if p.exists() and (p / "manifest.json").exists():
        return p
    # Fallback to root data/captures
    root_p = Path("data/captures").resolve()
    if root_p.exists() and (root_p / "manifest.json").exists():
        return root_p
    return p


class CaptureCorpus:
    """Repository accessing versioned network capture corpus."""

    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory or get_captures_dir()
        self._items: dict[str, CaptureManifestItem] = {}
        self.load()

    def load(self) -> None:
        """Loads manifest.json from corpus directory."""
        manifest_file = self.directory / "manifest.json"
        if not manifest_file.exists():
            # If not yet generated, attempt to run corpus builder
            from scripts.generate_capture_corpus import build_corpus

            build_corpus(self.directory)

        if manifest_file.exists():
            with open(manifest_file, encoding="utf-8") as f:
                data = json.load(f)
            self._items = {
                item["capture_id"]: CaptureManifestItem.model_validate(item) for item in data.get("captures", [])
            }

    def list_captures(self) -> list[CaptureManifestItem]:
        """Returns all capture manifest items in the corpus."""
        return list(self._items.values())

    def get_capture(self, capture_id: str) -> CaptureManifestItem | None:
        """Returns manifest item for a specific capture identifier."""
        return self._items.get(capture_id)

    def get_capture_path(self, capture_id: str) -> Path:
        """Returns absolute filesystem path to raw capture file."""
        item = self.get_capture(capture_id)
        if not item:
            raise KeyError(f"Capture fixture '{capture_id}' not found in corpus manifest.")
        path = self.directory / item.file_name
        if not path.exists():
            raise FileNotFoundError(f"Capture file '{item.file_name}' does not exist on disk.")
        return path

    def get_capture_bytes(self, capture_id: str) -> bytes:
        """Reads and returns the raw binary bytes of a capture file."""
        return self.get_capture_path(capture_id).read_bytes()
