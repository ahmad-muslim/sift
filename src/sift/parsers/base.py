"""Modular parser interface (Adapter Pattern) and auto-detecting registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from sift.models import RawFinding

PREVIEW_BYTES = 8192


class ParseError(ValueError):
    """Raised when a scan file cannot be parsed or no matching parser is found."""


class BaseParser(ABC):
    """Abstract base class for scanner output adapters.

    Contributors adding a new scanner only need to subclass `BaseParser`,
    set `name` / `description`, and implement `can_parse` and `parse_text`.
    """

    name: ClassVar[str]
    description: ClassVar[str] = ""
    supported_extensions: ClassVar[tuple[str, ...]] = ()

    @abstractmethod
    def can_parse(self, path: Path, preview: str) -> bool:
        """Return True if this parser recognizes the scan format from path/preview."""

    @abstractmethod
    def parse_text(self, content: str, *, source_name: str = "<memory>") -> list[RawFinding]:
        """Parse raw text content into unmerged `RawFinding` objects."""

    def parse(self, path: Path) -> list[RawFinding]:
        """Read a scan file from disk and parse it into `RawFinding` objects."""
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ParseError(f"Failed to read scan file '{path}': {exc}") from exc
        return self.parse_text(content, source_name=str(path))


class ParserRegistry:
    """Registry that manages scanner adapters and auto-detects scan formats."""

    def __init__(self) -> None:
        self._parsers: dict[str, BaseParser] = {}

    def register(self, parser: BaseParser, *, replace: bool = False) -> None:
        """Register a parser adapter by its normalized lowercase name."""
        key = parser.name.strip().lower()
        if not key:
            raise ValueError("Parser name must be a non-empty string")
        if key in self._parsers and not replace:
            raise ValueError(f"Parser '{key}' is already registered")
        self._parsers[key] = parser

    def get(self, name: str) -> BaseParser:
        """Look up a registered parser by name."""
        key = name.strip().lower()
        parser = self._parsers.get(key)
        if parser is None:
            available = ", ".join(sorted(self._parsers)) or "none"
            raise ParseError(f"Unknown parser '{name}'. Available parsers: {available}")
        return parser

    def list_parsers(self) -> list[BaseParser]:
        """Return all registered parsers sorted by name."""
        return [self._parsers[k] for k in sorted(self._parsers)]

    def detect(self, path: Path) -> BaseParser | None:
        """Auto-detect the appropriate parser by inspecting file preview bytes."""
        try:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                preview = handle.read(PREVIEW_BYTES)
        except OSError as exc:
            raise ParseError(f"Failed to inspect scan file '{path}': {exc}") from exc

        for parser in self._parsers.values():
            if parser.can_parse(path, preview):
                return parser
        return None

    def parse_file(
        self,
        path: Path,
        *,
        parser_name: str | None = None,
    ) -> tuple[str, list[RawFinding]]:
        """Parse a file using an explicit parser or auto-detection.

        Returns `(parser.name, findings)`.
        """
        if parser_name is not None:
            parser = self.get(parser_name)
        else:
            detected = self.detect(path)
            if detected is None:
                supported = ", ".join(sorted(self._parsers))
                raise ParseError(
                    f"Could not auto-detect scanner format for '{path}'. "
                    f"Supported parsers: {supported}"
                )
            parser = detected

        return parser.name, parser.parse(path)
