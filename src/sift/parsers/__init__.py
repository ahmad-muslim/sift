"""Modular scanner parser adapters and default registry."""

from sift.parsers.base import BaseParser, ParseError, ParserRegistry
from sift.parsers.nmap import NmapXmlParser
from sift.parsers.nuclei import NucleiJsonlParser
from sift.parsers.trivy import TrivyJsonParser


def create_default_registry() -> ParserRegistry:
    """Create a ParserRegistry pre-populated with all built-in scanner adapters."""
    registry = ParserRegistry()
    registry.register(NmapXmlParser())
    registry.register(NucleiJsonlParser())
    registry.register(TrivyJsonParser())
    return registry


__all__ = [
    "BaseParser",
    "NmapXmlParser",
    "NucleiJsonlParser",
    "ParseError",
    "ParserRegistry",
    "TrivyJsonParser",
    "create_default_registry",
]
