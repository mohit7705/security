from __future__ import annotations


class SecurityAnalyzerError(Exception):
    """Base exception for all Security Analyzer errors."""


class ConfigurationError(SecurityAnalyzerError):
    """Raised when configuration files or target parameters are invalid."""


class ScopeViolationError(SecurityAnalyzerError):
    """Raised when a URL, host, IP, port, or redirect falls outside authorized scope."""


class WorkspaceBoundaryError(SecurityAnalyzerError):
    """Raised when a file read/write attempts to escape ./output/<scan_id>/."""


class ArtifactValidationError(SecurityAnalyzerError):
    """Raised when a stage output file is missing, unreadable, or fails schema validation."""


class StageExecutionError(SecurityAnalyzerError):
    """Raised when a pipeline stage encounters an unrecoverable execution error."""
