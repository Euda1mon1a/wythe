"""Optional Swift & Systems IPC architecture plugin for Wythe (`wythe-plugin-apple-ipc`)."""

from __future__ import annotations

from wythe_plugin_apple_ipc.package_manifest import (
    MAX_NESTING_DEPTH,
    MAX_SOURCE_FILE_BYTES,
    PackageManifest,
    SwiftTargetDecl,
    SwiftTargetDependency,
    parse_package_manifest,
    parse_package_manifest_text,
    resolve_safe_source_path,
)
from wythe_plugin_apple_ipc.plugin import (
    APPLE_IPC_PLUGIN,
    WYTHE_PLUGIN,
    SwiftCliDisplayAdapter,
    SwiftIpcManipulatorAdapter,
    SwiftStoresTruthAdapter,
    register_wythe_plugin,
)
from wythe_plugin_apple_ipc.swift_extractor import (
    SwiftRepoExtraction,
    extract_swift_systems_repo,
    parse_safe_plist_bytes,
)

__all__ = [
    "APPLE_IPC_PLUGIN",
    "MAX_NESTING_DEPTH",
    "MAX_SOURCE_FILE_BYTES",
    "WYTHE_PLUGIN",
    "PackageManifest",
    "SwiftCliDisplayAdapter",
    "SwiftIpcManipulatorAdapter",
    "SwiftRepoExtraction",
    "SwiftStoresTruthAdapter",
    "SwiftTargetDecl",
    "SwiftTargetDependency",
    "extract_swift_systems_repo",
    "parse_package_manifest",
    "parse_package_manifest_text",
    "parse_safe_plist_bytes",
    "register_wythe_plugin",
    "resolve_safe_source_path",
]
