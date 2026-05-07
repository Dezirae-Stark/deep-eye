"""Client-side scope check (defense in depth).

deep-eye consults this before shipping a target to the bridge. The bridge's
own check is authoritative — this one just avoids obviously-out-of-scope
round-trips and gives the user a clearer local error message.

NEVER use this as a substitute for the bridge check. Per the spec §9: there
is no fallback path that bypasses scope. If the bridge is unreachable for a
non-CLI-A flow, the scan does not run.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from core.scope_manifest import ScopeManifest, ScopeResult, Target, load_manifest

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    def __init__(self, manifest_path: Path) -> None:
        self._path = Path(manifest_path)
        self._manifest: Optional[ScopeManifest] = None

    def manifest(self) -> ScopeManifest:
        if self._manifest is None:
            self._manifest = load_manifest(self._path)
        return self._manifest

    def check(self, target: Target) -> ScopeResult:
        result = self.manifest().validate(target)
        if not result.in_scope:
            logger.info(
                "Local scope check rejected target kind=%s value=%s reason=%s",
                target.kind, target.value, result.reason,
            )
        return result
