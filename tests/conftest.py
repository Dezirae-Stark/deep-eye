"""Shared pytest fixtures for deep-eye tests."""

import pytest


@pytest.fixture
def fixed_clock():
    """A clock that returns a stable monotonically-increasing fake timestamp.

    Tests that depend on time (HMAC timestamp checks, manifest expiry) call
    this fixture's `now()` rather than time.time() to keep tests deterministic.
    """
    state = {"now": 1735689600}  # 2025-01-01 00:00:00 UTC

    def now() -> int:
        return state["now"]

    def advance(seconds: int) -> None:
        state["now"] += seconds

    now.advance = advance  # type: ignore[attr-defined]
    return now
