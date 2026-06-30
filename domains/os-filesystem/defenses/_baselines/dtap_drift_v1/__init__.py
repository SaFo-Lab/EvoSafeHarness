"""dtap_drift_v1 — DRIFT (plan-then-validate trajectory defense) ported to the
DTAP defense framework. Exposes ``build() -> Defense``."""

from .defense import build

__all__ = ["build"]
