"""dtap_camel_v1 — CaMeL (capability/taint + deny-by-default security policy,
dual-LLM authorisation) ported to the DTAP defense framework. Exposes
``build() -> Defense``."""

from .defense import build

__all__ = ["build"]
