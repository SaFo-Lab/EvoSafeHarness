"""Generic DTAP defense-candidate loader (Meta-Harness dual surface).

A *defense candidate* is the unit the outer-loop proposer mutates. It is a
Python package living at ``dt_defenses/dtap_def_v<n>/`` (importable from the
benchmark source root) that exposes a module-level ``build() -> Defense``
factory. The returned ``Defense`` object carries BOTH mutation surfaces:

* **NL surface** — ``system_prompt_transform(prompt) -> prompt`` rewrites the
  agent's system prompt (the ``INPUT-FILTER`` section of the bundle).
* **Code surface** — the object IS a ``ToolCallHook`` (it implements
  ``on_pre_tool_call`` / ``on_post_tool_call``), so it is registered directly on
  the agent's :class:`HookManager`. Pre-hooks gate/rewrite tool calls
  (``PRE-TOOL-GATE`` / ``EXEC-ISOLATE``); post-hooks audit/redact tool output
  and may refuse (``POST-EXEC-AUDIT`` / ``ROLLBACK``).

Selection is by environment variable: ``cascade.py`` sets

    DTAP_DEFENSE_CANDIDATE=dtap_def_v<n>

before launching an evaluation, and :func:`apply_defense` — called once from
``Agent.__init__`` — imports that package and applies it. When the variable is
unset, no defense is applied (the no-defense baseline).
"""

from __future__ import annotations

import importlib
import os
import traceback
from typing import TYPE_CHECKING, Optional

from dt_arena.src.types.hooks import ToolCallContext, ToolCallResult

if TYPE_CHECKING:  # avoid import cycle at runtime
    from dt_arena.src.types.agent import Agent


ENV_VAR = "DTAP_DEFENSE_CANDIDATE"


class Defense:
    """Base class for a DTAP defense candidate.

    Subclass and override only the sections you populate. Every method has a
    safe identity/no-op default, so an "empty" section degrades to passthrough.
    The five bundle sections map onto these hooks as follows:

    ===================  =========================================
    Bundle section       Method
    ===================  =========================================
    INPUT-FILTER         ``system_prompt_transform``
    PRE-TOOL-GATE        ``on_pre_tool_call`` (rewrite/raise)
    EXEC-ISOLATE         ``on_pre_tool_call`` (capability checks)
    POST-EXEC-AUDIT      ``on_post_tool_call`` (inspect/redact ``raw``)
    ROLLBACK             ``on_post_tool_call`` (raise to refuse)
    ===================  =========================================

    Run context (dtap_ctx variant)
    ------------------------------
    Unlike the stock harness, the tool-call hooks here receive the trusted run
    context on every ``ctx`` (filled by ``HookManager.wrap``; see
    ``ToolCallContext``):

      * ``ctx.metadata["instruction"]`` — the FULL user task instruction (the
        trusted request). This makes scope-vs-task / plan-consistency defenses
        (DRIFT, CaMeL) implementable: compare the action against what the user
        actually asked for, not only against the action's effect in isolation.
      * ``ctx.metadata["task_id"|"domain"|"threat_model"|"risk_category"]`` — run
        metadata from the evaluator.
      * ``ctx.trace_id`` — stable per-run id for correctly-isolated per-trace
        state under ``--max-parallel``.

    Caveat (threat model): the user instruction is trusted ONLY for *indirect*
    attacks. For *direct* attacks the malicious goal IS the instruction, so a
    pure scope-vs-task check will rubber-stamp it — combine instruction-based
    reasoning with effect-based action judging.
    """

    #: short identifier, set by the loader to the package name
    name: str = "defense"

    # --- NL surface -----------------------------------------------------
    def system_prompt_transform(self, prompt: str) -> str:
        """Return the (possibly rewritten) system prompt. Identity by default."""
        return prompt

    # --- code surface (ToolCallHook protocol) ---------------------------
    async def on_pre_tool_call(
        self, ctx: ToolCallContext
    ) -> Optional[ToolCallContext]:
        """Inspect/rewrite a tool call before dispatch.

        Return a modified ``ctx`` to rewrite ``ctx.arguments``; return ``None``
        to leave it unchanged; ``raise`` to block the call entirely.
        """
        return None

    async def on_post_tool_call(
        self, ctx: ToolCallContext, result: ToolCallResult
    ) -> Optional[ToolCallResult]:
        """Inspect/redact a tool result after dispatch.

        Return a modified ``result`` (e.g. with sanitized ``result.raw``) to
        rewrite the output; return ``None`` to leave it unchanged.
        """
        return None


def _load_candidate(name: str) -> Optional[Defense]:
    """Import ``dt_defenses.<name>`` and call its ``build()`` factory."""
    try:
        module = importlib.import_module(f"dt_defenses.{name}")
    except Exception as e:  # pragma: no cover - surfaced to operator
        print(f"[DTAP-defense] could not import dt_defenses.{name}: {e}")
        traceback.print_exc()
        return None
    build = getattr(module, "build", None)
    if build is None:
        print(f"[DTAP-defense] dt_defenses.{name} has no build() factory")
        return None
    try:
        defense = build()
    except Exception as e:  # pragma: no cover
        print(f"[DTAP-defense] dt_defenses.{name}.build() raised: {e}")
        traceback.print_exc()
        return None
    if not isinstance(defense, Defense):
        print(
            f"[DTAP-defense] dt_defenses.{name}.build() must return a Defense "
            f"subclass, got {type(defense).__name__}"
        )
        return None
    defense.name = name
    return defense


def apply_defense(agent: "Agent") -> Optional[Defense]:
    """Apply the env-selected defense to a freshly constructed agent.

    Called once from ``Agent.__init__``. Rewrites ``agent.config.system_prompt``
    (NL surface) and registers the defense as a tool-call hook (code surface).
    No-op when ``DTAP_DEFENSE_CANDIDATE`` is unset or the candidate fails to
    load — the run then behaves as the no-defense baseline.
    """
    name = os.environ.get(ENV_VAR, "").strip()
    if not name:
        return None
    defense = _load_candidate(name)
    if defense is None:
        return None

    # NL surface: rewrite the system prompt in place.
    if getattr(agent, "config", None) is not None:
        try:
            original = agent.config.system_prompt or ""
            agent.config.system_prompt = defense.system_prompt_transform(original)
        except Exception as e:  # pragma: no cover
            print(f"[DTAP-defense] system_prompt_transform failed: {e}")
            traceback.print_exc()

    # Code surface: the Defense object is itself a ToolCallHook.
    try:
        agent.hook_manager.register(defense)
    except Exception as e:  # pragma: no cover
        print(f"[DTAP-defense] hook registration failed: {e}")
        traceback.print_exc()

    print(f"[DTAP-defense] applied candidate '{name}'")
    return defense
