"""dtap_def_v0 — no-defense baseline (no-op).

The reference candidate for the DTAP os-filesystem search. It applies NO
mutation on either surface: the system prompt passes through unchanged, and
both tool-call hooks are pure passthrough. Its measured (utility, ASR) is the
no-defense baseline every later candidate is scored against (score = util% −
ASR%), and it sets the Stage-2 gate in cascade.py.

All five bundle sections are intentionally empty — see BUNDLE.md.
"""

from __future__ import annotations

from dt_arena.src.defense.loader import Defense


class NoOpDefense(Defense):
    """Identity defense: every section degrades to passthrough.

    Inherits all base behaviour unchanged:
    - system_prompt_transform -> returns the prompt verbatim (INPUT-FILTER empty)
    - on_pre_tool_call        -> returns None (PRE-TOOL-GATE / EXEC-ISOLATE empty)
    - on_post_tool_call       -> returns None (POST-EXEC-AUDIT / ROLLBACK empty)
    """


def build() -> Defense:
    return NoOpDefense()
