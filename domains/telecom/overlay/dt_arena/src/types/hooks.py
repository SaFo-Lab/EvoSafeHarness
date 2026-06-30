from __future__ import annotations

import importlib
import json
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol, runtime_checkable


@dataclass
class ToolCallContext:
    """Describes an in-flight MCP tool call.

    A pre-hook may return a modified ToolCallContext to rewrite `arguments`
    or attach metadata before the call is dispatched.

    Run context (dtap_ctx variant): ``trace_id`` and ``metadata`` are now
    populated for every call by ``HookManager.wrap`` from the run context the
    agent binds at the start of ``run()`` (see ``HookManager.bind_run_context``).
    A defense's ``on_pre_tool_call`` / ``on_post_tool_call`` can therefore read:

      * ``ctx.metadata["instruction"]`` — the FULL, untruncated user task
        instruction for this run (the trusted request). Enables scope-vs-task
        defenses (DRIFT / CaMeL style) that the stock harness made impossible.
      * ``ctx.metadata["task_id" | "domain" | "threat_model" | "risk_category"]``
        — whatever the evaluator passed as run metadata.
      * ``ctx.trace_id`` — a stable per-run id, so per-trace state (taint /
        provenance ledgers) isolates correctly under ``--max-parallel`` instead
        of colliding in a single shared bucket.

    Backends that build the ctx may pre-set these fields; ``wrap`` only fills
    what is still empty, so nothing a backend sets is clobbered.
    """
    framework: str
    server: str
    tool_name: str
    arguments: Dict[str, Any]
    trace_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolCallResult:
    """Outcome of a dispatched MCP tool call.

    `raw` holds whatever the underlying SDK returned (shape is framework
    specific). `exception` is set if the call raised. `duration` is seconds.
    A post-hook may return a modified ToolCallResult to rewrite the output.
    """
    raw: Any = None
    is_error: bool = False
    duration: float = 0.0
    exception: Optional[BaseException] = None


@runtime_checkable
class ToolCallHook(Protocol):
    """Protocol every hook implementation satisfies.

    Either method may be omitted (return None). Returning a new context or
    result from pre/post replaces the in-flight value.
    """

    async def on_pre_tool_call(
        self, ctx: ToolCallContext
    ) -> Optional[ToolCallContext]: ...

    async def on_post_tool_call(
        self, ctx: ToolCallContext, result: ToolCallResult
    ) -> Optional[ToolCallResult]: ...


_HOOKS_CONFIG_PATH = Path(__file__).resolve().parents[1] / "hooks" / "hooks.json"


def _load_hooks_from_config() -> List["ToolCallHook"]:
    """Instantiate hooks listed in `dt_arena/src/hooks/hooks.json`.

    Expected format::

        {"hooks": ["dt_arena.src.hooks.audit_log:AuditHook", ...]}

    Missing file, empty list, or a malformed entry all degrade gracefully —
    we log and skip. Each spec is ``module.path:ClassName``; the class is
    imported and instantiated with no arguments.
    """
    if not _HOOKS_CONFIG_PATH.is_file():
        return []
    try:
        config = json.loads(_HOOKS_CONFIG_PATH.read_text())
    except Exception as e:
        print(f"[HookManager] failed to parse {_HOOKS_CONFIG_PATH}: {e}")
        return []

    hooks: List[ToolCallHook] = []
    for spec in config.get("hooks", []) or []:
        module_name, sep, class_name = spec.rpartition(":")
        if not sep or not module_name or not class_name:
            print(f"[HookManager] invalid hook spec '{spec}' (expected 'module:ClassName')")
            continue
        try:
            cls = getattr(importlib.import_module(module_name), class_name)
            hooks.append(cls())
        except Exception as e:
            print(f"[HookManager] failed to load hook '{spec}': {e}")
    return hooks


class HookManager:
    """Runs registered hooks around a framework's real tool-dispatch call.

    Hooks listed in ``dt_arena/src/hooks/hooks.json`` are auto-loaded on
    every construction, so any agent built via ``build_agent`` or directly
    inherits them without further wiring.
    """

    def __init__(self, hooks: Optional[List[ToolCallHook]] = None):
        # Config-file hooks run first; explicit per-agent hooks run after.
        self._hooks: List[ToolCallHook] = _load_hooks_from_config() + list(hooks or [])
        # Per-run context, bound by the agent at the start of run() and stamped
        # onto every ToolCallContext in wrap(). Empty until bound (the stock
        # behaviour: hooks then see only tool_name + arguments).
        self._run_metadata: Dict[str, Any] = {}
        self._run_trace_id: Optional[str] = None

    def bind_run_context(
        self,
        metadata: Optional[Dict[str, Any]] = None,
        trace_id: Optional[str] = None,
        instruction: Optional[str] = None,
    ) -> None:
        """Bind the current run's context so hooks can see it on every call.

        Called once at the start of each ``Agent.run()``. ``metadata`` is the
        run metadata (task_id / domain / threat_model / risk_category, and
        usually a possibly-truncated ``instruction``); pass ``instruction`` to
        override it with the FULL, untruncated task instruction — which is what a
        scope-vs-task defense needs. Re-binding replaces the previous context.
        """
        md = dict(metadata or {})
        if instruction is not None:
            md["instruction"] = instruction
        self._run_metadata = md
        self._run_trace_id = trace_id

    def _enrich(self, ctx: ToolCallContext) -> None:
        """Fill ctx.metadata / ctx.trace_id from the bound run context.

        Additive only: a backend that already populated these fields wins, so we
        never clobber per-call data with run-level data.
        """
        if self._run_metadata and not ctx.metadata:
            # Copy so a hook mutating ctx.metadata cannot corrupt the run state.
            ctx.metadata = dict(self._run_metadata)
        if ctx.trace_id is None and self._run_trace_id is not None:
            ctx.trace_id = self._run_trace_id

    def register(self, hook: ToolCallHook) -> None:
        self._hooks.append(hook)

    def clear(self) -> None:
        self._hooks.clear()

    @property
    def hooks(self) -> List[ToolCallHook]:
        return list(self._hooks)

    async def _run_pre(self, ctx: ToolCallContext) -> ToolCallContext:
        for hook in self._hooks:
            fn = getattr(hook, "on_pre_tool_call", None)
            if fn is None:
                continue
            new_ctx = await fn(ctx)
            if new_ctx is not None:
                ctx = new_ctx
        return ctx

    async def _run_post(
        self, ctx: ToolCallContext, result: ToolCallResult
    ) -> ToolCallResult:
        for hook in self._hooks:
            fn = getattr(hook, "on_post_tool_call", None)
            if fn is None:
                continue
            new_result = await fn(ctx, result)
            if new_result is not None:
                result = new_result
        return result

    async def wrap(
        self,
        ctx: ToolCallContext,
        call: Callable[[Dict[str, Any]], Awaitable[Any]],
    ) -> Any:
        """Run pre-hooks, dispatch `call(arguments)`, run post-hooks.

        `call` is a framework-specific async callable that performs the real
        MCP dispatch given the (possibly rewritten) arguments and returns
        whatever that SDK returns. Post-hooks run even on exception.
        """
        # Fast path: no hooks registered (nothing reads ctx, skip enrichment).
        if not self._hooks:
            return await call(ctx.arguments)

        # Stamp the bound run context (instruction / task metadata / trace_id)
        # onto this call so hooks can do scope-vs-task and per-trace reasoning.
        self._enrich(ctx)
        ctx = await self._run_pre(ctx)

        start = time.perf_counter()
        result = ToolCallResult()
        try:
            result.raw = await call(ctx.arguments)
        except BaseException as exc:
            result.exception = exc
            result.is_error = True
            result.duration = time.perf_counter() - start
            try:
                await self._run_post(ctx, result)
            except Exception:
                traceback.print_exc()
            raise
        else:
            result.duration = time.perf_counter() - start

        final = await self._run_post(ctx, result)
        if final.exception is not None and final.exception is not result.exception:
            raise final.exception
        return final.raw
