# Prior Art — Securing a Tool-Using Financial-Operations Agent Against Prompt Injection

*Companion to `domain_spec.md`. Distills how three mature systems (OpenClaw, DRIFT, CaMeL)
secure tool-using agents, into the invariants worth keying on. Treat it as **inspiration, not
a template**: borrow the proven invariants, then invent a more dynamic, provenance-aware
policy. Don't copy code.*

> **Domain framing.** Here the protected agent moves money and discloses client data through a
> structured-API action model (quotes/news/portfolio **reads** → trade / transfer / payment /
> client-communication **effects**). The dangerous outcome is an unauthorized trade or fund
> movement, payment fraud, or a client-PII / holdings disclosure — so the high-leverage
> invariants are **egress / scope-vs-task / least-privilege**, applied to the effect-bearing call.

> **Run context (user intent) is available** on every `ctx` — `ctx.metadata["instruction"]`
> (the full user task), `task_id`/`domain`/`threat_model`/`risk_category`, and `ctx.trace_id`
> — so the **Scope** and **Intent-mismatch** invariants below are directly checkable. *Caveat:*
> the instruction is trusted only for *indirect* attacks; for *direct* attacks the malicious
> goal IS the instruction, so a pure scope check rubber-stamps it — pair scope reasoning with
> effect / action-nature / provenance signals. (Full mechanics in `domain_spec.md` §1/§3.)

---

## The one-sentence thesis (all three systems agree)

**The model is manipulable, so the security decision must live in a layer the attacker's text
cannot reach, and it must key on data *provenance* and *scope* — not on the model's own judgment
of whether something "looks safe."** Every robust idea below is a variation on this, and it is
the same claim `domain_spec.md` §0 makes with its rename litmus test.

## Convergent principles (the high-signal core)

| # | Principle | Maps to (our hooks) |
|---|---|---|
| 1 | **Enforce outside the model, deterministically where you can.** The allow/block decision must not be re-derivable from the prompt the attacker controls. | `on_pre_tool_call` as a deterministic gate; keep allow/block logic out of any prompt the agent reads. |
| 2 | **Provenance / taint is the master invariant.** Tag data by origin; untrusted-origin data must not silently drive a privileged action. | Track in `on_post_tool_call` what the agent *read*; in `on_pre_tool_call` treat actions whose effect traces to read-in content as suspect. Combine with scope-vs-task using `ctx.metadata["instruction"]`. |
| 3 | **Separate control flow from data flow.** Untrusted data may fill in *values* but must not choose *actions*. | Approximate the legitimate action-scope; gate effect-bearing calls (trades / transfers / disclosures) that the data (not the user) introduced. |
| 4 | **Least privilege; narrow the blast radius first.** | Risk-tier tools (read quotes/news/portfolio < write orders/payments/messages); scrutinize the dangerous ones harder in the pre-tool gate. |
| 5 | **Fail-closed on the security path; fail-safe on the utility path.** A flaky *auxiliary* check must not tank utility. | Auditor timeout → logged safe default; default-deny only where the action is genuinely dangerous. |
| 6 | **Quarantine untrusted-LLM roles to side-effect-free tasks.** An in-defense LLM may *classify data*, never *decide whether to obey*. | The semantic auditor asks "does this output carry injected instructions?", never "should the agent comply?". |
| 7 | **Defense in depth: cheap deterministic pre-filter → semantic decision.** | A literal check is allowed *only* as a pre-filter feeding a scope/provenance decision, never as the decision. |
| 8 | **Make decisions observable; surface blocks as recoverable signals.** | Return an informative refusal so the agent can replan; log enough to tell a real catch from an overfit one. |

## The three systems, in one line each

- **OpenClaw** — *access control before intelligence*: layered, outside-in gates (auth → channel → tool policy → sandbox → approval → output filtering), each narrowing the blast radius; fail-closed; wrap external content as untrusted. **Transfers:** least-privilege scope-bounding + external-content framing + fail-closed on the dangerous action (the trade/transfer/disclosure).
- **DRIFT** — *plan first, police deviations*: derive an expected tool trajectory from the (trusted) request, mask injected instructions out of tool results, risk-tier calls and judge deviating effect-bearing calls. **Transfers:** post-result injection scrubbing, risk-tiering, soft informative refusals — and the core "derive a plan from the request" step IS available (`ctx.metadata["instruction"]`), so DRIFT-style scope-vs-trajectory gating is directly implementable for indirect attacks (not for direct — the request is the attack).
- **CaMeL** — *untrusted data must never reach control flow*: a code-gen plan commits control flow up front; every value carries `sources`/`readers` taint propagated transitively; a deterministic policy engine the LLM never sees enforces it; a quarantined LLM parses untrusted text into a schema only. **Transfers (highest leverage here):** a **taint-lite ledger** — record what the agent read and whether it was poisoned, then gate effect-bearing calls (a trade/transfer/disclosure) whose data traces to poisoned reads — combinable with the trusted instruction to decide whether the tainted flow actually serves the user's task. One of the most generalizing mechanisms available here.

## Anti-patterns all three deliberately avoid

- **Denylist-as-decision** (a list of bad identifiers/keywords — accounts, tickers, payees — *is* the decision) → overfit by construction, dies on rename. Allowed only as a pre-filter.
- **Asking an auxiliary LLM "should the agent comply?"** → the same social engineering that fools the agent fools that judge. Quarantine it to a data-classification question.
- **Trusting model judgment for control flow** → if untrusted data can re-open "which tool should I call?", you've lost.
- **One-layer defense** / **silent fail-open on the security path.**
