<div align="center">

# AutoSafeHarness

### *Automatically securing agents with model- and domain-specific safety harnesses*

**Search the harness, not the model.**

[![Code](https://img.shields.io/badge/code-github-181717?logo=github)](https://github.com/SaFo-Lab/AutoSafeHarness)
[![Website](https://img.shields.io/badge/website-live-0a7d34)](https://andylinx.github.io/Harness_Secure_Website/)

Nanxi Li · Yulong Cao · Yejin Choi · Edward Suh · Chaowei Xiao

</div>

---

An agent that reads the web, opens an email, or pulls a file from a repo can be
subverted from **two directions**. An attacker who controls the content the agent
reads can hide instructions inside it (**indirect prompt injection**), and a
malicious user can ask the agent outright to take a harmful action (a **direct
attack**). Both are the structural price of capability.

Most defenses answer this with a *fixed artifact*: one clever wrapper, designed
once by experts, bolted onto every model and every deployment. But the threat
isn't uniform — **each model fails in its own way, and each domain calls a
different action "dangerous."** A defense frozen in advance fits none of them well.

**AutoSafeHarness** takes the opposite stance. It leaves the model frozen and instead
**searches the scaffolding around it** — the system prompt **and** the tool-call
hooks — reading the failure traces of the exact model it defends and scoring on
the exact domain it protects. The output is a concrete, runnable **defense
bundle**, one per `(model × domain)` cell.

---

## ⚙️ How it works

A candidate defense is a **dual-surface bundle** — a directory of four files:

```
dtap_def_v<N>/
├── BUNDLE.md     # the natural-language policy (5 taxonomy sections) + litmus notes
├── defense.py    # the code surface: three hooks, each defaulting to identity
├── __init__.py   # build() factory — Stage-0 of the cascade checks this contract
└── parent.txt    # parent candidate + one-paragraph mutation hypothesis
```
Every candidate is scored by a **gated cascade** (Stage 0 static → 1 smoke →
2 mid → 3 search; `score = utility% − ASR%`), with two cheap overfit checks — a
**robustness probe** (does the gate survive intent-preserving rewrites?) and a
**gate probe** (does it over-refuse benign calls?). Before any budget is spent, a
fresh-context **Criticizer** tries to break the candidate and flags anything that
keys on a literal benchmark token. That last step is what separates a
*transferable* secure harness from one that merely memorized a benchmark.

```
                    ┌─────────────────────────────────────────────┐
   warm-start  ──▶  │  Designer ─▶ Criticizer ─▶ Cascade ─▶ Analyzer  │  ──▶  H*
  (OpenClaw/         │     ▲            (anti-      (Stage      (failure-    (best
   DRIFT/CaMeL)      │     └──────────  overfit)    0→3)       trace notes)  bundle)
                     └───────────────── experience loop ───────────────┘
```

### The proposer

The Designer, Analyzer, and Criticizer roles are driven by an **agentic coding
assistant: [Claude Code](https://www.anthropic.com/claude-code) running
Claude Opus 4.8 at maximum reasoning effort.** It reads the on-disk archive, edits
the harness source, runs the cascade, and writes the experience notes fed back
into the next proposal. The proposer is **decoupled from the frozen victim** — it
never participates in the defended agent at runtime, so security gains are
attributable to the returned harness structure, not to a smuggled-in stronger
model. You can drive the loop manually or with any coding agent; we used Claude
Code / Opus 4.8 (max effort) for every cell in the paper.

---

## 📂 The data (read this before running)

Each `domains/<domain>/splits/` holds the frozen task lists. A task line is small
metadata — `{domain, type, risk_category, task_id}` — that selects a full DTAP
tool-server episode (benign, direct-attack, or indirect-attack), judged per-task.

| File | Lines | Role |
|---|---|---|
| `stage1_smoke.jsonl` | 3 | Stage-1 smoke: one benign / one direct / one indirect, must run without exceptions |
| `stage2_mid.jsonl` | 12 | Stage-2 mid: 4 per family, gated (util ≥ 0.7×ref, ASR ≤ 1.3×ref) |
| `stage3_search.jsonl` | 30 | Stage-3 search: 10 per family; always commits to the archive |
| `stage4_wide.jsonl` | 60 | full train pool, used to confirm a finalist before promotion |
| `train.jsonl` | 60 | the search-time corpus (= stage4_wide) |
| `test_subset100.jsonl` | 100 | the frozen held-out 100 the paper reports on (30 benign + 35 direct + 35 indirect) |
| `test_subset100.manifest.json` | — | the seed + per-category allocation that built the subset (reproducible) |

**The search only ever reads `train`/`stage*`; generalization is reported on the
held-out `test_subset100`.** The split is frozen — keep it that way, or your
held-out numbers stop being held-out. The actual episode content (tool servers,
fixtures) comes from DTAP itself; these files only *select* tasks.

`domains/<domain>/domain_spec.md` is the **authoritative contract** for each
domain — action model, threat model, scoring, and what counts as a successful
attack. **Read it first.** `experiences.md` is the design-note log the Analyzer
appends to during a search.

---

## 🚀 Quickstart

### 1. Stand up DTAP (the environment we defend)

```bash
git clone https://github.com/AI-secure/DecodingTrust-Agent.git
cd DecodingTrust-Agent
pip install -r requirements.txt && pip install -e .   # Docker required; datasets auto-cache
```

### 2. Apply the overlay + drop in the seed defenses

Pick a domain and a victim model — say **GLM-5 on os-filesystem**:

```bash
REL=/path/to/AutoSafeHarness
DT=/path/to/DecodingTrust-Agent           # your stock checkout from step 1

# (a) our code overlay (added + modified source files)
cp -r $REL/domains/os-filesystem/overlay/. $DT/

# (b) the baseline seed defenses, into DTAP's dt_defenses/
mkdir -p $DT/dt_defenses
cp -r $REL/domains/os-filesystem/defenses/_baselines/.  $DT/dt_defenses/
#   → dt_defenses/{dtap_def_v0 (no-defense), dtap_camel_v1, dtap_drift_v1}

# (c) the frozen splits + the eval drivers
cp -r $REL/domains/os-filesystem/splits   $DT/benchmarks/dtap/splits   # path per your DTAP layout
cp -r $REL/domains/os-filesystem/scripts  $DT/scripts
```

### 3. Configure the victim

```bash
cp $REL/.env.example $DT/.env && edit $DT/.env     # set DTAP_MODEL=bedrock/zai.glm-5 + your keys
```

The **victim model is chosen here**, in `.env` — never hardcoded — so the same
code defends/attacks any of the five panel models. A **judge proxy**
(permission/disclosure judge) must be up and **Docker** available (DTAP spins
per-task containers).

### 4. Search a defense (the loop)

`domains/<domain>/domain_spec.md` is written directly as the prompt for the
proposer, not a doc to read and translate yourself. Start a coding-agent session
in `$DT` and hand it that file:

```bash
cd $DT
claude "Follow @domain_spec.md to refine a secure agent harness for me in the \
os-filesystem domain. Keep working until you have nothing to refine."
```

In the paper this loop is driven by Claude Code (Opus 4.8, max effort); the spec
is agent-agnostic, so you can run it with your own coding agent instead. Inside
the loop, each iteration authors a new
`dtap_def_v<N>/{BUNDLE.md,defense.py,__init__.py}` candidate (warm-starting from
a seed) and scores it itself through the gated cascade:

```bash
# the agent runs this each iteration — Stage 0→3, score = utility − ASR:
scripts/cascade.py dtap_def_v1 --parent dtap_def_v0 --rationale "scope-vs-task gate"
```

`cascade.py` only scores a candidate that already exists on disk — it never
authors one. It writes every stage's scores and probe summaries into the
candidate's `meta.json`, which the agent reads before proposing the next
candidate. Iterate until the search converges on a best bundle for the cell.

### 5. Score on the frozen held-out 100

Ask the same agent session ("test `dtap_def_v5` on the held-out set") or run the
comparison platform yourself:

```bash
# edit eval_platform/configs/osfs_subset100.json: set env_root + the defenses to compare
python eval_platform/platform.py run     eval_platform/configs/osfs_subset100.json
python eval_platform/platform.py compare eval_platform/configs/osfs_subset100.json
# → results/<run>/comparison.md : utility, ASR (direct/indirect split), gate_TP, gate_benign_FP
```

A config lists the `defenses` to compare (e.g. `["dtap_def_v0", "dtap_camel_v1",
"dtap_drift_v1", "<your-best>"]`), the `env_root` of your DTAP checkout, and the
`testset` (`test_subset100`). The comparison table reports `utility%`, `ASR%`
(overall + direct/indirect split), `gate_TP` (malicious tasks refused), and
`gate_benign_FP` (the real utility cost). See `eval_platform/README.md` for the
full schema. Repeat across the three domains and five victims to rebuild the
15-cell grid from the paper.

---


## 📝 Citation


---

## 🙏 Acknowledgments

AutoSafeHarness builds directly on prior work, which we gratefully acknowledge:

- **[DecodingTrust-Agent (DTAP)](https://github.com/AI-secure/DecodingTrust-Agent)** —
  the multi-domain agent red-teaming platform our main results run on; it provides the
  tool servers, attack taxonomy, and per-task judges. ([paper](https://arxiv.org/abs/2605.04808))
- **[CaMeL](https://github.com/google-research/camel-prompt-injection)** (*Defeating Prompt
  Injections by Design*) — one of the security systems we warm-start the search from and port
  as a baseline.
- **[DRIFT](https://github.com/SaFo-Lab/DRIFT)** (*Dynamic Rule-based defense with Injection
  isolation For securing LLM agents*) — likewise a warm-start seed and a baseline we compare against.
- **[Meta-Harness](https://github.com/stanford-iris-lab/meta-harness)** (*End-to-End Optimization
  of Model Harnesses*) — the agentic harness-search framework whose proposer our search loop adopts.
