<div align="center">

# EvoSafeHarness

### *Evolving model- and domain-specific harnesses for securing agents*

**Search the harness, not the model.**

[![Paper](https://img.shields.io/badge/paper-PDF-b31b1b)](https://andylinx.github.io/EvoSafeHarness/assets/EvoSafeHarness_paper.pdf)
[![Code](https://img.shields.io/badge/code-github-181717?logo=github)](https://github.com/SaFo-Lab/EvoSafeHarness)
[![Website](https://img.shields.io/badge/website-live-0a7d34)](https://andylinx.github.io/EvoSafeHarness/)

Nanxi Li<sup>1</sup> · Yingzi Ma<sup>2</sup> · Yulong Cao<sup>3</sup> · Edward Suh<sup>3</sup> · Bo Li<sup>4</sup> · Dawn Song<sup>5</sup> · Chaowei Xiao<sup>1,3</sup>

<sup>1</sup>Johns Hopkins University · <sup>2</sup>University of Wisconsin–Madison · <sup>3</sup>NVIDIA · <sup>4</sup>University of Illinois Urbana–Champaign · <sup>5</sup>UC Berkeley

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

**EvoSafeHarness** takes the opposite stance. It leaves the model frozen and instead
**searches the scaffolding around it** — the system prompt **and** the tool-call
hooks — reading the failure traces of the exact model it defends and scoring on
the exact domain it protects. The output is a concrete, runnable **defense
bundle**, one per `(model × domain)` cell.

---

## ⚙️ How it works

EvoSafeHarness runs an outer search loop around a **frozen victim model**. Each
iteration proposes a harness, tries to break it, scores it, and writes down what
was learned.

```
                   ┌────────────────────────────────────────────────────┐
  warm-start  ───▶ │  Designer ──▶ Criticizer ──▶ Cascade ──▶ Analyzer  │ ───▶  H*
 (DRIFT / CaMeL)   │     ▲        (anti-overfit)  (Stage 0→3)   (notes) │   (best bundle)
                   │     └───────────────── experience loop ────────────┘
                   └────────────────────────────────────────────────────┘
```

| Role | What it does |
|---|---|
| **Designer** | Reads the archive and the victim's failure traces, writes a new candidate bundle. |
| **Criticizer** | Fresh-context adversary: tries to break the candidate and flags anything keyed on a literal benchmark token. |
| **Cascade** | Gated scoring, Stage 0 static → 1 smoke → 2 mid → 3 search, `score = utility% − ASR%`, plus a robustness probe and an over-refusal probe. |
| **Analyzer** | Turns the run's failure traces into design notes fed to the next proposal. |

**The harness is a dual-surface bundle.** A candidate is one directory with a
natural-language surface and an executable surface:

```
dtap_def_v<N>/
├── BUNDLE.md     # policy + design rationale
├── defense.py    # system_prompt_transform · on_pre_tool_call · on_post_tool_call (+ state)
├── __init__.py   # build() factory
└── parent.txt    # parent candidate + mutation hypothesis
```

The three hooks are the whole contract. Anything expressible through them
(argument rewriting, recoverable blocking, provenance ledgers, semantic
auditors, verdict caches) is fair game for the proposer.

**The proposer is a coding agent.** Designer, Criticizer, and Analyzer are all
driven by [Claude Code](https://www.anthropic.com/claude-code) (Claude Opus 4.8,
max reasoning effort). It never participates in the defended agent at runtime,
so gains come from the returned harness, not from a stronger model in the loop.
The domain spec is agent-agnostic, so any coding agent can drive the search.

---

## 📂 Repository layout

```
domains/<domain>/            # finance · os-filesystem · telecom
├── domain_spec.md           # the domain contract, also the prompt handed to the proposer
├── splits/                  # frozen task lists: stage1_smoke … stage4_wide, train, test_subset100
├── defenses/_baselines/     # seed bundles: dtap_def_v0 (none), dtap_camel_v1, dtap_drift_v1
└── scripts/                 # cascade.py and the probes
eval_platform/               # held-out comparison runner (see eval_platform/README.md)
```

The search reads only `train` / `stage*`; results are reported on the frozen
held-out `test_subset100` (30 benign + 35 direct + 35 indirect). Keep the split
frozen. Episode content itself comes from DTAP; these files only select tasks.

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
REL=/path/to/EvoSafeHarness
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

```bibtex
@article{evosafeharness2026,
  title   = {EvoSafeHarness: Evolving Model- and Domain-Specific Harnesses for Securing Agents},
  author  = {Li, Nanxi and Ma, Yingzi and Cao, Yulong and Suh, Edward and Li, Bo and Song, Dawn and Xiao, Chaowei},
  year    = {2026}
}
```

---

## 🙏 Acknowledgments

EvoSafeHarness builds directly on prior work, which we gratefully acknowledge:

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
