#!/usr/bin/env python3
"""Minimal OpenAI-compatible shim for the os-filesystem MCP permission judge.

The judge (dt_arena/mcp_server/os-filesystem/main.py :: _call_llm_for_permission)
issues a raw OpenAI-style POST {base_url}/chat/completions with Bearer auth and
reads choices[0].message.content. Bedrock's Converse API is not OpenAI-compatible
on the wire, so this shim accepts the OpenAI request and routes it to Bedrock via
the litellm SDK -- the same auth path (AWS_BEARER_TOKEN_BEDROCK / AWS_REGION) the
agent backbone uses. litellm.completion returns an OpenAI-shaped response, which we
pass through unchanged.

Default judge model: anthropic.claude-haiku-4-5-20251001-v1:0 on Bedrock.

Run:  python scripts/judge_proxy.py --port 4111
Env:  JUDGE_BEDROCK_MODEL (override), AWS_REGION, AWS_BEARER_TOKEN_BEDROCK
"""
import argparse
import os

import litellm
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

# Bedrock Converse is stricter than OpenAI; let litellm massage/drop params.
litellm.modify_params = True
litellm.drop_params = True

# Token/cost accounting: track the permission-judge's LiteLLM calls too, into the
# same shared cost log as the agent (broken down per model). Best-effort.
try:
    import sys
    from pathlib import Path
    _SRC = Path(__file__).resolve().parent.parent / "benchmarks" / "dtap-src"
    if _SRC.is_dir() and str(_SRC) not in sys.path:
        sys.path.insert(0, str(_SRC))
    import dtap_cost
    dtap_cost.install(verbose=False)
except Exception as _cost_e:
    print(f"[judge_proxy] dtap_cost unavailable: {_cost_e}")

# JUDGE_MODEL (preferred) lets the judge run on any litellm route (e.g.
# openrouter/deepseek/deepseek-v4-flash when Bedrock quota is unavailable);
# JUDGE_BEDROCK_MODEL is kept as a back-compat fallback.
DEFAULT_MODEL = os.getenv("JUDGE_MODEL") or os.getenv(
    "JUDGE_BEDROCK_MODEL", "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0"
)
AWS_REGION = os.getenv("AWS_REGION") or os.getenv("AWS_REGION_NAME") or "us-east-1"
# aws_region_name must be sent ONLY for Bedrock routes; passing it to OpenRouter
# (or any non-Bedrock route) is wrong. OpenRouter uses OPENROUTER_API_KEY from env.
_IS_BEDROCK_JUDGE = (DEFAULT_MODEL.startswith("bedrock/")
                     or DEFAULT_MODEL.startswith("zai.")
                     or "anthropic" in DEFAULT_MODEL.lower())
# For an OpenRouter deepseek judge, prefer one provider (cost/consistency) but KEEP
# fallbacks: a failed judge call silently corrupts utility (fail-closed denial), so
# the judge must stay robust even though the victim is pinned strictly.
_JUDGE_OR_PROVIDER = (os.getenv("OPENROUTER_DEEPSEEK_PROVIDER", "gmicloud").strip()
                      if (DEFAULT_MODEL.startswith("openrouter/")
                          and "deepseek" in DEFAULT_MODEL.lower())
                      else "")

app = FastAPI(title="judge-proxy")


@app.get("/health/readiness")
@app.get("/health")
async def health():
    return {"status": "ok", "model": DEFAULT_MODEL}


@app.post("/v1/chat/completions")
@app.post("/chat/completions")
async def chat_completions(request: Request):
    body = await request.json()
    # The judge sends model="<PERMISSION_LLM_MODEL>"; ignore it and pin DEFAULT_MODEL.
    kwargs = {
        "model": DEFAULT_MODEL,
        "messages": body.get("messages", []),
        "temperature": body.get("temperature", 0.1),
    }
    if _IS_BEDROCK_JUDGE:
        kwargs["aws_region_name"] = AWS_REGION
    if _JUDGE_OR_PROVIDER:
        kwargs["extra_body"] = {"provider": {"order": [_JUDGE_OR_PROVIDER],
                                             "allow_fallbacks": True}}
    max_tok = body.get("max_completion_tokens") or body.get("max_tokens") or 500
    kwargs["max_tokens"] = max_tok
    try:
        resp = await litellm.acompletion(**kwargs)
        return JSONResponse(resp.model_dump())
    except Exception as e:  # surface a 502 with detail so the judge logs it
        return JSONResponse(status_code=502, content={"error": {"message": str(e)}})


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=4111)
    args = ap.parse_args()
    print(f"[judge-proxy] routing -> {DEFAULT_MODEL} (region={AWS_REGION}) "
          f"on {args.host}:{args.port}")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
